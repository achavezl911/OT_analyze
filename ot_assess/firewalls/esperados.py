"""M6: servicios de infraestructura que cabria esperar por zona y no se vieron cruzar, y cobertura temporal (D69).

Una politica "desde cero" se rompe con lo que no aparecio en la ventana (autenticacion contra el AD, actualizaciones,
respaldos, NTP, syslog, SNMP, tareas mensuales). Aqui no se agrega ninguna regla ni ningun hallazgo: se generan
preguntas para el cliente y la regla que habria que sumar si la respuesta es si. Es una limitacion de la evidencia,
no un riesgo del cliente. El catalogo vive en data/servicios_esperados.json; las condiciones son heuristicas simples
documentadas en D69. Funciones puras sobre el modelo ya calculado.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path

from ..i18n import t

CATALOGO = Path(__file__).resolve().parent.parent / "data" / "servicios_esperados.json"
VENTANA_CORTA_DIAS = 7
VENTANA_MENSUAL_DIAS = 31
MAX_FILAS = 500
COLUMNAS = ["zona", "interfaz", "servicio", "puertos", "motivo", "observado", "pregunta", "regla_sugerida"]
HOJA = "Servicios esperados"
ARCHIVO = "esperados_no_observados.csv"
COLUMNAS_CLIENTE = ["n", "servicio", "puertos", "zonas", "n_zonas", "equipos", "observado", "pregunta",
                    "regla_sugerida"]
HOJA_CLIENTE = "Preguntas al cliente"
ARCHIVO_CLIENTE = "preguntas_cliente.csv"
MAX_ZONAS_TEXTO = 10     # en la pregunta agrupada se nombran hasta 10 zonas; la columna zonas lleva todas

# Heuristica "equipo Windows": sistema operativo del inventario o trafico tipico de Windows desde o hacia el equipo.
PUERTOS_WINDOWS = frozenset({(445, "tcp"), (139, "tcp"), (137, "udp"), (138, "udp"), (3389, "tcp"),
                             (88, "tcp"), (88, "udp"), (135, "tcp")})
CAMPOS_SO = ("os", "sistema_operativo", "modelo", "firmware")
TEXTO_WINDOWS = "windows"
CAMPOS_TIPO = ("tipo_texto", "role", "tipo")
TIPOS_RED = ("switch", "router", "firewall", "access point", "punto de acceso")
TIPOS_OT = ("plc", "hmi", "rtu", "ied", "scada", "dcs", "historian", "historiador")
TIPOS_HISTORIADOR = ("historian", "historiador")

O_NO = "no"
O_DENTRO = "solo dentro de la zona"
O_NO_VERIFICABLE = "no verificable"
PREGUNTA_DENTRO = ("El servicio {servicio} se vio dentro de {zonas} pero no cruza el firewall. ¿Se resuelve con un "
                   "servidor de la misma zona? Confirmar que los {n} equipos no necesitan uno fuera de su zona.")
PREGUNTA_DENTRO_1 = ("El servicio {servicio} se vio dentro de {zonas} pero no cruza el firewall. ¿Se resuelve con un "
                     "servidor de la misma zona? Confirmar que el equipo no necesita uno fuera de su zona.")
REGLA_DENTRO = ("Sin regla si se resuelve dentro de la zona; si no, permitir {puertos} desde {zonas} hacia el "
                "servidor de {servicio} a confirmar, con registro.")
MOTIVOS = {
    "activos": "{n} activos en la zona",
    "windows": "{n} equipos Windows (sistema operativo del inventario o trafico SMB, RDP, Kerberos, NetBIOS o RPC)",
    "red_ot": "{n} activos de red u OT",
    "activos_red": "{n} activos de red",
    "historiador": "{n} historiadores",
}
MOTIVOS_1 = {      # variante para un solo equipo
    "activos": "1 activo en la zona",
    "windows": "1 equipo Windows (sistema operativo del inventario o trafico SMB, RDP, Kerberos, NetBIOS o RPC)",
    "red_ot": "1 activo de red u OT",
    "activos_red": "1 activo de red",
    "historiador": "1 historiador",
}
MOTIVO_GENERAL = "la evidencia cubre {dias} dias, menos de {m}"
NOTA = ("Preguntas para el cliente sobre servicios que cabria esperar y no se vieron cruzar el firewall en la "
        "ventana de las fuentes. No es un hallazgo ni un riesgo del cliente: es una limitacion de la evidencia.")


def catalogo(ruta=None) -> dict:
    return json.loads(Path(ruta or CATALOGO).read_text(encoding="utf-8"))


def _texto(a: dict, campos) -> str:
    return " ".join(str(a.get(k) or "") for k in campos).lower()


def _es_windows(a: dict) -> bool:
    if TEXTO_WINDOWS in _texto(a, CAMPOS_SO):
        return True
    return any(TEXTO_WINDOWS in (str(i.get("valor", "")) + " " + str(i.get("detalle", ""))).lower()
               for i in a.get("identidad") or () if isinstance(i, dict))


def _categorias(a: dict) -> set:
    """{'windows', 'red', 'ot', 'historiador'} de un activo del inventario."""
    from .politica import NIVELES_OT
    out = set()
    if _es_windows(a):
        out.add("windows")
    tipo = _texto(a, CAMPOS_TIPO + ("modelo",))
    if any(x in tipo for x in TIPOS_RED):
        out.add("red")
    if a.get("purdue") in NIVELES_OT or any(x in tipo for x in TIPOS_OT):
        out.add("ot")
    if any(x in tipo + " " + str(a.get("nombre") or "").lower() for x in TIPOS_HISTORIADOR):
        out.add("historiador")
    return out


def _coincide(conducto: tuple, puerto: int, l4: str) -> bool:
    return conducto[0] == puerto and (not conducto[1] or not l4 or conducto[1] == l4)


def calcular(fw, d: dict, conductos: list, assets: dict, ip_de, zona_de, cat=None) -> dict:
    """{'filas': [...], 'truncadas': n}: servicios esperados por interfaz del firewall que no cruzaron.

    `zona_de(interfaz)` da el nombre de la zona; `d` es integracion.contrastar de ese firewall.
    """
    from .cruces import _global, _puerto
    cat = cat or catalogo()
    cache: dict = {}

    def interfaz(ip):
        if ip not in cache:
            cache[ip] = None if _global(ip) else fw.interfaz_de(ip)
        return cache[ip]
    clave_ip = {ip: k for k, a in (assets or {}).items() for ip in a.get("ips") or ()}
    ents: dict = {}          # interfaz -> {entidad: activo o None}
    windows: dict = {}       # interfaz -> {entidad}

    def entidad(ip, trafico_windows=False):
        ifc = interfaz(ip)
        if not ifc:
            return
        k = clave_ip.get(ip)
        e = k if k is not None else ip
        ents.setdefault(ifc, {})[e] = assets[k] if k is not None else None
        if trafico_windows:
            windows.setdefault(ifc, set()).add(e)
    for a in (assets or {}).values():
        for ip in sorted(a.get("ips") or ()):
            entidad(ip)
    cruzan: set = set()      # (interfaz de origen, puerto, l4)
    dentro: set = set()      # (interfaz, puerto, l4) con origen y destino en la misma interfaz
    for i, c in enumerate(conductos):
        s, dd = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        puerto, l4 = _puerto(c), str(c.get("l4") or "").strip().lower()
        win = (puerto, l4) in PUERTOS_WINDOWS
        entidad(s, win)
        entidad(dd, win)
        if puerto is None:
            continue
        r = d["resultados"][i]
        if r["resultado"] not in ("no_cruza", "respuesta"):
            cruzan.add((r["if_origen"], puerto, l4))
        elif r["resultado"] == "no_cruza" and interfaz(s) and interfaz(s) == interfaz(dd):
            dentro.add((interfaz(s), puerto, l4))
    for ifc, es in ents.items():
        for e, a in es.items():
            if a is not None and _es_windows(a):
                windows.setdefault(ifc, set()).add(e)

    def vio(conj, ifc, puertos):
        return any((ifc, p["puerto"], p["l4"]) in conj or (ifc, p["puerto"], "") in conj for p in puertos)
    filas = []
    for ifc in sorted(ents, key=lambda x: (zona_de(x), x)):
        zona = zona_de(ifc)
        cats = {e: (_categorias(a) if a is not None else set()) for e, a in ents[ifc].items()}
        cuenta = {
            "activos": len(cats),
            "windows": len(windows.get(ifc, ())),
            "red_ot": sum(1 for v in cats.values() if v & {"red", "ot"}),
            "activos_red": sum(1 for v in cats.values() if "red" in v),
            "historiador": sum(1 for v in cats.values() if "historiador" in v)}
        for sv in cat["servicios"]:
            n = cuenta[sv["condicion"]]
            if not n:
                continue
            puertos = ", ".join(p["l4"] + "/" + str(p["puerto"]) for p in sv["puertos"])
            kw = {"zonas": [zona], "n": n, "servicio": sv["servicio"], "puertos": puertos}
            if not sv["puertos"]:
                obs = O_NO_VERIFICABLE
            elif vio(cruzan, ifc, sv["puertos"]):
                continue
            else:
                obs = O_DENTRO if vio(dentro, ifc, sv["puertos"]) else O_NO
            filas.append({
                "zona": zona, "interfaz": ifc, "servicio": sv["servicio"], "puertos": puertos,
                "motivo": (MOTIVOS[sv["condicion"]], {"n": n}), "motivo_1": MOTIVOS_1[sv["condicion"]],
                "observado": obs,
                "pregunta": (PREGUNTA_DENTRO if obs == O_DENTRO else sv["pregunta"], kw),
                "pregunta_1": PREGUNTA_DENTRO_1 if obs == O_DENTRO else sv.get("pregunta_1", sv["pregunta"]),
                "regla_sugerida": (REGLA_DENTRO if obs == O_DENTRO else sv["regla_sugerida"], kw)})
    return {"filas": filas[:MAX_FILAS], "truncadas": max(len(filas) - MAX_FILAS, 0), "generales": []}


def _dia(texto):
    try:
        return datetime.date.fromisoformat(str(texto).strip()[:10])
    except ValueError:
        return None


def _dia_epoch(x):
    try:
        return datetime.datetime.fromtimestamp(float(x), datetime.timezone.utc).date()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _fuente(nombre: str, tipo: str, a, b) -> dict:
    return {"fuente": nombre, "tipo": tipo, "primera": a.isoformat(), "ultima": b.isoformat(),
            "dias": (b - a).days + 1}


def cobertura(caps=(), conductos=()) -> dict:
    """Cobertura temporal por fuente y total (union de dias calendario, UTC).

    Capturas: cap.ventana (epoch, T5) o, sin ella, los tiempos del primer y ultimo paquete de capinfos.
    Exportaciones: primera y ultima de los conductos (las que usa la columna `dias` de la propuesta), por fuente si
    los conductos traen `fuentes`. Se toma el rango continuo entre la primera y la ultima fecha de cada fuente.
    """
    fuentes, rangos = [], []
    for c in caps or ():
        a = b = None
        if len(getattr(c, "ventana", ()) or ()) == 2:
            a, b = _dia_epoch(c.ventana[0]), _dia_epoch(c.ventana[1])
        if a is None or b is None:
            info = getattr(c, "info", None) or {}
            a, b = _dia(info.get("First packet time")), _dia(info.get("Last packet time"))
        if a is None or b is None:
            continue
        fuentes.append(_fuente(getattr(c, "name", "") or str(getattr(c, "path", "")), "captura", a, b))
        rangos.append((a, b))
    por: dict = {}
    for k in conductos or ():
        a, b = _dia(k.get("primera")), _dia(k.get("ultima"))
        if a is None or b is None:
            continue
        for nombre in k.get("fuentes") or ("exportacion",):
            r = por.get(nombre)
            por[nombre] = (min(r[0], a), max(r[1], b)) if r else (a, b)
    for nombre in sorted(por):
        fuentes.append(_fuente(nombre, "exportacion", *por[nombre]))
        rangos.append(por[nombre])
    dias: set = set()
    for a, b in rangos:
        dias.update(a + datetime.timedelta(days=n) for n in range((b - a).days + 1))
    total = len(dias)
    return {"fuentes": sorted(fuentes, key=lambda f: (f["tipo"], f["fuente"])), "dias": total,
            "primera": min(dias).isoformat() if dias else "", "ultima": max(dias).isoformat() if dias else "",
            "corta": total < VENTANA_CORTA_DIAS, "menor_que_mensual": total < VENTANA_MENSUAL_DIAS}


def aplicar(pol: dict, cob: dict, cat=None) -> None:
    """Guarda la cobertura en la politica y suma, una vez, las preguntas generales al primer firewall."""
    cat = cat or catalogo()
    pol["cobertura"] = cob
    if cob["menor_que_mensual"] and pol["firewalls"]:
        pol["firewalls"][0]["esperados"]["generales"] = [
            {"zona": "", "interfaz": "", "servicio": g["servicio"], "puertos": "",
             "motivo": (MOTIVO_GENERAL, {"dias": cob["dias"], "m": VENTANA_MENSUAL_DIAS}), "observado": O_NO,
             "pregunta": (g["pregunta"], {}), "regla_sugerida": (g["regla_sugerida"], {})}
            for g in cat["generales"]]
    pol["preguntas"] = sum(len(p["esperados"]["filas"]) + len(p["esperados"]["generales"])
                           for p in pol["firewalls"])
    pol["preguntas_cliente"] = len(agrupar(pol))


def lista(nombres, tope=None) -> str:
    """'A', 'A y B', 'A, B y C'; con tope y mas nombres: 'A, B, ... y N mas'."""
    nombres = list(nombres)
    if tope and len(nombres) > tope:
        return ", ".join(nombres[:tope]) + t(" y {k} mas", k=len(nombres) - tope)
    if len(nombres) < 2:
        return "".join(nombres)
    return t("{a} y {b}", a=", ".join(nombres[:-1]), b=nombres[-1])


def frase_zonas(zonas) -> str:
    """'la zona A' o 'las zonas A, B y C' (en ingles 'zone A' / 'zones A, B and C')."""
    if len(zonas) == 1:
        return t("la zona {z}", z=zonas[0])
    return t("las zonas {z}", z=lista(zonas, MAX_ZONAS_TEXTO))


def texto(f: dict, clave: str) -> str:
    """Texto de `pregunta`, `motivo` o `regla_sugerida` de una fila: variante singular si n = 1, zonas en frase."""
    plantilla, kw = f[clave]
    kw = dict(kw)
    if kw.get("n") == 1 and clave + "_1" in f:
        plantilla = f[clave + "_1"]
    if "zonas" in kw:
        kw["zonas"] = frase_zonas(kw["zonas"])
    return t(plantilla, **kw)


def filas(e: dict) -> list:
    """Filas del CSV (servicios por zona y luego las generales), con el texto ya traducido."""
    return [[f["zona"], f["interfaz"], t(f["servicio"]), f["puertos"], texto(f, "motivo"),
             t(f["observado"]), texto(f, "pregunta"), texto(f, "regla_sugerida")]
            for f in e["filas"] + e["generales"]]


def agrupar(pol: dict) -> list:
    """Preguntas para el cliente: una por servicio + puertos + observado, juntando zonas y firewalls.

    Cada elemento sirve a `texto()` como una fila (pregunta, regla_sugerida) y trae `zonas` (todas) y `equipos`.
    Orden: mas zonas, mas equipos, servicio; las generales (sin zona) van una sola vez al final.
    """
    grupos: dict = {}
    generales: dict = {}
    for p in pol["firewalls"]:
        for f in p["esperados"]["filas"]:
            g = grupos.setdefault((f["servicio"], f["puertos"], f["observado"]), {"base": f, "zonas": set(), "n": 0})
            g["zonas"].add(f["zona"])
            g["n"] += f["pregunta"][1]["n"]
        for f in p["esperados"]["generales"]:
            generales.setdefault(f["servicio"], f)
    out = []
    for (servicio, puertos, obs), g in grupos.items():
        f, zonas = g["base"], sorted(g["zonas"])
        kw = dict(f["pregunta"][1], zonas=zonas, n=g["n"])
        out.append({"servicio": servicio, "puertos": puertos, "observado": obs, "zonas": zonas, "equipos": g["n"],
                    "pregunta": (f["pregunta"][0], kw), "pregunta_1": f["pregunta_1"],
                    "regla_sugerida": (f["regla_sugerida"][0], dict(kw))})
    out.sort(key=lambda g: (-len(g["zonas"]), -g["equipos"], g["servicio"], g["puertos"], g["observado"]))
    for servicio in sorted(generales):
        f = generales[servicio]
        out.append({"servicio": servicio, "puertos": "", "observado": f["observado"], "zonas": [], "equipos": "",
                    "pregunta": f["pregunta"], "regla_sugerida": f["regla_sugerida"]})
    return out


def filas_cliente(pol: dict) -> list:
    """Filas de preguntas_cliente.csv, ya traducidas."""
    return [[i, t(g["servicio"]), g["puertos"], lista(g["zonas"]), len(g["zonas"]) if g["zonas"] else "",
             g["equipos"], t(g["observado"]), texto(g, "pregunta"), texto(g, "regla_sugerida")]
            for i, g in enumerate(agrupar(pol), 1)]


def texto_cobertura(cob: dict) -> str:
    if not cob["dias"]:
        return t("Cobertura temporal de la evidencia: sin fechas en las fuentes.")
    txt = t("Cobertura temporal de la evidencia: {dias} dias ({a} a {b}), {n} fuentes.", dias=cob["dias"],
            a=cob["primera"], b=cob["ultima"], n=len(cob["fuentes"]))
    if cob["corta"]:
        txt += " " + t("Ventana corta (menos de {c} dias): lo semanal puede no haber aparecido.",
                       c=VENTANA_CORTA_DIAS)
    elif cob["menor_que_mensual"]:
        txt += " " + t("Menos de {m} dias: las tareas mensuales pueden no haber aparecido.", m=VENTANA_MENSUAL_DIAS)
    return txt


def texto_resumen(pol: dict) -> str:
    """Linea para el encabezado de la propuesta; vacia si no hay cobertura calculada."""
    cob = pol.get("cobertura")
    if not cob:
        return ""
    return texto_cobertura(cob) + " " + t(
        "{q} preguntas por zona sobre servicios esperados no observados (esperados_no_observados.csv), "
        "{g} para el cliente en preguntas_cliente.csv.", q=pol["preguntas"], g=pol["preguntas_cliente"])


def registrar(res_fw: dict, caps=(), conductos=()) -> str:
    """Calcula y guarda la cobertura en res_fw['politica']; devuelve la linea para la consola ('' sin politica)."""
    pol = (res_fw or {}).get("politica")
    if not pol or not pol.get("firewalls"):
        return ""
    aplicar(pol, cobertura(caps, conductos))
    return texto_resumen(pol)
