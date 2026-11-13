"""FWLOG (D137): registro de eventos en firewalls y switches, desde la configuracion cargada.

Con la clave de perfil `registro_red` ({} vale) lee dos cosas que la herramienta ya tenia y no usaba: si cada regla
activa de firewall que permite trafico registra (Regla.registro) y a que destinos de syslog envia cada switch
(`logging host`, `logging trap`). Cruza los destinos con los colectores que declara el proyecto y con los colectores
que G1a observo en la captura. Es evidencia de la configuracion cargada: no prueba que los registros lleguen ni
dictamina cumplimiento. Del firewall solo usa la politica ya leida. Sin la clave no hace nada.
Funciones puras sobre el modelo ya calculado.
"""
from __future__ import annotations

import ipaddress
import os

from .i18n import t, unir

CLAVE = "registro_red"
ARCHIVO = "registro_red.csv"
HOJA = "Registro de red"
TITULO = "Registro de eventos en firewalls y switches"
COLUMNAS = ["equipo", "tipo", "plataforma", "destinos_syslog", "nivel_syslog", "destino_declarado",
            "reglas_que_permiten", "reglas_sin_registro", "ids_sin_registro", "colector_observado"]
COL_SECCION = ["equipo", "tipo", "destinos_syslog", "nivel_syslog", "destino_declarado", "reglas_que_permiten",
               "reglas_sin_registro", "colector_observado"]

TIPO_FW, TIPO_SW = "firewall", "switch"
SI, NO, SIN_DATO = "si", "no", "sin dato"
SIN_COLECTORES = "sin colectores declarados"
PLATAFORMA_SW = {"cli": "Cisco IOS/IOS-XE", "aoscx": "Aruba AOS-CX", "snmp": "SNMP"}

TIT_FW = "Reglas de firewall que permiten trafico sin registro (segun la configuracion del firewall)"
TIT_SW = "Switches sin envio de registros a un colector (segun la configuracion del switch)"

MAX_COLECTORES = 50
MAX_EXCLUIR = 500
MAX_TEXTO = 100
MAX_IDS = 20
MAX_SECCION = 30

NOTA = ("Evidencia de la configuracion cargada, no un dictamen de cumplimiento ni prueba de que los registros "
        "lleguen a un colector. Firewall: reglas activas que permiten trafico (sin la regla de defecto ni las "
        "excluidas en el perfil) y si registran segun su politica. Switch: destinos de syslog de la configuracion y "
        "nivel de envio; un switch sin configuracion cargada queda sin dato. Destino declarado: algun destino cae en "
        "los colectores que declara el proyecto. Colector observado: la IP de un destino o de un colector declarado "
        "aparece como colector en las fuentes de log observadas (G1a).")
AVISO = ("[!] registro_red: no hay firewall ni switches con configuracion cargada (--firewall, --switch); no se "
         "genera la tabla ni los hallazgos")


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #


def validar(v, fallo, objeto) -> dict:
    """Normaliza la clave de perfil `registro_red` ({} vale)."""
    v = objeto(v, CLAVE, ("colectores", "excluir_reglas"))
    out: dict = {"colectores": [], "excluir_reglas": []}
    c = v.get("colectores", [])
    if not isinstance(c, list) or len(c) > MAX_COLECTORES:
        fallo(f"'{CLAVE}.colectores' debe ser una lista de 0 a {MAX_COLECTORES} IP o redes CIDR.")
    for x in c:
        if not isinstance(x, str) or not x.strip():
            fallo(f"'{CLAVE}.colectores': '{x}' debe ser un texto con una IP o una red CIDR.")
        try:
            ipaddress.ip_network(x.strip(), strict=False)
        except ValueError:
            fallo(f"'{CLAVE}.colectores': '{x}' no es una IP ni una red valida.")
    out["colectores"] = list(dict.fromkeys(x.strip() for x in c))
    e = v.get("excluir_reglas", [])
    if not isinstance(e, list) or len(e) > MAX_EXCLUIR:
        fallo(f"'{CLAVE}.excluir_reglas' debe ser una lista de 0 a {MAX_EXCLUIR} ids o nombres de regla.")
    for x in e:
        if not isinstance(x, str) or not 1 <= len(x.strip()) <= MAX_TEXTO:
            fallo(f"'{CLAVE}.excluir_reglas' debe contener textos de 1 a {MAX_TEXTO} caracteres.")
    out["excluir_reglas"] = list(dict.fromkeys(x.strip() for x in e))
    return out


# --------------------------------------------------------------------------- #
# Construccion
# --------------------------------------------------------------------------- #


def _redes(textos) -> list:
    return [ipaddress.ip_network(x, strict=False) for x in textos]


def _ip(s):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _en(redes, ip) -> bool:
    return ip is not None and any(ip.version == r.version and ip in r for r in redes)


def _firewalls(fw: dict) -> list:
    """[(id, fabricante, reglas)] de lo que trae la politica ya leida; vacio sin reglas."""
    if not fw:
        return []
    if fw.get("firewalls"):
        return [(x["id"], x["fabricante"], x["datos"].get("reglas") or []) for x in fw["firewalls"]]
    if fw.get("reglas"):
        ident = fw.get("hostname") or os.path.basename(str(fw.get("archivo", ""))) or TIPO_FW
        return [(ident, fw.get("fabricante", ""), fw["reglas"])]
    return []


def _fila_fw(ident: str, fab: str, reglas: list, excluir: set) -> dict:
    permiten, sin = 0, []
    for r in reglas:
        if "registro" not in r or not r.get("activa", True) or r["accion"] not in ("permitir", "confiar"):
            continue
        if r.get("defecto") or {r["id"], r["nombre"], f"{ident}:{r['id']}"} & excluir:
            continue
        permiten += 1
        if not r["registro"]:
            sin.append(r)
    return {"equipo": ident, "tipo": TIPO_FW, "plataforma": fab, "destinos": [], "nivel": "",
            "declarado": "", "permiten": permiten, "sin": sin, "observado": SIN_DATO, "config": True}


def _fila_sw(sw, declarados: list) -> dict:
    destinos = list(sw.syslog_destinos)
    if not sw.config:
        decl = SIN_DATO
    elif not declarados:
        decl = SIN_COLECTORES
    else:
        decl = SI if any(_en(declarados, _ip(d)) for d in destinos) else NO
    return {"equipo": sw.hostname or sw.archivo or TIPO_SW, "tipo": TIPO_SW,
            "plataforma": PLATAFORMA_SW.get(sw.origen, sw.origen), "destinos": destinos, "nivel": sw.syslog_nivel,
            "declarado": decl, "permiten": None, "sin": [], "observado": SIN_DATO, "config": sw.config}


def construir(firewall: dict, switches: dict, perfil) -> dict:
    """{'filas', 'colectores', 'excluir_reglas'}; {} sin la clave de perfil. Con la clave y sin equipos,
    'filas' queda vacio (el CLI avisa)."""
    cfg = (perfil or {}).get(CLAVE)
    if cfg is None:
        return {}
    declarados = _redes(cfg["colectores"])
    excluir = set(cfg["excluir_reglas"])
    filas = [_fila_fw(i, f, r, excluir) for i, f, r in _firewalls(firewall)]
    filas += [_fila_sw(sw, declarados) for sw in (switches or {}).get("switches", ())]
    return {"filas": filas, "colectores": list(cfg["colectores"]), "excluir_reglas": list(cfg["excluir_reglas"])}


def completar(rr: dict, fuentes_log) -> None:
    """Llena colector_observado con los colectores de G1a (corre despues de fuentes_log.construir)."""
    if not hay(rr):
        return
    obs = [ip for ip in (_ip(c.get("ip", "")) for c in (fuentes_log or {}).get("colectores", ())) if ip]
    declarados = _redes(rr["colectores"])
    for f in rr["filas"]:
        if not obs:
            f["observado"] = SIN_DATO
            continue
        ips = [ip for ip in (_ip(d) for d in f["destinos"]) if ip]
        if not ips and not declarados:
            f["observado"] = SIN_DATO
            continue
        visto = any(ip in obs for ip in ips) or any(_en(declarados, o) for o in obs)
        f["observado"] = SI if visto else NO


def hay(rr: dict) -> bool:
    return bool(rr and rr.get("filas"))


def aviso(rr: dict) -> str:
    """Texto de consola cuando la clave esta y no hay equipos; vacio en cualquier otro caso."""
    return AVISO if rr and not rr.get("filas") else ""


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def _ids(f: dict) -> list:
    return [str(r["id"]) for r in f["sin"][:MAX_IDS]]


def fila_tabla(f: dict) -> list:
    fw = f["tipo"] == TIPO_FW
    return [f["equipo"], t(f["tipo"]), f["plataforma"], ";".join(f["destinos"]), f["nivel"],
            t(f["declarado"]) if f["declarado"] else "", f["permiten"] if fw else "", len(f["sin"]) if fw else "",
            ";".join(_ids(f)), t(f["observado"])]


def tablas(rr: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(rr):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, [fila_tabla(f) for f in rr["filas"]])]


def cuenta(rr: dict) -> dict:
    fws = [f for f in rr["filas"] if f["tipo"] == TIPO_FW]
    sws = [f for f in rr["filas"] if f["tipo"] == TIPO_SW]
    return {"firewalls": len(fws), "switches": len(sws),
            "reglas_que_permiten": sum(f["permiten"] for f in fws),
            "reglas_sin_registro": sum(len(f["sin"]) for f in fws),
            "switches_sin_syslog": sum(1 for f in sws if f["config"] and not f["destinos"]),
            "switches_destino_no_declarado": sum(1 for f in sws if f["declarado"] == NO)}


def resumen_texto(rr: dict) -> str:
    c = cuenta(rr)
    return t("{f} firewalls con {p} reglas activas que permiten trafico, {s} sin registro; {w} switches, {x} sin "
             "destino de syslog y {y} sin ningun destino entre los colectores declarados. Detalle en "
             "registro_red.csv.", f=c["firewalls"], p=c["reglas_que_permiten"], s=c["reglas_sin_registro"],
             w=c["switches"], x=c["switches_sin_syslog"], y=c["switches_destino_no_declarado"])


def seccion(rr: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    mas = len(rr["filas"]) - MAX_SECCION
    ix = [COLUMNAS.index(c) for c in COL_SECCION]
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_texto(rr), "cab": [t(c) for c in COL_SECCION],
            "filas": [[fila_tabla(f)[i] for i in ix] for f in rr["filas"][:MAX_SECCION]],
            "mas": t("Se muestran {n} filas; {m} mas estan en registro_red.csv.", n=MAX_SECCION, m=mas)
            if mas > 0 else ""}


def para_json(rr: dict) -> dict:
    if not hay(rr):
        return {}
    filas = []
    for f in rr["filas"]:
        fila = dict(zip(COLUMNAS, fila_tabla(f)))
        fila.update(destinos_syslog=f["destinos"], ids_sin_registro=_ids(f), destino_declarado=f["declarado"],
                    colector_observado=f["observado"], tipo=f["tipo"])
        filas.append(fila)
    return {"conteos": cuenta(rr), "colectores": rr["colectores"], "excluir_reglas": rr["excluir_reglas"],
            "filas": filas, "nota": t(NOTA)}


# --------------------------------------------------------------------------- #
# Hallazgos
# --------------------------------------------------------------------------- #


def _regla(r: dict) -> str:
    nom = f" ({r['nombre']})" if r["nombre"] else ""
    zonas = f" [{r['interfaces_origen'] or '*'} -> {r['interfaces_destino'] or '*'}]"
    return f"{r['id']}{nom}{zonas}"


def agregar_hallazgos(cap, rr: dict) -> None:
    """Hallazgos del registro en 'cap' (un Capture de extras). Marcas para el equipo, no cumplimiento."""
    from .rules.base import finding

    if not hay(rr):
        return
    fws = [f for f in rr["filas"] if f["tipo"] == TIPO_FW and f["sin"]]
    if fws:
        total = sum(len(f["sin"]) for f in fws)
        partes = [t("{fw}: {n} de {p} reglas que permiten: {lista}", fw=f["equipo"], n=len(f["sin"]),
                    p=f["permiten"], lista="; ".join(_regla(r) for r in f["sin"][:MAX_IDS])
                    + (" " + t("y {n} mas", n=len(f["sin"]) - MAX_IDS) if len(f["sin"]) > MAX_IDS else ""))
                  for f in fws]
        finding(cap, "Media", TIT_FW,
                unir("\n", [t("Reglas activas que permiten trafico sin registro: {n}. Detalle en registro_red.csv.",
                              n=total)] + partes),
                "Una regla que permite trafico sin registrarlo no deja huella en el firewall: ante un incidente "
                "no hay forma de reconstruir quien cruzo la frontera entre zonas ni de detectar un uso anomalo.",
                "Activar el registro al final de la conexion en las reglas que permiten, empezando por las que "
                "cruzan hacia zonas de control, y enviar los eventos al colector del proyecto; en ventana y con el "
                "dueno del proceso, porque el registro aumenta la carga del equipo y el volumen de eventos.",
                "Higiene", activos=[ip for f in fws for r in f["sin"] for ip in r.get("ips", ())])
    sws = [f for f in rr["filas"] if f["tipo"] == TIPO_SW and f["config"]
           and (not f["destinos"] or f["declarado"] == NO)]
    if sws:
        partes = [t("{h}: sin destino de syslog", h=f["equipo"]) if not f["destinos"]
                  else t("{h}: destinos {d}, ninguno entre los colectores declarados", h=f["equipo"],
                         d=";".join(f["destinos"])) for f in sws]
        finding(cap, "Baja", TIT_SW,
                unir("\n", [t("Switches: {n}.", n=len(sws))] + partes),
                "Un switch que no envia sus registros a un colector deja los eventos de acceso, cambios de "
                "configuracion y fallas de enlace solo en su memoria local, que se pierde al reiniciar.",
                "Configurar el envio de syslog hacia el colector del proyecto (logging host o logging <ip> en "
                "AOS-CX), con un nivel que incluya cambios de configuracion y eventos de seguridad, y confirmar la "
                "recepcion en el colector.", "Higiene")
