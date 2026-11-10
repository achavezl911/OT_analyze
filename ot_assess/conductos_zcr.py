"""Z1b (D51): conductos entre zonas (ZCR de IEC 62443-3-2), brechas, diagrama y hallazgos.

Agrupa los conductos observados por par NO ordenado de zonas (las de Z1a), con sus servicios, equipos,
firewalls del camino, reglas actuales y propuesta. Las brechas son marcas para revisar, no juicios: el
reporte nunca dice "cumple" ni "no cumple". Funciones puras sobre el modelo ya calculado.
"""
from __future__ import annotations

import collections
import ipaddress
import re

from .firewalls import cruces as _cr
from .i18n import t
from .zonas import mostrar_zona

SLUG = "diagrama_zcr"
TITULO = "Zonas y conductos"
HOJA = "Conductos (ZCR)"
ARCHIVO = "conductos_zcr.csv"
COLUMNAS = ["id", "zona_a", "zona_b", "conductos", "sentido", "servicios", "activos_a", "activos_b", "bytes",
            "firewalls", "reglas", "propuesta", "etiquetas", "sl_t", "brechas"]
MAX_SERVICIOS = 10
MAX_REGLAS = 5
MAX_TABLA = 20
MAX_DIAGRAMA = 40
MAX_EVIDENCIA = 20
INTERNET = "Internet"

B_SIN_FW = "sin firewall observado"
B_RIESGO = "servicios de riesgo"
B_SALTA = "salta niveles Purdue"
B_SL = "SL-T distinto"
B_INFERIDA = "zona inferida"
BRECHAS = [B_SIN_FW, B_RIESGO, B_SALTA, B_SL, B_INFERIDA]
SIN_DATOS_FW = "sin datos de firewall"
NINGUNO_FW = "ninguno observado"
_RIESGO = (_cr.ACCESO_REMOTO, _cr.CLARO, _cr.ARCHIVOS, _cr.DNS_EXT)
_NIVEL = re.compile(r"^Nivel (\d+(?:\.\d+)?)(?:-(\d+(?:\.\d+)?))?$")
_SL = re.compile(r"(\d+)")

TIT_SIN_FW = "Conductos entre zonas sin firewall observado en el camino (segun las zonas del analisis)"
TIT_RIESGO = "Conductos entre zonas con servicios de riesgo (segun las zonas del analisis)"
TIT_SALTA = "Conductos que saltan niveles Purdue (segun las zonas del analisis)"

NOTA = ("Los conductos entre zonas agrupan los conductos observados por par de zonas, siguiendo el metodo de "
        "IEC 62443-3-2 como referencia. Las brechas son marcas para revisar, no juicios: indican donde mirar "
        "primero. Esto es evidencia tecnica para ese ejercicio, no una determinacion de cumplimiento.")


# --------------------------------------------------------------------------- #
# Calculo
# --------------------------------------------------------------------------- #


def _ip_de(assets: dict):
    """Extremo de conducto -> IP: en capturas ya es la IP; en exportaciones puede ser el id del activo."""
    def de(x):
        if x in assets and _ip(x) is None:
            return next(iter(sorted(assets[x]["ips"])), x)
        return x
    return de


def _ip(x):
    try:
        return ipaddress.ip_address(str(x).strip())
    except ValueError:
        return None


def _niveles(purdue: str):
    """(bajo, alto) del nivel Purdue de un activo, o None. 'Externo' cuenta como nivel 5."""
    if purdue == "Externo":
        return 5.0, 5.0
    m = _NIVEL.match(str(purdue or ""))
    if not m:
        return None
    lo = float(m.group(1))
    return lo, float(m.group(2)) if m.group(2) else lo


def _sl_num(sl: str):
    m = _SL.search(str(sl or ""))
    return int(m.group(1)) if m else -1


def _sl_mayor(a: str, b: str) -> str:
    return max((a, b), key=lambda x: (_sl_num(x), x))


def _servicio(c: dict) -> str:
    l4 = str(c.get("l4") or "").strip().lower()
    p = _cr._puerto(c)
    if p is None:
        return l4 or "ip"
    return f"{l4}/{p}" if l4 else str(p)      # sin transporte (exportaciones de xDome): solo el puerto


def _info_zonas(assets: dict, zonas: dict) -> dict:
    """{zona: {origen, sl_t, inferida, activos, niveles}} desde las filas de Z1a y los activos."""
    info = {f["zona"]: {"origen": f["origen"], "sl_t": f["sl_t"], "inferida": f["inferida"] == "si",
                        "activos": f["activos"], "niveles": []} for f in zonas.get("filas", ())}
    for a in assets.values():
        z = info.get(a.get("zona_asignada"))
        n = _niveles(a.get("purdue"))
        if z is not None and n:
            z["niveles"].append(n)
    return info


def _politica_por_conducto(firewall: dict) -> dict:
    """{indice de conducto: [(decision, clave de regla o grupo bloqueado)]} de la politica propuesta (M3a)."""
    out: dict = collections.defaultdict(list)
    for p in ((firewall or {}).get("politica") or {}).get("firewalls", ()):
        for r in p["reglas"]:
            for i in {x["i"] for x in r["items"]}:
                out[i].append((r["decision"], (p["id"], r["nombre"])))
        for b in p["bloqueados"]:
            clave = (p["id"], b["interfaz_entrada"], b["interfaz_salida"], b["servicio"], b["razon"])
            for i in b.get("indices", ()):
                out[i].append(("bloquear", clave))
    return out


def construir(assets: dict, conductos: list, zonas: dict, firewall: dict | None = None) -> dict:
    """{'filas', 'zonas', 'internos', 'sin_zona', 'con_firewall'}; vacio si no hay zonas (Z1a) o conductos."""
    if not zonas or not zonas.get("filas") or not conductos:
        return {}
    info = _info_zonas(assets, zonas)
    por_ip: dict = {}
    for a in assets.values():
        for ip in a["ips"]:
            por_ip.setdefault(ip, a)
    ip_de = _ip_de(assets)
    fw = firewall or {}
    res_fw = fw.get("resultados") or []
    con_fw = "hostname" in fw and len(res_fw) == len(conductos)
    multiple = bool(fw.get("firewalls")) and len(fw["firewalls"]) > 1
    nombre_fw = fw.get("hostname") or fw.get("archivo") or ""
    pol = _politica_por_conducto(fw) if con_fw else {}

    def zona_de(ip):
        a = por_ip.get(ip)
        if a is not None and a.get("zona_asignada"):
            return a["zona_asignada"], a["mac"]
        x = _ip(ip)
        if x is not None and not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast
                                  or x.is_reserved or x.is_unspecified):
            externas.add(ip)
            return INTERNET, ip
        return None, ip

    pares: dict = {}
    externas: set = set()           # IP publicas sin activo en el inventario: forman la zona Internet
    internos = sin_zona = 0
    cache_et: dict = {}
    for i, c in enumerate(conductos):
        r = res_fw[i] if con_fw else {}
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        if r.get("sentido") == "invertido":
            s, d = d, s
        zs, ks = zona_de(s)
        zd, kd = zona_de(d)
        if zs is None or zd is None:
            sin_zona += 1
            continue
        if zs == zd:
            internos += 1
            continue
        es_ab = zs < zd
        if not es_ab:
            zs, zd, ks, kd = zd, zs, kd, ks
        g = pares.get((zs, zd))
        if g is None:
            g = pares[(zs, zd)] = {
                "conductos": 0, "ab": 0, "ba": 0, "servicios": collections.Counter(), "act_a": set(),
                "act_b": set(), "ips": set(), "bytes": 0, "fws": set(), "reglas": collections.Counter(), "et": set(),
                "pol": collections.defaultdict(set), "rids": set()}
        g["conductos"] += 1
        g["ab" if es_ab else "ba"] += 1
        g["servicios"][_servicio(c)] += 1
        g["act_a"].add(ks)
        g["act_b"].add(kd)
        g["ips"].update((s, d))
        g["bytes"] += int(c.get("bytes") or 0)
        if con_fw:
            camino = r.get("camino")
            if camino:
                for x in camino:
                    g["fws"].add(x["fw"])
                    if x["resultado"] == "permitido" and x.get("regla_id"):
                        g["rids"].add((x["fw"], str(x["regla_id"])))
                        g["reglas"][f"{x['fw']}: {x['regla_id']} {x.get('regla_nombre', '')}".strip()] += 1
            elif not multiple and r.get("resultado") not in (None, "no_cruza"):
                g["fws"].add(nombre_fw)
                if r["resultado"] in ("permitido", "respuesta") and r.get("regla"):
                    g["rids"].add(("", str(r["regla"])))
                    g["reglas"][(str(r["regla"]) + " " + str(r.get("regla_nombre", ""))).strip()] += 1
            for dec, clave in pol.get(i, ()):
                g["pol"][dec].add(clave)
        puerto = _cr._puerto(c)
        l4 = str(c.get("l4") or "").strip().lower()
        servicio = str(c.get("servicio") or "")
        app = "" if servicio == "-" else servicio
        tipo = (por_ip.get(d) or {}).get("tipo", "")
        denegado = r.get("resultado") == "denegado_observado"
        k = (puerto, l4, app, _cr._global(d), _cr._global(s), tipo, denegado)
        if k not in cache_et:
            cache_et[k] = _cr.etiquetas_de(puerto, l4, app, d if k[3] else "", s if k[4] else "", tipo, denegado)
        g["et"].update(cache_et[k])

    if externas and INTERNET not in info:
        info[INTERNET] = {"origen": "internet", "sl_t": "", "inferida": False,     # Internet no es una suposicion "activos": len(externas),
                          "niveles": []}
    filas = []
    for (za, zb), g in sorted(pares.items(), key=lambda kv: (-kv[1]["conductos"], kv[0])):
        filas.append(_fila(za, zb, g, info, con_fw))
    for n, f in enumerate(filas, 1):
        f["id"] = f"C-{n:02d}"
    return {"filas": filas, "zonas": info, "internos": internos, "sin_zona": sin_zona, "con_firewall": con_fw}


def _bajo(nivel) -> bool:
    """La zona tiene equipos de Nivel 0 a 2."""
    return nivel is not None and nivel <= 2


def _alto(z: dict) -> bool:
    """La zona es Internet o tiene equipos de Nivel 4 o mas."""
    return z["origen"] == "internet" or any(n[1] >= 4 for n in z["niveles"])


def _fila(za: str, zb: str, g: dict, info: dict, con_fw: bool) -> dict:
    a, b = info.get(za) or _SIN_INFO, info.get(zb) or _SIN_INFO
    sl_a, sl_b = a["sl_t"], b["sl_t"]
    fws = sorted(g["fws"])
    et = _cr._ordenar(g["et"])
    niv_a = min((n[0] for n in a["niveles"]), default=5.0 if a["origen"] == "internet" else None)
    niv_b = min((n[0] for n in b["niveles"]), default=5.0 if b["origen"] == "internet" else None)
    brechas = []
    if con_fw and not fws:
        brechas.append(B_SIN_FW)
    if any(e in _RIESGO for e in et):
        brechas.append(B_RIESGO)
    if niv_a is not None and niv_b is not None and abs(niv_a - niv_b) >= 2:
        brechas.append(B_SALTA)
    if sl_a and sl_b and sl_a != sl_b:
        brechas.append(B_SL)
    if a["inferida"] or b["inferida"]:
        brechas.append(B_INFERIDA)
    critico = (_bajo(niv_a) and _alto(b)) or (_bajo(niv_b) and _alto(a))
    return {
        "id": "", "zona_a": za, "zona_b": zb, "origen_a": a["origen"], "origen_b": b["origen"],
        "conductos": g["conductos"], "ab": g["ab"], "ba": g["ba"],
        "servicios": sorted(g["servicios"].items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_SERVICIOS],
        "n_servicios": len(g["servicios"]), "activos_a": len(g["act_a"]), "activos_b": len(g["act_b"]),
        "bytes": g["bytes"], "firewalls": fws, "estado_fw": "" if fws else (NINGUNO_FW if con_fw else SIN_DATOS_FW),
        "reglas": [k for k, _n in sorted(g["reglas"].items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_REGLAS]],
        "propuesta": {k: len(v) for k, v in g["pol"].items()}, "etiquetas": et, "sl_a": sl_a, "sl_b": sl_b,
        "sl_mayor": _sl_mayor(sl_a, sl_b) if sl_a and sl_b and sl_a != sl_b else "",
        "brechas": brechas, "critico": bool(critico), "ips": sorted(g["ips"]),
        "reglas_ids": sorted(g["rids"])}


_SIN_INFO = {"origen": "sin zona", "sl_t": "", "inferida": True, "activos": 0, "niveles": []}


# --------------------------------------------------------------------------- #
# Tablas
# --------------------------------------------------------------------------- #


def hay(zcr: dict) -> bool:
    return bool(zcr and zcr.get("filas"))


def nombre_zona(f: dict, lado: str) -> str:
    return mostrar_zona(f["zona_" + lado], f["origen_" + lado])


def _texto_brechas(f: dict) -> str:
    out = []
    for b in f["brechas"]:
        if b == B_SL:
            out.append(t("SL-T distinto: el conducto debe disenarse para el SL-T mayor ({sl})", sl=f["sl_mayor"]))
        else:
            out.append(t(b))
    return "; ".join(out)


def _texto_propuesta(f: dict) -> str:
    return "; ".join(f"{t(k)} {f['propuesta'][k]}" for k in ("permitir", "revisar", "bloquear")
                     if f["propuesta"].get(k))


def fila_tabla(f: dict) -> list:
    return [f["id"], nombre_zona(f, "a"), nombre_zona(f, "b"), f["conductos"],
            f"{f['ab']} a->b, {f['ba']} b->a", ", ".join(f"{s} ({n})" for s, n in f["servicios"]),
            f["activos_a"], f["activos_b"], f["bytes"] or "",
            ", ".join(f["firewalls"]) or t(f["estado_fw"]), "; ".join(f["reglas"]), _texto_propuesta(f),
            _cr._txt_et(f["etiquetas"]),
            f"{f['sl_a'] or '-'} / {f['sl_b'] or '-'}" if f["sl_a"] or f["sl_b"] else "", _texto_brechas(f)]


def filas_tabla(zcr: dict) -> list:
    return [fila_tabla(f) for f in zcr["filas"]]


def tabla_reporte(zcr: dict, n: int = MAX_TABLA) -> tuple:
    """(cabecera, filas) de los n conductos con mas conductos, para HTML, Markdown y Word."""
    return [t(c) for c in COLUMNAS], [fila_tabla(f) for f in zcr["filas"][:n]]


def resumen_texto(zcr: dict) -> str:
    n = len(zcr["filas"])
    con = sum(1 for f in zcr["filas"] if f["brechas"])
    txt = t("{n} conductos entre zonas ({b} con alguna brecha marcada); {i} conductos dentro de una misma zona "
            "no forman conducto entre zonas. Detalle en conductos_zcr.csv.", n=n, b=con, i=zcr["internos"])
    if zcr["sin_zona"]:
        txt += " " + t("{n} conductos no se pudieron ubicar en una zona (por ejemplo, difusion o multicast).",
                       n=zcr["sin_zona"])
    if n > MAX_TABLA:
        txt += " " + t("Se muestran los {n} con mas conductos.", n=MAX_TABLA)
    return txt


# --------------------------------------------------------------------------- #
# Diagrama
# --------------------------------------------------------------------------- #


def grafo(zcr: dict):
    """Grafo de zonas para los renderizadores: los MAX_DIAGRAMA conductos con mas conductos."""
    from .diagram.graph import Arista, Grafo, Nodo

    filas = zcr["filas"][:MAX_DIAGRAMA]
    usadas = {z for f in filas for z in (f["zona_a"], f["zona_b"])}
    info = zcr["zonas"]

    def orden(z):
        i = info.get(z) or _SIN_INFO
        niv = [n[0] for n in i["niveles"]] or ([5.0] if i["origen"] == "internet" else [])
        return (i["origen"] != "internet", -min(niv) if niv else 1, z)

    nodos = []
    for z in sorted(usadas, key=orden):
        i = info.get(z) or _SIN_INFO
        sub = t("{n} activos", n=i["activos"])
        if i["sl_t"]:
            sub += " - " + t("SL-T {sl}", sl=i["sl_t"])
        if i["inferida"]:
            sub += " - " + t("inferida")
        nombre = mostrar_zona(z, i["origen"])
        nodos.append(Nodo(z, nombre, sub, z, "externo" if i["origen"] == "internet" else "zona"))
    aristas = []
    for f in filas:
        det = [t("Servicios: {s}", s=", ".join(f"{s} ({n})" for s, n in f["servicios"][:6])),
               t("{c} conductos", c=f["conductos"]) + f" ({f['ab']} a->b, {f['ba']} b->a)"]
        if f["brechas"]:
            det.append(t("Brechas: {b}", b=_texto_brechas(f)))
        aristas.append(Arista(
            f["zona_a"], f["zona_b"], fwd=f["ab"] > 0, back=f["ba"] > 0, crit="Alta" if f["brechas"] else "Baja",
            servicios=dict(f["servicios"]), bytes=f["bytes"], conductos=f["conductos"], rotulo=f["id"],
            rotulo2=t("{n} servicios", n=f["n_servicios"]) if f["n_servicios"] != 1 else t("1 servicio"),
            detalle="\n".join(det)))
    return Grafo(nodos, aristas, [n.id for n in nodos], zonas=True, zcr=True,
                 aristas_omitidas=len(zcr["filas"]) - len(filas))


def nota_diagrama(zcr: dict) -> str:
    fuera = len(zcr["filas"]) - MAX_DIAGRAMA
    if fuera <= 0:
        return ""
    return t("Se dibujan los {n} conductos con mas conductos; {fuera} mas estan en conductos_zcr.csv.",
             n=MAX_DIAGRAMA, fuera=fuera)


# --------------------------------------------------------------------------- #
# Hallazgos
# --------------------------------------------------------------------------- #


def _lista(filas: list) -> str:
    return "; ".join(
        f"{f['id']} ({nombre_zona(f, 'a')} <-> {nombre_zona(f, 'b')}): "
        + ", ".join(s for s, _n in f["servicios"][:3]) for f in filas[:MAX_EVIDENCIA])


def _ips(filas: list) -> list:
    """IP de los extremos de los conductos de esas filas."""
    return [ip for f in filas for ip in f.get("ips", ())]


def agregar_hallazgos(cap, zcr: dict) -> None:
    """Hallazgos de los conductos entre zonas en 'cap' (un Capture de extras). Marcas, no cumplimiento."""
    from .rules.base import finding

    if not hay(zcr):
        return
    filas = zcr["filas"]
    sin_fw = [f for f in filas if B_SIN_FW in f["brechas"]]
    if sin_fw:
        finding(cap, "Alta" if any(f["critico"] for f in sin_fw) else "Media", TIT_SIN_FW,
                t("Conductos: {n}. {lista}", n=len(sin_fw), lista=_lista(sin_fw)),
                "Con datos de firewall cargados, estos conductos entre zonas no cruzan ningun firewall: nada en "
                "el camino observado impone la separacion entre las dos zonas.",
                "Confirmar con el cliente si hay otro punto de control no cargado; si no lo hay, valorar un "
                "firewall o una regla de filtrado que imponga el conducto entre esas zonas.", "Segmentacion",
                activos=_ips(sin_fw))
    riesgo = [f for f in filas if B_RIESGO in f["brechas"]]
    if riesgo:
        finding(cap, "Media", TIT_RIESGO,
                t("Conductos: {n}. {lista}", n=len(riesgo), lista=_lista(riesgo)),
                "Acceso remoto, protocolos en texto claro, compartir archivos o DNS externo entre zonas amplian "
                "lo que un atacante puede alcanzar desde una zona comprometida.",
                "Revisar si cada servicio es necesario entre esas zonas; limitarlo a los equipos que lo requieren "
                "o reemplazarlo por una alternativa cifrada.", "Segmentacion", activos=_ips(riesgo))
    salta = [f for f in filas if B_SALTA in f["brechas"]]
    if salta:
        finding(cap, "Media", TIT_SALTA,
                t("Conductos: {n}. {lista}", n=len(salta), lista=_lista(salta)),
                "Un conducto que une zonas separadas por dos o mas niveles Purdue evita las zonas intermedias "
                "que normalmente concentran el filtrado.",
                "Confirmar el nivel Purdue de los equipos y valorar pasar el flujo por una zona intermedia "
                "(por ejemplo una DMZ industrial).", "Segmentacion", activos=_ips(salta))
