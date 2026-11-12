"""E1a: vulnerabilidades por activo (CSV generico) cruzadas con el inventario.

Funciones puras salvo cargar(). No consulta bases de CVE en linea (D1): solo lo que trae el archivo.
El numero de fila en los mensajes es el N-esimo registro despues del encabezado.
"""
from __future__ import annotations

import re
import unicodedata
import zipfile
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree as ET

from . import cvss4
from .i18n import t, unir
from .importers.lector import leer_csv

MAX_FILAS = 200000

_ALIAS = {
    "activo": "activo", "asset": "activo", "host": "activo", "nombre": "activo", "name": "activo",
    "ip": "ip", "ip_address": "ip", "direccion": "ip",
    "mac": "mac",
    "cve": "cve", "cve_id": "cve", "vulnerabilidad": "cve", "vulnerability": "cve",
    "severidad": "severidad", "severity": "severidad", "criticidad": "severidad",
    "cvss": "cvss", "cvss_score": "cvss", "score": "cvss",
    "cvss_v4": "cvss_v4", "cvss4": "cvss_v4", "cvss_v4_score": "cvss_v4", "cvss_v4_base_score": "cvss_v4",
    "vector_cvss_v4": "vector_cvss_v4", "cvss_v4_vector": "vector_cvss_v4", "vector_v4": "vector_cvss_v4",
    "estado": "estado", "status": "estado", "state": "estado",
    "producto": "producto", "product": "producto",
    "version": "version",
    "fuente": "fuente", "source": "fuente",
}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SEVERIDAD = {
    "critical": "Critica", "critica": "Critica",
    "high": "Alta", "alta": "Alta",
    "medium": "Media", "media": "Media", "moderate": "Media",
    "low": "Baja", "baja": "Baja", "info": "Baja", "informativa": "Baja",
}
_ESTADO = {
    "": "abierta", "open": "abierta", "abierta": "abierta", "new": "abierta", "nueva": "abierta",
    "mitigated": "mitigada", "mitigada": "mitigada", "fixed": "mitigada",
    "remediada": "mitigada", "resuelta": "mitigada",
    "accepted": "aceptada", "aceptada": "aceptada", "riesgo aceptado": "aceptada",
}


def _norm(s) -> str:
    s = unicodedata.normalize("NFD", str(s or ""))
    return "".join(c for c in s if not unicodedata.combining(c)).strip().lower()


def _norm_mac(s) -> str:
    h = re.sub(r"[^0-9a-f]", "", str(s or "").lower())
    if len(h) == 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return str(s or "").strip().lower().replace("-", ":")


def _sev_de_cvss(x: float) -> str:
    if x >= 9.0:
        return "Critica"
    if x >= 7.0:
        return "Alta"
    if x >= 4.0:
        return "Media"
    return "Baja"


def vulns_de_filas(filas: list, nombre: str, version_cvss: str = "3") -> list:
    """Convierte los registros de leer_csv en vulnerabilidades normalizadas. 'nombre' es el archivo, sin ruta.

    Con version_cvss "4" (D114) la severidad no explicita se deriva de cvss_v4 si existe."""
    v4 = version_cvss == "4"
    if not filas:
        raise SystemExit(f"[!] '{nombre}': sin filas o sin encabezado")
    if len(filas) > MAX_FILAS:
        raise SystemExit(f"[!] '{nombre}': mas de {MAX_FILAS} filas")
    cabecera = {_norm(h).replace(" ", "_") for f in filas[:50] for h in f}
    if {"node_id", "cve"} <= cabecera and cabecera & {"cve_score", "cve_is_kev", "resolved"}:
        return _vulns_nozomi(filas, nombre)
    mapa = {}
    for h in dict.fromkeys(h for f in filas for h in f):    # union de claves: filas cortas omiten celdas
        campo = _ALIAS.get(_norm(h).replace(" ", "_"))
        if campo:
            mapa[h] = campo
    campos = set(mapa.values())
    if "cve" not in campos:
        raise SystemExit(f"[!] '{nombre}': falta la columna requerida 'cve'")
    if not campos & {"activo", "ip", "mac"}:
        raise SystemExit(f"[!] '{nombre}': falta una columna de identificacion (activo, ip o mac)")
    if not campos & ({"severidad", "cvss", "cvss_v4", "vector_cvss_v4"} if v4 else {"severidad", "cvss"}):
        raise SystemExit(f"[!] '{nombre}': falta la columna severidad o cvss")
    vulns = []
    for n, fila in enumerate(filas, 1):
        v: dict = {}
        for h, campo in mapa.items():           # ante columnas repetidas gana la primera con valor
            val = (fila.get(h) or "").strip()
            if val and not v.get(campo):
                v[campo] = val
        v = {c: v.get(c, "") for c in dict.fromkeys(mapa.values())}
        cve = v["cve"].upper()
        if not _CVE.match(cve):
            raise SystemExit(f"[!] '{nombre}': fila {n}: identificador CVE invalido '{v['cve']}'")
        cvss = None
        if v.get("cvss"):
            try:
                cvss = float(v["cvss"].replace(",", "."))
            except ValueError:
                cvss = float("nan")
            if not (0.0 <= cvss <= 10.0):       # tambien rechaza nan e inf
                raise SystemExit(f"[!] '{nombre}': fila {n}: cvss fuera de 0-10 '{v['cvss']}'")
        cvss_v4, vector_v4 = cvss4.resolver(v.get("cvss_v4"), v.get("vector_cvss_v4"))   # informativo salvo version_cvss 4 (D114)
        sev = _SEVERIDAD.get(_norm(v.get("severidad")))
        if sev is None and v4 and cvss_v4 is not None and cvss_v4 > 0:
            sev = cvss4.severidad(cvss_v4)
        if sev is None and cvss is not None and cvss > 0:
            sev = _sev_de_cvss(cvss)
        if sev is None:
            raise SystemExit(f"[!] '{nombre}': fila {n}: no se pudo determinar la severidad "
                             f"('{v.get('severidad', '')}', cvss '{v.get('cvss', '')}')")
        estado = _ESTADO.get(_norm(v.get("estado")))
        if estado is None:
            raise SystemExit(f"[!] '{nombre}': fila {n}: estado invalido '{v['estado']}'")
        vulns.append({
            "cve": cve, "severidad": sev, "cvss": cvss, "estado": estado,
            "activo": v.get("activo", ""), "ip": v.get("ip", ""), "mac": v.get("mac", ""),
            "producto": v.get("producto", ""), "version": v.get("version", ""),
            "fuente": v.get("fuente", ""), "cvss_v4": cvss_v4, "vector_cvss_v4": vector_v4,
        })
    return vulns


def _vulns_nozomi(filas: list, nombre: str) -> list:
    """Exportacion 'CVE por nodo' de Nozomi (D74): node_id es la MAC del nodo (o MAC@IP, o una IP).

    resolved=1 es mitigada (no cuenta como abierta); cve_is_kev y cve_epss_score vienen de la propia columna.
    Sin puntaje CVSS la severidad es Baja: la exportacion no dice mas."""
    verdad = ("1", "true", "yes", "si")
    vulns = []
    for n, fila in enumerate(filas, 1):
        g = {_norm(h).replace(" ", "_"): (v or "").strip() for h, v in fila.items()}
        cve = g.get("cve", "").upper()
        if not _CVE.match(cve):
            raise SystemExit(f"[!] '{nombre}': fila {n}: identificador CVE invalido '{g.get('cve', '')}'")
        nodo = g.get("node_id", "")
        mac, ip = "", ""
        if "@" in nodo:
            mac, ip = nodo.split("@", 1)
        elif re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", nodo):
            mac = nodo
        else:
            ip = nodo
        cvss = epss = None
        try:
            cvss = float(g.get("cve_score", "").replace(",", "."))
        except ValueError:
            pass
        if cvss is not None and not (0.0 <= cvss <= 10.0):
            cvss = None
        try:
            epss = float(g.get("cve_epss_score", "").replace(",", "."))
        except ValueError:
            pass
        vulns.append({
            "cve": cve, "severidad": _sev_de_cvss(cvss) if cvss else "Baja", "cvss": cvss,
            "estado": "mitigada" if g.get("resolved", "").lower() in verdad else "abierta",
            "activo": "", "ip": ip.strip(), "mac": _norm_mac(mac) if mac else "",
            "producto": g.get("matching_cpes", ""), "version": "", "fuente": g.get("cve_source", ""),
            "epss": epss, "kev_col": g.get("cve_is_kev", "").lower() in verdad})
    return vulns

# N2 (D101): fabricante, modelo, firmware y SO inferidos de los CPE de la exportacion de CVE.

def leer_cpes(celda) -> list:
    """[(parte, fabricante, producto, version)] de una celda con CPE 2.2 URI o 2.3 formateado separados por coma.

    Version '-', '*' o vacia = ''. Orden de aparicion; sin repetidos."""
    out = []
    for cpe in re.split(r",\s*(?=cpe:)", str(celda or "")):
        cpe = cpe.strip()
        if cpe.lower().startswith("cpe:2.3:"):
            campos = [re.sub(r"\\(.)", r"\1", x) for x in re.split(r"(?<!\\):", cpe)[2:]]
        elif cpe.lower().startswith("cpe:/"):
            campos = [unquote(x) for x in cpe[5:].split(":")]
        else:
            continue
        if len(campos) < 3 or campos[0].lower() not in ("h", "o", "a"):
            continue
        ver = campos[3].strip() if len(campos) > 3 else ""
        item = (campos[0].lower(), campos[1].strip().lower(), campos[2].strip().lower(),
                "" if ver in ("-", "*") else ver)
        if item[2] and item not in out:
            out.append(item)
    return out


def inferir_equipos(cruces: list) -> tuple:
    """({clave de activo: {campo: valor}}, activos con CPE ambiguo) a partir de las filas ya unidas al activo.

    modelo: producto h presente en todas las filas del activo que traen algun CPE h (interseccion) o, si la
    interseccion no deja uno solo, el presente en mas de la mitad de esas filas; firmware:
    version de <modelo>_firmware; sistema operativo: sin CPE h, un unico CPE o (que no es firmware) comun a todas."""
    filas: dict = {}
    for c in cruces:
        if c["activo"] is not None:
            filas.setdefault(c["activo"], []).append(leer_cpes(c["vuln"].get("producto", "")))
    out, ambiguos = {}, 0
    for clave in sorted(filas, key=str):
        cpes = filas[clave]
        con_h = [{(f, p) for pt, f, p, _v in fila if pt == "h"} for fila in cpes]
        con_h = [x for x in con_h if x]
        datos = {}
        if con_h:
            comunes = set.intersection(*con_h)
            if len(comunes) != 1:      # hay CVE cuyo CPE nombra solo la familia o el numero de pedido del equipo
                comunes = _mayoria(con_h)
            if len(comunes) != 1:
                ambiguos += 1
                continue
            fab, prod = next(iter(comunes))
            datos = {"fabricante": fab, "modelo": prod.replace("_", " ")}
            vers = {v for fila in cpes for pt, f, p, v in fila if pt == "o" and p == prod + "_firmware" and v}
            if len(vers) == 1:
                datos["firmware"] = next(iter(vers))
        else:
            por_fila = [{x for x in fila if x[0] == "o" and not x[2].endswith("_firmware")} for fila in cpes]
            por_fila = [x for x in por_fila if x]      # filas sin CPE o de sistema no vetan (como las sin h)
            comunes = set.intersection(*por_fila) if por_fila else set()
            if len(comunes) == 1:
                _pt, fab, prod, ver = next(iter(comunes))
                datos = {"fabricante": fab, "sistema_operativo": (prod.replace("_", " ") + " " + ver).strip()}
        if datos:
            out[clave] = datos
    return out, ambiguos


def _mayoria(conjuntos: list) -> set:
    """Productos presentes en mas de la mitad de los conjuntos (vale solo si queda uno)."""
    cuenta: dict = {}
    for c in conjuntos:
        for x in c:
            cuenta[x] = cuenta.get(x, 0) + 1
    return {x for x, n in cuenta.items() if 2 * n > len(conjuntos)}


def aviso_cpe_ambiguo(n: int) -> str:
    return f"{n} activos con CPE ambiguo: sin modelo inferido" if n else ""


def cargar(path, version_cvss: str = "3") -> list:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e}")
    if p.suffix.lower() == ".xlsx" or raw[:2] == b"PK":
        from .importers.lector import leer_xlsx
        try:
            return vulns_de_filas(leer_xlsx(raw), p.name, version_cvss)
        except (ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as e:
            raise SystemExit(f"[!] '{p.name}' no parece un XLSX valido: {e}")
    return vulns_de_filas(leer_csv(raw), p.name, version_cvss)


def aviso_sin_activo(cruces: list, nombre: str) -> str:
    """Aviso de las filas que no unen con ningun activo del inventario ('' si todas unen)."""
    sin = sum(1 for c in cruces if c["activo"] is None)
    if not sin:
        return ""
    return (f"{nombre}: {sin} de {len(cruces)} filas de vulnerabilidades no unen con ningun activo del "
            f"inventario (por IP, MAC o nombre); revise que el inventario incluya esos nodos.")


def cruzar(vulns: list, assets) -> list:
    """Asocia cada vulnerabilidad a un activo: IP exacta, luego MAC, luego nombre o alias.

    'assets' es {clave: activo} o una lista de activos (clave = su "mac"). Si varios activos
    comparten el dato, gana el de clave menor (determinista).
    """
    items = sorted(assets.items(), key=lambda kv: str(kv[0])) if isinstance(assets, dict) else \
        sorted(((a.get("mac", ""), a) for a in assets), key=lambda kv: str(kv[0]))
    por_ip, por_mac, por_nombre = {}, {}, {}
    for clave, a in items:
        for ip in a.get("ips") or ():
            por_ip.setdefault(str(ip).strip(), clave)
        por_mac.setdefault(_norm_mac(a.get("mac")), clave)
        for nom in {a.get("nombre"), *(a.get("alias") or ())}:
            if nom and str(nom).strip():
                por_nombre.setdefault(str(nom).strip().lower(), clave)
                if re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", str(nom).strip()):
                    por_mac.setdefault(_norm_mac(nom), clave)      # activo con varias MAC: todas unen
    por_mac.pop("", None)
    out = []
    for v in vulns:
        clave, por = None, ""
        if v.get("ip") and v["ip"].strip() in por_ip:
            clave, por = por_ip[v["ip"].strip()], "ip"
        elif v.get("mac") and _norm_mac(v["mac"]) in por_mac:
            clave, por = por_mac[_norm_mac(v["mac"])], "mac"
        elif v.get("activo") and v["activo"].strip().lower() in por_nombre:
            clave, por = por_nombre[v["activo"].strip().lower()], "nombre"
        out.append({"vuln": v, "activo": clave, "por": por})
    return out


NOTA = ("Datos del archivo importado: la herramienta no consulta bases de CVE (D1) "
        "ni verifica la version instalada.")
TITULO = "Vulnerabilidades conocidas en activos (segun el archivo importado)"
_SEV_HALLAZGO = {"Critica": "Alta", "Alta": "Alta", "Media": "Media", "Baja": "Baja"}
_ORDEN_SEV = ("Critica", "Alta", "Media", "Baja")
_ESTADOS = ("abierta", "mitigada", "aceptada")


def resumen(cruces: list, archivo: str) -> dict:
    """Conteos del cruce: total, asociadas, sin activo y matriz severidad x estado."""
    matriz = {s: {e: 0 for e in _ESTADOS} for s in _ORDEN_SEV}
    for c in cruces:
        matriz[c["vuln"]["severidad"]][c["vuln"]["estado"]] += 1
    asociadas = sum(1 for c in cruces if c["activo"] is not None)
    return {"archivo": archivo, "total": len(cruces), "asociadas": asociadas,
            "sin_activo": len(cruces) - asociadas, "matriz": matriz}


def agregar_hallazgo(cap, cruces: list, assets: dict) -> None:
    """Un hallazgo en 'cap' si hay vulnerabilidades abiertas asociadas a un activo."""
    from .rules.base import finding

    abiertas = [c for c in cruces if c["vuln"]["estado"] == "abierta" and c["activo"] is not None]
    if not abiertas:
        return
    sev = min((c["vuln"]["severidad"] for c in abiertas), key=_ORDEN_SEV.index)
    cuenta = {s: sum(1 for c in cruces if c["vuln"]["estado"] == "abierta"
                     and c["vuln"]["severidad"] == s) for s in _ORDEN_SEV}
    por_activo: dict = {}
    for c in abiertas:
        por_activo.setdefault(c["activo"], set()).add(c["vuln"]["cve"])

    def nombre(clave):
        a = assets.get(clave) or {}
        return a.get("nombre") or str(clave)
    activos = sorted(por_activo, key=lambda k: (-len(por_activo[k]), nombre(k), str(k)))
    lineas = []
    for k in activos[:10]:
        cves = sorted(por_activo[k])
        lineas.append(f"{nombre(k)}: {', '.join(cves[:3])}" + (f" (+{len(cves) - 3})" if len(cves) > 3 else ""))
    sin = sum(1 for c in cruces if c["activo"] is None)
    ev = t("Abiertas: {cuenta}. {lineas}{mas}. Filas sin activo en el inventario: {sin}",
           cuenta=", ".join(f"{t(s)} {n}" for s, n in cuenta.items() if n), lineas="; ".join(lineas),
           mas=t(" (y {n} activos mas)", n=len(activos) - 10) if len(activos) > 10 else "", sin=sin)
    if any(c.get("kev") for c in cruces):
        ev = unir("", [ev, t(" ({n} en KEV)", n=sum(1 for c in abiertas if c.get("kev") == "si"))])
    finding(cap, _SEV_HALLAZGO[sev], TITULO, ev,
            "Una vulnerabilidad abierta en un activo que se comunica en la red de control es una via "
            "de compromiso; la prioridad depende de su exposicion y de los conductos que la alcanzan.",
            "Aplicar el parche o la mitigacion del fabricante; si no es posible, aislar el activo y "
            "restringir sus conductos a lo imprescindible.", "Vulnerabilidades",
            activos=[str(ip) for k in {c["activo"] for c in cruces if c["activo"] is not None}
                     for ip in (assets.get(k) or {}).get("ips") or ()])


COLUMNAS = ["activo", "ip", "cve", "severidad", "cvss", "estado", "producto", "version",
            "fuente", "asociado_por", "kev", "kev_fecha_agregada", "kev_fecha_limite", "kev_ransomware",
            "avisos_ics", "remediacion_fabricante"]


def _con_epss(cruces: list) -> bool:
    return any(c["vuln"].get("epss") is not None for c in cruces)


def _con_v4(cruces: list) -> bool:
    return any(c["vuln"].get("cvss_v4") is not None or c["vuln"].get("vector_cvss_v4") for c in cruces)


def _entorno(v: dict, crit) -> tuple:
    """(puntuacion, vector) de entorno CVSS v4.0 (D120) de la fila, o ("", "")."""
    from .cvss4_entorno import entorno
    return entorno(v.get("vector_cvss_v4"), v.get("ip"), crit) if crit else ("", "")


def con_entorno(cruces: list, crit) -> bool:
    """True si el perfil declara criticidad y alguna fila obtiene puntuacion de entorno (D120)."""
    return bool(crit) and any(_entorno(c["vuln"], crit)[0] != "" for c in cruces)


def columnas(cruces: list, crit=None, plan=None) -> list:
    """COLUMNAS, mas 'epss' al final si el archivo importado la trae (Nozomi) y cvss_v4 y vector_cvss_v4
    junto a cvss si trae CVSS v4.0 (D113); con crit (criticidad_activos) y filas con entorno, las columnas D120."""
    cols = list(COLUMNAS)
    if _con_v4(cruces):
        i = cols.index("cvss") + 1
        cols[i:i] = ["cvss_v4", "vector_cvss_v4"]
        if con_entorno(cruces, crit):
            from .cvss4_entorno import COLUMNAS as ENT
            cols[i + 2:i + 2] = ENT
    return cols + (["epss"] if _con_epss(cruces) else []) + (["id_vulnerabilidad", "estado_confirmacion"] if plan else [])


def _confirmacion(plan, v: dict) -> list:
    """VCONF (D128): id y estado de la fila cuando hay plan de confirmacion."""
    if not plan:
        return []
    ident = plan.id_plataforma(v)
    return [ident, plan.mostrar(plan.revision(ident)[0])]


def filas_tabla(cruces: list, assets: dict, crit=None, plan=None) -> list:
    """Filas de vulnerabilidades.csv: asociadas por activo y CVE; al final las no asociadas."""
    from .avisos_cisa import columnas_kev
    epss = _con_epss(cruces)
    v4 = _con_v4(cruces)
    ent = v4 and con_entorno(cruces, crit)

    def fila(c):
        v = c["vuln"]
        a = assets.get(c["activo"]) if c["activo"] is not None else None
        return [a["nombre"] if a else "", v["ip"], v["cve"], t(v["severidad"]),
                "" if v["cvss"] is None else v["cvss"],
                *(["" if v.get("cvss_v4") is None else v["cvss_v4"], v.get("vector_cvss_v4") or "",
                    *(_entorno(v, crit) if ent else ())] if v4 else []),
                t(v["estado"]), v["producto"],
                v["version"], v["fuente"], c["por"], *columnas_kev(c),
                *(["" if v.get("epss") is None else v["epss"]] if epss else []),
                *_confirmacion(plan, v)]
    asoc = sorted((c for c in cruces if c["activo"] is not None),
                  key=lambda c: (fila(c)[0], c["vuln"]["cve"], str(c["activo"])))
    no = sorted((c for c in cruces if c["activo"] is None),
                key=lambda c: (c["vuln"]["cve"], c["vuln"]["ip"], c["vuln"]["activo"]))
    return [fila(c) for c in asoc + no]
