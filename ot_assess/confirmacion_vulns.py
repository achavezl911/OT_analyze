"""VCONF (D128): confirmacion de vulnerabilidades por el analista (candidato / confirmado / descartado).

Cada vulnerabilidad es candidata hasta que el equipo la confirma o la descarta. La herramienta no decide
nada: da un id estable por activo + CVE (el mismo en vulnerabilidades.csv y en vulnerabilidades_firmware.csv),
una columna de estado, un registro consolidado (vulnerabilidades_revision.csv) que el equipo llena y devuelve
con --vulnerabilidades-revision, y, si el perfil lo pide, hallazgos sin las descartadas. Sin la clave de
perfil `confirmacion_vulnerabilidades` ni la opcion no hace nada.
"""
from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path

from .i18n import catalogo, t

CLAVE = "confirmacion_vulnerabilidades"
ARCHIVO = "vulnerabilidades_revision.csv"
HOJA = "Revision de vulnerabilidades"
ATRIBUTO = "vconf_plan"
COLUMNAS = ["id_vulnerabilidad", "cve", "activo", "ip", "fuentes", "severidad", "cvss", "kev", "aviso",
            "estado_confirmacion", "confirmado_por", "fecha", "motivo"]
COL_ID = "id_vulnerabilidad"
COL_ESTADO = "estado_confirmacion"
ESTADOS_DEFECTO = ["candidato", "confirmado", "descartado"]
HALLAZGOS = ("todas", "sin_descartadas")
MAX_TEXTO = 200
MAX_BYTES = 20 * 1024 * 1024
MAX_FILAS = 100000
_ORDEN_SEV = ("Critica", "Alta", "Media", "Baja")
# Un archivo escrito con --idioma en lleva las cabeceras traducidas; los alias de firmware se aceptan.
ALIAS = {"id": ("id_vulnerabilidad", "vulnerability_id"),
         "estado": ("estado_confirmacion", "confirmation_status", "estado_revision", "review_status"),
         "por": ("confirmado_por", "confirmed_by", "revisado_por", "reviewed_by"),
         "fecha": ("fecha", "date"),
         "motivo": ("motivo", "reason", "comentario", "comment")}


def _defecto() -> dict:
    return {"estados": list(ESTADOS_DEFECTO), "inicial": ESTADOS_DEFECTO[0], "descartados": ESTADOS_DEFECTO[2],
            "hallazgos": "todas"}


def validar(v, fallo):
    """Normaliza la clave de perfil: None (apagada) o {estados, inicial, descartados, hallazgos}."""
    if v is False:
        return None
    if v is True:
        return _defecto()
    if not isinstance(v, dict):
        fallo("'confirmacion_vulnerabilidades' debe ser true, false o un objeto.")
    for k in v:
        if k not in ("estados", "inicial", "descartados", "hallazgos"):
            fallo("clave desconocida '" + str(k) + "' en 'confirmacion_vulnerabilidades'.")
    est = v.get("estados", ESTADOS_DEFECTO)
    if not isinstance(est, list) or not 2 <= len(est) <= 10:
        fallo("'confirmacion_vulnerabilidades.estados' debe ser una lista de 2 a 10 textos.")
    for x in est:
        if (not isinstance(x, str) or not 1 <= len(x) <= 40 or x != x.strip()
                or "\n" in x or "\r" in x):
            fallo("'confirmacion_vulnerabilidades.estados': cada estado es un texto de 1 a 40 caracteres, sin "
                  "saltos de linea ni espacios en los extremos.")
    if len(set(est)) != len(est):
        fallo("'confirmacion_vulnerabilidades.estados' tiene estados repetidos.")
    ini = v.get("inicial", est[0])
    if not isinstance(ini, str) or ini not in est:
        fallo("'confirmacion_vulnerabilidades.inicial' debe ser uno de los estados.")
    if "descartados" in v:
        desc = v["descartados"]
        if not isinstance(desc, str) or desc not in est:
            fallo("'confirmacion_vulnerabilidades.descartados' debe ser uno de los estados.")
    else:
        desc = ESTADOS_DEFECTO[2] if ESTADOS_DEFECTO[2] in est else None
    hall = v.get("hallazgos", "todas")
    if hall not in HALLAZGOS:
        fallo("'confirmacion_vulnerabilidades.hallazgos' debe ser 'todas' o 'sin_descartadas'.")
    return {"estados": list(est), "inicial": ini, "descartados": desc, "hallazgos": hall}


# ---- id -------------------------------------------------------------------------------------------------

def id_de(cve: str, clave: str) -> str:
    return "VU-" + hashlib.sha256((str(cve).upper() + "|" + clave).encode("utf-8")).hexdigest()[:10]


def clave_plataforma(v: dict) -> str:
    """ip de la fila; si no mac; si no el nombre del activo; si no 'producto version'."""
    for k in ("ip", "mac", "activo"):
        if str(v.get(k) or "").strip():
            return str(v[k]).strip()
    return (str(v.get("producto") or "") + " " + str(v.get("version") or "")).strip()


def ips_plataforma(cruces) -> dict:
    """{cve: {ip}} de las filas importadas que traen ip."""
    out: dict = {}
    for c in cruces or ():
        ip = str(c["vuln"].get("ip") or "").strip()
        if ip:
            out.setdefault(c["vuln"]["cve"].upper(), set()).add(ip)
    return out


# ---- lectura del archivo del equipo ---------------------------------------------------------------------

def _canon(estado: str, estados: list):
    if estado in estados:
        return estado
    if estados == ESTADOS_DEFECTO:       # un archivo escrito con --idioma en trae los estados traducidos
        en = catalogo("en")
        for es in ESTADOS_DEFECTO:
            if en.get(es) == estado:
                return es
    return None


def leer(ruta, estados: list) -> dict:
    """{id: (estado, confirmado_por, fecha, motivo)} de un archivo llenado por el equipo. ValueError si no sirve."""
    p = Path(ruta)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(t("'{a}' pesa mas de 20 MB.", a=p.name))
        texto = p.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(t("No pude leer '{a}': {e}", a=p.name, e=str(e)))
    cab = texto.split("\n", 1)[0]
    sep = ";" if cab.count(";") > cab.count(",") else ","
    out: dict = {}
    try:
        lector = csv.reader(io.StringIO(texto), delimiter=sep)
        cols = [c.strip() for c in (next(lector, None) or [])]
        idx = {}
        for k, alias in ALIAS.items():
            hay = [cols.index(a) for a in alias if a in cols]
            if hay:
                idx[k] = hay[0]
        if "id" not in idx:
            raise ValueError(t("'{a}' no tiene la columna id_vulnerabilidad.", a=p.name))
        n = 0
        for fila in lector:
            if not any(c.strip() for c in fila):
                continue
            n += 1
            if n > MAX_FILAS:
                raise ValueError(t("'{a}' tiene mas de {n} filas.", a=p.name, n=MAX_FILAS))
            cel = [(fila[idx[k]] if k in idx and idx[k] < len(fila) else "").strip()
                   for k in ("id", "estado", "por", "fecha", "motivo")]
            ident, estado, por, fecha, motivo = cel
            if not ident:
                continue
            if any(len(x) > MAX_TEXTO for x in cel):
                raise ValueError(t("Texto de mas de 200 caracteres en el id {i} de '{a}'.", i=ident, a=p.name))
            if estado:
                canon = _canon(estado, estados)
                if canon is None:
                    raise ValueError(t("Estado no permitido '{e}' en el id {i}. Permitidos: {l}.",
                                       e=estado, i=ident, l=", ".join(estados)))
                estado = canon
            valores = (estado, por, fecha, motivo)
            if ident in out and out[ident] != valores:
                raise ValueError(t("id_vulnerabilidad repetido con valores distintos: {i}.", i=ident))
            out[ident] = valores
    except csv.Error as e:
        raise ValueError(t("'{a}' no es un CSV valido: {e}", a=p.name, e=str(e)))
    return out


# ---- plan -----------------------------------------------------------------------------------------------

class Plan:
    """Configuracion activa y lo trasladado de una corrida anterior."""

    def __init__(self, cfg: dict, previos: dict):
        self.cfg = cfg
        self.previos = previos
        self.tabla: list = []
        self.json: dict = {}

    @property
    def excluye(self) -> bool:
        return self.cfg["hallazgos"] == "sin_descartadas" and self.cfg["descartados"] is not None

    def revision(self, ident: str) -> tuple:
        """(estado, confirmado_por, fecha, motivo); una celda vacia del archivo no pisa el estado inicial."""
        est, por, fecha, motivo = self.previos.get(ident, ("", "", "", ""))
        return est or self.cfg["inicial"], por, fecha, motivo

    def mostrar(self, estado: str) -> str:
        """Los estados por defecto se traducen; los del perfil son datos del proyecto."""
        return t(estado) if self.cfg["estados"] == ESTADOS_DEFECTO and estado in ESTADOS_DEFECTO else estado

    def descartada(self, ident: str) -> bool:
        return self.cfg["descartados"] is not None and self.revision(ident)[0] == self.cfg["descartados"]

    def id_plataforma(self, v: dict) -> str:
        return id_de(v["cve"], clave_plataforma(v))

    def id_firmware(self, x: dict, ips_plat: dict) -> str:
        """ip del activo (la que ya trae la plataforma para ese CVE si coincide); si no el nombre; si no modelo y firmware."""
        ips = [i for i in x.get("ips") or () if i]
        comunes = ips_plat.get(x["reg"]["cve"].upper(), set())
        clave = next((i for i in ips if i in comunes), ips[0] if ips else
                     str(x.get("nombre") or "").strip() or (str(x.get("modelo") or "") + " " + str(x.get("fw") or "")).strip())
        return id_de(x["reg"]["cve"], clave)

    def filtrar_cruces(self, cruces):
        if not self.excluye or not cruces:
            return cruces
        return [c for c in cruces if not self.descartada(self.id_plataforma(c["vuln"]))]

    def filtrar_vf(self, vf):
        if not self.excluye or not vf or not vf.get("filas"):
            return vf
        return {**vf, "filas": [x for x in vf["filas"] if not self.descartada(x.get("id_vuln", ""))]}


def de_args(args):
    return getattr(args, ATRIBUTO, None)


def leer_opcion(ap, args, perfil) -> None:
    """Lee --vulnerabilidades-revision antes de crear salidas (codigo 2 si no sirve) y deja el plan en args."""
    cfg = (perfil or {}).get(CLAVE)
    ruta = getattr(args, "vulnerabilidades_revision", None)
    setattr(args, ATRIBUTO, None)
    if not cfg and not ruta:
        return
    cfg = cfg or _defecto()
    previos: dict = {}
    if ruta:
        try:
            previos = leer(ruta, cfg["estados"])
        except ValueError as e:
            ap.error(str(e))
    setattr(args, ATRIBUTO, Plan(cfg, previos))


# ---- tabla consolidada ----------------------------------------------------------------------------------

def _sev_orden(sev: str) -> int:
    return _ORDEN_SEV.index(sev) if sev in _ORDEN_SEV else len(_ORDEN_SEV)


def preparar(args, cruces, assets, vf) -> None:
    """Arma el registro consolidado (plataforma + firmware) y el bloque JSON. Sin plan no hace nada."""
    plan = de_args(args)
    if plan is None:
        return
    reg: dict = {}
    for c in cruces or ():
        v = c["vuln"]
        ident = plan.id_plataforma(v)
        a = assets.get(c["activo"]) if c["activo"] is not None else None
        nuevo = {"cve": v["cve"], "activo": (a["nombre"] if a else "") or v.get("activo", ""),
                 "ip": v.get("ip", ""), "fuentes": {"plataforma"}, "sev": v["severidad"],
                 "cvss": "" if v["cvss"] is None else v["cvss"], "kev": t(c["kev"]) if c.get("kev") else "",
                 "aviso": ";".join(av["id"] for av in c.get("avisos") or ())}
        _unir(reg, ident, nuevo)
    cols = (vf or {}).get("columnas") or []
    for x in (vf or {}).get("filas") or ():
        d = dict(zip(cols, x["celdas"]))
        nuevo = {"cve": x["cve"], "activo": x["nombre"], "ip": ";".join(x["ips"]), "fuentes": {"firmware"},
                 "sev": x.get("sev_int", ""), "cvss": "" if x["cvss"] is None else x["cvss"],
                 "kev": d.get("kev", ""), "aviso": d.get("aviso", "")}
        _unir(reg, x["id_vuln"], nuevo)
    ids = sorted(reg, key=lambda i: (_sev_orden(reg[i]["sev"]), i))
    filas, por_estado = [], {e: 0 for e in plan.cfg["estados"]}
    for i in ids:
        r = reg[i]
        est, por, fecha, motivo = plan.revision(i)
        por_estado[est] = por_estado.get(est, 0) + 1
        fuentes = "; ".join(t(f) for f in ("plataforma", "firmware") if f in r["fuentes"])
        filas.append([i, r["cve"], r["activo"], r["ip"], fuentes, t(r["sev"]) if r["sev"] else "", r["cvss"],
                      r["kev"], r["aviso"], plan.mostrar(est), por, fecha, motivo])
    importados = sum(1 for i in plan.previos if i in reg)
    no_encontrados = len(plan.previos) - importados
    if no_encontrados:
        print(t("[!] --vulnerabilidades-revision: {n} id_vulnerabilidad del archivo ya no existen en esta corrida; "
                "no se trasladan.", n=no_encontrados))
    plan.tabla = filas
    plan.json = {"filas": len(filas), "estados": list(plan.cfg["estados"]), "por_estado": por_estado,
                 "importados": importados, "ids_no_encontrados": no_encontrados,
                 "hallazgos": plan.cfg["hallazgos"],
                 "excluidas_de_hallazgos": sum(1 for i in ids if plan.descartada(i)) if plan.excluye else 0}


def _unir(reg: dict, ident: str, nuevo: dict) -> None:
    if ident not in reg:
        reg[ident] = nuevo
        return
    actual = reg[ident]
    actual["fuentes"] |= nuevo["fuentes"]
    for k in ("activo", "ip", "sev", "cvss", "kev", "aviso"):
        if actual[k] == "" and nuevo[k] != "":
            actual[k] = nuevo[k]


def tablas(args) -> list:
    plan = de_args(args)
    if plan is None or not plan.tabla:
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, plan.tabla)]


def para_json(args):
    plan = de_args(args)
    return plan.json if plan is not None and plan.json else None
