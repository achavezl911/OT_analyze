"""M2: varias fuentes de flujos con nombre, su procedencia y el mapa de cobertura (D46).

Una fuente es el conjunto de exportaciones de un sensor. `separar` y `expandir` leen `--fuente NOMBRE=RUTA`;
`calcular` cruza los conductos (que llevan `fuentes`) con el inventario y dice que segmentos ve cada fuente
y cuales no ve ninguna. La cobertura es sobre lo importado: un segmento sin trafico en las exportaciones
puede estar sin sensor o simplemente callado. Funciones puras salvo `expandir`.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

from . import rutas_firewall as _rf
from .i18n import t

COL_COBERTURA = ["segmento", "fuente", "conductos_vistos", "equipos_vistos", "solo_esta_fuente", "espejo_switch"]
COL_RESUMEN = ["fuente", "tipo", "conductos", "unicos_de_la_fuente", "compartidos", "primera_fecha", "ultima_fecha"]
HOJA_COBERTURA = "Cobertura de fuentes"
HOJA_RESUMEN = "Fuentes de trafico"
TITULO = "Fuentes de trafico"
NOTA = ("La cobertura es la de las exportaciones importadas: un segmento sin conductos puede no tener sensor o "
        "no haber tenido trafico en el periodo. Un conducto visto por varias fuentes cuenta una sola vez, con "
        "el mayor volumen por fecha entre ellas.")
TIT_SIN_COBERTURA = "Segmentos sin cobertura de las fuentes de trafico (segun las fuentes importadas)"
MAX_SEGMENTOS = 20
_EXT = (".csv", ".xlsx", ".tsv")
_EXT_PCAP = (".pcap", ".pcapng", ".cap")


def es_captura(ruta) -> bool:
    """Captura = extension .pcap/.pcapng/.cap o primeros bytes de una cabecera pcap/pcapng (M2b)."""
    p = Path(ruta)
    if p.suffix.lower() in _EXT_PCAP:
        return True
    if p.suffix.lower() in _EXT:
        return False
    from .anonimizar import PCAP_MAGICOS
    try:
        with open(p, "rb") as fh:
            return fh.read(4) in PCAP_MAGICOS
    except OSError:
        return False


def tipo_fuente(archivos) -> str:
    """exportacion | captura | mixta, segun los archivos de la fuente."""
    n = sum(1 for a in archivos if es_captura(a))
    return "captura" if n and n == len(archivos) else ("mixta" if n else "exportacion")


def expandir(ruta: str) -> list:
    """Archivo -> [archivo]; carpeta -> sus CSV/XLSX/TSV y capturas ordenados. Sale con mensaje si no hay nada."""
    p = Path(ruta)
    if p.is_dir():
        out = sorted(str(x) for x in p.iterdir()
                     if x.is_file() and (x.suffix.lower() in _EXT or es_captura(x)))
        if not out:
            raise SystemExit(f"[!] La carpeta de la fuente '{ruta}' no tiene archivos CSV, XLSX o capturas.")
        return out
    if not p.is_file():
        raise SystemExit(f"[!] No existe el archivo de la fuente: {ruta}")
    return [str(p)]


def separar(valores: list, error=None) -> dict:
    """Valores de --fuente-flujos ('NOMBRE=RUTA') -> {nombre: [archivos]}. Un valor mal formado o una ruta que
    no existe llama a `error` (ap.error en el CLI) o lanza ValueError."""
    fuentes: dict = {}
    for v in valores or []:
        nombre, _sep, ruta = v.partition("=")
        if not (_sep and nombre.strip() and Path(ruta).exists()):
            msg = f"--fuente-flujos espera NOMBRE=RUTA existente: '{v}'"
            if error:
                error(msg)
            raise ValueError(msg)
        fuentes.setdefault(nombre.strip(), []).extend(expandir(ruta))
    return fuentes


def procesar_capturas(archivos: list, tshark: str | None = None, max_packets: int = 1_000_000) -> tuple:
    """({ruta: [registros]}, [avisos]). Mismo camino que el CLI de capturas (tshark, Capture, flujos y
    `build_conduits`) sin el pase de detalle. Cada registro: src, dst, l4, port, servicio, bidireccional, pkts,
    bytes y `dia` (UTC, de la primera vez que se vio el flujo; el modulo de flujos guarda solo primera y
    ultima marca, asi que cada conducto cuenta como un solo dia). Sin tshark, o con una captura ilegible,
    devuelve un aviso y sigue sin ella."""
    import shutil
    import tempfile
    from datetime import datetime, timezone

    from .consolidate import build_conduits
    from .fields import FLOW_FIELDS
    from .flows import analyze_flows
    from .model import Capture
    from .tools import CapturaIlegible, Tshark, find_tool
    from .util import port_info

    avisos: list = []
    try:
        bins = [find_tool(n, tshark) for n in ("tshark", "capinfos", "editcap")]
    except SystemExit as e:
        return {}, [f"{len(archivos)} capturas de las fuentes no se procesaron (sin tshark): {e.code}"]
    tmp = Path(tempfile.mkdtemp(prefix="ot_fuentes_"))
    try:
        ts = Tshark(*bins, tmp / ".probe")
        legibles = []
        for f in map(Path, archivos):
            try:
                ts.capinfos(f)
                legibles.append(f)
            except CapturaIlegible as e:
                avisos.append(f"{f.name}: captura ilegible, no se analiza ({e})")
        if not legibles:
            return {}, avisos
        ts.make_probe(legibles[0])
        campos = ts.valid_fields(FLOW_FIELDS)
        out: dict = {}
        for f in legibles:
            cap = Capture(f)
            try:
                analyze_flows(ts, cap, campos, max_packets)
            except CapturaIlegible as e:
                avisos.append(f"{f.name}: captura ilegible, no se analiza ({e})")
                continue
            regs = []
            for k in build_conduits([cap], {}):
                fl = cap.flows.get((k["src"], k["dst"], k["port"], k["l4"])) or {}
                t0 = fl.get("first") or 0
                dia = datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%d") if t0 else ""
                # el servicio por puerto lo deduce el importador (igual que en una exportacion sin protocolo);
                # solo se pasa el nombre que dio tshark cuando el puerto no lo da y no es solo TCP/UDP
                svc = "" if k["servicio"] in ("-", port_info(k["port"], k["l4"])[0]) or \
                    k["servicio"].lower() in ("tcp", "udp") else k["servicio"]
                regs.append({"src": k["src"], "dst": k["dst"], "l4": k["l4"], "port": k["port"],
                             "servicio": svc,
                             "bidireccional": k["bidireccional"], "pkts": k["pkts"], "bytes": k["bytes"],
                             "dia": dia})
            out[str(f)] = regs
        return out, avisos
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def segmentador(rutas: dict | None, fw: dict | None):
    """IP -> segmento: interfaz del firewall (firewall:interfaz si hay varios) o, sin ella, la red /24 (/64)."""
    tablas = []
    if (fw or {}).get("firewalls"):
        tablas = [(f["id"], (f["datos"].get("rutas_info") or {}).get("asignacion") or {})
                  for f in fw["firewalls"]]
    elif rutas:
        tablas = [("", rutas.get("asignacion") or {})]
    cache: dict = {}

    def seg(ip):
        if ip in cache:
            return cache[ip]
        r = None
        for fid, asg in tablas:
            ifc = asg.get(ip)
            if ifc and ifc != _rf.SIN_RUTA and not _rf._RE_FW.match(ifc):
                r = (fid + ":" if fid else "") + _rf.mostrar_iface(ifc)
                break
        if r is None:
            try:
                a = ipaddress.ip_address(str(ip).strip())
                r = str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))
            except ValueError:
                r = None
        cache[ip] = r
        return r
    return seg


def _espejo_segmento(estados: set) -> str:
    """Columna espejo_switch: estados SPAN (si/parcial/no) de las VLAN de los equipos del segmento."""
    if not estados:
        return ""
    if estados == {"si"}:
        return t("si")
    return t("no") if estados == {"no"} else t("parcial")


def calcular(conductos: list, assets: dict, info: dict, seg_de, espejo: dict | None = None) -> dict:
    """{'filas': [...], 'resumen': [...], 'sin_cobertura': [segmentos], 'nombres': [...]} desde los conductos
    con `fuentes` y el inventario. `info` es Importacion.fuentes; `seg_de` viene de `segmentador`.
    `espejo` ({vlan: si|parcial|no}, de switches.integracion.espejo_por_vlan) llena `espejo_switch` por
    segmento con la VLAN de sus equipos (la que dio la tabla MAC); sin ella o sin VLAN conocida, queda vacia."""
    nombres = info["nombres"]
    memo: dict = {}

    def seg_ep(ep):
        if ep not in memo:
            a = assets.get(ep)
            ips = sorted(a["ips"]) if a is not None else [ep]
            memo[ep] = seg_de(ips[0]) if ips else None
        return memo[ep]

    inventario = {s for s in (seg_ep(k) for k in assets) if s}
    total: dict = {}
    vistos: dict = {}
    for k in conductos:
        fs = k.get("fuentes") or []
        eps = {ep: seg_ep(ep) for ep in (k["src"], k["dst"])}
        for s in {s for s in eps.values() if s}:
            total[s] = total.get(s, 0) + 1
            for f in fs:
                c = vistos.setdefault((s, f), [0, set(), 0])
                c[0] += 1
                c[2] += len(fs) == 1
        for ep, s in eps.items():
            if s:
                for f in fs:
                    vistos.setdefault((s, f), [0, set(), 0])[1].add(ep)
    estados: dict = {}
    for k, a in assets.items():
        v = str(a.get("vlan") or "")
        if espejo and v in espejo and seg_ep(k):
            estados.setdefault(seg_ep(k), set()).add(espejo[v])
    filas = []
    for s in sorted(inventario | set(total)):
        for f in nombres:
            c = vistos.get((s, f)) or [0, (), 0]
            filas.append([s, f, c[0], len(c[1]), c[2], _espejo_segmento(estados.get(s, set()))])
    sin = sorted(s for s in inventario if not total.get(s))
    equipos = sorted({str(ip) for k, a in assets.items() if seg_ep(k) in sin for ip in a.get("ips") or ()})
    return {"filas": filas, "nombres": nombres, "resumen": info["resumen"],
            "sin_cobertura": sin, "equipos_sin_cobertura": equipos}


def hay(cob: dict | None) -> bool:
    return bool(cob and cob.get("filas"))


def filas_resumen(cob: dict) -> list:
    return [[x["fuente"], x["tipo"], x["conductos"], x["unicos"], x["compartidos"], x["primera"], x["ultima"]]
            for x in cob["resumen"]]


def cabecera_resumen() -> list:
    return [t("Fuente"), t("Tipo"), t("Conductos"), t("Solo esta fuente"), t("Compartidos"), t("Primera fecha"),
            t("Ultima fecha")]


def resumen_texto(cob: dict) -> str:
    txt = t("{n} fuentes de trafico; segmentos considerados: {s}. Detalle en fuentes_cobertura.csv y "
            "fuentes_resumen.csv.", n=len(cob["nombres"]), s=len({f[0] for f in cob["filas"]}))
    sin = cob["sin_cobertura"]
    if sin:
        txt += " " + t("Segmentos con equipos inventariados y sin trafico en ninguna fuente: {lista}.",
                       lista=", ".join(sin[:MAX_SEGMENTOS]))
    return txt


def agregar_hallazgo(cap, cob: dict) -> None:
    """Hallazgo informativo con los segmentos con equipos inventariados que ninguna fuente vio."""
    from .rules.base import finding

    sin = cob["sin_cobertura"]
    if not sin:
        return
    mas = len(sin) - MAX_SEGMENTOS
    lista = ", ".join(sin[:MAX_SEGMENTOS]) + (t(" y {n} mas", n=mas) if mas > 0 else "")
    finding(cap, "Informativa", TIT_SIN_COBERTURA,
            t("Segmentos con equipos en el inventario y ningun conducto en las fuentes ({n} fuentes: {f}): "
              "{lista}", n=len(cob["nombres"]), f=", ".join(cob["nombres"]), lista=lista),
            "Si ningun sensor ve un segmento, la actividad de sus equipos queda fuera de lo analizado y de "
            "cualquier deteccion basada en estas fuentes.",
            "Confirmar si el segmento tiene sensor o si solo estuvo callado en el periodo; si no tiene, "
            "valorar un punto de captura (SPAN o TAP).", "Visibilidad",
            activos=cob.get("equipos_sin_cobertura"))
