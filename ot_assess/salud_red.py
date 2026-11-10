"""L1 (D81): salud de la red y linea base de trafico.

Reutiliza lo que ya lee C1 (cobertura_captura.Acumulador: bytes por IP, mezcla de protocolos, difusion, ARP, TCP por
conducto) y los flujos de flows.py (serie por minuto de cada flujo); no vuelve a leer el pcap. De los switches toma lo
que lee `show interfaces` (BW, tasa de 5 minutos, errores y descartes). Los umbrales son heuristicas sin calibrar
(D81). Es evidencia tecnica de una captura, no un diagnostico ni cumplimiento de nada.
"""
from __future__ import annotations

import math

from . import __version__
from . import cobertura_captura as _cc
from .catalog import OT_PORTS
from .i18n import t
from .util import port_info

# --- umbrales (D81) ---------------------------------------------------------------------------------------- #
TOP = 10                       # filas de cada top
TOP_ARP = 5                    # equipos que mas ARP emiten
DIF_P95_PPS = 500              # p95 de paquetes/s de difusion (promedio de cada minuto)
DIF_PICO_PPS = 5000            # pico de paquetes de difusion en un segundo
RETRANS_MIN_SEG = 200          # segmentos TCP minimos de un conducto para evaluar retransmisiones
RETRANS_PCT = 5.0              # % de retransmisiones que dispara el hallazgo (conductos industriales)
UTIL_PCT = 70.0                # utilizacion de una interfaz en 5 minutos
DESCARTES_PCT = 0.1            # % de descartes de salida sobre los paquetes de salida
CRC_MAX = 1000                 # errores CRC acumulados

TITULO = "Salud de la red y linea base de trafico"
NOTA = ("Heuristicas sin calibrar (D81). Es evidencia tecnica de la captura (y de los contadores del switch, si se "
        "entregaron): no es un diagnostico ni un resultado de cumplimiento. El porcentaje de un equipo cuenta cada "
        "paquete en sus dos extremos, por eso la suma puede pasar de 100 %. El detalle completo, con IP, esta en "
        "salud_red.csv, top_equipos.csv, top_conductos.csv, mezcla_protocolos.csv e interfaces_switch.csv.")
NOTA_EXPORTACION = ("Analisis a partir de una exportacion: solo hay bytes y paquetes totales por conducto; no hay "
                    "series por minuto, difusion, ARP ni retransmisiones, y la linea base no trae percentiles por "
                    "minuto.")

A_SALUD, H_SALUD = "salud_red.csv", "Salud de la red"
A_EQUIPOS, H_EQUIPOS = "top_equipos.csv", "Top equipos"
A_CONDUCTOS, H_CONDUCTOS = "top_conductos.csv", "Top conductos"
A_MEZCLA, H_MEZCLA = "mezcla_protocolos.csv", "Mezcla de protocolos"
A_SWITCH, H_SWITCH = "interfaces_switch.csv", "Interfaces del switch"
A_BASE, H_BASE = "linea_base_trafico.csv", "Linea base de trafico"
A_BASE_JSON = "linea_base_trafico.json"

C_SALUD = ["punto", "duracion_s", "paquetes", "bytes", "mbps_promedio", "mbps_p95_minuto", "mbps_max_minuto",
           "difusion_multidifusion_pct", "difusion_pps_p95", "difusion_pps_max_minuto", "difusion_pico_pps",
           "arp_por_minuto_p95", "arp_por_minuto_max", "arp_paquetes", "arp_emisores_top", "segmentos_tcp",
           "perdida_tcp_pct", "retransmisiones_pct", "conductos_tcp_evaluados", "conductos_tcp_sobre_umbral"]
C_EQUIPOS = ["punto", "orden", "posicion", "equipo", "ip", "bytes", "bytes_pct", "paquetes", "paquetes_pct"]
C_CONDUCTOS = ["punto", "posicion", "origen", "origen_ip", "destino", "destino_ip", "servicio", "l4", "puerto",
               "bytes", "bytes_pct", "paquetes", "paquetes_pct"]
C_MEZCLA = ["punto", "tipo", "servicio", "bytes", "bytes_pct", "paquetes", "paquetes_pct"]
C_TCP = ["punto", "cliente", "cliente_ip", "servidor", "servidor_ip", "puerto", "segmentos",
         "retransmisiones_pct", "perdida_pct", "industrial"]
A_TCP = "tcp_conductos.csv"
C_SWITCH = ["switch", "interfaz", "rol", "bw_kbit", "entrada_bps", "salida_bps", "utilizacion_pct",
            "errores_entrada", "crc", "descartes_salida", "descartes_pct", "destino_span", "cuello_de_botella"]
C_BASE = ["origen", "origen_ip", "destino", "destino_ip", "servicio", "l4", "puerto", "sentido", "bytes_total",
          "paquetes_total", "bytes_min_p50", "bytes_min_p95", "paquetes_min_p50", "paquetes_min_p95",
          "minutos_ventana", "minutos_activos", "periodicidad", "primer_visto", "ultimo_visto", "serie_por_minuto"]

TOTAL = "Total"


def hay(rep: dict) -> bool:
    return bool(rep and (rep.get("puntos") or rep.get("switch") or rep.get("exportacion") or rep.get("linea_base")))


# --- ayudas ------------------------------------------------------------------------------------------------ #

def _pct(a, b) -> float:
    return a * 100.0 / b if b else 0.0


def _serie(contador: dict, t0, t1, div: float = 1.0) -> list:
    """Valor de cada minuto entre el de t0 y el de t1, con ceros en los minutos sin dato."""
    if t0 is None:
        return []
    return [contador.get(m, 0) / div for m in range(int(t0 // 60), int(t1 // 60) + 1)]


def nombres_por_ip(assets: dict) -> dict:
    out: dict = {}
    for a in assets.values():
        for ip in a.get("ips", ()):
            if ip not in out or a.get("pkts", 0) > out[ip][1]:
                out[ip] = (a.get("nombre") or ip, a.get("pkts", 0))
    return {ip: v[0] for ip, v in out.items()}


def _nombres_por_mac(assets: dict) -> dict:
    return {str(a["mac"]).lower(): a.get("nombre") or a["mac"] for a in assets.values() if a.get("mac")}


def _etq(ip: str, nombres: dict) -> str:
    return nombres.get(ip) or ip


# --- estadisticas sobre los datos de C1 -------------------------------------------------------------------- #

def stats_difusion(raw: dict) -> dict:
    """pps de difusion y multidifusion (promedio de cada minuto: p95 y maximo), pico en un segundo y ARP."""
    t0, t1 = raw.get("t0"), raw.get("t1")
    pps = _serie(raw.get("dif_min", {}), t0, t1, 60.0)
    arp = _serie(raw.get("arp_min", {}), t0, t1)
    pico = raw.get("dif_pico", {})
    m_pico = max(pico, key=lambda m: (pico[m], -m)) if pico else None
    return {"pps_p95": _cc.p95(pps), "pps_max": max(pps) if pps else 0.0,
            "pico_s": pico[m_pico] if pico else 0, "minuto_pico": m_pico,
            "arp_p95": _cc.p95(arp), "arp_max": max(arp) if arp else 0, "arp_total": sum(raw.get("arp_min", {}).values())}


def tormenta(raw: dict) -> bool:
    d = stats_difusion(raw)
    return d["pps_p95"] > DIF_P95_PPS or d["pico_s"] > DIF_PICO_PPS


def tcp_conductos(raw: dict) -> list:
    """Conductos TCP con al menos RETRANS_MIN_SEG segmentos, del peor al mejor: (cliente, servidor, puerto, segmentos,
    % retransmisiones, % perdida, industrial)."""
    out = []
    for (cli, srv, puerto), (seg, ret, perd) in raw.get("tcp_serv", {}).items():
        if seg >= RETRANS_MIN_SEG:
            ind = OT_PORTS.get((puerto, "tcp"), ("", ""))[1] == "ot"
            out.append((cli, srv, puerto, seg, _pct(ret, seg), _pct(perd, seg), ind))
    out.sort(key=lambda x: (-x[4], -x[5], -x[3], x[0], x[1], x[2]))
    return out


def tcp_sobre_umbral(raw: dict) -> list:
    return [x for x in tcp_conductos(raw) if x[6] and x[4] > RETRANS_PCT]


def top_equipos(raw: dict, nombres: dict) -> tuple:
    """([por bytes], [por paquetes]); cada fila es (etiqueta, ip, bytes, %bytes, paquetes, %paquetes)."""
    tb, tp = raw.get("bytes", 0), raw.get("paquetes", 0)
    filas = []
    for ip, e in raw.get("ips", {}).items():
        b = e[3] + e[4] if len(e) > 4 else 0
        p = e[0] + e[1] + e[2]
        filas.append((_etq(ip, nombres), ip, b, _pct(b, tb), p, _pct(p, tp)))
    por_b = sorted(filas, key=lambda x: (-x[2], x[1]))[:TOP]
    por_p = sorted(filas, key=lambda x: (-x[4], x[1]))[:TOP]
    return por_b, por_p


def mezcla(raw: dict) -> list:
    """Filas (tipo, servicio, bytes, %bytes, paquetes, %paquetes) por servicio; los industriales aparte (primero)."""
    m = raw.get("mezcla", {})
    tb = sum(v[0] for v in m.values())
    tp = sum(v[1] for v in m.values())
    filas = []
    for k, (b, p) in m.items():
        ind = k.startswith("ot:")
        filas.append((ind, k[k.index(":") + 1:], b, _pct(b, tb), p, _pct(p, tp)))
    filas.sort(key=lambda x: (not x[0], -x[2], x[1]))
    return [("industrial" if i else "otro", s, b, pb, p, pp) for i, s, b, pb, p, pp in filas]


def _conductos_de(caps: list) -> dict:
    """{(origen, destino, l4, puerto): [bytes, paquetes]} de los flujos de las capturas."""
    out: dict = {}
    for c in caps:
        for f in c.flows.values():
            if not f["src"] or not f["dst"]:
                continue
            e = out.setdefault((f["src"], f["dst"], f["l4"], f["dport"]), [0, 0])
            e[0] += f["bytes"]
            e[1] += f["pkts"]
    return out


def top_conductos(cond: dict, nombres: dict, tb: int, tp: int) -> list:
    """(origen, ip, destino, ip, servicio, l4, puerto, bytes, %bytes, paquetes, %paquetes), por bytes."""
    filas = []
    for (s, d, l4, p), (b, k) in sorted(cond.items(), key=lambda x: (-x[1][0], x[0])):
        svc = port_info(p, l4)[0] or "-"
        filas.append((_etq(s, nombres), s, _etq(d, nombres), d, svc, l4, p, b, _pct(b, tb), k, _pct(k, tp)))
        if len(filas) >= TOP:
            break
    return filas


# --- un punto de captura ----------------------------------------------------------------------------------- #

def _bloque(nombre: str, raw: dict, cond: dict, nombres: dict, macs: dict) -> dict:
    m = _cc.metricas(raw)
    d = stats_difusion(raw)
    tcp = tcp_conductos(raw)
    emisores = sorted(raw.get("arp_src", {}).items(), key=lambda x: (-x[1], x[0]))[:TOP_ARP]
    por_b, por_p = top_equipos(raw, nombres)
    return {"punto": nombre, "m": m, "dif": d,
            "arp_emisores": [(macs.get(str(mac).lower()) or mac, n) for mac, n in emisores],
            "equipos_bytes": por_b, "equipos_paquetes": por_p,
            "conductos": top_conductos(cond, nombres, raw["bytes"], raw["paquetes"]),
            "mezcla": mezcla(raw), "nombres": nombres, "tcp": tcp[:TOP], "tcp_evaluados": len(tcp),
            "tcp_sobre_umbral": len(tcp_sobre_umbral(raw))}


# --- switch ------------------------------------------------------------------------------------------------ #

def _es_troncal(sw, nombre: str) -> bool:
    p = sw.puerto(nombre)
    return bool(p and (p.modo == "trunk" or p.canal)) or nombre.lower().startswith(("po", "port-channel"))


def interfaces_switch(switches: dict) -> dict:
    """Filas por interfaz de los `show interfaces` entregados y los cuellos de botella (D81). La interfaz destino de un
    SPAN no se evalua aqui: sus descartes ya son un hallazgo de T10c."""
    from .switches.cisco_ios import clave_if
    from .switches.higiene import _destinos_span
    filas, cuellos = [], []
    for sw in switches.get("switches", ()) if switches else ():
        destinos = _destinos_span(sw)
        for c in sw.contadores:
            if c.paquetes is None and c.bw_kbit is None and c.tasa_entrada_bps is None:
                continue          # solo salio de `counters errors`: sin tasas ni paquetes
            tasa = max(c.tasa_entrada_bps or 0, c.tasa_salida_bps or 0)
            hay_tasa = c.tasa_entrada_bps is not None or c.tasa_salida_bps is not None
            util = tasa * 100.0 / (c.bw_kbit * 1000) if c.bw_kbit and hay_tasa else None
            enviados = (c.descartes + c.paquetes_salida) if c.paquetes_salida is not None else 0
            dpct = c.descartes * 100.0 / enviados if enviados else None
            span = clave_if(c.puerto) in destinos
            tronc = _es_troncal(sw, c.puerto)
            motivos = []
            if not span:
                if util is not None and util >= UTIL_PCT:
                    motivos.append(t("utilizacion de {p} % en 5 minutos", p=f"{util:.1f}"))
                if dpct is not None and dpct > DESCARTES_PCT:
                    motivos.append(t("descartes de salida: {p} % de los paquetes de salida", p=f"{dpct:.2f}"))
                if c.crc > CRC_MAX:
                    motivos.append(t("{n} errores CRC", n=c.crc))
            fila = {"switch": sw.hostname, "interfaz": c.puerto, "troncal": tronc, "bw_kbit": c.bw_kbit,
                    "entrada": c.tasa_entrada_bps, "salida": c.tasa_salida_bps, "util": util,
                    "errores": c.errores, "crc": c.crc, "descartes": c.descartes, "dpct": dpct, "span": span,
                    "motivos": motivos}
            filas.append(fila)
            if motivos:
                cuellos.append(fila)
    cuellos.sort(key=lambda f: (not f["troncal"], -(f["util"] or 0), f["switch"], f["interfaz"]))
    return {"filas": filas, "cuellos": cuellos} if filas else {}


# --- linea base --------------------------------------------------------------------------------------------- #

def _rango(nz: list, ceros: int, p: float):
    """Valor del percentil p (rango mas cercano) de la lista `nz` (ordenada) mas `ceros` ceros."""
    n = ceros + len(nz)
    if n == 0:
        return 0
    r = max(math.ceil(p * n) - 1, 0)
    return 0 if r < ceros else nz[r - ceros]


def _iso(x) -> str:
    return _cc._iso(x) if x else ""


def linea_base(caps: list, conductos: list, version: str, cliente: str = "") -> dict:
    """Linea base por conducto: bytes y paquetes por minuto (p50 y p95) dentro de la ventana de las capturas, la clase
    de periodicidad de T5 y el primer y ultimo visto. Los minutos sin trafico cuentan como cero; las ventanas de
    capturas distintas se suman (el lapso entre ellas no cuenta)."""
    from .periodicidad import conductos as _per
    ventanas = [c.ventana for c in caps if not c.error and len(c.ventana) == 2]
    total_min = sum(int(v[1] // 60) - int(v[0] // 60) + 1 for v in ventanas)
    acc: dict = {}
    patron: dict = {}
    for c in caps:
        if c.error:
            continue
        for f in c.flows.values():
            k = (f["src"], f["dst"], f["l4"], f["dport"])
            a = acc.setdefault(k, {"b": [], "p": [], "serie": True, "ini": None, "fin": None})
            if f.get("min") is None:
                a["serie"] = False
            else:
                for v in f["min"].values():
                    a["b"].append(v >> 32)
                    a["p"].append(v & 0xFFFFFFFF)
            if f.get("first"):
                a["ini"] = f["first"] if a["ini"] is None else min(a["ini"], f["first"])
            a["fin"] = f["last"] if a["fin"] is None else max(a["fin"], f["last"])
        for x in _per(c):
            kk = (x["src"], x["dst"], x["l4"], x["dport"])
            if kk not in patron or x["peticiones"] > patron[kk][1]:
                patron[kk] = (x["patron"], x["peticiones"])
    filas = []
    for k in conductos:
        a = acc.get((k["src"], k["dst"], k["l4"], k["port"]))
        base = {"origen": k.get("src_nombre") or k["src"], "origen_ip": k["src"], "destino": k.get("dst_nombre") or k["dst"], "destino_ip": k["dst"],
                "servicio": k["servicio"], "l4": k["l4"], "puerto": k["port"], "bidireccional": k["bidireccional"],
                "bytes_total": k["bytes"], "paquetes_total": k["pkts"], "bytes_min_p50": None,
                "bytes_min_p95": None, "paquetes_min_p50": None, "paquetes_min_p95": None, "minutos_ventana": None,
                "minutos_activos": None, "periodicidad": patron.get((k["src"], k["dst"], k["l4"], k["port"]),
                                                                       ("",))[0],
                "primer_visto": _iso(a["ini"]) if a else "", "ultimo_visto": _iso(a["fin"]) if a else "",
                "serie_por_minuto": False}
        if a and a["serie"] and total_min:
            nb, npk = sorted(a["b"]), sorted(a["p"])
            base.update(bytes_min_p50=_rango(nb, total_min - len(nb), 0.5),
                        bytes_min_p95=_rango(nb, total_min - len(nb), 0.95),
                        paquetes_min_p50=_rango(npk, total_min - len(npk), 0.5),
                        paquetes_min_p95=_rango(npk, total_min - len(npk), 0.95),
                        minutos_ventana=total_min, minutos_activos=len(npk), serie_por_minuto=True)
        filas.append(base)
    filas.sort(key=lambda f: (f["origen_ip"], f["destino_ip"], f["l4"], str(f["puerto"])))
    meta = {"version": version, "cliente": cliente,
            "ventana": {"inicio": _iso(min((v[0] for v in ventanas), default=None)),
                        "fin": _iso(max((v[1] for v in ventanas), default=None)), "minutos": total_min},
            "puntos_de_captura": sorted({c.path.parent.name or c.name for c in caps if not c.error}),
            "capturas": sorted(c.name for c in caps if not c.error)}
    return {"meta": meta, "conductos": filas}


def linea_base_exportacion(conductos: list, version: str, cliente: str = "") -> dict:
    """Linea base de una exportacion: solo totales por conducto; sin series por minuto."""
    filas = []
    for k in conductos:
        filas.append({"origen": k.get("src_nombre") or k["src"], "origen_ip": k["src"], "destino": k.get("dst_nombre") or k["dst"],
                      "destino_ip": k["dst"], "servicio": k["servicio"], "l4": k["l4"], "puerto": k["port"],
                      "bidireccional": k["bidireccional"], "bytes_total": k["bytes"], "paquetes_total": k["pkts"],
                      "bytes_min_p50": None, "bytes_min_p95": None, "paquetes_min_p50": None,
                      "paquetes_min_p95": None, "minutos_ventana": None, "minutos_activos": None,
                      "periodicidad": "", "primer_visto": "", "ultimo_visto": "", "serie_por_minuto": False})
    filas.sort(key=lambda f: (f["origen_ip"], f["destino_ip"], f["l4"], str(f["puerto"])))
    return {"meta": {"version": version, "cliente": cliente, "ventana": {"inicio": "", "fin": "", "minutos": 0},
                     "puntos_de_captura": [], "capturas": [], "origen": "exportacion"}, "conductos": filas}


# --- construccion ------------------------------------------------------------------------------------------ #

def construir(cobertura: dict, caps: list, assets: dict, conductos: list, switches: dict, perfil: dict | None = None) -> dict:
    """Resultado de L1 para una corrida de capturas. `cobertura`: cobertura_captura.construir (trae `raw` y `paths`)."""
    perfil = perfil or {}
    nombres, macs = nombres_por_ip(assets), _nombres_por_mac(assets)
    por_path = {str(c.path): c for c in caps}
    puntos, raws, cond_total = [], [], {}
    for p in (cobertura or {}).get("puntos", ()):
        cond = _conductos_de([por_path[x] for x in p["paths"] if x in por_path])
        for k, (b, n) in cond.items():
            e = cond_total.setdefault(k, [0, 0])
            e[0] += b
            e[1] += n
        puntos.append(_bloque(p["punto"], p["raw"], cond, nombres, macs))
        raws.append(p["raw"])
    rep: dict = {"origen": "captura"}
    if puntos:
        total = _cc.fusionar(raws) if len(raws) > 1 else raws[0]
        rep["puntos"] = puntos
        rep["total"] = _bloque(TOTAL, total, cond_total, nombres, macs)
        rep["linea_base"] = linea_base(caps, conductos, __version__, perfil.get("cliente", ""))
    sw = interfaces_switch(switches)
    if sw:
        rep["switch"] = sw
    return rep if (puntos or sw) else {}


def de_exportacion(assets: dict, conductos: list, perfil: dict | None = None) -> dict:
    """L1 con lo que traiga una exportacion (`diagrama`): bytes y paquetes por conducto, sin series por minuto."""
    perfil = perfil or {}
    cond = {(k["src"], k["dst"], k["l4"], k["port"]): [k["bytes"], k["pkts"]] for k in conductos}
    tb = sum(v[0] for v in cond.values())
    tp = sum(v[1] for v in cond.values())
    if not tb and not tp:
        return {}
    nombres = nombres_por_ip(assets)
    ips: dict = {}
    for (s, d, _l4, _p), (b, n) in cond.items():
        for ip in (s, d):
            e = ips.setdefault(ip, [0, 0, 0, 0, 0])
            e[0 if ip == s else 1] += n
            e[3 if ip == s else 4] += b
    mz: dict = {}
    for k in conductos:
        e = mz.setdefault(("ot:" if k["categoria"] == "ot" else "p:") + (k["servicio"] or "otros"), [0, 0])
        e[0] += k["bytes"]
        e[1] += k["pkts"]
    por_b, por_p = top_equipos({"bytes": tb, "paquetes": tp, "ips": ips}, nombres)
    bloque = {"punto": TOTAL, "m": None, "dif": None, "arp_emisores": [], "equipos_bytes": por_b,
              "equipos_paquetes": por_p, "conductos": top_conductos(cond, nombres, tb, tp),
              "mezcla": mezcla({"mezcla": mz}), "nombres": nombres, "tcp": [], "tcp_evaluados": 0, "tcp_sobre_umbral": 0}
    return {"origen": "exportacion", "exportacion": True, "puntos": [], "total": bloque,
            "linea_base": linea_base_exportacion(conductos, __version__, perfil.get("cliente", ""))}


# --- hallazgos del switch ---------------------------------------------------------------------------------- #

TIT_INTERFAZ = "Interfaz de switch saturada o con descartes"


def agregar_hallazgos(cap, rep: dict) -> None:
    """Hallazgo de interfaces de switch saturadas o con descartes (L1, D81). `cap`: Capture auxiliar."""
    from .rules.base import finding
    cuellos = (rep or {}).get("switch", {}).get("cuellos", [])
    if not cuellos:
        return
    lineas = []
    for f in cuellos[:TOP]:
        rol = t("troncal o uplink") if f["troncal"] else t("acceso")
        lineas.append(f"{f['switch']} {f['interfaz']} ({rol}): " + "; ".join(f["motivos"]))
    if len(cuellos) > TOP:
        lineas.append(t(" y {n} mas", n=len(cuellos) - TOP).strip())
    finding(cap, "Media", TIT_INTERFAZ,
            t("{n} interfaces: utilizacion de al menos {u} % en 5 minutos, descartes de salida de mas de {d} % o mas "
              "de {c} errores CRC. Los contadores son acumulados desde el arranque o el ultimo clear y la tasa de 5 "
              "minutos es una sola lectura.", n=len(cuellos), u=UTIL_PCT, d=DESCARTES_PCT, c=CRC_MAX)
            + "\n" + "\n".join(lineas),
            "Una interfaz cerca de su capacidad o que descarta paquetes retrasa o pierde el trafico de control que "
            "pasa por ella; en un troncal afecta a todas las VLAN que lo usan. Los errores CRC apuntan a cableado, "
            "conectores o duplex.",
            "Repetir la lectura en horas de mayor trafico para confirmar la tendencia, identificar que trafico "
            "llena la interfaz (top de conductos de esta herramienta), y dimensionar el enlace, separar VLAN o "
            "aplicar calidad de servicio; revisar el cableado si hay CRC. Cambios en ventana acordada.",
            categoria="Higiene")


# --- salidas ----------------------------------------------------------------------------------------------- #

def _bps(x) -> str:
    return "" if x is None else str(x)


def tablas(rep: dict) -> list:
    """[(archivo_csv, hoja, cabecera, filas)]."""
    if not hay(rep):
        return []
    out = []
    bloques = [*rep.get("puntos", ()), *([rep["total"]] if rep.get("total") else [])]
    if bloques:
        sal, eq, co, mz, tc = [], [], [], [], []
        for b in bloques:
            nom = t(TOTAL) if b["punto"] == TOTAL else b["punto"]
            m, d = b["m"], b["dif"]
            if m:
                sal.append([nom, f"{m['duracion_s']:.0f}", m["paquetes"], m["bytes"], f"{m['mbps']:.3f}",
                            f"{m['mbps_p95']:.3f}", f"{m['mbps_max']:.3f}", f"{m['difusion_pct']:.2f}",
                            f"{d['pps_p95']:.2f}", f"{d['pps_max']:.2f}", d["pico_s"], f"{d['arp_p95']:.0f}",
                            d["arp_max"], d["arp_total"], ";".join(f"{e}={n}" for e, n in b["arp_emisores"]),
                            m["tcp"], f"{m['perdida_pct']:.2f}", f"{m['retrans_pct']:.2f}", b["tcp_evaluados"],
                            b["tcp_sobre_umbral"]])
            for orden, lista in (("bytes", b["equipos_bytes"]), ("paquetes", b["equipos_paquetes"])):
                for i, (n, ip, by, pb, pk, pp) in enumerate(lista, 1):
                    eq.append([nom, t(orden), i, n, ip, by, f"{pb:.2f}", pk, f"{pp:.2f}"])
            for i, (o, oi, de, di, sv, l4, pu, by, pb, pk, pp) in enumerate(b["conductos"], 1):
                co.append([nom, i, o, oi, de, di, sv, l4, pu, by, f"{pb:.2f}", pk, f"{pp:.2f}"])
            for tipo, sv, by, pb, pk, pp in b["mezcla"]:
                mz.append([nom, t(tipo), sv, by, f"{pb:.2f}", pk, f"{pp:.2f}"])
            for cli, srv, pu, seg, rp, pp, ind in b["tcp"]:
                tc.append([nom, _etq(cli, b["nombres"]), cli, _etq(srv, b["nombres"]), srv, pu, seg, f"{rp:.2f}",
                           f"{pp:.2f}", t("si") if ind else t("no")])
        if sal:
            out.append((A_SALUD, H_SALUD, C_SALUD, sal))
        out += [(A_EQUIPOS, H_EQUIPOS, C_EQUIPOS, eq), (A_CONDUCTOS, H_CONDUCTOS, C_CONDUCTOS, co),
                (A_MEZCLA, H_MEZCLA, C_MEZCLA, mz)]
        if tc:
            out.append((A_TCP, None, C_TCP, tc))
    sw = rep.get("switch")
    if sw:
        filas = [[f["switch"], f["interfaz"], t("troncal o uplink") if f["troncal"] else t("acceso"),
                  _bps(f["bw_kbit"]), _bps(f["entrada"]), _bps(f["salida"]),
                  "" if f["util"] is None else f"{f['util']:.1f}", f["errores"], f["crc"], f["descartes"],
                  "" if f["dpct"] is None else f"{f['dpct']:.3f}", t("si") if f["span"] else t("no"),
                  "; ".join(f["motivos"])] for f in sw["filas"]]
        out.append((A_SWITCH, H_SWITCH, C_SWITCH, filas))
    lb = rep.get("linea_base")
    if lb and lb["conductos"]:
        out.append((A_BASE, H_BASE, C_BASE, [
            [f["origen"], f["origen_ip"], f["destino"], f["destino_ip"], f["servicio"], f["l4"], f["puerto"],
             t("bidireccional") if f["bidireccional"] else t("unidireccional"), f["bytes_total"], f["paquetes_total"],
             *["" if f[c] is None else f[c] for c in ("bytes_min_p50", "bytes_min_p95", "paquetes_min_p50",
                                                       "paquetes_min_p95", "minutos_ventana", "minutos_activos")],
             f["periodicidad"] and t(f["periodicidad"]), f["primer_visto"], f["ultimo_visto"],
             t("si") if f["serie_por_minuto"] else t("no")] for f in lb["conductos"]]))
    return out


def seccion(rep: dict) -> dict:
    """Seccion de los reportes: tablas cortas (el detalle esta en los CSV)."""
    tot = rep.get("total")
    out: dict = {"titulo": t(TITULO), "nota": t(NOTA), "tablas": []}
    if rep.get("exportacion"):
        out["nota"] = t(NOTA_EXPORTACION) + " " + t(NOTA)
    if rep.get("puntos"):
        cab = [t(c) for c in ("Punto", "Mbps promedio", "Mbps p95", "Difusion %", "Difusion pps p95",
                              "Pico difusion pps", "Retransmisiones TCP %", "Perdida TCP %")]
        filas = [[b["punto"], f"{b['m']['mbps']:.2f}", f"{b['m']['mbps_p95']:.2f}", f"{b['m']['difusion_pct']:.2f}",
                  f"{b['dif']['pps_p95']:.1f}", b["dif"]["pico_s"], f"{b['m']['retrans_pct']:.2f}",
                  f"{b['m']['perdida_pct']:.2f}"] for b in rep["puntos"]]
        out["tablas"].append((t("Metricas por punto de captura"), cab, filas))
    if tot:
        cab = [t(c) for c in ("Equipo", "Bytes", "% de bytes", "Paquetes", "% de paquetes")]
        filas = [[n, b, f"{pb:.1f}", pk, f"{pp:.1f}"] for n, _ip, b, pb, pk, pp in tot["equipos_bytes"][:5]]
        out["tablas"].append((t("Equipos que mas trafico mueven (total)"), cab, filas))
        cab = [t(c) for c in ("Origen", "Destino", "Servicio", "Bytes", "% de bytes")]
        filas = [[o, de, sv, b, f"{pb:.1f}"] for o, _oi, de, _di, sv, _l4, _pu, b, pb, _pk, _pp in tot["conductos"][:5]]
        out["tablas"].append((t("Conductos que mas trafico mueven (total)"), cab, filas))
        cab = [t(c) for c in ("Tipo", "Servicio", "% de bytes", "% de paquetes")]
        filas = [[t(tipo), sv, f"{pb:.1f}", f"{pp:.1f}"] for tipo, sv, _b, pb, _k, pp in tot["mezcla"][:8]]
        out["tablas"].append((t("Mezcla de protocolos (total)"), cab, filas))
        if tot["tcp"]:
            cab = [t(c) for c in ("Cliente", "Servidor", "Puerto", "Segmentos", "Retransmisiones %", "Perdida %")]
            filas = [[_etq(c, tot["nombres"]), _etq(s, tot["nombres"]), p, seg, f"{rp:.1f}", f"{pp:.1f}"]
                     for c, s, p, seg, rp, pp, _i in tot["tcp"][:5]]
            out["tablas"].append((t("TCP con mas retransmisiones (conductos con al menos {n} segmentos)",
                                    n=RETRANS_MIN_SEG), cab, filas))
    sw = rep.get("switch")
    if sw:
        cab = [t(c) for c in ("Switch", "Interfaz", "Rol", "Utilizacion %", "Descartes %", "CRC", "Motivo")]
        filas = [[f["switch"], f["interfaz"], t("troncal o uplink") if f["troncal"] else t("acceso"),
                  "-" if f["util"] is None else f"{f['util']:.1f}", "-" if f["dpct"] is None else f"{f['dpct']:.2f}",
                  f["crc"], "; ".join(f["motivos"])] for f in sw["cuellos"][:TOP]]
        if filas:
            out["tablas"].append((t("Cuellos de botella del switch"), cab, filas))
    lb = rep.get("linea_base")
    n = len(lb["conductos"]) if lb else 0
    con_serie = sum(1 for f in lb["conductos"] if f["serie_por_minuto"]) if lb else 0
    partes = [t("Linea base de trafico: {n} conductos, {s} con percentiles por minuto. Archivos {j} y {c}.",
                n=n, s=con_serie, j=A_BASE_JSON, c=A_BASE)]
    if sw:
        partes.append(t("{k} interfaces de switch leidas, {c} con cuello de botella. Detalle en {f}.",
                        k=len(sw["filas"]), c=len(sw["cuellos"]), f=A_SWITCH))
    if rep.get("exportacion"):
        partes.append(t(NOTA_EXPORTACION))
    elif lb and n and not con_serie:
        partes.append(t("Ningun conducto tiene serie por minuto (cupo de memoria agotado o captura sin hora)."))
    out["resumen"] = " ".join(partes)
    return out


def para_json(rep: dict) -> dict:
    """Resumen para resultado.json (la linea base completa va en linea_base_trafico.json)."""
    if not hay(rep):
        return {}
    out: dict = {"origen": rep.get("origen", "captura")}
    if rep.get("total"):
        b = rep["total"]
        out["total"] = {"equipos_top_bytes": [{"equipo": n, "bytes": by, "bytes_pct": round(pb, 2)}
                                              for n, _i, by, pb, _k, _p in b["equipos_bytes"]],
                        "mezcla": [{"tipo": tp, "servicio": sv, "bytes_pct": round(pb, 2),
                                    "paquetes_pct": round(pp, 2)} for tp, sv, _b, pb, _k, pp in b["mezcla"]]}
        if b["m"]:
            out["total"].update(mbps_p95=round(b["m"]["mbps_p95"], 3), difusion_pct=round(b["m"]["difusion_pct"], 2),
                                difusion_pps_p95=round(b["dif"]["pps_p95"], 2), difusion_pico_pps=b["dif"]["pico_s"],
                                retransmisiones_pct=round(b["m"]["retrans_pct"], 2),
                                perdida_tcp_pct=round(b["m"]["perdida_pct"], 2))
    out["puntos"] = [{"punto": b["punto"], "mbps_p95": round(b["m"]["mbps_p95"], 3),
                      "difusion_pps_p95": round(b["dif"]["pps_p95"], 2), "difusion_pico_pps": b["dif"]["pico_s"],
                      "retransmisiones_pct": round(b["m"]["retrans_pct"], 2),
                      "conductos_tcp_sobre_umbral": b["tcp_sobre_umbral"]} for b in rep.get("puntos", ())]
    if rep.get("switch"):
        out["switch"] = {"interfaces": len(rep["switch"]["filas"]),
                         "cuellos_de_botella": [{"switch": f["switch"], "interfaz": f["interfaz"],
                                                 "motivos": f["motivos"]} for f in rep["switch"]["cuellos"]]}
    if rep.get("linea_base"):
        out["linea_base_conductos"] = len(rep["linea_base"]["conductos"])
    return out


def linea_base_json(rep: dict) -> dict:
    """Contenido de linea_base_trafico.json ({} si no hay)."""
    lb = (rep or {}).get("linea_base")
    return lb if lb and lb["conductos"] else {}

