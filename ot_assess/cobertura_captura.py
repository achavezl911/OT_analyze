"""Validacion de la cobertura de la captura (C1, D80): veredicto por punto de captura.

El primer dia de un sensor (SPAN o TAP) hay que decidir si la captura sirve: si el espejo pierde paquetes, si ve un
solo sentido, si faltan VLAN o zonas. Este modulo mide eso por archivo y por punto (carpeta) y emite un veredicto con
motivos. Las constantes son heuristicas sin calibrar (D80). El veredicto no es cumplimiento de nada: es una
advertencia sobre la calidad de la evidencia.

`Acumulador` lee las filas de tshark con memoria acotada (un histograma por minuto, un byte por sesion TCP, un
contador por IP). `fusionar` junta archivos de un punto; `construir` arma el resultado que leen los reportes.
"""
from __future__ import annotations

import collections
import ipaddress
import math
from datetime import datetime, timezone
from pathlib import Path

from .catalog import OT_PORTS
from .i18n import t
from .util import g, human_duration, is_host_ip

# --- constantes del veredicto (D80) ------------------------------------------------------------------------ #
HUECO_S = 300                  # lapso sin paquetes mayor que esto es un hueco
PERDIDA_NO_APTA = 5.0        # % de segmentos TCP con perdida detectada
PERDIDA_LIMITE = 1.0
UNSENTIDO_NO_APTA = 50.0       # % de sesiones TCP con datos de un solo lado
UNSENTIDO_LIMITE = 20.0
DURACION_NO_APTA_S = 600       # menos de 10 min
DURACION_CICLO_S = 86400       # menos de 24 h: no cubre un ciclo diario
MAX_IPS = 100_000              # tope de IP distintas por archivo (memoria acotada)
MAX_SESIONES = 20_000_000      # tope del indice de tcp.stream (un byte por sesion)
MAX_CLAVES = 2_000             # tope de etiquetas distintas de la mezcla de protocolos (L1, D81)
MAX_TCP_SERV = 50_000          # tope de conductos TCP (cliente, servidor, puerto) con conteo de segmentos (L1)

APTA, LIMITADA, NO_APTA = "apta", "apta con limitaciones", "no apta"
ESTADO_VISTA, ESTADO_DIFUSION, ESTADO_SIN = "vista", "solo difusion", "sin trafico"

# Protocolos industriales por el nombre que pone Wireshark a la trama (los de puerto salen de OT_PORTS).
_NOMBRES_OT = {"MODBUS", "MODBUS/TCP", "DNP3", "ENIP", "CIP", "CIPCM", "S7COMM", "S7COMM-PLUS", "GOOSE", "MMS",
               "SV", "BACAPP", "BACNET", "BVLC", "OPCUA", "IEC 60870-5-104", "IEC104", "PN-DCP", "PN-RT", "PN-IO",
               "PN-PTCP", "PROFINET", "FINS", "OMRON FINS", "SRTP", "EPICS", "HART_IP", "IEC61850", "COTP"}

NOTA = ("Heuristicas sin calibrar (D80): el veredicto advierte sobre la calidad de la captura como evidencia; "
        "no es un resultado de cumplimiento. Perdida TCP: segmentos con huecos de secuencia vistos en el espejo. "
        "Sentido unico: sesiones TCP con datos de un solo lado.")
TITULO = "Validacion de la captura"
ARCHIVO, HOJA = "cobertura_captura.csv", "Cobertura de captura"
ARCHIVO_ZONAS = "cobertura_zonas.csv"
COLUMNAS = ["nivel", "punto", "archivo", "veredicto", "motivos", "inicio", "fin", "duracion_s", "huecos",
            "hueco_mayor_s", "paquetes", "bytes", "pps_promedio", "mbps_promedio", "mbps_p95_minuto",
            "mbps_max_minuto", "difusion_multidifusion_pct", "truncados", "duplicados", "fragmentos_ip",
            "segmentos_tcp", "perdida_tcp_pct", "retransmisiones_pct", "sesiones_un_sentido_pct",
            "sesiones_con_datos", "vlans_vistas", "vlans_esperadas_sin_trafico", "protocolos_industriales",
            "muestreada", "error"]
COLUMNAS_ZONAS =["punto", "tipo", "nombre", "redes", "activos_vistos", "paquetes", "estado"]


# --- lectura -------------------------------------------------------------------------------------------- #

def _verdadero(v: str) -> bool:
    return any(x in ("1", "True", "true") for x in v.split("|"))


def _entero(v: str) -> int:
    try:
        return int(v.split("|")[0])
    except ValueError:
        return 0


class Acumulador:
    """Estadisticas de un archivo a partir de las filas de tshark. `idx`: campo -> posicion en la fila."""

    def __init__(self, idx: dict):
        self.idx = idx
        self.sin_campos = sorted(c for c in ("frame.cap_len", "tcp.stream", "tcp.analysis.lost_segment",
                                             "tcp.analysis.ack_lost_segment", "tcp.analysis.retransmission",
                                             "ip.flags.mf", "ip.frag_offset") if c not in idx)
        self.t0 = self.t1 = None
        self.prev = None
        self.n = self.bytes = self.difusion = self.truncados = self.fragmentos = 0
        self.ip_pkts = self.tcp_pkts = self.perdidos = self.retrans = 0
        self.huecos_n, self.hueco_max = 0, 0.0
        self.minuto: dict = collections.defaultdict(int)
        self.vlans: collections.Counter = collections.Counter()
        self.ips: dict = {}
        self.ot: collections.Counter = collections.Counter()
        self.sesiones = bytearray()
        # L1 (D81): salud de la red. Todo acotado: por minuto, por IP/MAC y por conducto con tope.
        self.mezcla: dict = {}                 # "ot:Modbus/TCP" | "p:ARP" -> [bytes, paquetes]
        self.dif_min: dict = collections.defaultdict(int)    # minuto -> paquetes de difusion o multidifusion
        self.dif_pico: dict = {}               # minuto -> maximo de paquetes de difusion en un segundo
        self._dseg, self._dn = None, 0
        self.arp_min: dict = collections.defaultdict(int)
        self.arp_src: dict = {}                # MAC -> paquetes ARP emitidos
        self.tcp_serv: dict = {}               # (cliente, servidor, puerto) -> [segmentos, retrans, perdidos]

    def fila(self, row: list) -> None:
        idx = self.idx
        try:
            ts_ = float(g(row, idx, "frame.time_epoch"))
        except ValueError:
            return
        self.n += 1
        ln = _entero(g(row, idx, "frame.len"))
        self.bytes += ln
        self.minuto[int(ts_ // 60)] += ln
        if self.t0 is None or ts_ < self.t0:
            self.t0 = ts_
        if self.t1 is None or ts_ > self.t1:
            self.t1 = ts_
        if self.prev is not None and ts_ - self.prev > HUECO_S:
            self.huecos_n += 1
            self.hueco_max = max(self.hueco_max, ts_ - self.prev)
        self.prev = ts_
        cap = g(row, self.idx, "frame.cap_len")
        if cap and ln and _entero(cap) < ln:
            self.truncados += 1
        edst = g(row, idx, "eth.dst")
        grupo = len(edst) > 1 and _hex(edst[:2]) and int(edst[:2], 16) & 1 == 1
        if grupo:
            self.difusion += 1
            self._grupo(ts_)
        for v in g(row, idx, "vlan.id").split("|"):
            if v:
                self.vlans[v] += 1
        mf = g(row, idx, "ip.flags.mf")
        fo = g(row, idx, "ip.frag_offset")
        if (mf and _verdadero(mf)) or (fo and any(x.isdigit() and int(x) > 0 for x in fo.split("|"))):
            self.fragmentos += 1
        sip = (g(row, idx, "ip.src") or g(row, idx, "ipv6.src")).split("|")[0]
        dip = (g(row, idx, "ip.dst") or g(row, idx, "ipv6.dst")).split("|")[0]
        if sip and dip:
            self.ip_pkts += 1
            self._ips(sip, dip, grupo, ln)
        tsp, tdp = g(row, idx, "tcp.srcport"), g(row, idx, "tcp.dstport")
        usp, udp = g(row, idx, "udp.srcport"), g(row, idx, "udp.dstport")
        if tdp:
            self.tcp_pkts += 1
            perd = 1 if (g(row, idx, "tcp.analysis.lost_segment")
                         or g(row, idx, "tcp.analysis.ack_lost_segment")) else 0
            ret = 1 if g(row, idx, "tcp.analysis.retransmission") else 0
            self.perdidos += perd
            self.retrans += ret
            if sip and dip:
                self._tcp_serv(sip, tsp, dip, tdp, ret, perd)
            if sip and _entero(g(row, idx, "tcp.len")) > 0:
                self._sesion(g(row, idx, "tcp.stream"), sip, tsp, dip, tdp)
            col = g(row, idx, "_ws.col.protocol")
            self._mezclar(self._industrial(tsp, tdp, "tcp", col), col, ln)
        elif udp:
            col = g(row, idx, "_ws.col.protocol")
            self._mezclar(self._industrial(usp, udp, "udp", col), col, ln)
        else:
            col = g(row, idx, "_ws.col.protocol")
            self._mezclar(self._industrial("", "", "", col), col, ln)
            if col == "ARP":
                self.arp_min[int(ts_ // 60)] += 1
                mac = g(row, idx, "eth.src")
                if mac in self.arp_src or len(self.arp_src) < MAX_IPS:
                    self.arp_src[mac] = self.arp_src.get(mac, 0) + 1

    def _grupo(self, ts_: float) -> None:
        """Difusion y multidifusion: paquetes por minuto y pico por segundo (L1, D81)."""
        seg = int(ts_)
        if seg != self._dseg:
            self._cerrar_seg()
            self._dseg, self._dn = seg, 0
        self._dn += 1
        self.dif_min[seg // 60] += 1

    def _cerrar_seg(self) -> None:
        if self._dseg is not None and self._dn > self.dif_pico.get(self._dseg // 60, 0):
            self.dif_pico[self._dseg // 60] = self._dn

    def _mezclar(self, ot: str, col: str, ln: int) -> None:
        k = ("ot:" + ot) if ot else ("p:" + (col or "otros"))
        e = self.mezcla.get(k)
        if e is None:
            if len(self.mezcla) >= MAX_CLAVES:
                k = "p:otros"
                e = self.mezcla.setdefault(k, [0, 0])
            else:
                e = self.mezcla[k] = [0, 0]
        e[0] += ln
        e[1] += 1

    def _tcp_serv(self, sip: str, sp: str, dip: str, dp: str, ret: int, perd: int) -> None:
        """Segmentos, retransmisiones y perdidas por (cliente, servidor, puerto de servicio), en ambos sentidos."""
        try:
            a, b = int(sp), int(dp)
        except ValueError:
            return
        if (b, "tcp") in OT_PORTS or ((a, "tcp") not in OT_PORTS and b <= a):
            k = (sip, dip, b)
        else:
            k = (dip, sip, a)
        e = self.tcp_serv.get(k)
        if e is None:
            if len(self.tcp_serv) >= MAX_TCP_SERV:
                return
            e = self.tcp_serv[k] = [0, 0, 0]
        e[0] += 1
        e[1] += ret
        e[2] += perd

    def _ips(self, sip: str, dip: str, grupo: bool, ln: int = 0) -> None:
        """ips[ip] = [emitidos, recibidos, de difusion, bytes emitidos, bytes recibidos]."""
        if is_host_ip(sip):
            e = self.ips.get(sip)
            if e is None and len(self.ips) < MAX_IPS:
                e = self.ips[sip] = [0, 0, 0, 0, 0]
            if e is not None:
                e[2 if grupo else 0] += 1
                e[3] += ln
        if not grupo and is_host_ip(dip):
            e = self.ips.get(dip)
            if e is None and len(self.ips) < MAX_IPS:
                e = self.ips[dip] = [0, 0, 0, 0, 0]
            if e is not None:
                e[1] += 1
                e[4] += ln

    def _sesion(self, stream: str, sip: str, sp: str, dip: str, dp: str) -> None:
        s = _entero(stream) if stream else -1
        if s < 0 or s >= MAX_SESIONES:
            return
        if s >= len(self.sesiones):
            self.sesiones.extend(bytes(s + 1024 - len(self.sesiones)))
        self.sesiones[s] |= 1 if (sip, _entero(sp)) <= (dip, _entero(dp)) else 2

    def _industrial(self, sp: str, dp: str, l4: str, col: str) -> str:
        nombre = ""
        if l4:
            for p in (dp, sp):
                if p.isdigit():
                    n, cat = OT_PORTS.get((int(p), l4), ("", ""))
                    if cat == "ot":
                        nombre = n
                        break
        if not nombre and col.upper() in _NOMBRES_OT:
            nombre = col
        if nombre:
            self.ot[nombre] += 1
        return nombre

    def cerrar(self) -> dict:
        self._cerrar_seg()
        self._dseg, self._dn = None, 0
        datos = sum(1 for b in self.sesiones if b)
        uno = sum(1 for b in self.sesiones if b in (1, 2))
        return {"t0": self.t0, "t1": self.t1, "paquetes": self.n, "bytes": self.bytes, "difusion": self.difusion,
                "truncados": self.truncados, "fragmentos": self.fragmentos, "ip_pkts": self.ip_pkts,
                "tcp_pkts": self.tcp_pkts, "perdidos": self.perdidos, "retrans": self.retrans,
                "huecos_n": self.huecos_n, "hueco_max": self.hueco_max, "minuto": dict(self.minuto),
                "vlans": self.vlans, "ips": self.ips, "ot": self.ot, "ses_datos": datos, "ses_uno": uno,
                "sin_campos": self.sin_campos, "mezcla": self.mezcla, "dif_min": dict(self.dif_min),
                "dif_pico": self.dif_pico, "arp_min": dict(self.arp_min), "arp_src": self.arp_src,
                "tcp_serv": self.tcp_serv}


def _hex(x: str) -> bool:
    try:
        int(x, 16)
        return True
    except ValueError:
        return False


# --- fusion y metricas ----------------------------------------------------------------------------------- #

_SUMAS = ("paquetes", "bytes", "difusion", "truncados", "fragmentos", "ip_pkts", "tcp_pkts", "perdidos", "retrans",
          "huecos_n", "ses_datos", "ses_uno")


def fusionar(datos: list) -> dict:
    """Une los datos de varios archivos de un mismo punto. Los lapsos entre archivos (ordenados por inicio) mayores
    que HUECO_S cuentan como huecos."""
    out: dict = {k: 0 for k in _SUMAS}
    out.update(t0=None, t1=None, hueco_max=0.0, minuto=collections.Counter(), vlans=collections.Counter(),
               ips={}, ot=collections.Counter(), sin_campos=set(), duplicados=None, muestreada=False,
               mezcla={}, dif_min=collections.Counter(), dif_pico={}, arp_min=collections.Counter(),
               arp_src=collections.Counter(), tcp_serv={})
    fin = None
    for d in sorted((d for d in datos if d.get("t0") is not None), key=lambda x: x["t0"]):
        for k in _SUMAS:
            out[k] += d[k]
        out["t0"] = d["t0"] if out["t0"] is None else min(out["t0"], d["t0"])
        out["t1"] = d["t1"] if out["t1"] is None else max(out["t1"], d["t1"])
        out["hueco_max"] = max(out["hueco_max"], d["hueco_max"])
        if fin is not None and d["t0"] - fin > HUECO_S:
            out["huecos_n"] += 1
            out["hueco_max"] = max(out["hueco_max"], d["t0"] - fin)
        fin = d["t1"] if fin is None else max(fin, d["t1"])
        for m, b in d["minuto"].items():
            out["minuto"][m] += b
        out["vlans"].update(d["vlans"])
        out["ot"].update(d["ot"])
        for ip, c in d["ips"].items():
            e = out["ips"].setdefault(ip, [0, 0, 0, 0, 0])
            for i in range(len(c)):
                e[i] += c[i]
        for k, c in d.get("mezcla", {}).items():
            e = out["mezcla"].setdefault(k, [0, 0])
            e[0] += c[0]
            e[1] += c[1]
        out["dif_min"].update(d.get("dif_min", {}))
        out["arp_min"].update(d.get("arp_min", {}))
        out["arp_src"].update(d.get("arp_src", {}))
        for m, n in d.get("dif_pico", {}).items():
            out["dif_pico"][m] = max(out["dif_pico"].get(m, 0), n)
        for k, c in d.get("tcp_serv", {}).items():
            e = out["tcp_serv"].setdefault(k, [0, 0, 0])
            for i in range(3):
                e[i] += c[i]
        out["sin_campos"].update(d.get("sin_campos", ()))
        if d.get("duplicados") is not None:
            out["duplicados"] = (out["duplicados"] or 0) + d["duplicados"]
        out["muestreada"] = out["muestreada"] or bool(d.get("muestreada"))
    out["sin_campos"] = sorted(out["sin_campos"])
    return out


def mbps_por_minuto(minuto: dict, t0, t1) -> list:
    """Mbps de cada minuto entre el de t0 y el de t1, incluidos los minutos sin paquetes (cero)."""
    if t0 is None:
        return []
    return [minuto.get(m, 0) * 8 / 60 / 1e6 for m in range(int(t0 // 60), int(t1 // 60) + 1)]


def p95(valores: list) -> float:
    """Percentil 95 por rango mas cercano (el valor en la posicion ceil(0.95 n))."""
    if not valores:
        return 0.0
    v = sorted(valores)
    return v[max(math.ceil(0.95 * len(v)) - 1, 0)]


def _pct(a: int, b: int) -> float:
    return a * 100.0 / b if b else 0.0


def metricas(raw: dict) -> dict:
    t0, t1 = raw["t0"], raw["t1"]
    dur = (t1 - t0) if t0 is not None else 0.0
    mb = mbps_por_minuto(raw["minuto"], t0, t1)
    return {
        "inicio": t0, "fin": t1, "duracion_s": dur, "huecos": raw["huecos_n"], "hueco_mayor_s": raw["hueco_max"],
        "paquetes": raw["paquetes"], "bytes": raw["bytes"],
        "pps": raw["paquetes"] / dur if dur > 0 else 0.0,
        "mbps": raw["bytes"] * 8 / dur / 1e6 if dur > 0 else 0.0,
        "mbps_p95": p95(mb), "mbps_max": max(mb) if mb else 0.0,
        "difusion_pct": _pct(raw["difusion"], raw["paquetes"]), "truncados": raw["truncados"],
        "duplicados": raw["duplicados"], "fragmentos": raw["fragmentos"], "tcp": raw["tcp_pkts"],
        "perdida_pct": _pct(raw["perdidos"], raw["tcp_pkts"]),
        "retrans_pct": _pct(raw["retrans"], raw["tcp_pkts"]),
        "un_sentido_pct": _pct(raw["ses_uno"], raw["ses_datos"]), "ses_datos": raw["ses_datos"],
        "ip_pkts": raw["ip_pkts"], "vlans": sorted(raw["vlans"], key=_clave_vlan),
        "industriales": sorted(raw["ot"]), "muestreada": raw["muestreada"], "sin_campos": raw["sin_campos"],
    }


def _clave_vlan(v) -> tuple:
    return (0, int(v)) if str(v).isdigit() else (1, str(v))


# --- zonas y subredes ------------------------------------------------------------------------------------ #

def _estado_ips(miembros: list) -> tuple:
    """(activos, paquetes, estado) de las IP dadas: cada una es [emitidos, recibidos, de difusion]."""
    activos = [c for c in miembros if c[0] or c[1] or c[2]]
    paquetes = sum(c[0] + c[1] + c[2] for c in activos)
    if any(c[0] or c[1] for c in activos):
        return len(activos), paquetes, ESTADO_VISTA
    return len(activos), paquetes, ESTADO_DIFUSION if activos else ESTADO_SIN


def zonas_de_punto(punto: str, ips: dict, zonas: list) -> list:
    """Filas por zona declarada y por subred inferida (/24 privadas) de un punto."""
    analizadas = []
    for ip, c in ips.items():
        try:
            analizadas.append((ipaddress.ip_address(ip), c))
        except ValueError:
            continue
    filas = []
    for z in zonas:
        redes = [ipaddress.ip_network(r) for r in z["redes"]]
        miembros = [c for a, c in analizadas if any(a in r for r in redes if r.version == a.version)]
        n, p, est = _estado_ips(miembros)
        filas.append({"punto": punto, "tipo": "zona", "nombre": z["nombre"], "redes": ";".join(z["redes"]),
                      "activos": n, "paquetes": p, "estado": est})
    subredes: dict = {}
    for a, c in analizadas:
        if a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local):
            subredes.setdefault(ipaddress.ip_network(f"{a}/24", strict=False), []).append(c)
    for red in sorted(subredes):
        n, p, est = _estado_ips(subredes[red])
        filas.append({"punto": punto, "tipo": "subred inferida", "nombre": str(red), "redes": str(red),
                      "activos": n, "paquetes": p, "estado": est})
    return filas


# --- veredicto --------------------------------------------------------------------------------------------- #

def _dur(s: float) -> str:
    return human_duration(f"{s:.0f} seconds")


def veredicto(m: dict, vlans_sin_trafico: list, zonas_sin_trafico: list) -> tuple:
    """(estado, [motivos]) de un punto. Las constantes y su significado: D80."""
    no_apta, limites = [], []
    if m["ip_pkts"] == 0:
        no_apta.append(t("ningun paquete con IP"))
    if m["perdida_pct"] > PERDIDA_NO_APTA:
        no_apta.append(t("perdida de segmentos TCP en el espejo de {p} % (mayor que {u} %)",
                         p=f"{m['perdida_pct']:.2f}", u=PERDIDA_NO_APTA))
    elif m["perdida_pct"] > PERDIDA_LIMITE:
        limites.append(t("perdida de segmentos TCP en el espejo de {p} % (mayor que {u} %)",
                         p=f"{m['perdida_pct']:.2f}", u=PERDIDA_LIMITE))
    if m["un_sentido_pct"] > UNSENTIDO_NO_APTA:
        no_apta.append(t("sesiones TCP vistas en un solo sentido: {p} % (mayor que {u} %)",
                         p=f"{m['un_sentido_pct']:.1f}", u=UNSENTIDO_NO_APTA))
    elif m["un_sentido_pct"] > UNSENTIDO_LIMITE:
        limites.append(t("sesiones TCP vistas en un solo sentido: {p} % (mayor que {u} %)",
                         p=f"{m['un_sentido_pct']:.1f}", u=UNSENTIDO_LIMITE))
    if m["muestreada"]:
        limites.append(t("metricas sobre una muestra de {n} paquetes (--max-packets): la duracion no se evalua; "
                         "validar-captura lee todo", n=m["paquetes"]))
    elif m["duracion_s"] < DURACION_NO_APTA_S:
        no_apta.append(t("duracion de {d}: menos de {u} minutos", d=_dur(m["duracion_s"]),
                         u=DURACION_NO_APTA_S // 60))
    elif m["duracion_s"] < DURACION_CICLO_S:
        limites.append(t("duracion de {d}: menos de un ciclo diario (24 h)", d=_dur(m["duracion_s"])))
    if m["huecos"]:
        limites.append(t("{n} huecos sin paquetes de mas de {u} minutos (el mayor, {d})", n=m["huecos"],
                         u=HUECO_S // 60, d=_dur(m["hueco_mayor_s"])))
    if m["truncados"]:
        limites.append(t("{n} paquetes truncados (la captura no guarda el paquete completo)", n=m["truncados"]))
    if vlans_sin_trafico:
        limites.append(t("VLAN esperadas sin trafico: {lista}", lista=", ".join(vlans_sin_trafico)))
    if zonas_sin_trafico:
        limites.append(t("zonas declaradas sin trafico: {lista}", lista=", ".join(zonas_sin_trafico)))
    if not m["industriales"] and m["ip_pkts"]:
        limites.append(t("ningun protocolo industrial visto en este punto"))
    if m["sin_campos"]:
        limites.append(t("este tshark no soporta los campos {lista}: esas metricas valen cero",
                         lista=", ".join(m["sin_campos"])))
    if no_apta:
        return NO_APTA, no_apta + limites
    return (LIMITADA if limites else APTA), limites


# --- puntos y resultado ------------------------------------------------------------------------------------ #

def _puntos(archivos: list) -> list:
    """[(nombre, [archivo])]: una carpeta es un punto; un archivo solo en su carpeta, el archivo."""
    por_carpeta: dict = collections.OrderedDict()
    for a in archivos:
        por_carpeta.setdefault(Path(a["path"]).resolve().parent, []).append(a)
    out, usados = [], collections.Counter()
    for carpeta, lista in sorted(por_carpeta.items(), key=lambda x: str(x[0])):
        nombre = Path(lista[0]["path"]).name if len(lista) == 1 else (carpeta.name or str(carpeta))
        usados[nombre] += 1
        out.append((nombre if usados[nombre] == 1 else f"{nombre} ({usados[nombre]})", lista))
    return sorted(out, key=lambda x: x[0])


def vlans_del_span(switches: dict) -> set:
    """VLAN que alguna sesion SPAN de los switches entregados espeja (completa o parcialmente), como texto."""
    from .switches.integracion import NO
    out = set()
    for esp in switches.get("espejos", ()):
        for v, (estado, _s) in esp.items():
            if estado and estado != NO:     # "" = desconocido (switch SNMP, sin sesiones SPAN)
                out.add(str(v))
    return out


def de_captura(c) -> dict:
    """Entrada de `construir` para una Capture ya analizada (con o sin cache)."""
    dato = {}
    if not c.error and c.cobertura:
        dup = c.info.get("Number of duplicate packets", "")
        dato = dict(c.cobertura, duplicados=int(dup) if dup.isdigit() else None, muestreada=bool(c.sampled))
    return {"path": c.path, "dato": dato, "error": c.error}


def construir(archivos: list, perfil: dict | None = None, vlans_esperadas=(), span: set = frozenset()) -> dict:
    """`archivos`: [{"path", "dato" (cerrar() + duplicados/muestreada), "error"}]. Devuelve el resultado
    ({} si no hay ninguna captura legible)."""
    perfil = perfil or {}
    esperadas = sorted({str(v) for v in [*perfil.get("vlans_esperadas", ()), *vlans_esperadas, *span]},
                       key=_clave_vlan)
    zonas = perfil.get("zonas", [])
    puntos, filas_arch, filas_zonas = [], [], []
    for nombre, lista in _puntos(archivos):
        legibles = [a for a in lista if not a.get("error") and a.get("dato")]
        for a in lista:
            if not a.get("error") and a.get("dato"):
                m = metricas(fusionar([a["dato"]]))
                filas_arch.append({"punto": nombre, "archivo": Path(a["path"]).name, "m": m, "error": ""})
            else:
                filas_arch.append({"punto": nombre, "archivo": Path(a["path"]).name, "m": None,
                                   "error": a.get("error") or t("sin datos")})
        raw = fusionar([a["dato"] for a in legibles])
        m = metricas(raw)
        zf = zonas_de_punto(nombre, raw["ips"], zonas)
        sin_vlan = [v for v in esperadas if v not in raw["vlans"]]
        sin_zona = [f["nombre"] for f in zf if f["tipo"] == "zona" and f["estado"] == ESTADO_SIN]
        est, motivos = veredicto(m, sin_vlan, sin_zona)
        puntos.append({"punto": nombre, "archivos": [Path(a["path"]).name for a in lista], "m": m,
                       "veredicto": est, "motivos": motivos, "vlans_sin_trafico": sin_vlan,
                       "raw": raw, "paths": [str(a["path"]) for a in lista]})      # raw/paths: los lee L1 (salud_red)
        filas_zonas += zf
    if not any(p["m"]["paquetes"] for p in puntos):
        return {}
    por = collections.Counter(p["veredicto"] for p in puntos)
    return {"puntos": puntos, "archivos": filas_arch, "zonas": filas_zonas, "vlans_esperadas": esperadas,
            "resumen": {"puntos": len(puntos), **{e: por.get(e, 0) for e in (APTA, LIMITADA, NO_APTA)}}}


def hay(rep: dict) -> bool:
    return bool(rep and rep.get("puntos"))


# --- salidas ----------------------------------------------------------------------------------------------- #

def _iso(t_: float | None) -> str:
    return datetime.fromtimestamp(t_, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t_ is not None else ""


def _celdas(nivel: str, punto: str, archivo: str, veredicto_: str, motivos: str, m: dict | None, extra: list,
            error: str) -> list:
    if m is None:
        return [t(nivel), punto, archivo, veredicto_, motivos] +[""] * (len(COLUMNAS) - 6) + [error]
    dup = "" if m["duplicados"] is None else m["duplicados"]
    return [t(nivel), punto, archivo, veredicto_, motivos, _iso(m["inicio"]), _iso(m["fin"]),
            f"{m['duracion_s']:.0f}", m["huecos"], f"{m['hueco_mayor_s']:.0f}", m["paquetes"], m["bytes"],
            f"{m['pps']:.2f}", f"{m['mbps']:.3f}", f"{m['mbps_p95']:.3f}", f"{m['mbps_max']:.3f}",
            f"{m['difusion_pct']:.2f}", m["truncados"], dup, m["fragmentos"], m["tcp"],
            f"{m['perdida_pct']:.2f}", f"{m['retrans_pct']:.2f}", f"{m['un_sentido_pct']:.1f}", m["ses_datos"],
            ";".join(m["vlans"]), extra[0], ";".join(m["industriales"]), t("si") if m["muestreada"] else t("no"),
            error]


def tablas(rep: dict) -> list:
    """[(archivo_csv, hoja, cabecera, filas)]; la hoja de zonas es None (solo CSV)."""
    if not hay(rep):
        return []
    filas = []
    for p in rep["puntos"]:
        filas.append(_celdas("punto", p["punto"], "", t(p["veredicto"]), "; ".join(p["motivos"]), p["m"],
                             [";".join(p["vlans_sin_trafico"])], ""))
    for f in rep["archivos"]:
        filas.append(_celdas("archivo", f["punto"], f["archivo"], "", "", f["m"], [""], f["error"]))
    zonas = [[f["punto"], t(f["tipo"]), f["nombre"], f["redes"], f["activos"], f["paquetes"], t(f["estado"])]
             for f in rep["zonas"]]
    return [(ARCHIVO, HOJA, COLUMNAS, filas), (ARCHIVO_ZONAS, None, COLUMNAS_ZONAS, zonas)]


def seccion(rep: dict) -> dict:
    """Seccion de los reportes: veredicto por punto con motivos y la tabla de zonas."""
    r = rep["resumen"]
    resumen = t("{n} puntos de captura: {a} aptos, {l} aptos con limitaciones, {x} no aptos. Detalle en {f} y {z}.",
                n=r["puntos"], a=r[APTA], l=r[LIMITADA], x=r[NO_APTA], f=ARCHIVO, z=ARCHIVO_ZONAS)
    cab = [t(c) for c in ("Punto", "Veredicto", "Duracion", "Paquetes", "Perdida TCP %", "Un solo sentido %",
                          "Huecos", "Motivos")]
    filas = [[p["punto"], t(p["veredicto"]), _dur(p["m"]["duracion_s"]), p["m"]["paquetes"],
              f"{p['m']['perdida_pct']:.2f}", f"{p['m']['un_sentido_pct']:.1f}", p["m"]["huecos"],
              "; ".join(p["motivos"]) or "-"] for p in rep["puntos"]]
    cabz = [t(c) for c in ("Punto", "Tipo", "Nombre", "Redes", "Activos vistos", "Paquetes", "Estado")]
    zonas = [[f["punto"], t(f["tipo"]), f["nombre"], f["redes"], f["activos"], f["paquetes"], t(f["estado"])]
             for f in rep["zonas"]]
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen, "tabla": (cab, filas),
            "tabla_zonas": (cabz, zonas)}


def para_json(rep: dict) -> dict:
    if not hay(rep):
        return {}
    return {"resumen": rep["resumen"], "vlans_esperadas": rep["vlans_esperadas"],
            "puntos": [{"punto": p["punto"], "veredicto": p["veredicto"], "motivos": p["motivos"],
                        "duracion_s": round(p["m"]["duracion_s"]), "paquetes": p["m"]["paquetes"],
                        "perdida_tcp_pct": round(p["m"]["perdida_pct"], 2),
                        "sesiones_un_sentido_pct": round(p["m"]["un_sentido_pct"], 1),
                        "huecos": p["m"]["huecos"]} for p in rep["puntos"]]}
