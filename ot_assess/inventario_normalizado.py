"""I1a (D78): inventario normalizado y trazable, y exclusion de equipos propios del analista.

Cada valor de cada campo lleva su fuente (captura:<archivo>, plataforma:<nombre>, switch:<host>,
firewall:<host>, manual, perfil o inferido), la ultima vez que la fuente lo vio y un estado (observado,
importado, declarado, inferido o en conflicto). Precedencia del valor mostrado en los campos descriptivos:
manual > perfil > plataforma > switch/firewall > captura > inferido. Los campos de conjunto (IP, MAC, VLAN,
servicios, protocolos) son la union de todas las fuentes. Nunca se descarta el valor de una fuente: el
detalle completo queda en inventario_procedencia.csv.

Un valor inferido (heuristica de la herramienta) nunca provoca conflicto: solo se muestra si nadie mas
dice nada. Los equipos propios (perfil `equipos_propios`) se sacan antes de armar conductos, zonas,
politica y linea base; aqui solo se definen la coincidencia y el recuento.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import ipaddress
import re
from pathlib import Path

from . import json_entrada
from .catalog import CRIT_ORDER
from .i18n import t
from .importers import perfiles as pf
from .importers.plataformas import (
    _encabezados,
    _ip_publica,
    _ips,
    _ipv4_unicast,
    _mac,
    _tokens,
    _valor,
)
from .roles import mostrar as mostrar_rol

CAMPOS = ("ips", "mac", "mac_salto", "nombre", "fabricante", "modelo", "firmware", "sistema_operativo", "rol",
          "nivel_purdue", "zona", "vlan", "puerto_switch", "servicios", "protocolos", "criticidad")
CONJUNTOS = ("ips", "mac", "mac_salto", "vlan", "servicios", "protocolos")
ESTADOS = ("observado", "importado", "declarado", "inferido", "en conflicto")
RANGO = {"manual": 0, "perfil": 1, "plataforma": 2, "switch": 3, "firewall": 3, "captura": 4, "inferido": 5}
ESTADO_DE = {"manual": "declarado", "perfil": "declarado", "plataforma": "importado", "switch": "observado",
             "firewall": "observado", "captura": "observado", "inferido": "inferido"}
OBSERVAN = ("captura", "plataforma", "switch", "firewall")
QA = ("validado_por", "revisado_por", "fecha_validacion", "comentario")
COLUMNAS = (["id"] + [x for c in CAMPOS for x in (c, c + "_fuente", c + "_estado")]
            + ["ultima_observacion", "conflictos", "observado_declarado", *QA])
COL_PROCEDENCIA = ["id", "campo", "valor", "fuente", "ultima_observacion", "estado"]
COL_PROCEDENCIA_CLASE = COL_PROCEDENCIA + ["clase"]
RUTA_MODELO = Path(__file__).parent / "data" / "modelo_evidencia.json"
CLASES_ESTADO = (*ESTADOS, "sin dato")
ARCHIVO = "inventario_normalizado.csv"
ARCHIVO_PROCEDENCIA = "inventario_procedencia.csv"
HOJA = "Inventario normalizado"
HOJA_PROCEDENCIA = "Inventario procedencia"
TITULO = "Inventario normalizado"
NOTA = ("Cada valor lleva su fuente, la ultima vez que esa fuente lo vio y su estado (observado, importado, "
        "declarado, inferido o en conflicto). Los valores inferidos son heuristicas de la herramienta. Las "
        "columnas de validacion estan vacias a proposito: las llena el analista que valida y el que revisa. "
        "Las horas de las capturas son UTC; las de las exportaciones, la hora local de la exportacion.")
MAX_PROTOS = 12
_modelo_base: dict = {}


def modelo_base() -> dict:
    """Tabla propia de clases (data/modelo_evidencia.json, sin revisar)."""
    if not _modelo_base:
        _modelo_base.update(json_entrada.cargar(RUTA_MODELO.read_text(encoding="utf-8")))
    return _modelo_base


def modelo_valido(d, fallo) -> dict:
    """Valida la clave de perfil `modelo_evidencia` (EVID1, D122); devuelve {'clases', 'por_fuente'}."""
    if not isinstance(d, dict):
        fallo("'modelo_evidencia' debe ser un objeto.")
    for k in d:
        if k not in ("clases", "por_fuente"):
            fallo(f"clave desconocida '{k}' en 'modelo_evidencia'.")
    out = {}
    for k, validas in (("clases", CLASES_ESTADO), ("por_fuente", None)):
        if k not in d:
            continue
        if not isinstance(d[k], dict):
            fallo(f"'modelo_evidencia.{k}' debe ser un objeto.")
        o = {}
        for clave, et in d[k].items():
            if validas is not None and clave not in validas:
                fallo(f"modelo_evidencia.clases: '{clave}' no es uno de {', '.join(validas)}.")
            if validas is None:
                tipo, _s, nombre = clave.partition(":")
                if tipo.lower() not in RANGO or (_s and not nombre.strip()):
                    fallo(f"modelo_evidencia.por_fuente: '{clave}' no es un tipo de fuente "
                          f"({', '.join(RANGO)}) ni 'tipo:nombre'.")
            if (not isinstance(et, str) or not et.strip() or len(et.strip()) > 20 or "\n" in et or "\r" in et):
                fallo(f"modelo_evidencia.{k}.{clave}: la etiqueta debe ser un texto de 1 a 20 caracteres "
                      "sin saltos de linea.")
            o[clave] = et.strip()
        out[k] = o
    return out


def modelo_de(perfil) -> dict | None:
    """Modelo efectivo (tabla por defecto reemplazada clave por clave por el perfil), o None sin la clave."""
    if "modelo_evidencia" not in (perfil or {}):
        return None
    m = perfil["modelo_evidencia"]
    base = modelo_base()
    clases = {**base["clases"], **m.get("clases", {})}
    por_fuente = {**base.get("por_fuente", {}), **m.get("por_fuente", {})}
    return {"clases": clases, "por_fuente": {k.lower(): v for k, v in por_fuente.items()},
            "del_perfil": bool(m.get("clases") or m.get("por_fuente"))}


def clase_de(modelo: dict, estado: str, fuente: str = "") -> str:
    """Clase del valor: en conflicto > por_fuente (clave mas larga, luego el tipo) > clases[estado]."""
    if estado == "en conflicto":
        return modelo["clases"]["en conflicto"]
    f = fuente.split(";")[0].strip().lower()
    mejor = ""
    for k in modelo["por_fuente"]:
        if (f == k or f.startswith(k) and (":" in k or f[len(k):len(k) + 1] == ":")) and len(k) > len(mejor):
            mejor = k
    return modelo["por_fuente"][mejor] if mejor else modelo["clases"][estado]


def columnas(inv: dict) -> list:
    """COLUMNAS, con X_clase tras cada X_estado si el inventario trae modelo de evidencia."""
    if not (inv or {}).get("modelo"):
        return list(COLUMNAS)
    return (["id"] + [x for c in CAMPOS for x in (c, c + "_fuente", c + "_estado", c + "_clase")]
            + ["ultima_observacion", "conflictos", "observado_declarado", *QA])
_RE_MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
_CLAVES_EVENTO = ("ip", "mac", "src", "dst", "sip", "servidor", "cliente", "origen", "destino", "maestro",
                  "outstation")
_CRITICIDAD = {"critica": "critica", "critical": "critica", "crit": "critica", "alta": "alta", "high": "alta",
               "media": "media", "medium": "media", "moderada": "media", "baja": "baja", "low": "baja"}


# ---------------------------------------------------------------------------
# Equipos propios

class Propios:
    """Equipos del analista (sensor, NUC, laptop) que no son parte del cliente. Falsos si no hay ninguno."""

    def __init__(self, entradas=()):
        self.entradas = list(entradas)
        self._redes, self._macs, self._cache = [], {}, {}
        for e in self.entradas:
            d = e["direccion"]
            if _RE_MAC.fullmatch(d):
                self._macs[d] = e["etiqueta"]
            else:
                self._redes.append((ipaddress.ip_network(d, strict=False), e["etiqueta"]))
        self.cuenta = {"paquetes": 0, "conductos": set(), "equipos": set(), "hallazgos": 0, "registros": 0}

    @classmethod
    def de_perfil(cls, perfil):
        return cls((perfil or {}).get("equipos_propios") or ())

    def __bool__(self):
        return bool(self._redes or self._macs)

    def ip(self, valor) -> str:
        """Etiqueta del equipo propio al que pertenece la IP, o ''."""
        v = str(valor or "").strip()
        r = self._cache.get(v)
        if r is None:
            r = ""
            try:
                a = ipaddress.ip_address(v)
            except ValueError:
                a = None
            if a is not None:
                r = next((et for red, et in self._redes if a.version == red.version and a in red), "")
            self._cache[v] = r
        return r

    def mac(self, valor) -> str:
        return self._macs.get(str(valor or "").strip().lower().replace("-", ":"), "")

    def contiene(self, valor) -> bool:
        return bool(self.ip(valor) or self.mac(valor))

    def resumen(self) -> dict:
        c = self.cuenta
        return {"paquetes": c["paquetes"], "conductos": len(c["conductos"]), "equipos": len(c["equipos"]),
                "hallazgos": c["hallazgos"], "registros": c["registros"],
                "declarados": [{"direccion": e["direccion"], "etiqueta": e["etiqueta"]} for e in self.entradas]}


def _evento_propio(ev, p: Propios) -> bool:
    return isinstance(ev, dict) and any(isinstance(ev.get(k), str) and p.contiene(ev[k]) for k in _CLAVES_EVENTO)


def excluir_captura(cap, p: Propios) -> None:
    """Saca de una captura (ya leida o venida de la cache) todo lo que involucra a un equipo propio."""
    if not p:
        return
    quitar, ips_propias = [], set()
    for mac, h in cap.hosts.items():
        if p.mac(mac):
            quitar.append(mac)
            ips_propias |= set(h["ips"])
        elif h["ips"] and all(p.ip(i) for i in h["ips"]):
            quitar.append(mac)
    for mac in quitar:
        h = cap.hosts.pop(mac)
        p.cuenta["paquetes"] += h["tx_pkts"] + h["rx_pkts"]
        p.cuenta["equipos"].add(mac)

    def propia(ip):
        return bool(p.ip(ip)) or ip in ips_propias
    for h in cap.hosts.values():
        h["ips"] = {i for i in h["ips"] if not propia(i)}
        h["peers"] = {i for i in h["peers"] if not propia(i)}
    for clave in [k for k, f in cap.flows.items() if propia(f["src"]) or propia(f["dst"])]:
        f = cap.flows.pop(clave)
        p.cuenta["conductos"].add((f["src"], f["dst"], f["l4"], f["dport"]))
    for k in [k for k in cap.l2_flows if any(m in quitar or p.mac(m) for m in k)]:
        del cap.l2_flows[k]
    for nombre in ("identity", "cleartext", "control_ops", "protocolo_eventos", "arp_events", "dns_eventos",
                   "nombres_servidor"):
        lista = getattr(cap, nombre)
        setattr(cap, nombre, [e for e in lista if not _evento_propio(e, p)])


def filtrar_hallazgos(cap, p: Propios) -> None:
    """Quita la IP propia de `activos`; un hallazgo que solo involucraba equipos propios no se emite."""
    if not p:
        return
    out = []
    for f in cap.findings:
        act = f.get("activos")
        if act:
            resto = [a for a in act if not p.ip(a)]
            if not resto:
                p.cuenta["hallazgos"] += 1
                continue
            f["activos"] = resto
        out.append(f)
    cap.findings = out


def excluir_importacion(imp, p: Propios) -> None:
    """Lo mismo para una importacion de plataforma: activos, conductos y dominios de acceso remoto."""
    if not p:
        return
    ids, ips_propias = set(), set()
    for k, a in list(imp.assets.items()):
        macs = {x for x in {a["mac"], *a.get("alias", ())} if _mac(x)}
        if any(p.mac(m) for m in macs):
            ips_propias |= set(a["ips"])
        elif not (a["ips"] and all(p.ip(i) for i in a["ips"])):
            continue
        ids |= {k, a["mac"], *a.get("alias", ()), *a["ips"]}
        p.cuenta["equipos"].add(a["mac"])
        del imp.assets[k]

    def propio(x):
        return x in ids or x in ips_propias or p.contiene(x)
    quedan = []
    for c in imp.conduits:
        if propio(c["src"]) or propio(c["dst"]):
            p.cuenta["paquetes"] += c.get("pkts", 0)
            p.cuenta["conductos"].add((c["src"], c["dst"], c["l4"], c["port"]))
        else:
            quedan.append(c)
    imp.conduits[:] = quedan
    imp.dominios[:] = [d for d in imp.dominios if not (propio(d["cliente"]) or propio(d["servidor"]))]
    imp.resumen["activos"], imp.resumen["conductos"] = len(imp.assets), len(imp.conduits)


# ---------------------------------------------------------------------------
# Registros de cada fuente: {"macs", "ips", "entradas": [(campo, valor, fuente, ultima)]}

def _hora(epoch) -> str:
    if not epoch:
        return ""
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _enrutamiento(ips) -> bool:
    """MAC de un equipo de enrutamiento (D74): trae muchas IP o alguna publica; no identifica a un solo equipo."""
    v4 = [i for i in ips if _ipv4_unicast(i)]
    return len(v4) > 4 or any(_ip_publica(i) for i in v4)


def _nombre_fw(firewall) -> str:
    fw = firewall or {}
    return "firewall:" + str(fw.get("hostname") or fw.get("archivo") or "firewall")


def _flujos_por_ip(caps) -> dict:
    """{ip: {captura: {pkts, ultima, serv, protos}}} a partir de los flujos ya leidos (no se relee el pcap)."""
    out = {}
    for c in caps:
        for f in c.flows.values():
            for ip in {f["src"], f["dst"]}:
                d = out.setdefault(ip, {}).setdefault(c.name, {"pkts": 0, "bytes": 0, "ultima": 0,
                                                                  "serv": collections.Counter(),
                                                                  "usa": collections.Counter(),
                                                                  "protos": collections.Counter()})
                d["pkts"] += f.get("pkts", 0)
                d["bytes"] += f.get("bytes", 0)
                d["ultima"] = max(d["ultima"], f.get("last") or 0)
                if f.get("proto"):
                    d["protos"][f["proto"]] += f.get("pkts", 0)
                if ip == f["dst"] and f.get("dport") and f.get("l4"):
                    d["serv"][f"{f['dport']}/{f['l4']}"] += f.get("pkts", 0)
                if ip == f["src"] and f.get("dport") and f.get("l4"):
                    d["usa"][f"{f['dport']}/{f['l4']}"] += f.get("pkts", 0)
    return out


def _ip_del_router(mac: str, ips, caps):
    """La unica IPv4 que responde ARP con esa MAC; si hay cero o varias (proxy ARP), '' (no se inventa)."""
    vistas = {ev["sip"] for c in caps for ev in c.arp_events
              if str(ev.get("opcode")) == "2" and str(ev.get("hw", "")).lower() == mac and ev.get("sip") in ips}
    return next(iter(vistas)) if len(vistas) == 1 else ""


def _dividir_enrutada(a: dict, caps, por_ip: dict, zonas, firewall, fprim: str, ult_mac: str) -> list:
    """Una MAC de enrutamiento no identifica un equipo: un registro por IP unicast, con lo que se sabe de esa IP.
    La MAC va en `mac_salto`; solo la IP que responde ARP con ella (el router) la conserva como `mac`."""
    from .zonas import _zona_activo, mostrar_zona
    mac = a["mac"]
    ips = sorted(a["ips"])
    router = _ip_del_router(mac, a["ips"], caps)
    out = []
    for ip in ips:
        d = _ipv4_unicast(ip)
        if d is None or d.is_link_local or d.is_loopback:      # no son equipos: se omiten
            continue
        e = []
        por_cap = por_ip.get(ip, {})
        if por_cap:
            nombre_cap = min(por_cap, key=lambda n: (-por_cap[n]["pkts"], n))
            fuente = "captura:" + nombre_cap
        else:
            fuente = fprim
        ult = _hora(max((d["ultima"] for d in por_cap.values()), default=0)) or ("" if por_cap else ult_mac)

        def poner(campo, valor, fte, u="", e=e):
            if str(valor).strip():
                e.append((campo, str(valor).strip(), fte, u))
        poner("ips", ip, fuente, ult)
        servicios, protos = collections.Counter(), collections.Counter()
        for d in por_cap.values():
            servicios.update(d["serv"])
            protos.update(d["protos"])
        for s in sorted(servicios):
            poner("servicios", s, fuente, ult)
        for pr, _n in sorted(protos.items(), key=lambda x: (-x[1], x[0]))[:MAX_PROTOS]:
            poner("protocolos", pr, fuente, ult)
        ot = (a.get("ot_por_ip") or {}).get(ip) or {}      # V1b (D90): lo que ESTA IP dice de si misma
        fot = {c: f"captura:{ot['captura']} ({ot['tipo_' + c]})" for c in ("fabricante", "modelo", "firmware", "nombre")
               if ot.get(c)}
        if ip == router:
            poner("mac", mac, fprim, ult_mac)
            for h in sorted(a["hostnames"])[:1]:
                poner("nombre", h, fprim, ult_mac)
            if ot.get("fabricante"):
                poner("fabricante", ot["fabricante"], fot["fabricante"], ult)
            else:
                poner("fabricante", a["vendor"], fprim, ult_mac)
            poner("modelo", a.get("modelo"), fprim, ult_mac)
            poner("firmware", a.get("firmware"), fprim, ult_mac)
            for campo in ("modelo", "firmware"):
                if ot.get(campo) and not str(a.get(campo) or "").strip():
                    poner(campo, ot[campo], fot[campo], ult)
            if ot.get("nombre") and not a["hostnames"]:
                poner("nombre", ot["nombre"], fot["nombre"], ult)
        else:
            poner("mac_salto", mac, fprim, ult)     # la hora es la de esta IP, no la de toda la MAC
            for campo in ("fabricante", "modelo", "firmware", "nombre"):
                if ot.get(campo):
                    poner(campo, ot[campo], fot[campo], ult)
        z, o = _zona_activo({"ips": {ip}}, *((zonas or {}).get("tablas") or ([], [])))
        if o not in ("perfil", "sin zona"):
            poner("zona", mostrar_zona(z, o), _nombre_fw(firewall) if o == "firewall" else "inferido")
        out.append({"macs": [mac] if ip == router else [], "ips": [ip], "entradas": e})
    return out


def registros_activos(assets: dict, caps=(), plataforma: str = "", fin_periodo: str = "", firewall=None,
                      zonas=None, inferidos=None, fuente_inferida: str = "") -> list:
    """Un registro por activo del analisis (de capturas si hay `caps`, si no de una importacion de plataforma).

    En capturas, una MAC de enrutamiento (D74) se parte en un activo por IP (D78)."""
    from .remediacion import criticidad_activo
    from .zonas import mostrar_zona
    por_ip = None
    ultima, mejor = {}, {}
    for c in caps:
        for mac, h in c.hosts.items():
            if h.get("last"):
                ultima[mac] = max(ultima.get(mac, 0), h["last"])
            n = h["tx_pkts"] + h["rx_pkts"]
            if mac not in mejor or n > mejor[mac][0] or (n == mejor[mac][0] and c.name < mejor[mac][1]):
                mejor[mac] = (n, c.name)
    fplat = "plataforma:" + (plataforma or "generico")
    out = []
    for clave_a, a in assets.items():
        ips = sorted(a["ips"])
        if caps and _enrutamiento(ips) and _mac(a["mac"]):
            if por_ip is None:
                por_ip = _flujos_por_ip(caps)
            cap_prim = mejor.get(a["mac"], (0, next(iter(sorted(a["capturas"])), "")))[1]
            out += _dividir_enrutada(a, caps, por_ip, zonas, firewall, "captura:" + cap_prim,
                                     _hora(ultima.get(a["mac"])))
            continue
        macs = sorted({x for x in {a["mac"], *a.get("alias", ())} if _mac(x)}) if not caps else \
            ([a["mac"]] if _mac(a["mac"]) else [])
        e = []

        def poner(campo, valor, fuente, ult="", e=e):   # e de esta vuelta (B023)
            valor = str(valor).strip() if valor is not None else ""
            if valor:
                e.append((campo, valor, fuente, ult))
        if caps:
            fuente = fprim = "captura:" + mejor.get(a["mac"], (0, next(iter(sorted(a["capturas"])), "")))[1]
            ult = _hora(ultima.get(a["mac"]))
            fot = a.get("fuente_ot") or {}      # V1b (D90): campos que salieron de un protocolo OT

            def fte_ot(campo, fot=fot, fuente=fuente):
                return f"captura:{fot[campo][1]} ({fot[campo][0]})" if campo in fot else fuente
            for h in sorted(a["hostnames"])[:1]:
                poner("nombre", h, fuente, ult)
            poner("fabricante", a["vendor"], fte_ot("fabricante"), ult)
            poner("modelo", a.get("modelo"), fte_ot("modelo"), ult)
            poner("firmware", a.get("firmware"), fte_ot("firmware"), ult)
            for p_, l4 in a["ports_served"]:
                poner("servicios", f"{p_}/{l4}", fuente, ult)
            for pr, _n in a["protos"].most_common(MAX_PROTOS):
                poner("protocolos", pr, fuente, ult)
            if a.get("role") and a["role"] != "Indeterminado":
                poner("rol", mostrar_rol(a["role"]), "inferido")
                poner("nivel_purdue", mostrar_rol(a.get("purdue", "")), "inferido")
        else:
            fprim = fplat
            ult = a.get("ultima") or fin_periodo
            if a["nombre"] not in a["ips"] and a["nombre"] != a["mac"]:
                poner("nombre", a["nombre"], fplat, ult)
            for campo, clave in (("fabricante", "vendor"), ("modelo", "modelo"), ("firmware", "firmware"),
                                 ("sistema_operativo", "so"), ("rol", "role"), ("criticidad", "criticidad")):
                poner(campo, a.get(clave), fplat, ult)
            poner("nivel_purdue", mostrar_rol(a.get("purdue", "")), "inferido" if a.get("nivel_por_tipo") else fplat,
                  "" if a.get("nivel_por_tipo") else ult)
            for pr in sorted(a.get("protocolos") or ()):
                poner("protocolos", pr, fplat, ult)
        for v in sorted(a.get("vlans") or ()):
            poner("vlan", v, fprim, ult)
        if a.get("role") and a["role"] != "Indeterminado":
            poner("criticidad", t(criticidad_activo(a, {})[0]), "inferido")
        if a.get("switch_puerto"):
            sw = "switch:" + a["switch_puerto"].split(":", 1)[0]
            poner("puerto_switch", a["switch_puerto"], sw)
            poner("vlan", a.get("vlan"), sw)
        z, o = a.get("zona_asignada"), a.get("origen_zona")
        if z and o not in ("perfil", "sin zona"):
            poner("zona", mostrar_zona(z, o), _nombre_fw(firewall) if o == "firewall"
                  else fplat if o == "plataforma" else "inferido")
        for campo, valor in sorted((inferidos or {}).get(clave_a, {}).items()):    # N2 (D101)
            poner(campo, valor, "inferido:" + fuente_inferida)
        for i in ips:
            poner("ips", i, fprim, ult)
        salto = _enrutamiento(ips)      # exportaciones: la MAC de enrutamiento es del salto, no del activo
        for m in macs:
            poner("mac_salto" if salto else "mac", m, fprim, ult)
        out.append({"macs": [] if salto else macs, "ips": ips, "entradas": e})
    return out


def cargar_manual(path, mapeo=None) -> tuple:
    """(registros, avisos) del inventario manual (CSV, JSON o XLSX) con el lector y los alias del importador."""
    from .importers.lector import leer_tabla
    filas = leer_tabla(path)
    m = pf.mapear(_encabezados(filas), pf.ACTIVOS, mapeo or {}) if filas else {}
    out, sin_id = [], 0
    for f in filas:
        ips = _ips(_valor(f, m, "ip"))
        macs = [x for x in (_mac(x) for x in _tokens(_valor(f, m, "mac"))) if x]
        if not ips and not macs:
            sin_id += 1
            continue
        e = []

        def poner(campo, valor, e=e):   # e de esta vuelta (B023)
            if valor:
                e.append((campo, valor, "manual", ""))
        for campo, v in (("nombre", _valor(f, m, "nombre")),
                         ("fabricante", _valor(f, m, "vendor") or _valor(f, m, "vendor_alt")),
                         ("modelo", _valor(f, m, "modelo")),
                         ("firmware", _valor(f, m, "firmware") or _valor(f, m, "firmware_alt")),
                         ("sistema_operativo", _valor(f, m, "so")),
                         ("rol", _valor(f, m, "tipo") or _valor(f, m, "roles")),
                         ("zona", _valor(f, m, "zona")),
                         ("puerto_switch", _valor(f, m, "puerto_switch")),
                         ("criticidad", _valor(f, m, "criticidad"))):
            poner(campo, v)
        raw = _valor(f, m, "nivel")
        poner("nivel_purdue", raw and mostrar_rol(pf.parse_nivel(raw) or raw))
        for v in _tokens(_valor(f, m, "vlan")):
            poner("vlan", v)
        for v in _tokens(_valor(f, m, "servicios")):
            poner("servicios", v)
        for v in re.split(r"[;,|]", _valor(f, m, "protocolos")):
            poner("protocolos", v.strip())
        e += [("ips", i, "manual", "") for i in ips] + [("mac", x, "manual", "") for x in macs]
        out.append({"macs": macs, "ips": ips, "entradas": e})
    avisos = []
    if sin_id:
        avisos.append(t("{n} filas del inventario manual sin IP ni MAC se descartaron.", n=sin_id))
    if filas and "ip" not in m and "mac" not in m:
        avisos.append(t("No se reconocio una columna de IP ni de MAC en el inventario manual: indiquela con "
                        "--mapeo, clave \"manual\"."))
    return out, avisos


# ---------------------------------------------------------------------------
# Union de fuentes

def _clave_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (0, a.version, int(a), "")
    except ValueError:
        return (1, 0, 0, ip)


def _norm(campo: str, valor: str) -> str:
    s = " ".join(str(valor).lower().split())
    if campo == "firmware":
        s = re.sub(r"^v(?=\d)", "", s)
        s = re.sub(r"(?<!\d)0+(?=\d)", "", s)
    elif campo == "criticidad":
        s = _CRITICIDAD.get(s.replace("í", "i").replace("á", "a").replace("é", "e"), s)
    return s


def _tipo(fuente: str) -> str:
    return fuente.split(":", 1)[0]


def _rango(fuente: str) -> int:
    return RANGO[_tipo(fuente)]


def _id_activo(macs, ips, nombre) -> str:
    clave = min(macs) if macs else (min(ips, key=_clave_ip) if ips else nombre)
    return "A-" + hashlib.sha256(clave.encode("utf-8")).hexdigest()[:8]


def _agrupar(registros: list) -> list:
    """Grupos de registros del mismo activo: por MAC; sin MAC, por IP (una IP de dos MAC son dos equipos)."""
    grupos, por_mac, por_ip = [], {}, {}
    for r in sorted(registros, key=lambda r: not r["macs"]):       # primero los que traen MAC (estable)
        g = next((por_mac[m] for m in r["macs"] if m in por_mac), None)
        if g is None:
            g = next((por_ip[i] for i in r["ips"] if i in por_ip and not (r["macs"] and por_ip[i]["macs"])), None)
        if g is None:
            g = {"macs": set(), "ips": set(), "entradas": []}
            grupos.append(g)
        g["macs"] |= set(r["macs"])
        g["ips"] |= set(r["ips"])
        g["entradas"] += r["entradas"]
        for m in r["macs"]:
            por_mac.setdefault(m, g)
        for i in r["ips"]:
            por_ip.setdefault(i, g)
    return grupos


def _perfil_entradas(g: dict, perfil: dict) -> list:
    from .zonas import _mas_especifica
    ips = [ipaddress.ip_address(i) for i in sorted(g["ips"], key=_clave_ip) if _clave_ip(i)[0] == 0]
    e = []
    redes = [(ipaddress.ip_network(r), z["nombre"]) for z in perfil.get("zonas") or [] for r in z["redes"]]
    z = _mas_especifica(ips, redes) if redes else None
    if z:
        e.append(("zona", z, "perfil", ""))
    crit = [c for ip, c in (perfil.get("criticidad_activos") or {}).items() if ip in g["ips"]]
    if crit:
        e.append(("criticidad", min(crit, key=CRIT_ORDER.get), "perfil", ""))
    return e


def _campo_conjunto(entradas: list) -> dict:
    vals = {}
    for _c, v, f, u in entradas:
        vals.setdefault(v, []).append((f, u))
    ordenados = sorted(vals, key=_clave_ip)
    fuentes = sorted({f for _c, _v, f, _u in entradas}, key=lambda f: (_rango(f), f))
    return {"valor": ";".join(ordenados), "fuente": "; ".join(fuentes), "estado": ESTADO_DE[_tipo(fuentes[0])],
            "ultima": max((u for _c, _v, _f, u in entradas), default="")}


def _campo_descriptivo(campo: str, entradas: list) -> tuple:
    """(campo calculado, texto de conflicto o '')."""
    mejor = min(entradas, key=lambda x: (_rango(x[2]), x[2], x[1]))
    normal = {x[1]: _norm(campo, x[1]) for x in entradas}
    reales = [x for x in entradas if _tipo(x[2]) != "inferido"]
    distintos = {normal[x[1]] for x in reales}
    ultima = max((x[3] for x in entradas if normal[x[1]] == normal[mejor[1]]), default="")
    out = {"valor": mejor[1], "fuente": mejor[2], "ultima": ultima,
           "estado": ESTADO_DE[_tipo(mejor[2])]}
    if len(distintos) < 2:
        return out, ""
    out["estado"] = "en conflicto"
    por_valor = collections.OrderedDict()
    for x in sorted(reales, key=lambda x: (_rango(x[2]), x[2], x[1])):
        por_valor.setdefault(normal[x[1]], (x[1], []))[1].append(x[2])
    texto = f"{t(campo)}: " + " / ".join(f"{v} ({', '.join(dict.fromkeys(fs))})" for v, fs in por_valor.values())
    return out, texto


def construir(registros: list, perfil: dict | None = None, con_manual: bool = False,
              propios: Propios | None = None) -> dict:
    """Inventario normalizado: {'filas', 'procedencia', 'resumen'}. `registros` = lo que dieron los adaptadores."""
    modelo = modelo_de(perfil)
    perfil = perfil or {}
    if propios:
        quedan = []
        for r in registros:
            if any(propios.ip(i) for i in r["ips"]) or any(propios.mac(m) for m in r["macs"]):
                propios.cuenta["registros"] += 1
            else:
                quedan.append(r)
        registros = quedan
    filas, procedencia = [], []
    por_fuente, por_estado = collections.Counter(), collections.Counter()
    por_clase = collections.Counter()
    campos_conflicto = activos_conflicto = declarados_no = observados_no = ambos = 0
    for g in _agrupar(registros):
        entradas = list(g["entradas"]) + _perfil_entradas(g, perfil)
        por_campo = collections.OrderedDict((c, {}) for c in CAMPOS)
        for c, v, f, u in entradas:
            previa = por_campo[c].get((v, f))
            por_campo[c][(v, f)] = max(u, previa) if previa is not None else u
        nombre = next((v for (v, _f) in por_campo["nombre"]), "")
        ident = _id_activo(g["macs"], g["ips"], nombre)
        campos, conflictos, detalle = {}, [], []
        for c in CAMPOS:
            lista = [(c, v, f, u) for (v, f), u in por_campo[c].items()]
            if not lista:
                continue
            if c in CONJUNTOS:
                campos[c] = _campo_conjunto(lista)
                comun = ""
            else:
                campos[c], comun = _campo_descriptivo(c, lista)
            if comun:
                conflictos.append(comun)
                campos_conflicto += 1
            enconf = campos[c]["estado"] == "en conflicto"
            for _c, v, f, u in sorted(lista, key=lambda x: (_rango(x[2]), x[2], _clave_ip(x[1]))):
                est = "en conflicto" if enconf and _tipo(f) != "inferido" else ESTADO_DE[_tipo(f)]
                detalle.append([ident, c, v, f, u, est] + ([clase_de(modelo, est, f)] if modelo else []))
            if modelo:
                campos[c]["clase"] = clase_de(modelo, campos[c]["estado"], campos[c]["fuente"])
                por_clase[campos[c]["clase"]] += 1
            por_estado[campos[c]["estado"]] += 1
        if modelo:
            por_clase[modelo["clases"]["sin dato"]] += len(CAMPOS) - len(campos)
        fuentes = {f for _c, _v, f, _u in entradas}
        for f in fuentes:
            por_fuente[f] += 1
        observado = any(_tipo(f) in OBSERVAN for f in fuentes)
        declarado = "manual" in fuentes
        if con_manual:
            if observado and declarado:
                presencia, ambos = "observado y declarado", ambos + 1
            elif declarado:
                presencia, declarados_no = "declarado, no observado", declarados_no + 1
            else:
                presencia, observados_no = "observado, no declarado", observados_no + 1
        else:
            presencia = "observado" if observado else ""
        activos_conflicto += bool(conflictos)
        filas.append({"id": ident, "campos": campos, "ultima": max((c["ultima"] for c in campos.values()
                                                                   if c["estado"] != "inferido"), default=""),
                      "conflictos": conflictos, "presencia": presencia,
                      "_orden": (sorted(g["ips"], key=_clave_ip)[:1] or [""], sorted(g["macs"])[:1], ident)})
        procedencia += detalle
    filas.sort(key=lambda f: (_clave_ip(f["_orden"][0][0]), f["_orden"][1], f["_orden"][2]))
    for f in filas:
        del f["_orden"]
    orden = {f["id"]: i for i, f in enumerate(filas)}
    procedencia.sort(key=lambda r: orden[r[0]])         # estable: conserva el orden de campo y precedencia
    resumen = {"activos": len(filas), "con_manual": con_manual, "por_fuente": dict(sorted(por_fuente.items())),
               "por_estado": {e: por_estado[e] for e in ESTADOS if por_estado[e]},
               "campos_en_conflicto": campos_conflicto, "activos_con_conflicto": activos_conflicto,
               "declarados_no_observados": declarados_no, "observados_no_declarados": observados_no,
               "observados_y_declarados": ambos, "excluidos": propios.resumen() if propios else {}}
    out = {"filas": filas, "procedencia": procedencia, "resumen": resumen}
    if modelo:
        resumen["por_clase"] = dict(sorted(por_clase.items()))
        out["modelo"] = modelo
    return out


# ---------------------------------------------------------------------------
# Salidas

def hay(inv: dict) -> bool:
    return bool(inv and inv.get("filas"))


def filas_tabla(inv: dict) -> list:
    modelo = inv.get("modelo")
    out = []
    for f in inv["filas"]:
        fila = [f["id"]]
        for c in CAMPOS:
            x = f["campos"].get(c)
            fila += [x["valor"], x["fuente"], t(x["estado"])] if x else ["", "", ""]
            if modelo:
                fila.append(x["clase"] if x else modelo["clases"]["sin dato"])
        fila += [f["ultima"], " | ".join(f["conflictos"]),
                 t(f["presencia"]) if f["presencia"] else "", "", "", "", ""]
        out.append(fila)
    return out


def filas_procedencia(inv: dict) -> list:
    return [[i, t(c), v, fu, u, t(e), *cl] for i, c, v, fu, u, e, *cl in inv["procedencia"]]


def tablas(inv: dict) -> list:
    if not hay(inv):
        return []
    return [(ARCHIVO, HOJA, columnas(inv), filas_tabla(inv)),
            (ARCHIVO_PROCEDENCIA, HOJA_PROCEDENCIA,
             COL_PROCEDENCIA_CLASE if inv.get("modelo") else COL_PROCEDENCIA, filas_procedencia(inv))]


def seccion(inv: dict) -> dict:
    """Para HTML, Markdown y Word: tabla breve de conteos y la nota."""
    r = inv["resumen"]
    def mostrar(f):         # solo el reporte traduce el tipo de fuente; los CSV llevan el identificador
        tipo, _s, resto = f.partition(":")
        return t(tipo) + (_s + resto)
    filas = [[t("fuente"), mostrar(f), n] for f, n in r["por_fuente"].items()]
    filas += [[t("estado"), t(e), n] for e, n in r["por_estado"].items()]
    if "por_clase" in r:
        filas += [[t("clase de evidencia"), c, n] for c, n in r["por_clase"].items()]
    filas += [[t("control de calidad"), t("campos en conflicto"), r["campos_en_conflicto"]],
              [t("control de calidad"), t("activos con conflicto"), r["activos_con_conflicto"]]]
    if r["con_manual"]:
        filas += [[t("control de calidad"), t("declarado, no observado"), r["declarados_no_observados"]],
                  [t("control de calidad"), t("observado, no declarado"), r["observados_no_declarados"]],
                  [t("control de calidad"), t("observado y declarado"), r["observados_y_declarados"]]]
    x = r["excluidos"]
    resumen = t("{n} activos en el inventario normalizado. Detalle en {a} y {b}.", n=r["activos"],
                a=ARCHIVO, b=ARCHIVO_PROCEDENCIA)
    if x and x["declarados"]:
        filas += [[t("equipos propios excluidos"), t("equipos"), x["equipos"]],
                  [t("equipos propios excluidos"), t("paquetes"), x["paquetes"]],
                  [t("equipos propios excluidos"), t("conductos"), x["conductos"]],
                  [t("equipos propios excluidos"), t("hallazgos omitidos"), x["hallazgos"]]]
        resumen += " " + t("Se excluyeron {e} equipos propios del analista ({p} paquetes, {c} conductos, {h} "
                           "hallazgos omitidos); no estan en el inventario, los conductos, las zonas, la politica "
                           "propuesta ni la linea base.", e=x["equipos"], p=x["paquetes"], c=x["conductos"],
                           h=x["hallazgos"])
    nota = t(NOTA)
    if inv.get("modelo"):
        nota += " " + (t("Las clases de evidencia son las del modelo del perfil del proyecto.")
                       if inv["modelo"]["del_perfil"] else
                       t("Las clases de evidencia son las de la tabla propia de la herramienta, sin revisar."))
    return {"titulo": t(TITULO), "nota": nota, "resumen": resumen,
            "tabla": ([t("categoria"), t("elemento"), t("cantidad")], filas)}
