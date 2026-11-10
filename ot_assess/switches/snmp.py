"""SN1 (D97): lector de recorridos SNMP (net-snmp snmpwalk/snmpbulkwalk) como fuente de switch.

Lee un archivo de texto que el analista ya genero; NO consulta SNMP. Produce el mismo `modelo.Switch` que
el lector de la CLI de Cisco, con MIB estandar (SNMPv2-MIB, ENTITY-MIB, IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB,
LLDP-MIB, EtherLike-MIB), sin depender del fabricante.

Seguridad: una linea que no es `OID = valor` se descarta sin guardarla, imprimirla ni citarla (puede ser el
comando con la comunidad); solo se cuenta. Nunca se lee ni guarda una comunidad o credencial SNMPv3, y de los
objetos solo se toman los de la tabla `_NOMBRES`.
"""
from __future__ import annotations

import re
from pathlib import Path

from .modelo import CambioStp, Contador, Puerto, Switch, Vecino

_RE_LINEA = re.compile(r"^\s*(\S+) = ?(.*)$")
_RE_NUM = re.compile(r"^(?:\.?1|iso)((?:\.\d+)+)$")
_RE_SIM = re.compile(r"^[A-Za-z0-9-]+::([A-Za-z0-9]+)(.*)$")
_RE_CORCHETE = re.compile(r"^\s*[A-Za-z0-9-]+::[A-Za-z0-9]+\[")
_RE_DETECTA = re.compile(r"^\s*(?:(?:\.?1|iso)\.[0-9.]+ = |[A-Za-z0-9-]+::[A-Za-z0-9]+[.\[])")
_RE_CMD = re.compile(r"^\s*(?:\S*[$#>]\s+)?snmp\w*\s", re.I)
_RE_HEXLINEA = re.compile(r"^\s*(?:[0-9A-Fa-f]{2}\s*)+$")
_RE_TIPO = re.compile(r"^(Hex-STRING|STRING|INTEGER|Integer32|Counter32|Counter64|Gauge32|Unsigned32|UInteger32|"
                      r"Timeticks|OID|IpAddress|Network Address|BITS|Opaque):\s?(.*)$", re.S)
_RE_PAREN = re.compile(r"\((-?\d+)\)")
_RE_ENTERO = re.compile(r"^\s*(-?\d+)")
_RE_VIRTUAL = re.compile(r"^(?:vlan|vl|loopback|lo|tunnel|null|nve|cpu)[\d./]*$", re.I)
MAX_PLATAFORMA = 80
MAX_LINEAS_DETECCION = 20

# nombre simbolico -> OID numerico (sin punto inicial). Solo estos objetos se leen.
_NOMBRES = {
    "sysDescr": "1.3.6.1.2.1.1.1", "sysName": "1.3.6.1.2.1.1.5",
    "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5", "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8", "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19", "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHCInUcastPkts": "1.3.6.1.2.1.31.1.1.1.7", "ifHCInMulticastPkts": "1.3.6.1.2.1.31.1.1.1.8",
    "ifHCInBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.9", "ifHCOutUcastPkts": "1.3.6.1.2.1.31.1.1.1.11",
    "ifHCOutMulticastPkts": "1.3.6.1.2.1.31.1.1.1.12", "ifHCOutBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.13",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "dot3StatsFCSErrors": "1.3.6.1.2.1.10.7.2.1.3",
    "dot1dBaseBridgeAddress": "1.3.6.1.2.1.17.1.1", "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
    "dot1dStpPriority": "1.3.6.1.2.1.17.2.2", "dot1dStpTimeSinceTopologyChange": "1.3.6.1.2.1.17.2.3",
    "dot1dStpTopChanges": "1.3.6.1.2.1.17.2.4", "dot1dStpDesignatedRoot": "1.3.6.1.2.1.17.2.5",
    "dot1dTpFdbPort": "1.3.6.1.2.1.17.4.3.1.2", "dot1dTpFdbStatus": "1.3.6.1.2.1.17.4.3.1.3",
    "dot1qTpFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2", "dot1qTpFdbStatus": "1.3.6.1.2.1.17.7.1.2.2.1.3",
    "dot1qVlanFdbId": "1.3.6.1.2.1.17.7.1.4.2.1.3", "dot1qVlanCurrentEgressPorts": "1.3.6.1.2.1.17.7.1.4.2.1.4",
    "dot1qVlanCurrentUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.2.1.5",
    "dot1qVlanStaticName": "1.3.6.1.2.1.17.7.1.4.3.1.1", "dot1qPvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3", "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7", "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9", "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
}
_PREFIJOS = tuple(o + "." for o in _NOMBRES.values())
_APRENDIDA = 3          # dot1qTpFdbStatus / dot1dTpFdbStatus learned(3)
_CHASIS = 3             # entPhysicalClass chassis(3)


def es_snmp(ruta) -> bool:
    """True si alguna de las primeras lineas no vacias del archivo es una linea de OID."""
    vistas = 0
    with open(ruta, encoding="utf-8", errors="replace") as f:
        for ln in f:
            if not ln.strip():
                continue
            if _RE_DETECTA.match(ln):
                return True
            vistas += 1
            if vistas >= MAX_LINEAS_DETECCION:
                break
    return False


# ---------- analisis de lineas ----------

def _oid(tok: str):
    """(es_linea_de_oid, oid numerico o None, es_corchete). None si el nombre no se lee."""
    m = _RE_NUM.match(tok)
    if m:
        return True, "1" + m.group(1)
    m = _RE_SIM.match(tok)
    if not m:
        return False, None
    base = _NOMBRES.get(m.group(1))
    if base and re.fullmatch(r"(?:\.\d+)+", m.group(2)):
        return True, base + m.group(2)
    return True, None


def _valor(v: str):
    """(tipo, dato, abierto) o None si no hay valor (No Such ..., fin de MIB, vacio)."""
    v = v.strip()
    if v == '""':
        return "STRING", '""', False
    m = _RE_TIPO.match(v)
    if not m:
        return None
    tipo, resto = m.group(1), m.group(2)
    if tipo == "Hex-STRING":
        return "HEX", resto, False
    if tipo == "STRING":
        r = resto.strip()
        if r.startswith('"'):
            return "STRING", r, not (len(r) >= 2 and r.endswith('"'))
        return "STRING", r, False
    if tipo == "OID":
        return "OID", resto.strip(), False
    p = _RE_PAREN.search(resto) if tipo in ("INTEGER", "Integer32", "Timeticks") else None
    if p:
        return "INT", int(p.group(1)), False
    e = _RE_ENTERO.match(resto)
    if e and tipo not in ("IpAddress", "Network Address", "BITS", "Opaque"):
        return "INT", int(e.group(1)), False
    return "OTRO", resto, False


def _cerrar(reg: dict, pend):
    """Convierte el registro pendiente en (tipo, dato) y lo guarda (el primero gana)."""
    if not pend or pend["oid"] is None:
        return None
    tipo, partes = pend["tipo"], pend["partes"]
    if tipo == "STRING":
        s = "\n".join(partes)
        if s.startswith('"'):
            s = s[1:].removesuffix('"')
        dato = s
    elif tipo == "HEX":
        h = "".join(re.findall(r"[0-9A-Fa-f]{2}", " ".join(partes)))
        dato = bytes.fromhex(h)
    else:
        dato = partes[0]
    rec = (tipo, dato)
    reg.setdefault(pend["oid"], rec)
    return rec


def _leer_registros(texto: str) -> tuple:
    """(registros {oid: (tipo, dato)}, sysNames, descartadas, corchetes). Solo conteos de lo descartado."""
    reg: dict = {}
    nombres = []
    descartadas = corchetes = 0
    pend = None

    def cerrar():
        nonlocal descartadas
        if pend and pend["abierto"] and len(pend["partes"]) > 1:
            # comillas que nunca cierran: lo que siguio no era del valor (puede traer una credencial)
            descartadas += len(pend["partes"]) - 1
            del pend["partes"][1:]
        rec = _cerrar(reg, pend)
        if rec is not None and pend["oid"] == _NOMBRES["sysName"] + ".0":
            nombres.append(rec)

    for linea in texto.splitlines():
        if not linea.strip():
            continue
        if _RE_CORCHETE.match(linea):
            cerrar()
            pend = None
            corchetes += 1
            continue
        m = _RE_LINEA.match(linea)
        es_oid, oid = _oid(m.group(1)) if m else (False, None)
        if m and es_oid:
            cerrar()
            val = _valor(m.group(2))
            if val is None:
                pend = None
                continue
            tipo, dato, abierto = val
            pend = {"oid": oid, "tipo": tipo, "partes": [dato], "abierto": abierto}
        elif pend and pend["abierto"] and not _RE_CMD.match(linea):
            pend["partes"].append(linea)
            if linea.rstrip().endswith('"'):
                pend["abierto"] = False
        elif pend and pend["tipo"] == "HEX" and _RE_HEXLINEA.match(linea):
            pend["partes"].append(linea)
        else:
            descartadas += 1
    cerrar()
    return reg, nombres, descartadas, corchetes


# ---------- acceso a valores ----------

def _texto(rec) -> str:
    if rec is None:
        return ""
    tipo, d = rec
    s = d.decode("utf-8", "replace") if tipo == "HEX" else str(d)
    return " ".join(s.replace("\x00", " ").split())


def _bytes(rec) -> bytes:
    if rec is None:
        return b""
    tipo, d = rec
    if tipo == "HEX":
        return d
    return d.encode("latin-1", "replace") if tipo == "STRING" else b""


def _int(rec):
    return rec[1] if rec is not None and rec[0] == "INT" else None


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b) if len(b) == 6 else ""


_RE_MAC_PISTA = re.compile(r"^[0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5}$")


def _mac_rec(rec) -> str:
    """MacAddress: Hex-STRING o, con la MIB cargada, STRING con la pista "1x:" de net-snmp (`0:1a:2b:3c:4d:5e`)."""
    if rec is not None and rec[0] == "STRING" and _RE_MAC_PISTA.match(str(rec[1]).strip()):
        return ":".join(f"{int(x, 16):02x}" for x in str(rec[1]).strip().split(":"))
    return _mac(_bytes(rec))


def _lista_puertos(rec) -> set:
    """PortList: primer octeto, bit mas alto = puerto de puente 1."""
    out = set()
    for i, byte in enumerate(_bytes(rec)):
        for bit in range(8):
            if byte & (0x80 >> bit):
                out.add(i * 8 + bit + 1)
    return out


class _Tablas:
    def __init__(self, reg: dict):
        self.reg = reg

    def escalar(self, nombre: str):
        return self.reg.get(_NOMBRES[nombre] + ".0")

    def tabla(self, nombre: str) -> dict:
        pre = _NOMBRES[nombre] + "."
        n = len(pre)
        return {tuple(int(x) for x in o[n:].split(".")): rec for o, rec in self.reg.items() if o.startswith(pre)}


# ---------- construccion del Switch ----------

def _chasis(tb, sw) -> None:
    clases = tb.tabla("entPhysicalClass")
    idx = sorted(k for k, r in clases.items() if _int(r) == _CHASIS)
    if idx:
        sw.modelo = _texto(tb.tabla("entPhysicalModelName").get(idx[0]))
        sw.version = _texto(tb.tabla("entPhysicalSoftwareRev").get(idx[0]))


def _puertos(tb, sw) -> tuple:
    """(puertos por nombre, nombres por ifIndex, ifIndex por texto de nombre)."""
    ifname, ifdescr = tb.tabla("ifName"), tb.tabla("ifDescr")
    alias, adm, ope = tb.tabla("ifAlias"), tb.tabla("ifAdminStatus"), tb.tabla("ifOperStatus")
    nombres: dict = {}
    por_texto: dict = {}
    for tab in (ifname, ifdescr):
        for (i,), rec in tab.items():
            txt = _texto(rec)
            if txt:
                por_texto.setdefault(txt, i)
    for i in sorted({k[0] for k in list(ifname) + list(ifdescr)}):
        nombres[i] = _texto(ifname.get((i,))) or _texto(ifdescr.get((i,)))
    puertos: dict = {}
    for i, nom in nombres.items():
        if not nom or _RE_VIRTUAL.match(nom):
            continue
        a, o = _int(adm.get((i,))), _int(ope.get((i,)))
        p = Puerto(nombre=nom, descripcion=_texto(alias.get((i,))))
        if a == 2:
            p.apagado, p.estado = True, "admin down"
        elif o is not None:
            p.estado = "up" if o == 1 else "down"
        if o is not None:
            p.protocolo = "up" if o == 1 else "down"
        puertos[nom] = p
        sw.puertos.append(p)
    return puertos, nombres, por_texto


def _contadores(tb, sw, nombres, puertos) -> None:
    def tab(n):
        return {k[0]: _int(r) for k, r in tb.tabla(n).items() if len(k) == 1 and _int(r) is not None}
    ent = [tab(n) for n in ("ifHCInUcastPkts", "ifHCInMulticastPkts", "ifHCInBroadcastPkts")]
    sal = [tab(n) for n in ("ifHCOutUcastPkts", "ifHCOutMulticastPkts", "ifHCOutBroadcastPkts")]
    err, desc, crc, hs = tab("ifInErrors"), tab("ifOutDiscards"), tab("dot3StatsFCSErrors"), tab("ifHighSpeed")
    for i, nom in nombres.items():
        if nom not in puertos:
            continue
        if not any(i in t for t in ent + sal + [err, desc, crc, hs]):
            continue
        pin = [t[i] for t in ent if i in t]
        pout = [t[i] for t in sal if i in t]
        sw.contadores.append(Contador(
            puerto=nom, paquetes=sum(pin) if pin else None, broadcast=ent[2].get(i),
            errores=err.get(i, 0), crc=crc.get(i, 0), descartes=desc.get(i, 0),
            paquetes_salida=sum(pout) if pout else None, bw_kbit=hs[i] * 1000 if hs.get(i) else None))
    if sw.contadores:
        sw.leyo.append("interfaces")


def _puente(tb, sw, nombres, puertos, por_texto) -> None:
    mapa = {k[0]: _int(r) for k, r in tb.tabla("dot1dBasePortIfIndex").items() if _int(r) is not None}
    usa_puente = [False]

    def nombre_bp(bp: int) -> str:
        usa_puente[0] = True
        i = mapa.get(bp, bp) if mapa else bp
        nom = nombres.get(i) or str(bp)
        if nom not in puertos:
            p = Puerto(nombre=nom)
            puertos[nom] = p
            sw.puertos.append(p)
        return nom

    # tabla MAC: Q-BRIDGE; si no hay, BRIDGE-MIB sin VLAN
    fdb_vlan: dict = {}
    for k, r in tb.tabla("dot1qVlanFdbId").items():
        if len(k) == 2 and _int(r) is not None:
            fdb_vlan.setdefault(_int(r), k[1])
    macs = set()
    q, qst = tb.tabla("dot1qTpFdbPort"), tb.tabla("dot1qTpFdbStatus")
    if q:
        for k, r in q.items():
            bp = _int(r)
            if len(k) != 7 or not bp or (k in qst and _int(qst[k]) != _APRENDIDA):
                continue
            m = _mac(bytes(x & 0xFF for x in k[1:]))
            macs.add((fdb_vlan.get(k[0], k[0]), m, nombre_bp(bp)))
    else:
        d, dst = tb.tabla("dot1dTpFdbPort"), tb.tabla("dot1dTpFdbStatus")
        for k, r in d.items():
            bp = _int(r)
            if len(k) != 6 or not bp or (k in dst and _int(dst[k]) != _APRENDIDA):
                continue
            macs.add((0, _mac(bytes(x & 0xFF for x in k)), nombre_bp(bp)))
        if macs:
            sw.avisos.append("sin Q-BRIDGE-MIB: la VLAN de las MAC es desconocida (0)")
    sw.mac = sorted(macs)

    # VLAN, PVID y pertenencia
    for k, r in tb.tabla("dot1qVlanStaticName").items():
        if len(k) == 1:
            sw.vlans[k[0]] = _texto(r)
    pvid = {k[0]: _int(r) for k, r in tb.tabla("dot1qPvid").items() if len(k) == 1 and _int(r) is not None}
    egreso, sin_etiq = tb.tabla("dot1qVlanCurrentEgressPorts"), tb.tabla("dot1qVlanCurrentUntaggedPorts")
    etiquetada: dict = {}
    plana: dict = {}
    if egreso and sin_etiq:
        for k, r in egreso.items():
            if len(k) != 2:
                continue
            ut = _lista_puertos(sin_etiq.get(k))
            for bp in _lista_puertos(r):
                (plana if bp in ut else etiquetada).setdefault(nombre_bp(bp), set()).add(k[1])
    pv = {nombre_bp(bp): v for bp, v in pvid.items()}
    for nom, v in pv.items():
        if nom not in plana and nom not in etiquetada:
            puertos[nom].vlan_acceso = v
    for nom, vs in etiquetada.items():
        p = puertos[nom]
        p.modo, p.vlans_trunk = "trunk", sorted(vs)
        p.vlan_nativa = pv.get(nom)
    for nom, vs in plana.items():
        p = puertos[nom]
        if nom in etiquetada:
            continue
        p.modo = "access"
        p.vlan_acceso = pv.get(nom, min(vs))
    if usa_puente[0] and not mapa:
        sw.avisos.append("sin dot1dBasePortIfIndex: se trata el puerto de puente como ifIndex")
    return mapa


def _lldp(tb, sw, nombres, por_texto, mapa) -> None:
    nom_r, id_r = tb.tabla("lldpRemSysName"), tb.tabla("lldpRemPortId")
    des_r, sys_r = tb.tabla("lldpRemPortDesc"), tb.tabla("lldpRemSysDesc")
    loc_id, loc_desc = tb.tabla("lldpLocPortId"), tb.tabla("lldpLocPortDesc")

    def local(n: int) -> str:
        for rec in (loc_id.get((n,)), loc_desc.get((n,))):
            txt = _texto(rec)
            if txt in por_texto:
                return nombres[por_texto[txt]]
        if n in nombres:
            return nombres[n]
        return nombres.get(mapa.get(n), str(n))

    for k in sorted({k for k in list(nom_r) + list(id_r) + list(des_r) + list(sys_r) if len(k) == 3}):
        pid = id_r.get(k)
        remoto = _texto(des_r.get(k)) or (_mac(_bytes(pid)) if pid and pid[0] == "HEX" else _texto(pid))
        sw.cdp.append(Vecino(id_equipo=_texto(nom_r.get(k)) or "(sin nombre)",
                             plataforma=_texto(sys_r.get(k))[:MAX_PLATAFORMA], interfaz=local(k[1]),
                             puerto_remoto=remoto))


def _stp(tb, sw) -> None:
    cambios, hace = _int(tb.escalar("dot1dStpTopChanges")), _int(tb.escalar("dot1dStpTimeSinceTopologyChange"))
    prio, raiz = _int(tb.escalar("dot1dStpPriority")), _bytes(tb.escalar("dot1dStpDesignatedRoot"))
    puente = _mac_rec(tb.escalar("dot1dBaseBridgeAddress"))
    if cambios is None and hace is None and prio is None and len(raiz) != 8:
        return
    c = CambioStp(instancia="STP", cambios=cambios or 0, hace_s=None if hace is None else hace // 100,
                  prioridad=prio, puente=puente)
    if len(raiz) == 8:
        r = _mac(raiz[2:])
        c.raiz = "local" if puente and r == puente else r
    sw.stp.append(c)
    sw.leyo.append("stp")


def leer(texto: str, nombre: str = "") -> Switch:
    """Recorrido SNMP (texto) -> Switch con origen "snmp". `nombre` (archivo) da el hostname si falta sysName."""
    sw = Switch(archivo=nombre, origen="snmp")
    reg, sysnames, descartadas, corchetes = _leer_registros(texto)
    if descartadas:
        sw.avisos.append(f"{descartadas} lineas no son 'OID = valor' y se descartaron sin guardarlas")
    if corchetes:
        sw.avisos.append(f"{corchetes} lineas con indices entre corchetes (-OX) no se leen: use -On")
    stem = Path(nombre).stem
    if not any(o.startswith(_PREFIJOS) for o in reg):
        sw.avisos.append("el archivo no trae ningun objeto SNMP reconocido (SNMPv2-MIB, IF-MIB, BRIDGE-MIB, "
                         "Q-BRIDGE-MIB, ENTITY-MIB, LLDP-MIB); genere el recorrido con snmpbulkwalk -On")
        sw.hostname = stem
        return sw
    tb = _Tablas(reg)
    nombres_sys = [_texto(r) for r in sysnames]
    if len(set(nombres_sys)) > 1:
        sw.avisos.append("el archivo trae mas de un sysName (equipos concatenados); se usa el primero")
    sw.hostname = (nombres_sys[0] if nombres_sys else "") or stem
    _chasis(tb, sw)
    puertos, nombres, por_texto = _puertos(tb, sw)
    _contadores(tb, sw, nombres, puertos)
    mapa = _puente(tb, sw, nombres, puertos, por_texto)
    _lldp(tb, sw, nombres, por_texto, mapa)
    _stp(tb, sw)
    return sw


def leer_archivo(ruta) -> Switch:
    p = Path(ruta)
    return leer(p.read_text(encoding="utf-8", errors="replace"), p.name)
