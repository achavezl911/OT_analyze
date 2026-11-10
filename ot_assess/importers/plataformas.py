"""Importacion de inventario y comunicaciones exportados de una plataforma OT.

Convierte las tablas en las dos estructuras que consumen los diagramas (las mismas que
produce el analisis de capturas): `assets` y `conduits`. No sabe nada de lectura o escritura:
las exportaciones de inventario y de enlaces no distinguen operaciones de control, asi que
ningun conducto importado se marca como critico por escritura.
"""
from __future__ import annotations

import collections
import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import fuentes as _fu
from .. import json_entrada
from ..acceso_remoto import herramienta_de_nombre
from ..consolidate import criticidad_conducto
from ..evasion import entrada_de_nombre
from ..util import port_info
from . import perfiles as pf
from .lector import leer_tabla

PRINCIPAL = "principal"      # nombre de la fuente que forman los archivos dados con --enlaces
LIMITE_XDOME = 100000       # filas por consulta que exporta xDome; si hay exactamente tantas, se corto


@dataclass
class Importacion:
    assets: dict
    conduits: list
    fuente: str                          # nombre de la plataforma, para el encabezado
    perfil: str
    agrupar: str                         # "nivel" o "zona"
    mapeos: dict                         # {"activos": {campo: columna}, "enlaces": {...}}
    resumen: dict
    advertencias: list = field(default_factory=list)
    fuentes: dict = field(default_factory=dict)      # M2: vacio sin fuentes con nombre (ver D46)
    dominios: list = field(default_factory=list)     # T8: [{cliente, servidor, dominio, bytes, fecha}] (side_b_domains)


def _encabezados(filas: list) -> list:
    vistos: dict = {}
    for f in filas:
        for k in f:
            vistos.setdefault(k, None)
    return list(vistos)


def _valor(fila: dict, mapeo: dict, campo: str) -> str:
    col = mapeo.get(campo)
    v = (fila.get(col) or "").strip() if col else ""
    # xDome (y otras): "N/A" es "sin dato"; Nozomi exporta el vacio como "'-" o "-" (D74)
    return "" if v.upper() == "N/A" or v in ("'-", "-") else v


def _tokens(celda: str) -> list:
    return [t for t in re.split(r"[;,|\s]+", celda) if t]


def _ips(celda: str) -> list:
    out = []
    for t in _tokens(celda):
        try:
            out.append(str(ipaddress.ip_address(t.split("/")[0].split("%")[0])))
        except ValueError:
            continue
    return out


def _mac(t: str) -> str:
    t = t.strip().lower().replace("-", ":")
    return t if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", t) else ""


def _separar(crudo: str) -> tuple:
    """(MAC, IP) de un extremo: IPv4, IPv6, MAC o 'MAC@IP' (Nozomi: la IP vista con esa MAC). '' si falta."""
    crudo = (crudo or "").strip()
    if "@" in crudo:
        a, b = crudo.split("@", 1)
        return _mac(a), (_ips(b) or [""])[0]
    if _mac(crudo):
        return _mac(crudo), ""
    return "", (_ips(crudo) or [""])[0]


def _ip_difusion(ip: str, redes: set) -> bool:
    """Multicast, 0.0.0.0, 255.255.255.255 o el .255 de una /24 conocida: destinos, no equipos (D74)."""
    try:
        d = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if d.is_multicast or d.is_unspecified or ip == "255.255.255.255":
        return True
    return d.version == 4 and ip.endswith(".255") and ip.rsplit(".", 1)[0] in redes


def _redes_de(assets: dict) -> set:
    """Prefijos /24 (a.b.c) de las IPv4 de los activos, sin contar los .255."""
    return {ip.rsplit(".", 1)[0] for a in assets.values() for ip in a["ips"]
            if ip.count(".") == 3 and not ip.endswith(".255")}


def _es_difusion(crudo: str, redes: set) -> bool:
    mac, ip = _separar(crudo)
    if ip:
        return _ip_difusion(ip, redes)
    return bool(mac) and bool(int(mac[:2], 16) & 1)       # bit de grupo de la MAC: multicast o broadcast


# Redes que cuentan como publicas aunque Python las trate como reservadas (solo las usan las pruebas, con
# documentacion RFC 5737 como "Internet" simulado).
_PUBLICAS_FORZADAS: tuple = ()
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ROL_ENRUTAMIENTO = re.compile(r"router|firewall|gateway|dhcp_server", re.IGNORECASE)


def _ipv4_unicast(ip: str):
    try:
        d = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if d.version != 4 or d.is_multicast or d.is_unspecified or ip == "255.255.255.255" or ip.endswith(".255"):
        return None
    return d


def _ip_publica(ip: str) -> bool:
    """IPv4 publica: ni privada, ni link-local, ni CGNAT, ni reservada."""
    d = _ipv4_unicast(ip)
    if d is None:
        return False
    if any(d in ipaddress.ip_network(r) for r in _PUBLICAS_FORZADAS):
        return True
    return not (d.is_private or d.is_link_local or d.is_loopback or d.is_reserved or d in _CGNAT)


def _link_local(ip: str) -> bool:
    try:
        d = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return d.is_link_local


def _macs_de_enrutamiento(unidades: list) -> tuple:
    """(MAC de enrutamiento, IP que cada MAC trae en Assets). En Nodes, los equipos remotos aparecen con la MAC
    del router por el que se ven: esa MAC no identifica a un solo equipo (D74)."""
    ips: dict = {}
    texto: dict = {}
    propias: dict = {}
    for _f, ips_f, macs_f, es_assets, rol in unidades:
        for x in macs_f:
            ips.setdefault(x, set()).update(i for i in ips_f if _ipv4_unicast(i))
            texto[x] = texto.get(x, "") + " " + rol
            if es_assets:
                propias.setdefault(x, set()).update(ips_f)
    rutas = set()
    for x, v4 in ips.items():
        redes = {i.rsplit(".", 1)[0] for i in v4}
        if (len(v4) > 4 or any(_ip_publica(i) for i in v4)
                or (len(redes) > 1 and _ROL_ENRUTAMIENTO.search(texto[x]))):
            rutas.add(x)
    return rutas, propias


def _fecha_valor(s: str):
    """datetime sin zona de un numero de serie de Excel (dias desde 1899-12-30) o de un ISO sin zona; None si no."""
    s = (s or "").strip()
    if re.fullmatch(r"\d{5}(\.\d+)?", s) and 20000 < float(s) < 80000:
        return datetime.datetime(1899, 12, 30) + datetime.timedelta(days=float(s))
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    except ValueError:
        return None
    return d if d is not None and d.tzinfo is None else None


def _entero(s: str) -> int:
    m = re.search(r"\d[\d.,]*", s or "")
    if not m:
        return 0
    n = m.group().replace(",", "")
    try:
        return int(float(n))
    except ValueError:
        return 0


def _bytes(s: str) -> int:
    m = re.match(r"\s*([\d.,]+)\s*([kmgt]?)i?b?\s*$", (s or "").lower())
    if not m:
        return _entero(s)
    try:
        v = float(m.group(1).replace(",", ""))
    except ValueError:
        return 0
    return int(v * 1024 ** "bkmgt".index(m.group(2) or "b"))


def _clave_texto(s: str) -> str:
    return s.strip().lower()


class _Resolutor:
    """Encuentra el activo al que se refiere un extremo de enlace: por IP, id, MAC o nombre."""

    def __init__(self, assets: dict):
        self.tabla: dict = {}
        for a in assets.values():
            for k in {a["mac"], *a["ips"], *a["alias"]}:
                self.tabla.setdefault(_clave_texto(k), a)

    def __call__(self, crudo: str):
        crudo = crudo.strip()
        if not crudo:
            return None
        if "@" in crudo:                  # MAC@IP: manda la MAC, la IP puede ser compartida
            cand = [x for x in _separar(crudo) if x]
        else:
            cand = [crudo]
            cand += _ips(crudo)[:1]
            m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$", crudo)
            if m:
                cand.append(m.group(1))
            if _mac(crudo):
                cand.append(_mac(crudo))
        for c in cand:
            a = self.tabla.get(_clave_texto(c))
            if a is not None:
                return a
        return None


def _construir_activos(filas: list, m: dict, nozomi: bool = False) -> tuple:
    """(activos, filas descartadas). Cada activo lleva '_por_tipo': su nivel se dedujo del tipo.

    Un activo se identifica por 'id' si la plataforma lo da; si no, por MAC y por IP: una fila con una
    MAC o una IP ya vista (otro archivo, p. ej. Nodes tras Assets) se une al mismo activo sin duplicar. La IP
    solo une si la fila no trae MAC o el activo previo no tiene (una IP compartida por dos MAC son dos equipos).
    Con `nozomi`, multicast y broadcast no son equipos y los roles sustituyen al tipo vacio (D74)."""
    assets: dict = {}
    por_mac: dict = {}
    por_ip: dict = {}
    descartados = 0
    if nozomi:       # los datos de Assets mandan sobre los de Nodes (la fila de Nodes trae 'address')
        filas = sorted(filas, key=lambda f: bool(_valor(f, m, "address")))
    unidades = []    # (fila, IP, MAC, viene de Assets, tipo y roles)
    for f in filas:
        ips = _ips(_valor(f, m, "ip"))
        macs = [x for x in (_mac(t) for t in _tokens(_valor(f, m, "mac"))) if x]
        direccion = _valor(f, m, "address")
        if direccion:
            mac_d, ip_d = _separar(direccion)
            if mac_d and mac_d not in macs:
                macs.insert(0, mac_d)
            if ip_d and ip_d not in ips:
                ips.append(ip_d)
        unidades.append((f, ips, macs, not direccion, f"{_valor(f, m, 'tipo')} {_valor(f, m, 'roles')}"))
    ajenas: set = set()
    macs_ajenas: set = set()
    if nozomi:
        rutas, propias = _macs_de_enrutamiento(unidades)
        expandidas = []
        for f, ips, macs, es_assets, rol in unidades:
            enr = [x for x in macs if x in rutas]
            if enr and not es_assets:
                # solo se unen por MAC las IP del propio equipo: las de Assets y las link-local
                ok = [i for i in ips if _link_local(i) or any(i in propias.get(x, ()) for x in enr)]
                fuera = [i for i in ips if i not in ok]
                if fuera:
                    ajenas.update(fuera)
                    macs_ajenas.update(enr)
                    expandidas.extend((f, [i], [], False, rol) for i in fuera if not _ip_publica(i))
                    if not ok:
                        continue
                    ips = ok
            expandidas.append((f, ips, macs, es_assets, rol))
        unidades = expandidas
    for f, ips, macs, _es_assets, _rol in unidades:
        if nozomi and ((ips and all(_ip_difusion(i, set()) for i in ips)) or
                       (not ips and macs and all(int(x[:2], 16) & 1 for x in macs))):
            continue
        ident = _valor(f, m, "id")
        nombre = _valor(f, m, "nombre")
        clave = ident or (macs[0] if macs else (ips[0] if ips else nombre))
        if not clave:
            descartados += 1
            continue
        tipo_texto = _valor(f, m, "tipo")
        if nozomi and not tipo_texto:        # type vacio: el tipo sale de los roles ("other" no dice nada)
            tipo_texto = ", ".join(r for r in (x.strip() for x in re.split(r"[;,|]", _valor(f, m, "roles")))
                                   if r and r.lower() != "other")
        modelo = _valor(f, m, "modelo")
        tipo, sugerida = pf.clasificar_tipo(f"{tipo_texto} {modelo}")
        nivel = pf.parse_nivel(_valor(f, m, "nivel"))
        por_tipo = False
        if nivel is None and sugerida == "Infraestructura":
            nivel, por_tipo = sugerida, True           # un switch o firewall es infraestructura
        if nivel is None:
            nivel = pf.parse_nivel(_valor(f, m, "zona"))   # zonas llamadas "DMZ", "Level 2"...
            por_tipo = nivel is not None
        if nivel is None and sugerida:
            nivel, por_tipo = sugerida, True
        # Nombres multiples (hostnames) separados por ; o |; nunca por espacio: 'PLC 1' es un solo nombre.
        alias = {x.strip() for x in (ident, *macs, *re.split(r"[;|]", nombre)) if x and x.strip()}
        a = assets.get(clave) if ident else None
        if a is None and not ident:
            a = next((por_mac[x] for x in macs if x in por_mac), None)
            if a is None:
                a = next((por_ip[i] for i in ips if i in por_ip
                          and (not macs or not _mac(por_ip[i]["mac"]))), None)
            if a is None:
                a = assets.get(clave)
        if a is None:
            a = assets[clave] = {
                "mac": clave, "ips": set(), "alias": set(), "nombre": "", "vendor": "", "modelo": "",
                "firmware": "", "tipo": "otro", "tipo_texto": "", "role": "", "purdue": "", "zona": "",
                "pkts": 0, "vlans": set(), "so": "", "protocolos": set(), "_por_tipo": False}
        a["ips"] |= set(ips)
        a["alias"] |= alias | {clave}
        if nozomi:       # en xDome la VLAN no se leia y cambiaria la zona asignada (zonas.py)
            a["vlans"] |= {t for t in _tokens(_valor(f, m, "vlan")) if t.isdigit()}
        a["protocolos"] |= {p.strip() for p in re.split(r"[;,|]", _valor(f, m, "protocolos")) if p.strip()}
        for x in macs:
            por_mac.setdefault(x, a)
        for i in ips:
            por_ip.setdefault(i, a)
        for campo, val in (("nombre", nombre), ("vendor", _valor(f, m, "vendor") or _valor(f, m, "vendor_alt")),
                           ("modelo", modelo), ("so", _valor(f, m, "so")),
                           ("firmware", _valor(f, m, "firmware") or _valor(f, m, "firmware_alt")),
                           ("tipo_texto", tipo_texto), ("zona", _valor(f, m, "zona")),
                           ("criticidad", _valor(f, m, "criticidad"))):
            a[campo] = a.get(campo) or val
        d_ult = _fecha_valor(_valor(f, m, "ultima"))      # I1a: ultima actividad del activo, si la exportacion la trae
        if d_ult is not None:
            a["ultima"] = max(a.get("ultima") or "", d_ult.strftime("%Y-%m-%d %H:%M:%S"))
        if a["tipo"] == "otro":
            a["tipo"] = tipo
        if not a["purdue"] and nivel:
            a["purdue"], a["_por_tipo"] = nivel, por_tipo
    if nozomi:       # el .255 de una red conocida (se sabe al final) es broadcast, no un equipo
        redes = _redes_de(assets)
        for k in [k for k, a in assets.items() if a["ips"] and not _mac(a["mac"])
                  and all(_ip_difusion(i, redes) for i in a["ips"])]:
            del assets[k]
    for a in assets.values():
        a["role"] = a["tipo_texto"]
        a["nombre"] = a["nombre"] or (min(a["ips"]) if a["ips"] else a["mac"])
    return assets, descartados, ({"direcciones": len(ajenas), "macs": len(macs_ajenas)} if ajenas else {})


def _elegir_agrupacion(assets: dict, pedido: str) -> str:
    if pedido in ("nivel", "zona"):  # "interfaz" no se elige aqui: la fija el CLI si hay rutas de firewall
        return pedido
    n = len(assets) or 1
    con_nivel = sum(1 for a in assets.values() if a["purdue"] and not a["_por_tipo"])
    con_zona = sum(1 for a in assets.values() if a["zona"])
    if con_nivel / n >= 0.5 or not con_zona:
        return "nivel"
    return "zona"


def importar(activos: list, enlaces: list, formato: str = "auto", mapeo: dict | None = None,
             agrupar: str = "auto", fuentes: dict | None = None, tshark: str | None = None) -> Importacion:
    """`fuentes`: {nombre: [archivos]} de sensores con nombre (M2, D46); lo dado en `enlaces` es la
    fuente "principal". Sin `fuentes` no hay procedencia y todo sale como siempre."""
    fuentes = fuentes or {}
    multi = bool(fuentes)
    if not enlaces and not fuentes:
        raise SystemExit("[!] Falta el archivo de enlaces o comunicaciones (--enlaces): sin el no hay diagrama.")
    mapeo = mapeo or {}
    filas_a = [f for p in activos for f in leer_tabla(p)]
    por_fuente = ([(PRINCIPAL, list(enlaces))] if enlaces else []) + list(fuentes.items())
    tablas_e = [(nom, Path(p).name, leer_tabla(p)) for nom, ps in por_fuente for p in ps if not _fu.es_captura(p)]
    n_filas_e = sum(len(t) for _f, _n, t in tablas_e)
    pcaps = sorted({p for _nom, ps in por_fuente for p in ps if _fu.es_captura(p)})
    de_capturas, avisos_c = _fu.procesar_capturas(pcaps, tshark) if pcaps else ({}, [])
    if not n_filas_e and not sum(len(v) for v in de_capturas.values()):
        raise SystemExit("[!] El archivo de enlaces no tiene filas de datos.")
    cab_a = _encabezados(filas_a)
    cab_e = _encabezados([f for _f, _n, t in tablas_e for f in t])

    perfil = formato
    if formato == "auto":
        perfil = pf.detectar_perfil(cab_a + cab_e)
    if perfil not in pf.PERFILES:
        raise SystemExit(f"[!] Formato desconocido: '{formato}'. Validos: auto, {', '.join(pf.PERFILES)}")

    forz_a: dict = {}
    col_tipo = pf.TIPO_PREFERIDO.get(perfil)
    if col_tipo and any(pf.normalizar(h) == col_tipo for h in cab_a):
        forz_a["tipo"] = col_tipo
    if perfil == "nozomi":      # 'address' (Nodes) puede ser MAC@IP; 'ip' y 'roles' no se confunden con el
        for campo, col in (("ip", "ip"), ("address", "address"), ("roles", "roles")):
            h = next((h for h in cab_a if pf.normalizar(h) == col), None)
            if h is not None:
                forz_a[campo] = h
    forz_a.update(mapeo.get("activos") or {})
    m_a = pf.mapear(cab_a, pf.ACTIVOS, forz_a) if filas_a else {}
    m_e = pf.mapear(cab_e, pf.ENLACES, mapeo.get("enlaces")) if cab_e else {}
    faltan = [c for c in pf.OBLIGATORIOS["enlaces"] if c not in m_e] if cab_e else []
    if faltan:
        raise SystemExit(
            f"[!] No reconoci la columna de {' ni de '.join(faltan)} en los enlaces. Columnas: "
            f"{', '.join(cab_e)}. Indicala con --mapeo, por ejemplo: "
            f"{{\"enlaces\": {{\"{faltan[0]}\": \"<columna>\"}}}}")

    adv: list = list(avisos_c)
    es_nozomi = perfil == "nozomi"
    assets, descartados, enrut = _construir_activos(filas_a, m_a, es_nozomi) if filas_a else ({}, 0, {})
    redes = _redes_de(assets) if es_nozomi else set()
    por_tipo = sum(1 for a in assets.values() if a["_por_tipo"])
    agr = _elegir_agrupacion(assets, agrupar)
    banda = (lambda a: a["zona"]) if agr == "zona" else (lambda a: a["purdue"])
    resolver = _Resolutor(assets)

    # protocolo vs transporte: algunas exportaciones llaman "protocol" a TCP/UDP
    if "protocolo" in m_e and "l4" not in m_e:
        muestra = [f for _f, _n, t in tablas_e for f in t[:500]][:500]
        vals = {pf.normalizar(_valor(f, m_e, "protocolo")) for f in muestra} - {""}
        if vals and vals <= {"tcp", "udp", "icmp", "ip", "sctp"}:
            m_e["l4"] = m_e.pop("protocolo")
            adv.append("La columna de protocolo contiene solo transporte (TCP/UDP): el servicio se deduce del puerto.")

    por_id = {a["mac"]: a for a in assets.values()}

    def nuevo_activo(ip: str) -> dict:
        a = assets[ip] = por_id[ip] = {
            "mac": ip, "ips": {ip}, "alias": {ip}, "nombre": ip, "vendor": "", "modelo": "",
            "firmware": "", "tipo": "otro", "tipo_texto": "", "role": "", "purdue": "", "zona": "",
            "pkts": 0, "vlans": set(), "_por_tipo": False, "_nuevo": True}
        resolver.tabla.setdefault(_clave_texto(ip), a)
        return a

    def completar(a: dict, tipo: str, nombre: str, externo: bool) -> None:
        """Lo que dice la fila de comunicaciones sobre un extremo, solo donde el inventario calla."""
        if nombre and a["nombre"] == a["mac"]:
            a["nombre"] = nombre
        if externo and a.get("_nuevo"):
            a.update(tipo="externo", purdue="Externo", zona="Externo")
        elif tipo and a["tipo"] == "otro":
            t, sugerida = pf.clasificar_tipo(tipo)
            if t != "otro" or not a["tipo_texto"]:
                a["tipo"], a["tipo_texto"], a["role"] = t, a["tipo_texto"] or tipo, a["tipo_texto"] or tipo
                if sugerida and not a["purdue"]:
                    a["purdue"], a["_por_tipo"] = sugerida, True

    cache: dict = {}

    def extremo(raw: str, tipo: str = "", nombre: str = "", externo: bool = False) -> tuple:
        """(activo o None, identificador). Crea el activo si la fila trae tipo, nombre o ambito."""
        c = cache.get(raw)
        if c is None:
            a = resolver(raw)
            mac_r, ip_r = _separar(raw) if "@" in raw else ("", "")
            c = cache[raw] = [a, a["mac"] if a else (ip_r or mac_r or (_ips(raw) or [raw])[0])]
        if tipo or nombre or externo:
            if c[0] is None and _ips(raw):
                c[0] = nuevo_activo(c[1])
            if c[0] is not None:
                completar(c[0], tipo, nombre, externo)
        return c[0], c[1]

    agregados: dict = {}
    cache_proto: dict = {}
    no_res = vacios = 0
    es_xdome = perfil == "xdome"
    def acumular(nom_f, n_arch, src, dst, bidir, l4, puerto, protos, pk, by, fecha):
        """Suma un registro de comunicacion (fila de exportacion o conducto de captura) en su conducto."""
        for proto in protos:
            clave = ((("=",) + tuple(sorted((src, dst)))) if bidir else (">", src, dst)) + (l4, puerto, proto)
            k = agregados.get(clave)
            if k is None:
                c = cache_proto.get((proto, puerto, l4, dst))
                if c is None:
                    try:
                        mc = ipaddress.ip_address(dst).is_multicast
                    except ValueError:
                        mc = False
                    nombre_p, cat_p = port_info(str(puerto), l4 or "tcp") if puerto else ("", "")
                    cat = pf.categoria_protocolo(proto) or cat_p or ("multicast" if mc else "otro")
                    c = cache_proto[(proto, puerto, l4, dst)] = (mc, nombre_p, cat)
                k = agregados[clave] = {
                    "src": src, "dst": dst, "l4": l4, "port": str(puerto) if puerto else "",
                    "servicio": proto or c[1] or "-", "categoria": c[2],
                    "pkts": 0, "bytes": 0, "escrituras": 0, "multicast": c[0], "bidireccional": bidir,
                    "primera": "", "ultima": "", "_f": {}}
            ac = k["_f"].get((nom_f, n_arch))      # por archivo: se suma dentro, maximo entre archivos
            if ac is None:
                ac = k["_f"][(nom_f, n_arch)] = {}
            cel = ac.get(fecha)
            if cel is None:
                cel = ac[fecha] = [0, 0, 0]
            cel[0] += pk // len(protos)
            cel[1] += by // len(protos)
            cel[2] += max(pk // len(protos), 1)

    vistas: dict = {}
    difusion: collections.Counter = collections.Counter()
    t_ini: list = []
    t_fin: list = []
    dominios_ar: list = []
    arch_captura: set = set()
    n_arch = 0
    n_archivos = collections.Counter(nom for nom, _n, _t in tablas_e)
    repetidas: collections.Counter = collections.Counter()
    while tablas_e:
        nom_f, nombre_t, filas_t = tablas_e.pop(0)
        vistas_f = vistas.setdefault(nom_f, {})
        n_arch += 1
        varios = n_archivos[nom_f] > 1      # el solape solo es posible con mas de un archivo en la fuente
        if es_nozomi and filas_t and m_e.get("puerto") not in filas_t[0]:
            adv.append(f"{nombre_t}: este archivo no trae puerto ni transporte (Links de Nozomi): los conductos "
                       f"quedan sin puerto y no se pueden proponer reglas por servicio. Exporte Sessions para "
                       f"obtenerlos.")
        if len(filas_t) == LIMITE_XDOME:
            adv.append(f"{nombre_t}: posible exportacion truncada por el limite de {LIMITE_XDOME} filas de "
                       f"xDome: divide la consulta por subred o por periodo.")
        for f in filas_t:
            a_raw, b_raw = _valor(f, m_e, "origen"), _valor(f, m_e, "destino")
            if not a_raw or not b_raw:
                vacios += 1
                continue
            if es_nozomi:
                for lista, campo in ((t_ini, "t_ini"), (t_fin, "t_fin")):
                    d = _fecha_valor(_valor(f, m_e, campo))
                    if d is not None:
                        lista.append(d)
                if (resolver(a_raw) is None and _es_difusion(a_raw, redes)) or \
                        (resolver(b_raw) is None and _es_difusion(b_raw, redes)):
                    # multicast, broadcast o 0.0.0.0: no es un equipo; se cuenta aparte y no genera conducto
                    difusion[_valor(f, m_e, "protocolo") or _valor(f, m_e, "l4") or "-"] += 1
                    continue
            fecha = _valor(f, m_e, "fecha")
            if fecha and varios:       # fila con fecha identica a una de OTRO archivo de la misma fuente = solape: una vez
                fila_id = tuple(f.values())
                previo = vistas_f.setdefault(fila_id, n_arch)
                if previo != n_arch:
                    repetidas[nom_f] += 1
                    continue
            sentido = pf.normalizar(_valor(f, m_e, "direccion"))
            invertir = sentido in ("from_b_to_a", "b_to_a")
            bidir = sentido in ("bidirectional", "both") or (es_xdome and not invertir and
                                                             sentido not in ("from_a_to_b", "a_to_b"))
            externo = "external" in pf.normalizar(_valor(f, m_e, "ambito"))
            nom_b = re.split(r"[;,|]", _valor(f, m_e, "nombre_destino"))[0].strip()
            ao, src = extremo(a_raw, _valor(f, m_e, "tipo_origen"))
            ad, dst = extremo(b_raw, _valor(f, m_e, "tipo_destino"), nom_b, externo)
            for dom in dict.fromkeys(d.strip().lower().rstrip(".") for d in
                                     re.split(r"[;,|]", _valor(f, m_e, "nombre_destino"))):
                # T8 y T9: el dominio es del lado B; el cliente es el A
                if dom and (herramienta_de_nombre(dom) or entrada_de_nombre(dom)):
                    dominios_ar.append({"cliente": src, "servidor": dst, "dominio": dom, "fecha": fecha,
                                        "bytes": _bytes(_valor(f, m_e, "bytes"))})
            if invertir:
                ao, src, ad, dst = ad, dst, ao, src
            if filas_a:
                no_res += (ao is None) + (ad is None)
            l4 = pf.normalizar(_valor(f, m_e, "l4"))
            l4 = l4 if l4 in ("tcp", "udp") else ""
            puerto = _entero(_valor(f, m_e, "puerto"))
            protos = [t.strip() for t in re.split(r"[;|]", _valor(f, m_e, "protocolo")) if t.strip()] or [""]
            pk, by = _entero(_valor(f, m_e, "paquetes")), _bytes(_valor(f, m_e, "bytes"))
            acumular(nom_f, n_arch, src, dst, bidir, l4, puerto, protos, pk, by, fecha)
    for ruta, regs in sorted(de_capturas.items()):     # una captura es un archivo mas de cada fuente que la trae
        n_arch += 1
        arch_captura.add(n_arch)
        for nom_f, ps in por_fuente:
            if ruta not in ps:
                continue
            for r in regs:
                ao, src = extremo(r["src"])
                ad, dst = extremo(r["dst"])
                if filas_a:
                    no_res += (ao is None) + (ad is None)
                acumular(nom_f, n_arch, src, dst, r["bidireccional"], r["l4"], _entero(r["port"]),
                         [r["servicio"]], r["pkts"], r["bytes"], r["dia"])

    if multi:
        agregados = _unir_entre_fuentes(agregados, arch_captura)
    conduits: list = []
    resumen_f = {nom: {"fuente": nom, "tipo": _fu.tipo_fuente(ps), "conductos": 0, "unicos": 0,
                       "compartidos": 0, "primera": "", "ultima": ""} for nom, ps in por_fuente}
    for k in agregados.values():
        ao, ad = por_id.get(k["src"]), por_id.get(k["dst"])
        por_archivo = k.pop("_f")
        celdas = _unir_fuentes(por_archivo)
        fs: dict = {}
        for (nom, _arch), ac in por_archivo.items():
            fs.setdefault(nom, {}).update(ac)
        k["pkts"] = sum(c[0] for c in celdas.values())
        k["bytes"] = sum(c[1] for c in celdas.values())
        n = sum(c[2] for c in celdas.values())
        dias = [d for d in celdas if d]
        if dias:
            k["primera"], k["ultima"] = min(dias), max(dias)
        if multi:
            k["fuentes"] = sorted(fs)
            for nom, ac in fs.items():
                r_f = resumen_f[nom]
                r_f["conductos"] += 1
                r_f["unicos" if len(fs) == 1 else "compartidos"] += 1
                fe = [d for d in ac if d]
                if fe:
                    r_f["primera"] = min(r_f["primera"] or min(fe), min(fe))
                    r_f["ultima"] = max(r_f["ultima"], max(fe))
        for a in (ao, ad):
            if a is not None:
                a["pkts"] += n
        bz, dz = (banda(ao) if ao else ""), (banda(ad) if ad else "")
        k["cruza_zona"] = bool(bz and dz and bz != dz and not k["multicast"])
        k["criticidad"] = criticidad_conducto(k["categoria"], k["cruza_zona"], 0)
        k["dias"] = len(dias)
        conduits.append(k)

    sin_ip = sum(1 for a in assets.values() if not a["ips"])
    sin_nivel = sum(1 for a in assets.values() if not a["purdue"])
    if filas_a and "nivel" not in m_a:
        adv.append("No se reconocio una columna de nivel Purdue: los equipos se ubican por su tipo.")
    if filas_a and "tipo" not in m_a:
        adv.append("No se reconocio una columna de tipo de equipo: los iconos y el nivel inferido seran genericos.")
    if agr == "zona" and "zona" not in m_a:
        adv.append("Se pidio agrupar por zona pero no hay columna de zona.")
    if no_res:
        adv.append(f"{no_res} extremos de enlaces no coinciden con ningun activo del inventario (por IP, id, "
                   f"MAC o nombre); se dibujan como equipos no inventariados.")
    if difusion:
        top = ", ".join(f"{p} {n}" for p, n in sorted(difusion.items(), key=lambda x: (-x[1], x[0]))[:8])
        adv.append(f"{sum(difusion.values())} filas de comunicaciones hacia multicast o broadcast (no son "
                   f"equipos) se contaron aparte, sin dibujarlas ni proponer reglas de firewall: {top}.")
    if enrut:
        adv.append(f"{enrut['direcciones']} direcciones de Nodes comparten la MAC de un equipo de enrutamiento "
                   f"({enrut['macs']} MAC); no se unieron por MAC.")
    if descartados:
        adv.append(f"{descartados} filas de activos sin ningun identificador se descartaron.")
    for nom, n in repetidas.items():
        donde = f"en la fuente '{nom}'" if multi else "en los archivos de enlaces"
        adv.append(f"{n} filas repetidas exactas (misma fecha y mismas columnas) {donde} se contaron una vez.")
    if vacios:
        adv.append(f"{vacios} filas de enlaces sin origen o destino se descartaron.")
    if not filas_a:
        adv.append("Sin archivo de activos: los equipos salen solo con su direccion, sin tipo ni nivel "
                   "(salvo lo que traigan las propias comunicaciones).")
    resumen = {
        "activos": len(assets), "filas_enlaces": n_filas_e + sum(len(v) for v in de_capturas.values()),"conductos": len(conduits),
        "activos_sin_ip": sin_ip, "activos_sin_nivel": sin_nivel, "activos_nivel_por_tipo": por_tipo,
        "extremos_no_resueltos": no_res,
        "por_tipo": dict(collections.Counter(a["tipo"] for a in assets.values())),
    }
    if enrut:
        resumen["mac_enrutamiento"] = enrut
    if difusion:
        resumen["difusion"] = dict(sorted(difusion.items()))
    if t_ini or t_fin:       # fecha local de la exportacion: el numero de serie de Excel no trae zona horaria
        desde, hasta = min(t_ini or t_fin), max(t_fin or t_ini)
        resumen["periodo"] = {"desde": desde.strftime("%Y-%m-%d %H:%M"), "hasta": hasta.strftime("%Y-%m-%d %H:%M"),
                              "zona": "sin zona horaria"}
    for a in assets.values():
        a["nivel_por_tipo"] = bool(a.pop("_por_tipo", False) and a["purdue"])     # I1a: nivel inferido del tipo
        a.pop("_nuevo", None)
    info = {}
    if multi:
        info = {"nombres": [nom for nom, _ps in por_fuente], "resumen": list(resumen_f.values()),
                "archivos": {nom: [Path(p).name for p in ps] for nom, ps in por_fuente},
                "repetidas": dict(repetidas)}
    return Importacion(assets, conduits, pf.PERFILES[perfil].nombre, perfil, agr,
                       {"activos": m_a, "enlaces": m_e}, resumen, adv, info, dominios_ar)


def _unir_entre_fuentes(agregados: dict, arch_captura: set) -> dict:
    """Une, entre fuentes distintas, los conductos del mismo flujo (D46, M2c).

    Identidad entre fuentes = (extremos y marca bidireccional, puerto, l4); el protocolo de aplicacion no entra
    porque cada fuente lo nombra distinto (HTTPS / TLS / TLS 1.2). Un l4 vacio (exportacion sin transporte) casa
    con el unico l4 conocido del grupo; con tcp y udp conocidos en el mismo puerto no se une (ambiguo).
    Dentro de una sola fuente no se une nada: la clave no cambia."""
    claves = list(agregados)
    padre = list(range(len(claves)))

    def raiz(i):
        while padre[i] != i:
            padre[i] = padre[padre[i]]
            i = padre[i]
        return i

    fuentes_de = [{nom for nom, _a in agregados[c]["_f"]} for c in claves]
    grupos: dict = {}
    for i, c in enumerate(claves):
        grupos.setdefault(c[:-3] + (c[-2],), []).append(i)
    for idx in grupos.values():
        conocidos = {claves[i][-3] for i in idx if claves[i][-3]}
        for ai, i in enumerate(idx):
            for j in idx[ai + 1:]:
                li, lj = claves[i][-3], claves[j][-3]
                if li and lj:
                    ok = li == lj
                else:
                    ok = len(conocidos) <= 1
                if ok and any(a != b for a in fuentes_de[i] for b in fuentes_de[j]):
                    padre[raiz(i)] = raiz(j)
    comps: dict = {}
    for i in range(len(claves)):
        comps.setdefault(raiz(i), []).append(i)
    out: dict = {}
    for miembros in comps.values():
        ks = [agregados[claves[i]] for i in miembros]
        if len(ks) == 1:
            k = ks[0]
            k["protocolos"] = [k["servicio"]]
            out[claves[miembros[0]]] = k
            continue

        def rango(i):
            k = agregados[claves[i]]
            return (all(a not in arch_captura for _n, a in k["_f"]), len(k["servicio"]), k["servicio"])
        base = max(miembros, key=rango)
        k = dict(agregados[claves[base]])
        k["l4"] = next((agregados[claves[i]]["l4"] for i in miembros if agregados[claves[i]]["l4"]), "")
        k["protocolos"] = sorted({agregados[claves[i]]["servicio"] for i in miembros})
        f: dict = {}
        for i in miembros:
            for llave, ac in agregados[claves[i]]["_f"].items():
                dest = f.setdefault(llave, {})
                for fe, c in ac.items():
                    m = dest.setdefault(fe, [0, 0, 0])
                    m[0] += c[0]
                    m[1] += c[1]
                    m[2] += c[2]
        k["_f"] = f
        out[claves[min(miembros)]] = k
    return out


def _unir_fuentes(por_archivo: dict) -> dict:
    """{fecha: [paquetes, bytes, n]} de un conducto a partir de {(fuente, archivo): {fecha: celda}}.

    Dentro de un archivo las filas se suman. Entre archivos (de la misma fuente o de otra) se toma, por fecha,
    el maximo (D46): cada archivo es una vista del mismo trafico y un flujo entre dos rangos exportados
    ("X to any" y "Y to any") aparece en los dos; sumarlos lo duplicaba. Un archivo sin fecha se compara por
    su total: el conducto vale el mayor entre la suma de los maximos por fecha y el total sin fecha."""
    if len(por_archivo) == 1:
        return next(iter(por_archivo.values()))
    out: dict = {}
    sin_fecha = [0, 0, 0]
    for ac in por_archivo.values():
        for fe, c in ac.items():
            if not fe:
                sin_fecha = [max(a, b) for a, b in zip(sin_fecha, c)]
                continue
            m = out.get(fe)
            if m is None:
                out[fe] = list(c)
            else:
                m[0], m[1], m[2] = max(m[0], c[0]), max(m[1], c[1]), max(m[2], c[2])
    if any(sin_fecha):
        suma = [sum(c[i] for c in out.values()) for i in range(3)]
        resto = [max(0, u - t) for u, t in zip(sin_fecha, suma)]
        if any(resto):
            out[""] = resto
    return out


def cargar_mapeo(path: str | Path) -> dict:
    try:
        d = json_entrada.cargar(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"[!] No pude leer el mapeo '{path}': {e}")
    if not isinstance(d, dict) or not set(d) <= {"activos", "enlaces", "manual"}:
        raise SystemExit("[!] El mapeo debe ser un objeto con las claves 'activos', 'enlaces' y/o 'manual'.")
    return d
