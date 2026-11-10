"""T9 (D71): canales que evaden la inspeccion: DNS cifrado (DoH, DoQ), Tor, VPN, tuneles y proxies hacia Internet.

Evidencia tecnica, no un veredicto: un nombre, una IP o un puerto del catalogo (data/evasion.json, con estado
'verificado' o 'sin verificar' por entrada) indica que alguien intenta usar el canal; no prueba una sesion ni que
no este autorizada. Funciones puras sobre el modelo ya calculado: sin tshark, sin red y sin reglas. La lista de
relays Tor la aporta el usuario (--tor-relays): la herramienta nunca descarga nada (D1).
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
from pathlib import Path

from . import json_entrada
from .i18n import t
from .indicadores import (
    _METODO_SNI,
    M_DNS,
    M_EXPORT,
    M_HTTP,
    M_PUERTO,
    SIN_VERIFICAR,
    VERIFICADO,
    _Acum,
    _limpio,
    _mapas_captura,
    _pares_captura,
    _publica,
    ayudas_exportacion,
    coincide_dominio,
    destinos_de_muchos_puertos,
    puertos_por_destino,
)
from .periodicidad import iso

ARCHIVO = "evasion.csv"
COLUMNAS = ["activo", "ip", "tipo", "herramienta_o_servicio", "estado_indicador", "metodo", "indicador", "destino",
            "destino_ip", "ambito", "conductos", "bytes", "primera", "ultima", "fuente", "nota"]
DATOS = Path(__file__).resolve().parent / "data" / "evasion.json"

M_IP, M_RELAY, M_PROTOCOLO = "IP y puerto", "lista de relays Tor", "protocolo"
T_DOH, T_DOQ, T_TOR, T_VPN, T_TUNEL, T_PROXY, T_CANARIO = "doh", "doq", "tor", "vpn", "tunel", "proxy", "canario_doh"
TIPOS_DNS = (T_DOH, T_DOQ)
TIPOS_CANAL = (T_TOR, T_VPN, T_TUNEL, T_PROXY)
ETIQUETA = {T_DOH: "DoH", T_DOQ: "DoQ", T_TOR: "Tor", T_VPN: "VPN", T_TUNEL: "tunel", T_PROXY: "proxy",
            T_CANARIO: "canario DoH"}
PUERTO_DOH = "443"
MAX_BYTES_RELAYS = 50 * 1024 * 1024
MAX_RELAYS = 500000
DIAS_VIEJO = 7


def _cargar() -> dict:
    return json.loads(DATOS.read_text(encoding="utf-8"))


_DATOS = _cargar()
CATALOGO = _DATOS["entradas"]


def _norm_ip(ip) -> str:
    try:
        return ipaddress.ip_address(str(ip).strip()).compressed
    except ValueError:
        return ""


# IP publicadas de los resolvedores publicos conocidos (DoH por IP y 443): {ip normalizada: entrada}
IPS_RESOLVEDORES = {_norm_ip(ip): e for e in CATALOGO for ip in e["ips"]}
CANARIO = {"herramienta": "Canario de Firefox (use-application-dns.net)", "tipo": T_CANARIO, "estado": SIN_VERIFICAR,
           "dominios": [_DATOS["canario"]["dominio"]], "fuente": _DATOS["canario"]["fuente"]}
TOR_LISTA = {"herramienta": "Tor (relay de la lista)", "tipo": T_TOR, "estado": VERIFICADO,
             "fuente": "lista de relays aportada con --tor-relays"}


# --------------------------------------------------------------------------- #
# Catalogo
# --------------------------------------------------------------------------- #


def entrada_de_nombre(nombre: str):
    """Entrada cuyo dominio cubre el nombre (resolvedores DoH, VPN comerciales, canario), o None."""
    for e in [*CATALOGO, CANARIO]:
        if any(coincide_dominio(nombre, d) for d in e["dominios"]):
            return e
    return None


def entrada_de_puerto(puerto, l4: str = "", con_lista: bool = False):
    """Entrada que usa ese puerto y transporte, o None. Los puertos de Tor no cuentan si hay lista de relays.

    Sin transporte (exportaciones que no lo traen) basta el puerto, salvo DoQ: 853 sin transporte no se
    distingue de DoT (TCP/853, que cubre dns_dot) y no cuenta."""
    l4 = str(l4 or "").lower()
    try:
        p = int(puerto)
    except (TypeError, ValueError):
        return None
    for e in CATALOGO:
        if e.get("solo_sin_lista") and con_lista:
            continue
        if not l4 and e["tipo"] == T_DOQ:
            continue
        if any(x["puerto"] == p and (not l4 or x["l4"] == l4) for x in e["puertos"]):
            return e
    return None


def entrada_de_protocolo(proto):
    p = str(proto or "").strip().lower()
    if not p:
        return None
    for e in CATALOGO:
        if p in e.get("protocolos", ()):
            return e
    return None


# --------------------------------------------------------------------------- #
# Lista de relays Tor aportada por el usuario
# --------------------------------------------------------------------------- #


def _ip_de_texto(s) -> str:
    """IP de 'ip', 'ip:puerto' o '[ipv6]:puerto'; '' si no es una IP."""
    s = str(s or "").strip()
    if s.startswith("["):
        s = s[1:].split("]")[0]
    elif s.count(":") == 1:
        s = s.split(":")[0]
    return _norm_ip(s)


def _fecha(s):
    try:
        return datetime.date.fromisoformat(str(s or "").strip()[:10])
    except ValueError:
        return None


def cargar_relays(path, hoy=None) -> dict:
    """Lista de relays Tor de un archivo local: texto con una IP por linea o JSON de Onionoo (summary o details).

    Se detecta por contenido. SystemExit si no se puede leer o no trae ninguna IP. Devuelve
    {archivo, fecha, ips (frozenset), total, avisos, entrada}; `entrada` es lo que registra entorno.py.
    """
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES_RELAYS:
            raise SystemExit(f"[!] '{p.name}': la lista de relays pasa de {MAX_BYTES_RELAYS // (1 << 20)} MB")
        raw = p.read_bytes()
    except OSError as e:
        raise SystemExit(f"[!] No pude leer '{p.name}': {e.strerror or e}")
    ips: set = set()
    fecha = None
    if raw.lstrip(b"\xef\xbb\xbf \r\n\t")[:1] in (b"{", b"["):
        try:
            datos = json_entrada.cargar(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            raise SystemExit(f"[!] '{p.name}': JSON invalido")
        relays = datos.get("relays") if isinstance(datos, dict) else None
        if not isinstance(relays, list):
            raise SystemExit(f"[!] '{p.name}': no es un documento de Onionoo (falta 'relays')")
        fecha = _fecha(datos.get("relays_published"))
        for r in relays:
            if not isinstance(r, dict):
                continue
            for campo in ("a", "or_addresses"):
                v = r.get(campo)
                for x in (v if isinstance(v, list) else [v]):
                    ip = _ip_de_texto(x)
                    if ip:
                        ips.add(ip)
            if len(ips) > MAX_RELAYS:
                break
    else:
        for linea in raw.decode("utf-8-sig", errors="replace").splitlines():
            linea = linea.split("#")[0].strip()
            ip = _ip_de_texto(linea) if linea else ""
            if ip:
                ips.add(ip)
            if len(ips) > MAX_RELAYS:
                break
    if not ips:
        raise SystemExit(f"[!] '{p.name}': sin direcciones IP reconocibles (se esperaba texto con una IP por "
                         "linea o JSON de Onionoo)")
    avisos = []
    if len(ips) > MAX_RELAYS:
        ips = set(sorted(ips)[:MAX_RELAYS])
        avisos.append(f"--tor-relays: la lista pasa de {MAX_RELAYS} direcciones; se usaron las primeras {MAX_RELAYS}")
    hoy = hoy or datetime.datetime.now(datetime.timezone.utc).date()
    if fecha is None:
        avisos.append("--tor-relays: la lista no trae fecha; los relays Tor cambian a diario y puede estar "
                      "desactualizada")
    elif (hoy - fecha).days > DIAS_VIEJO:
        avisos.append(f"--tor-relays: la lista es del {fecha.isoformat()} (mas de {DIAS_VIEJO} dias); los relays Tor "
                      "cambian a diario y puede estar desactualizada")
    return {"archivo": p.name, "fecha": fecha.isoformat() if fecha else "", "ips": frozenset(ips),
            "total": len(ips), "avisos": avisos,
            "entrada": {"archivo": p.name, "sha256": hashlib.sha256(raw).hexdigest(), "tamano": len(raw)}}


def preparar(args, hoy=None):
    """Lista de relays segun --tor-relays (o None). Imprime los avisos y deja args.tor_entrada para entorno.py."""
    ruta = getattr(args, "tor_relays", None)
    args.tor_entrada = None
    if not ruta:
        return None
    r = cargar_relays(ruta, hoy)
    args.tor_entrada = r["entrada"]
    for adv in r["avisos"]:
        print(f"[!] {adv}")
    return r


# --------------------------------------------------------------------------- #
# Capturas
# --------------------------------------------------------------------------- #


def de_captura(cap, relays=None, muchos=None) -> list:
    """Indicadores de una captura: nombres (DNS, SNI, Host), IP de resolvedores, relays Tor, puertos y protocolos.

    `relays`: resultado de cargar_relays o None. `muchos`: destinos de muchos puertos de toda la entrada; si
    falta, se calcula con esta captura sola. Los puertos y protocolos solo cuentan hacia IP publicas."""
    nivel_de, nombre_de = _mapas_captura(cap)
    if muchos is None:
        muchos = destinos_de_muchos_puertos(puertos_por_destino(_pares_captura(cap)))
    ac = _Acum(cap.name, nivel_de, nombre_de, muchos)
    flows = list(getattr(cap, "flows", {}).values())
    por_par: dict = {}
    for f in flows:
        por_par.setdefault((f["src"], f["dst"]), []).append(f)

    def par(src, dst):
        fs = por_par.get((src, dst), [])
        return ({(f["dst"], f["dport"], f["l4"]) for f in fs}, sum(f["bytes"] for f in fs))

    resueltos: dict = {}
    for e in cap.dns_eventos:
        if e["resp"] and e["rcode"] in ("", "NOERROR"):
            for _dueno, tipo, valor, _ttl in e["respuestas"]:
                if tipo in ("A", "AAAA") and valor:
                    resueltos.setdefault((e["dst"], e["nombre"]), set()).add(valor)
    for e in cap.dns_eventos:
        h = None if e["resp"] else entrada_de_nombre(e["nombre"])
        if h is None or not e["src"]:
            continue
        ips = resueltos.get((e["src"], e["nombre"]), set())
        cond = set()
        for ip in ips:
            cond |= par(e["src"], ip)[0]
        ac.sumar(e["src"], h, M_DNS, e["nombre"], ips, cond, 0, iso(e["t"]) if e["t"] else "",
                 iso(e["t"]) if e["t"] else "")
    for n in cap.nombres_servidor:
        h = entrada_de_nombre(n["nombre"])
        if h is None or not n.get("src"):
            continue
        cond, nb = par(n["src"], n["ip"])
        ac.sumar(n["src"], h, _METODO_SNI.get(n["fuente"], M_HTTP), n["nombre"], [n["ip"]], cond, nb,
                 iso(n["t"]) if n.get("t") else "", iso(n["t"]) if n.get("t") else "")
    for f in flows:
        dst, l4, dport = f["dst"], f["l4"], f["dport"]
        cond = [(dst, dport, l4)]
        t0 = iso(f["first"]) if f["first"] else ""
        t1 = iso(f["last"]) if f["last"] else ""
        norm = _norm_ip(dst)
        res = IPS_RESOLVEDORES.get(norm)
        if res is not None and dport == PUERTO_DOH and l4 in ("tcp", "udp"):
            ac.sumar(f["src"], res, M_IP, f"{l4}/{dport} hacia {dst}", [dst], cond, f["bytes"], t0, t1, True)
        if relays is not None and norm in relays["ips"]:
            ac.sumar(f["src"], TOR_LISTA, M_RELAY, dst, [dst], cond, f["bytes"], t0, t1, True)
        if not _publica(dst):
            continue
        h = entrada_de_puerto(dport, l4, relays is not None) if l4 else entrada_de_protocolo(f["proto"])
        if h is None:
            continue
        if l4:
            ac.sumar(f["src"], h, M_PUERTO, f"{l4}/{dport}", [dst], cond, f["bytes"], t0, t1)
        else:
            ac.sumar(f["src"], h, M_PROTOCOLO, str(f["proto"]).upper(), [dst], cond, f["bytes"], t0, t1)
    return ac.lista()


# --------------------------------------------------------------------------- #
# Exportaciones de plataformas (camino diagrama)
# --------------------------------------------------------------------------- #


def de_exportacion(fuente: str, dominios: list, conductos: list, assets: dict, relays=None) -> list:
    """Indicadores de una exportacion. `dominios`: [{cliente, servidor, dominio, bytes, fecha}] con ids de activo."""
    ip_de, nivel_de, nombre_de, externo = ayudas_exportacion(assets)
    muchos = destinos_de_muchos_puertos(puertos_por_destino((ip_de(c["dst"]), c.get("port")) for c in conductos))
    ac = _Acum(fuente, nivel_de, nombre_de, muchos)
    for d in dominios:
        h = entrada_de_nombre(d["dominio"])
        if h is None:
            continue
        srv = ip_de(d["servidor"])
        ac.sumar(ip_de(d["cliente"]), h, M_EXPORT, _limpio(d["dominio"]), [srv], [(srv, "", "")],
                 d.get("bytes", 0), d.get("fecha", ""), d.get("fecha", ""), externo(d["servidor"]))
    for c in conductos:
        srv = ip_de(c["dst"])
        l4 = str(c.get("l4") or "").lower()
        port = str(c.get("port") or "")
        ext = externo(c["dst"])
        cli, nb = ip_de(c["src"]), c.get("bytes", 0)
        t0, t1 = c.get("primera", ""), c.get("ultima", "")
        cond = [(srv, port, l4)]
        norm = _norm_ip(srv)
        res = IPS_RESOLVEDORES.get(norm)
        if res is not None and port == PUERTO_DOH and l4 in ("tcp", "udp", ""):
            ac.sumar(cli, res, M_IP, f"{l4}/{port} hacia {srv}" if l4 else f"{port} hacia {srv}", [srv], cond, nb,
                     t0, t1, True)
        if relays is not None and norm in relays["ips"]:
            ac.sumar(cli, TOR_LISTA, M_RELAY, srv, [srv], cond, nb, t0, t1, True)
        if not (ext or _publica(srv)):
            continue
        proto = l4 if l4 in ("gre", "esp") else str(c.get("servicio") or "").lower()
        if port:
            h = entrada_de_puerto(port, l4, relays is not None)
            if h is not None:
                ac.sumar(cli, h, M_PUERTO, f"{l4}/{port}" if l4 else port, [srv], cond, nb, t0, t1, ext)
        else:
            h = entrada_de_protocolo(proto)
            if h is not None:
                ac.sumar(cli, h, M_PROTOCOLO, proto.upper(), [srv], cond, nb, t0, t1, ext)
    return ac.lista()


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def indicadores(res) -> list:
    """Indicadores de todas las capturas del analisis mas los de la exportacion (res.evasion)."""
    out = []
    caps = [c for c in getattr(res, "caps", ()) if not getattr(c, "error", "")]
    muchos = destinos_de_muchos_puertos(puertos_por_destino(p for c in caps for p in _pares_captura(c)))
    relays = getattr(res, "tor_relays", None)
    for cap in caps:
        out += de_captura(cap, relays, muchos)
    return out + list(getattr(res, "evasion", None) or [])


def hay(res) -> bool:
    return bool(indicadores(res))


def fila(x: dict) -> list:
    return [x["activo"], x["ip"], x["tipo"], x["herramienta"], t(x["estado"]), t(x["metodo"]), x["indicador"],
            t(x["destino"]), x["destino_ip"], t(x["ambito"]), x["conductos"], x["bytes"], x["primera"], x["ultima"],
            x["fuente"], x.get("nota", "")]


def filas(res) -> list:
    return [fila(x) for x in indicadores(res)]
