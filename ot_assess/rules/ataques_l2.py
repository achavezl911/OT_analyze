"""Reglas de ataques de capa 2 y bucles vistos en una captura pasiva (T10a, D72).

Los hallazgos son evidencia tecnica de una captura, no una conclusion: cada uno dice que se vio y que puede ser
tambien una configuracion legitima. La evidencia se recoge en detail/l2.py y bucles.py con memoria acotada.
"""
from __future__ import annotations

import datetime
import re

from ..bucles import ICMP11_RAFAGA, LAZO_TTL_PAQUETES, LAZO_TTL_VISTAS
from ..catalog import SWITCH_HINTS
from ..i18n import t, unir
from ..model import Capture
from .base import RULES, finding

# Inundacion de la tabla MAC: mas de MAC_NUEVAS_POR_VENTANA MAC de origen nuevas en VENTANA_S segundos, sin
# contar los primeros ARRANQUE_S segundos de la captura (ahi aparecen todos los equipos legitimos) y con al
# menos MAC_PCT_PEQUENOS de ellas con no mas de MAC_PAQUETES_MAX paquetes (una MAC falsa habla una vez).
MAC_NUEVAS_POR_VENTANA = 200
VENTANA_S = 10
ARRANQUE_S = 30
MAC_PAQUETES_MAX = 3
MAC_PCT_PEQUENOS = 0.8
# Mismo umbral que la regla de cambios de topologia STP (anomaly.stp).
STP_TC_MIN = 20
# Fabricantes de equipo de red que no estan en catalog.SWITCH_HINTS; sus RA no se tratan como de un equipo final.
ROUTER_FABRICANTES = ("fortinet", "palo alto", "juniper", "mikrotik", "ubiquiti", "aruba", "huawei", "extreme",
                      "netgear", "tp-link", "d-link", "check point", "sophos", "arista")
# Puertos UDP de descubrimiento sobre IPv6 que no prueban que la red use IPv6 (mDNS, LLMNR, DHCPv6, SSDP, WSD).
IPV6_RUIDO_UDP = frozenset({"5353", "5355", "546", "547", "1900", "3702"})
MAX_LINEAS = 10


def _iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _es_equipo_de_red(h: dict, con_rol: bool = True) -> bool:
    """Por fabricante o nombre; con `con_rol` tambien por el rol inferido (para quien habla STP ya es de red)."""
    vendor = (h.get("vendor") or "").lower()
    texto = " ".join(list(h.get("fingerprints", ())) + list(h.get("hostnames", ()))).lower()
    return ((con_rol and str(h.get("role", "")).startswith("Equipo de red"))
            or any(s in vendor or s in texto for s in SWITCH_HINTS + ROUTER_FABRICANTES))


def _vendor(cap: Capture, mac: str) -> str:
    return cap.hosts.get(mac, {}).get("vendor") or "?"


def _ips(cap: Capture, macs) -> list:
    out: set = set()
    for m in macs:
        out |= {i for i in cap.hosts.get(m, {}).get("ips", ()) if i}
    return sorted(out)


@RULES
def dhcp_no_autorizado(cap: Capture) -> None:
    servidores = cap.l2x.get("dhcp", {})
    if len(servidores) < 2:
        return
    clientes: set = set()
    lineas = []
    for srv in sorted(servidores)[:MAX_LINEAS]:
        e = servidores[srv]
        clientes |= set(e["clientes"])
        lineas.append(t("- servidor {srv} (MAC {macs}): {o} ofertas, {a} ACK, {c} clientes",
                        srv=srv, macs=", ".join(sorted(e["macs"])[:3]) or "?", o=e["ofertas"], a=e["acks"],
                        c=len(e["clientes"])))
    finding(
        cap, "Alta",
        "Mas de un servidor DHCP respondiendo en el segmento",
        unir("\n", lineas + [t("{n} servidores y {c} clientes distintos con respuesta DHCP (OFFER o ACK)",
                               n=len(servidores), c=len(clientes))]),
        "Un servidor DHCP que no es el del cliente (o un segundo servidor mal configurado) entrega a los equipos "
        "puerta de enlace y DNS propios: es una via de intercepcion del trafico de control y puede dejar "
        "equipos sin direccion valida. Dos servidores tambien pueden ser un par de respaldo legitimo; hay que "
        "confirmarlo con el cliente.",
        "Confirmar cual es el servidor autorizado; habilitar DHCP snooping en los switches con solo los puertos "
        "del servidor como confiables y, donde se pueda, direccionamiento estatico para los equipos de control.",
        categoria="Anomalia",
        activos=[servidores[s]["ip"] for s in servidores if servidores[s]["ip"]],
    )


@RULES
def cambio_raiz_stp(cap: Capture) -> None:
    cambios = {v: e for v, e in cap.l2x.get("stp_raiz", {}).items() if e["n_cambios"]}
    if not cambios:
        return
    lineas = []
    for vlan in sorted(cambios)[:MAX_LINEAS]:
        e = cambios[vlan]
        lineas.append(t("- VLAN {vlan}: raiz inicial {a}; {n} cambios; primero a {b} el {cuando} (trama {frame})",
                        vlan=vlan or t("sin etiqueta"), a=e["primera"], n=e["n_cambios"], b=e["cambios"][0][0],
                        cuando=_iso(e["cambios"][0][1]), frame=e["cambios"][0][2]))
    finding(
        cap, "Alta",
        "Cambio del puente raiz de STP durante la captura",
        unir("\n", lineas),
        "Si un equipo anuncia una prioridad mejor que la del puente raiz, toma la raiz y el trafico pasa por "
        "su puerto: puede interceptarse o interrumpirse, y la reconvergencia causa microcortes. Tambien ocurre "
        "legitimamente si falla o se reinicia el switch raiz.",
        "Fijar la raiz a proposito (prioridad baja en el switch elegido y secundaria en otro), activar Root Guard "
        "en los puertos que no deben recibir la raiz y BPDU Guard en los puertos de borde.",
        categoria="Anomalia",
    )


@RULES
def bpdu_equipo_final(cap: Capture) -> None:
    origen = cap.l2x.get("stp_origen", {})
    finales = []
    for mac in sorted(origen):
        h = cap.hosts.get(mac)
        if h and h["ips"] and not _es_equipo_de_red(h, con_rol=False):
            finales.append(mac)
    if not finales:
        return
    finding(
        cap, "Alta",
        "BPDU enviadas por un equipo que no es switch",
        unir("\n", (t("- {mac} ({vendor}): {n} BPDU; tambien origina trafico IP ({ips})", mac=m,
                      vendor=_vendor(cap, m), n=origen[m], ips=", ".join(_ips(cap, [m])[:3]))
                    for m in finales[:MAX_LINEAS])),
        "Un equipo final que habla STP puede ser un puente de software o un intento de convertirse en raiz "
        "para intercepcion o denegacion de servicio; tambien indica un puerto sin BPDU Guard. Un switch "
        "no reconocido por fabricante podria aparecer aqui por error del inventario.",
        "Confirmar que es el equipo (puerto de switch y dueno), activar BPDU Guard y Root Guard en el puerto "
        "y filtrar BPDU en los puertos de borde.",
        categoria="Anomalia",
        activos=_ips(cap, finales),
    )


@RULES
def salto_vlan(cap: Capture) -> None:
    dobles = cap.l2x.get("doble_vlan", {})
    dtp = cap.l2x.get("dtp", {})
    if not dobles and not dtp:
        return
    lineas = []
    for par in sorted(dobles)[:MAX_LINEAS]:
        e = dobles[par]
        lineas.append(t("- doble etiqueta 802.1Q {par}: {n} tramas desde {macs}", par=par, n=e["n"],
                        macs=", ".join(sorted(e["macs"])[:3]) or "?"))
    for mac in sorted(dtp)[:MAX_LINEAS]:
        lineas.append(t("- DTP desde {mac} ({vendor}): {n} tramas", mac=mac, vendor=_vendor(cap, mac), n=dtp[mac]))
    finding(
        cap, "Media",
        "Indicios de salto de VLAN (doble etiqueta o DTP)",
        unir("\n", lineas[:MAX_LINEAS]),
        "Un puerto de acceso que negocia troncal (DTP visible) o que envia tramas con doble etiqueta puede "
        "alcanzar VLAN a las que no pertenece y saltarse la segmentacion. La doble etiqueta tambien es normal "
        "en redes de proveedor (802.1ad) y en algunos anillos.",
        "Poner `switchport mode access` y `switchport nonegotiate` en los puertos de borde, no usar la VLAN "
        "nativa 1 en los troncales y cambiar la VLAN nativa por una sin uso.",
        categoria="Anomalia",
    )


@RULES
def ha_sin_autenticacion(cap: Capture) -> None:
    lineas = []
    activos: set = set()
    for clave in sorted(cap.l2x.get("ha", {})):
        e = cap.l2x["ha"][clave]
        motivos = []
        if e["auth"] - {"md5", "ah"}:
            motivos.append(t("autenticacion {auth}", auth=", ".join(sorted(e["auth"] - {"md5", "ah"}))))
        nuevo = sorted(ip for ip, p in e["equipos"].items() if p >= 255 and ip != e["primero"])
        if nuevo and len(e["equipos"]) > 1:
            motivos.append(t("prioridad 255 desde {ip}, que no fue el primero visto", ip=nuevo[0]))
        if not motivos:
            continue
        activos |= set(e["equipos"])
        lineas.append(t("- {proto} grupo {grupo}: {motivos}; {n} equipos ({ips})", proto=e["proto"],
                        grupo=e["grupo"], motivos="; ".join(motivos), n=len(e["equipos"]),
                        ips=", ".join(sorted(e["equipos"])[:4])))
    if not lineas:
        return
    finding(
        cap, "Media",
        "Redundancia de puerta de enlace (HSRP/VRRP) sin autenticacion",
        unir("\n", lineas[:MAX_LINEAS]),
        "Sin autenticacion, o con una clave en texto claro visible en la red, cualquier equipo puede anunciar "
        "prioridad maxima, volverse la puerta de enlace y desviar o interrumpir el trafico entre zonas. HSRPv1 "
        "solo define texto claro y VRRPv3 no define autenticacion.",
        "Usar autenticacion MD5 (o cadena de claves) en HSRP/VRRP donde la version lo permita, filtrar estos "
        "protocolos en los puertos de borde y limitar con ACL quien puede anunciarlos.",
        categoria="Anomalia",
        activos=sorted(activos),
    )


def _usa_ipv6(cap: Capture) -> bool:
    """True si hay flujos IPv6 que no son solo descubrimiento (TCP, o UDP fuera de IPV6_RUIDO_UDP)."""
    for f in cap.flows.values():
        if ":" not in f["src"] or ":" not in f["dst"]:
            continue
        if f["l4"] == "tcp" or (f["l4"] == "udp" and f["dport"] not in IPV6_RUIDO_UDP):
            return True
    return False


@RULES
def ra_no_esperado(cap: Capture) -> None:
    ras = cap.l2x.get("ra", {})
    if not ras:
        return
    usa = _usa_ipv6(cap)
    lineas = []
    for mac in sorted(ras):
        h = cap.hosts.get(mac)
        router = bool(h) and _es_equipo_de_red(h)
        if router and usa:
            continue
        e = ras[mac]
        motivo = t("no es un equipo de red") if not router else t("la red no usa IPv6 para nada mas")
        lineas.append(t("- {mac} ({vendor}, {ip6}): {n} Router Advertisement; {motivo}", mac=mac,
                        vendor=_vendor(cap, mac), ip6=e["ip"] or "?", n=e["n"], motivo=motivo))
    if not lineas:
        return
    finding(
        cap, "Media",
        "Anuncios de router IPv6 no esperados",
        unir("\n", lineas[:MAX_LINEAS]),
        "Un Router Advertisement falso hace que los equipos con IPv6 (activo por defecto en Windows) tomen al "
        "emisor como puerta de enlace o DNS y le envien su trafico, aunque la red de control sea solo IPv4. "
        "Tambien lo emiten equipos con comparticion de conexion o puentes mal configurados.",
        "Activar RA Guard en los puertos de acceso; si IPv6 no se usa, desactivarlo en los equipos y bloquear "
        "ICMPv6 tipo 134 en el segmento.",
        categoria="Anomalia",
        activos=_ips(cap, ras),
    )


def _ventana_de_macs(cap: Capture):
    """(cantidad, inicio) de la ventana con mas MAC de origen nuevas que cumple el patron de inundacion, o None."""
    t0 = cap.ventana[0] if cap.ventana else 0
    nuevas = sorted((h["first"], h["tx_pkts"] <= MAC_PAQUETES_MAX) for h in cap.hosts.values()
                    if h["tx_pkts"] and h["first"] and h["first"] >= t0 + ARRANQUE_S)
    if len(nuevas) < MAC_NUEVAS_POR_VENTANA:
        return None
    acumulado = [0]
    for _, pequena in nuevas:
        acumulado.append(acumulado[-1] + (1 if pequena else 0))
    j = 0
    mejor = None
    for i, (inicio, _) in enumerate(nuevas):
        while j < len(nuevas) and nuevas[j][0] < inicio + VENTANA_S:
            j += 1
        n = j - i
        if n >= MAC_NUEVAS_POR_VENTANA and (acumulado[j] - acumulado[i]) / n >= MAC_PCT_PEQUENOS:
            if mejor is None or n > mejor[0]:
                mejor = (n, inicio)
    return mejor


@RULES
def inundacion_mac(cap: Capture) -> None:
    v = _ventana_de_macs(cap)
    if v is None:
        return
    finding(
        cap, "Alta",
        "Posible inundacion de la tabla MAC del switch",
        t("{n} MAC de origen nuevas en {seg} s desde {cuando} (umbral {umbral}); la mayoria habla muy poco",
          n=v[0], seg=VENTANA_S, cuando=_iso(v[1]), umbral=MAC_NUEVAS_POR_VENTANA),
        "Llenar la tabla de direcciones MAC hace que el switch reenvie por todos sus puertos el trafico que "
        "no conoce: quien inunda puede ver el trafico de control de otros equipos. Un switch con la tabla "
        "llena tambien pierde rendimiento y puede descartar trafico legitimo.",
        "Activar port-security (maximo de MAC por puerto de acceso, con accion de apagado o restriccion) y "
        "storm-control; localizar el puerto de origen y revisar si es un equipo virtualizado con muchas MAC.",
        categoria="Anomalia",
    )


@RULES
def bucle_l2(cap: Capture) -> None:
    b = cap.l2x.get("bucle", {})
    lineas = []
    for ini, fin, maximo, _ in b.get("rachas", [])[:5]:
        lineas.append(t("- difusion o multicast sostenido: {max} paquetes/s como maximo, {seg} s desde {cuando}",
                        max=maximo, seg=fin - ini + 1, cuando=_iso(ini)))
    if b.get("ttl_n", 0) >= LAZO_TTL_PAQUETES:
        ej = b["ttl_ejemplos"][0]
        lineas.append(t("- {n} paquetes IP vistos con TTL decreciente al menos {v} veces, desde {cuando}; "
                        "por ejemplo {src} a {dst}, TTL de {a} a {z}", n=b["ttl_n"], v=LAZO_TTL_VISTAS,
                        cuando=_iso(b["ttl_primero"]), src=ej[0], dst=ej[1], a=ej[2], z=ej[3]))
    if b.get("i11_max", 0) >= ICMP11_RAFAGA:
        lineas.append(t("- rafaga de ICMP time exceeded: {max} en un segundo ({cuando}), {total} en total",
                        max=b["i11_max"], cuando=_iso(b["i11_en"]), total=b["i11_total"]))
    # Los duplicados y los TCN solo acompanan: por si solos ya tienen su regla (visibility.duplicados y
    # anomaly.stp) y juntos tambien salen de un SPAN duplicado o de un anillo que reconverge, sin bucle.
    if not lineas:
        return
    apoyo = []
    if cap.stp_tc > STP_TC_MIN:
        apoyo.append(t("- cambios de topologia STP: {n}", n=cap.stp_tc))
    m = re.fullmatch(r"[1-9]\d*", str(cap.info.get("Number of duplicate packets") or ""))
    if m:
        apoyo.append(t("- paquetes duplicados segun editcap: {n}", n=m.group(0)))
    finding(
        cap, "Alta",
        "Indicios de bucle de capa 2 o de enrutamiento",
        unir("\n", lineas + apoyo),
        "Un bucle multiplica las tramas hasta saturar enlaces y CPU de los switches y de los equipos de campo: "
        "provoca perdida de comunicacion con los controladores y microcortes. Los indicios son compatibles con "
        "un bucle, no lo prueban: una captura desde varios puntos puede ver el mismo paquete mas de una vez.",
        "Localizar el enlace redundante sin STP o el cable puesto por error, activar storm-control en los "
        "puertos de acceso y BPDU Guard en los de borde, y revisar las rutas que se anuncian entre si.",
        categoria="Desempeno",
    )
