"""G1b (D88): direccionamiento IP observado por sitio.

Redes (prefijos) con su origen (perfil, interfaces del firewall, SVI del switch o /24 inferido), cuantas IP se usaron,
en que zonas y VLAN estan, que tipos de equipo (T1b) tienen y observaciones para validar con el cliente. Solo cuenta lo
observado: el uso es un minimo. No lee mas configuracion de la que ya lee la corrida, no genera hallazgos y nunca
concluye cumplimiento. Solo lee el modelo ya calculado (zonas, switches, inventario normalizado).
"""
from __future__ import annotations

import collections
import ipaddress

from . import hardening as _hd
from .i18n import t
from .zonas import _global, _ip, _red24, mostrar_zona

TITULO = "Direccionamiento IP observado"
HOJA = "Direccionamiento IP"
ARCHIVO = "direccionamiento_ip.csv"
COLUMNAS = ["red", "origen_prefijo", "vlan", "zonas", "activos", "primera_ip", "ultima_ip", "hosts_utiles",
            "uso_pct", "tipos", "puerta_enlace", "observaciones", "estado_revision", "revisado_por", "fecha",
            "comentario"]
CAB_SECCION = ["Red", "Origen del prefijo", "VLAN", "Zonas", "Activos", "Uso (%)", "Tipos", "Puerta de enlace",
               "Observaciones"]
CAB_OBS = ["Observacion", "Redes"]
MAX_REDES = 30
MAX_TIPOS = 3
USO_ALTO = 80.0
USO_ALTO_MIN_HOSTS = 6
PREFIJO_HOST = 31      # /31 y /32: rutas de host, no definen una red

O_PERFIL, O_FIREWALL, O_SWITCH, O_INFERIDA = "perfil", "firewall", "switch", "inferida /24"
PRIORIDAD = (O_PERFIL, O_FIREWALL, O_SWITCH)

OBS_SIN_ACTIVOS = "red declarada sin activos observados (verificar cobertura de la captura)"
OBS_FUERA = "IP fuera de las redes declaradas"
OBS_ZONAS = "subred en varias zonas (verificar la frontera)"
OBS_PUBLICO = "rango publico usado como red interna (verificar si es propio)"
OBS_USO_ALTO = "uso alto del rango"
ORDEN_OBS = (OBS_SIN_ACTIVOS, OBS_FUERA, OBS_ZONAS, OBS_PUBLICO, OBS_USO_ALTO)

TIPOS_CORTOS = {"controlador": "controlador", "estacion": "estacion de trabajo", "servidor": "servidor",
                "red": "equipo de red", "seguridad": "equipo de seguridad", "otro": "otro"}

PRIVADAS = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                              "169.254.0.0/16", "127.0.0.0/8")]

NOTA = ("Direccionamiento segun lo observado: cada prefijo viene del perfil del proyecto, de las rutas por interfaz "
        "del firewall, de una interfaz VLAN (SVI) de un switch o, si ninguno lo declara, se infiere el /24 de la IP "
        "observada (hay que validarlo con el cliente). El uso es un minimo: solo cuenta los activos vistos en la "
        "corrida, no las IP asignadas; una red sin activos puede deberse a la cobertura de la captura. Las IP de la zona "
        "Internet, las publicas sin prefijo declarado y las IPv6 no entran a la tabla y se cuentan en el resumen; las "
        "rutas de host (/31 y /32) del firewall o de los switches sin activos observados no se listan. Las "
        "observaciones son puntos para validar con el cliente; no son hallazgos ni una determinacion de cumplimiento.")


def _privada_rfc(red) -> bool:
    return red.version == 4 and any(red.subnet_of(p) for p in PRIVADAS)


def _hosts_utiles(red) -> int:
    n = red.num_addresses
    return n if n <= 2 else n - 2


def _declarados(zonas: dict, switches: dict) -> dict:
    """{red: {'origenes': set, 'svis': [(vlan, ip)]}} solo IPv4 y sin ruta por defecto."""
    out: dict = {}

    def poner(red, origen, svi=None):
        if red.version != 4 or not red.prefixlen:
            return
        d = out.setdefault(red, {"origenes": set(), "svis": []})
        d["origenes"].add(origen)
        if svi:
            d["svis"].append(svi)
    declaradas, tablas_fw = (zonas or {}).get("tablas") or ([], [])
    for red, _z in declaradas:
        poner(red, O_PERFIL)
    for tabla in tablas_fw:
        for red, _z in tabla:
            poner(red, O_FIREWALL)
    for sw in (switches or {}).get("switches") or ():
        for s in sw.svis:
            if not s.mascara:
                continue
            try:
                red = ipaddress.ip_network(f"{s.ip}/{s.mascara}", strict=False)
            except ValueError:
                continue
            poner(red, O_SWITCH, (str(s.vlan), str(s.ip)))
    return out


def _entidades(assets: dict, inventario) -> list:
    """[(activo con la forma de `assets`, vlans)]: una por fila del inventario normalizado; sin el, por activo."""
    if inventario and inventario.get("filas"):
        por_id = _hd._activos_de_inventario(inventario["filas"])
        return [(por_id[f["id"]], _hd._conjunto(f, "vlan")) for f in inventario["filas"]]
    out = []
    for a in assets.values():
        v = {str(x) for x in (a.get("vlans") or ()) if str(x)}
        if str(a.get("vlan") or ""):
            v.add(str(a["vlan"]))
        out.append((a, v))
    return out


def _clave_ip(red) -> tuple:
    return (red.version, int(red.network_address), red.prefixlen)


def construir(assets: dict, zonas: dict | None = None, switches: dict | None = None, inventario=None,
              hallazgos=()) -> dict:
    """{'filas', 'totales'}; vacio si ningun activo trae una IP IPv4 privada. Las filas llevan claves, no texto."""
    entidades = _entidades(assets, inventario)
    if not entidades:
        return {}
    decl = _declarados(zonas, switches)
    origen_ip: dict = {}
    for a in assets.values():
        for ip in a["ips"]:
            origen_ip.setdefault(ip, a.get("origen_zona") or "")
    por_hallazgo = _hd.tipos_por_hallazgo(list(hallazgos))
    grupos: dict = collections.OrderedDict()      # red -> {'ips', 'activos': {indice}, 'zonas', 'tipos', 'vlans'}
    externas, ipv6, observadas = set(), set(), set()
    for i, (a, vlans) in enumerate(entidades):
        tipo = None
        for ip_txt in sorted(a["ips"]):
            ip = _ip(ip_txt)
            if ip is None or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local \
                    or ip.is_reserved:
                continue
            if ip.version != 4:
                ipv6.add(ip_txt)
                continue
            if origen_ip.get(ip_txt) == "internet":
                externas.add(ip_txt)
                continue
            cand = [r for r in decl if ip in r]
            if cand:
                red = max(cand, key=lambda r: (r.prefixlen, -min(PRIORIDAD.index(o) for o in decl[r]["origenes"])))
            elif _global(ip):
                externas.add(ip_txt)
                continue
            else:
                red = ipaddress.ip_network(_red24(ip_txt))
            if tipo is None:
                tipo = _hd.tipo_y_base(a, por_hallazgo)[0]
            g = grupos.setdefault(red, {"ips": set(), "activos": set(), "zonas": set(), "tipos": {}, "vlans": []})
            g["ips"].add(ip)
            observadas.add(ip_txt)
            g["activos"].add(i)
            g["zonas"].add((a.get("zona_asignada") or "", origen_ip.get(ip_txt) or a.get("origen_zona") or ""))
            g["tipos"][i] = tipo
            g["vlans"].append(vlans)
    hay_declarados = bool(decl)
    filas = []
    omitidas = 0
    for red in sorted(set(decl) | set(grupos), key=_clave_ip):
        d = decl.get(red)
        g = grupos.get(red) or {"ips": set(), "activos": set(), "zonas": set(), "tipos": {}, "vlans": []}
        origen = min(d["origenes"], key=PRIORIDAD.index) if d else O_INFERIDA
        svis = d["svis"] if d else []
        vlan = sorted({v for v, _ip_ in svis}, key=lambda x: (not x.isdigit(), int(x) if x.isdigit() else 0, x))
        if not vlan:
            todas = {v for vs in g["vlans"] for v in vs}
            vlan = sorted(todas) if len(todas) == 1 else []
        zonas_g = sorted({(z, o) for z, o in g["zonas"] if z})
        hosts = _hosts_utiles(red)
        n = len(g["activos"])
        if d and not n and O_PERFIL not in d["origenes"] and red.prefixlen >= PREFIJO_HOST:
            omitidas += 1       # ruta de host del firewall o del switch sin activos: no es una red del sitio
            continue
        uso = round(n * 100.0 / hosts, 1)
        cuenta = collections.Counter(g["tipos"].values())
        obs = []
        if d and not n:
            obs.append(OBS_SIN_ACTIVOS)
        if not d and hay_declarados:
            obs.append(OBS_FUERA)
        if len({z for z, _o in zonas_g}) > 1:
            obs.append(OBS_ZONAS)
        if d and not _privada_rfc(red):
            obs.append(OBS_PUBLICO)
        if uso >= USO_ALTO and hosts >= USO_ALTO_MIN_HOSTS:
            obs.append(OBS_USO_ALTO)
        filas.append({"red": str(red), "origen": origen, "vlan": vlan, "zonas": zonas_g, "activos": n,
                      "primera_ip": str(min(g["ips"])) if g["ips"] else "",
                      "ultima_ip": str(max(g["ips"])) if g["ips"] else "", "hosts_utiles": hosts, "uso_pct": uso,
                      "tipos": sorted(cuenta.items(), key=lambda x: (-x[1], x[0]))[:MAX_TIPOS],
                      "puerta": sorted({ip for _v, ip in svis}, key=lambda x: int(ipaddress.ip_address(x))),
                      "observaciones": obs})
    if not filas:
        return {}
    por_origen = collections.Counter(f["origen"] for f in filas)
    por_obs = collections.Counter(o for f in filas for o in f["observaciones"])
    return {"filas": filas,
            "totales": {"redes": len(filas), "por_origen": {o: por_origen.get(o, 0) for o in (*PRIORIDAD, O_INFERIDA)},
                        "ip_observadas": len(observadas), "ip_externas": len(externas), "ip_v6": len(ipv6), "rutas_host_omitidas": omitidas,
                        "por_observacion": {o: por_obs[o] for o in ORDEN_OBS if por_obs.get(o)}}}


# --------------------------------------------------------------------------- #
# Salidas
# --------------------------------------------------------------------------- #


def hay(dr: dict) -> bool:
    return bool(dr) and bool(dr.get("filas"))


def _tipos_texto(f: dict) -> str:
    return "; ".join(f"{t(TIPOS_CORTOS[c])} {n}" for c, n in f["tipos"])


def _zonas_texto(f: dict) -> str:
    return "; ".join(sorted({mostrar_zona(z, o) for z, o in f["zonas"]}))


def _obs_texto(f: dict) -> str:
    return "; ".join(t(o) for o in f["observaciones"])


def filas_tabla(dr: dict) -> list:
    return [[f["red"], t(f["origen"]), ";".join(f["vlan"]), _zonas_texto(f), f["activos"], f["primera_ip"],
             f["ultima_ip"], f["hosts_utiles"], f"{f['uso_pct']:.1f}", _tipos_texto(f), ";".join(f["puerta"]),
             _obs_texto(f), "", "", "", ""] for f in dr["filas"]]


def tablas(dr: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para el CSV y el XLSX."""
    if not hay(dr):
        return []
    return [(ARCHIVO, HOJA, COLUMNAS, filas_tabla(dr))]


def resumen_texto(dr: dict) -> str:
    x = dr["totales"]
    o = x["por_origen"]
    return t("{n} redes ({p} del perfil, {f} del firewall, {s} de switches, {i} inferidas /24), {a} IP observadas, "
             "{e} IP externas (fuera de la tabla) y {v} IPv6 (fuera de la tabla). Detalle en direccionamiento_ip.csv.",
             n=x["redes"], p=o[O_PERFIL], f=o[O_FIREWALL], s=o[O_SWITCH], i=o[O_INFERIDA], a=x["ip_observadas"],
             e=x["ip_externas"], v=x["ip_v6"]) + (
        " " + t("{h} rutas de host (/31 o /32) sin activos observados no se listan.", h=x["rutas_host_omitidas"])
        if x.get("rutas_host_omitidas") else "")


def seccion(dr: dict) -> dict:
    """Datos de la seccion de los reportes (todo traducido)."""
    orden = sorted(range(len(dr["filas"])), key=lambda i: (-dr["filas"][i]["activos"], i))[:MAX_REDES]
    filas = filas_tabla(dr)
    tabla = [[filas[i][0], filas[i][1], filas[i][2], filas[i][3], filas[i][4], filas[i][8], filas[i][9],
              filas[i][10], filas[i][11]] for i in orden]
    mas = len(dr["filas"]) - len(tabla)
    return {"titulo": t(TITULO), "nota": t(NOTA), "resumen": resumen_texto(dr),
            "cab_redes": [t(c) for c in CAB_SECCION], "redes": tabla,
            "mas": t("Se muestran {n} redes; {m} mas estan en direccionamiento_ip.csv.", n=len(tabla), m=mas)
            if mas > 0 else "",
            "cab_obs": [t(c) for c in CAB_OBS],
            "observaciones": [[t(o), n] for o, n in dr["totales"]["por_observacion"].items()]}


def para_json(dr: dict) -> dict:
    if not hay(dr):
        return {}
    return {"nota": t(NOTA), "totales": dr["totales"],
            "filas": [dict(zip(COLUMNAS[:12], fila), origen_clave=f["origen"], observaciones_clave=f["observaciones"])
                      for fila, f in zip(filas_tabla(dr), dr["filas"])]}
