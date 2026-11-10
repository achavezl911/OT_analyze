"""F5a: inventario de lo que cruza el firewall (D44).

Toma los conductos que cruzan (resultado distinto de `no_cruza`) y los agrega por par de interfaces y servicio.
Las etiquetas son marcas para la revision del analista, no juicios ni cumplimiento. Funciones puras.
"""
from __future__ import annotations

import ipaddress

from ..acceso_remoto import puertos_verificados
from ..catalog import OT_PORTS
from ..i18n import t
from ..util import port_info

COL_DETALLE = ["interfaz_origen", "interfaz_destino", "ip_origen", "ip_destino", "nombre_origen", "nombre_destino",
               "ambito_destino", "protocolo_l4", "puerto", "protocolo_aplicacion", "conductos", "bytes",
               "regla_actual", "resultado", "l4_inferido", "etiquetas"]
COL_AGREGADO = ["interfaz_origen", "interfaz_destino", "protocolo_l4", "puerto", "protocolo_aplicacion",
                "origenes", "destinos", "ejemplos_origen", "ejemplos_destino", "conductos", "bytes",
                "permitidos", "denegados", "reglas_actuales", "destino_internet", "etiquetas"]
COL_NAT = ["ip_origen_real", "ip_destino_real", "nat_regla", "nat_sentido"]    # D70, al final y solo con NAT
HOJA_DETALLE = "Cruces del firewall (detalle)"
HOJA_AGREGADO = "Cruces del firewall"
TITULO = "Trafico que cruza el firewall"
NOTA = ("Las etiquetas son marcas para la revision, no juicios: indican donde mirar primero al decidir que se "
        "permite. El inventario sale del trafico observado en la ventana de captura o de la exportacion.")

ACCESO_REMOTO = "acceso remoto"
ADMIN = "administracion"
ARCHIVOS = "compartir archivos"
CLARO = "texto claro"
OT = "protocolo OT"
HACIA_NET = "hacia Internet"
DESDE_NET = "desde Internet"
DNS_EXT = "DNS externo"
MUCHOS_O = "muchos origenes"
MUCHOS_D = "muchos destinos"
DENEGADO = "denegado observado"
ALTO = "puerto alto"
ETIQUETAS = [ACCESO_REMOTO, ADMIN, ARCHIVOS, CLARO, OT, HACIA_NET, DESDE_NET, DNS_EXT, MUCHOS_O, MUCHOS_D,
             DENEGADO, ALTO]

UMBRAL_MUCHOS = 50
MAX_EJEMPLOS = 5
_REMOTO = {22, 23, 3389, 3391, 5900, 5901, 5902, 5903, 5938} | puertos_verificados()     # T8: catalogo
_ADMIN = {161, 162}
_ADMIN_WEB = {443, 8443}
_ARCHIVOS = {139, 445, 2049, 21}
_CLARO = {21, 23, 80, 110, 143, 161, 389, 513, 514, 1883, 502}
_TIPOS_RED = ("red", "firewall")
_SIN_APP = ("", "-", "tcp", "udp", "data")


def _global(x) -> bool:
    try:
        ip = ipaddress.ip_address(str(x).strip())
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


def _puerto(c):
    p = str(c.get("port") if c.get("port") is not None else "")
    return int(p) if p.isdigit() else None


def _orden_ip(x):
    try:
        ip = ipaddress.ip_address(x)
        return (0, ip.version, int(ip), "")
    except ValueError:
        return (1, 0, 0, str(x))


def etiquetas_de(puerto, l4: str, app: str, destino_ip, origen_ip, tipo_destino: str, denegado: bool) -> list:
    """Etiquetas de un conducto (tabla fija; ver D44)."""
    et = []
    if puerto in _REMOTO:
        et.append(ACCESO_REMOTO)
    if puerto in _ADMIN or (puerto in _ADMIN_WEB and tipo_destino in _TIPOS_RED):
        et.append(ADMIN)
    if puerto in _ARCHIVOS:
        et.append(ARCHIVOS)
    if puerto in _CLARO:
        et.append(CLARO)
    nombre, cat = port_info(str(puerto) if puerto is not None else "", l4 or "tcp")
    if puerto is not None and not cat:      # sin transporte: se busca el puerto en cualquiera
        cat = next((v[1] for (p, _l), v in OT_PORTS.items() if p == puerto and v[1] == "ot"), "")
    if cat == "ot":
        et.append(OT)
    if _global(destino_ip):
        et.append(HACIA_NET)
    if _global(origen_ip):
        et.append(DESDE_NET)
    if puerto == 53 and _global(destino_ip):
        et.append(DNS_EXT)
    if denegado:
        et.append(DENEGADO)
    if puerto is not None and puerto >= 1024 and not nombre and str(app or "").lower() in _SIN_APP:
        et.append(ALTO)
    return et


def _ordenar(et) -> list:
    return [e for e in ETIQUETAS if e in et]


def _indice_ips(assets: dict) -> dict:
    idx = {}
    for a in (assets or {}).values():
        for ip in a.get("ips") or ():
            idx.setdefault(ip, a)
    return idx


def construir(conductos: list, resultados: list, assets=None, ip_de=None) -> dict:
    """{'detalle': [...], 'agregado': [...], 'totales': {...}} con filas como dicts.

    `resultados[i]` es el contraste del conducto i (con if_origen / if_destino cuando cruza)."""
    ip_de = ip_de or (lambda x: x)
    idx = _indice_ips(assets)
    detalle: dict = {}
    no_cruza = 0
    for c, r in zip(conductos, resultados):
        if r["resultado"] == "no_cruza":
            no_cruza += 1
            continue
        s, d = str(ip_de(c.get("src"))), str(ip_de(c.get("dst")))
        nat = r.get("nat")                      # D70: IP reales con las que se evaluo
        sr, dr = (nat["s"], nat["d"]) if nat else (s, d)
        if r.get("sentido") == "invertido":     # D43: los cruces llevan el sentido real (quien inicia)
            s, d, sr, dr = d, s, dr, sr
        l4 = str(c.get("l4") or "").strip().lower()
        puerto = _puerto(c)
        servicio = str(c.get("servicio") or "")
        app = "" if servicio == "-" else servicio
        k = (r["if_origen"], r["if_destino"], s, d, l4, puerto, app, sr if nat else "", dr if nat else "",
             nat["regla"] if nat else "", nat["lado"] if nat else "")
        g = detalle.get(k)
        if g is None:
            a_s, a_d = idx.get(sr, {}), idx.get(dr, {})
            ns, nd = ((c.get("dst_nombre"), c.get("src_nombre")) if r.get("sentido") == "invertido"
                      else (c.get("src_nombre"), c.get("dst_nombre")))
            if nat:         # el nombre de la plataforma es el de la IP observada: se resuelve con la real
                ns, nd = (ns if sr == s else ""), (nd if dr == d else "")
            n_s = ns or a_s.get("nombre") or ""
            n_d = nd or a_d.get("nombre") or ""
            g = detalle[k] = {
                "nombre_origen": "" if n_s == s else n_s, "nombre_destino": "" if n_d == d else n_d,
                "tipo_destino": a_d.get("tipo", ""), "conductos": 0, "bytes": 0, "r": r,
                "fuentes": set()}
        g["fuentes"].update(c.get("fuentes") or ())
        g["conductos"] += 1
        g["bytes"] += int(c.get("bytes") or 0)
    filas = []
    for k in sorted(detalle, key=lambda k: (k[0], k[1], _orden_ip(k[2]), _orden_ip(k[3]), k[4],
                                            -1 if k[5] is None else k[5], k[6])):
        ifo, ifd, s, d, l4, puerto, app, sr, dr, nregla, nlado = k
        g = detalle[k]
        r = g["r"]
        res = r["resultado"]
        regla = (r["regla"] + (" " + r["regla_nombre"] if r.get("regla_nombre") else "")).strip()
        filas.append({
            "interfaz_origen": ifo, "interfaz_destino": ifd, "ip_origen": s, "ip_destino": d,
            "nombre_origen": g["nombre_origen"], "nombre_destino": g["nombre_destino"],
            "ambito_destino": "Internet" if _global(dr or d) else "interna", "protocolo_l4": l4,
            "puerto": "" if puerto is None else puerto, "protocolo_aplicacion": app,
            "conductos": g["conductos"], "bytes": g["bytes"] or "", "regla_actual": regla, "resultado": res,
            "l4_inferido": bool(r.get("l4_inferido")), "camino": r.get("camino"),
            "fuentes": sorted(g["fuentes"]),
            "orden_verificado": r.get("orden_verificado", True),
            "ip_origen_real": sr, "ip_destino_real": dr, "nat_regla": nregla, "nat_sentido": nlado,
            "etiquetas": _ordenar(etiquetas_de(puerto, l4, app, dr or d, sr or s, g["tipo_destino"],
                                               res == "denegado_observado"))})
    grupos: dict = {}
    for f in filas:
        grupos.setdefault((f["interfaz_origen"], f["interfaz_destino"], f["protocolo_l4"], f["puerto"],
                           f["protocolo_aplicacion"]), []).append(f)
    agregado = []
    for k, fs in grupos.items():
        origenes = {f["ip_origen"]: f["nombre_origen"] for f in fs}
        destinos = {f["ip_destino"]: f["nombre_destino"] for f in fs}
        et = {e for f in fs for e in f["etiquetas"]}
        if len(origenes) >= UMBRAL_MUCHOS:
            et.add(MUCHOS_O)
        if len(destinos) >= UMBRAL_MUCHOS:
            et.add(MUCHOS_D)
        reglas = sorted({f["regla_actual"] for f in fs if f["regla_actual"]})
        by = sum(f["bytes"] for f in fs if f["bytes"] != "")
        agregado.append({
            "interfaz_origen": k[0], "interfaz_destino": k[1], "protocolo_l4": k[2], "puerto": k[3],
            "protocolo_aplicacion": k[4], "origenes": len(origenes), "destinos": len(destinos),
            "ejemplos_origen": _ejemplos(origenes), "ejemplos_destino": _ejemplos(destinos),
            "conductos": sum(f["conductos"] for f in fs), "bytes": by or "",
            "permitidos": sum(f["conductos"] for f in fs if f["resultado"] == "permitido"),
            "denegados": sum(f["conductos"] for f in fs if f["resultado"] == "denegado_observado"),
            "reglas_actuales": "; ".join(reglas[:MAX_EJEMPLOS]),
            "destino_internet": len({f["ip_destino_real"] or f["ip_destino"] for f in fs
                                     if f["ambito_destino"] == "Internet"}),
            "fuentes": sorted({x for f in fs for x in f["fuentes"]}),
            "etiquetas": _ordenar(et)})
    agregado.sort(key=lambda a: (a["interfaz_origen"], a["interfaz_destino"], -a["conductos"],
                                 str(a["protocolo_l4"]), -1 if a["puerto"] == "" else a["puerto"],
                                 a["protocolo_aplicacion"]))
    pares = {(a["interfaz_origen"], a["interfaz_destino"]) for a in agregado}
    internet = {f["ip_destino"] for f in filas if f["ambito_destino"] == "Internet"}
    return {"detalle": filas, "agregado": agregado, "con_nat": any(f["nat_regla"] for f in filas),
            "con_fuentes": any(c.get("fuentes") for c in conductos),
            "totales": {"pares_interfaces": len(pares), "filas_agregadas": len(agregado),
                        "conductos_cruzan": sum(f["conductos"] for f in filas), "no_cruza": no_cruza,
                        "destinos_internet": len(internet)}}


def _ejemplos(d: dict) -> str:
    ips = sorted(d, key=_orden_ip)[:MAX_EJEMPLOS]
    return "; ".join(f"{ip} ({d[ip]})" if d[ip] else ip for ip in ips)


def _txt_et(et: list) -> str:
    return "; ".join(t(e) for e in et)


def _bool(v) -> str:
    return t("si") if v else t("no")


def texto_camino(camino: list, verificado: bool = True) -> str:
    """'FW1 (a -> b) > FW2 (c -> d)'; con el orden sin verificar lo dice al final."""
    txt = " > ".join(f"{x['fw']} ({x['interfaz_entrada']} -> {x['interfaz_salida']})" for x in camino)
    return txt if verificado else txt + " [" + t("orden no verificado") + "]"


def columnas_detalle(cr: dict) -> list:
    cab = COL_DETALLE + ["camino"] if cr.get("multiple") else COL_DETALLE
    cab = cab + ["fuentes"] if cr.get("con_fuentes") else cab
    return cab + COL_NAT if cr.get("con_nat") else cab


def columnas_agregado(cr: dict) -> list:
    cab = ["firewall"] + COL_AGREGADO if cr.get("multiple") else COL_AGREGADO
    return cab + ["fuentes"] if cr.get("con_fuentes") else cab


def filas_detalle(cr: dict) -> list:
    filas = [[x["interfaz_origen"], x["interfaz_destino"], x["ip_origen"], x["ip_destino"], x["nombre_origen"],
              x["nombre_destino"], t(x["ambito_destino"]), x["protocolo_l4"], x["puerto"],
              x["protocolo_aplicacion"], x["conductos"], x["bytes"], x["regla_actual"], t(x["resultado"]),
              _bool(x["l4_inferido"]), _txt_et(x["etiquetas"])] for x in cr["detalle"]]
    if cr.get("multiple"):
        for f, x in zip(filas, cr["detalle"]):
            f.append(texto_camino(x["camino"] or [], x["orden_verificado"]))
    if cr.get("con_fuentes"):
        for f, x in zip(filas, cr["detalle"]):
            f.append("; ".join(x["fuentes"]))
    if cr.get("con_nat"):
        for f, x in zip(filas, cr["detalle"]):
            f.extend([x["ip_origen_real"], x["ip_destino_real"], x["nat_regla"], x["nat_sentido"]])
    return filas


def filas_agregado(cr: dict) -> list:
    filas = _filas_agregado(cr)
    if cr.get("multiple"):
        filas = [[x["firewall"]] + f for f, x in zip(filas, cr["agregado"])]
    if cr.get("con_fuentes"):
        for f, x in zip(filas, cr["agregado"]):
            f.append("; ".join(x["fuentes"]))
    return filas


def _filas_agregado(cr: dict) -> list:
    return [[x["interfaz_origen"], x["interfaz_destino"], x["protocolo_l4"], x["puerto"],
             x["protocolo_aplicacion"], x["origenes"], x["destinos"], x["ejemplos_origen"],
             x["ejemplos_destino"], x["conductos"], x["bytes"], x["permitidos"], x["denegados"],
             x["reglas_actuales"], x["destino_internet"], _txt_et(x["etiquetas"])] for x in cr["agregado"]]


def resumen_texto(cr: dict) -> str:
    v = cr["totales"]
    return t("{c} conductos cruzan el firewall en {p} pares de interfaces ({f} filas agregadas); {n} no cruzan; "
             "destinos en Internet: {i}. Detalle en firewall_cruces.csv y firewall_cruces_detalle.csv.",
             c=v["conductos_cruzan"], p=v["pares_interfaces"], f=v["filas_agregadas"], n=v["no_cruza"],
             i=v["destinos_internet"])


def cabecera_pares() -> list:
    return [t("Interfaz de origen"), t("Interfaz de destino"), t("Conductos"), t("Servicios")]


def pares_top(cr: dict, n: int = 15) -> list:
    """Los n pares de interfaces con mas conductos: filas [origen, destino, conductos, servicios]."""
    acum: dict = {}
    for a in cr["agregado"]:
        fw = (a["firewall"] + ": ") if cr.get("multiple") else ""
        p = acum.setdefault((fw + a["interfaz_origen"], a["interfaz_destino"]), [0, 0])
        p[0] += a["conductos"]
        p[1] += 1
    orden = sorted(acum, key=lambda k: (-acum[k][0], k))[:n]
    return [[k[0], k[1], acum[k][0], acum[k][1]] for k in orden]


def hay(fw: dict) -> bool:
    cr = (fw or {}).get("cruces")
    return bool(cr and cr["totales"]["conductos_cruzan"])
