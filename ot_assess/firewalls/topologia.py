"""M1: varios firewalls en cadena (D45): enlaces entre ellos, camino de cada conducto y coherencia.

Cada firewall se contrasta por separado (integracion.contrastar); aqui se unen los resultados:
- enlaces: una ruta de A cuyo salto es una IP de una interfaz de B, o interfaces de A y B en la misma red;
- camino de un conducto: los firewalls que lo cruzan (interfaz de entrada distinta de la de salida), en el
  orden que dan los enlaces;
- coherencia: marcas por conducto cuando las decisiones o las rutas de los firewalls no cuadran.
Supuesto: red en arbol o cadena, sin caminos alternos; con dos caminos posibles el resultado puede quedar
incompleto. Es evidencia pasiva sobre el modelo, no un motor de decision. Funciones puras.
"""
from __future__ import annotations

import collections
import ipaddress
import re

from ..i18n import Traducido, t
from . import cruces as _cr

RUTA = "ruta"
RED = "red compartida"
T_MIXTO = "permitido en uno y denegado en otro"
T_SALTO = "salto hacia un firewall que no cruza"
T_SIN_FW = "sin firewall en el camino"
TIPOS = [T_MIXTO, T_SALTO, T_SIN_FW]
COL_ENLACES = ["fw_a", "interfaz_a", "red", "fw_b", "interfaz_b", "ip_b", "descubierto_por"]
COL_FIREWALLS = ["firewall", "fabricante", "hostname", "interfaces", "reglas", "rutas"]
COL_COHERENCIA = ["ip_origen", "ip_destino", "protocolo_l4", "puerto", "camino", "marca"]
HOJA_ENLACES = "Topologia de firewalls"
HOJA_COHERENCIA = "Coherencia entre firewalls"
TITULO = "Firewalls"
NOTA = ("Los enlaces y el camino se infieren de las rutas e interfaces de cada firewall y suponen una red en "
        "cadena o arbol, sin caminos alternos; las marcas de coherencia indican donde revisar, no un error "
        "confirmado.")
_NO_ARCHIVO = re.compile(r"[^A-Za-z0-9._-]+")


def identificadores(fws: list, nombres: list) -> list:
    """Hostname; si falta o se repite, el nombre del archivo (y #n si aun se repite)."""
    cuenta = collections.Counter(f.hostname for f in fws if f.hostname)
    ids = [f.hostname if f.hostname and cuenta[f.hostname] == 1 else n for f, n in zip(fws, nombres)]
    total, vistos, out = collections.Counter(ids), collections.Counter(), []
    for i in ids:
        vistos[i] += 1
        out.append(f"{i}#{vistos[i]}" if total[i] > 1 else i)
    return out


def prefijo_archivo(ident: str) -> str:
    return _NO_ARCHIVO.sub("_", ident).strip("_") or "fw"


def _interfaces(fw) -> list:
    """[(nameif, IPv4Interface)] de las interfaces con IP y mascara."""
    out = []
    for i in fw.interfaces:
        if i.ip and i.mascara:
            try:
                out.append((i.nombre or i.fisica, ipaddress.IPv4Interface(f"{i.ip}/{i.mascara}")))
            except ValueError:
                continue
    return out


def enlaces(ids: list, fws: list) -> list:
    """Enlaces entre firewalls, ordenados; cada uno con a/b (indices) y como se descubrio."""
    redes = [_interfaces(f) for f in fws]
    por_ip: dict = {}
    for k, rs in enumerate(redes):
        for nombre, ifc in rs:
            por_ip.setdefault(str(ifc.ip), (k, nombre, ifc))
    hallados: dict = {}

    def alta(a, ia, b, ib, red, ip_b, via):
        if a > b:      # orientacion fija: el firewall de menor indice primero
            a, ia, b, ib = b, ib, a, ia
            ip_b = next((str(i.ip) for n, i in redes[b] if n == ib), "")
        e = hallados.setdefault((a, ia, b, ib), {"red": str(red), "ip_b": ip_b, "via": []})
        if via not in e["via"]:
            e["via"].append(via)

    for a, f in enumerate(fws):
        for r in f.rutas:
            if r.salto in por_ip:
                b, ib, ifc = por_ip[r.salto]
                if b != a:
                    alta(a, r.interfaz, b, ib, ifc.network, r.salto, RUTA)
    for a in range(len(fws)):
        for b in range(a + 1, len(fws)):
            for na, ia in redes[a]:
                for nb, ib in redes[b]:
                    if ia.network == ib.network and ia.network.prefixlen < 32:
                        alta(a, na, b, nb, ia.network, str(ib.ip), RED)
    return [{"a": a, "b": b, "fw_a": ids[a], "interfaz_a": ia, "red": e["red"], "fw_b": ids[b],
             "interfaz_b": ib, "ip_b": e["ip_b"],
             "descubierto_por": "; ".join(v for v in (RUTA, RED) if v in e["via"])}
            for (a, ia, b, ib), e in sorted(hallados.items())]


def _vecinos(enl: list) -> dict:
    v: dict = {}
    for e in enl:
        v.setdefault((e["a"], e["interfaz_a"]), set()).add(e["b"])
        v.setdefault((e["b"], e["interfaz_b"]), set()).add(e["a"])
    return v


def ordenar(miembros: list, vec: dict) -> tuple:
    """(miembros ordenados, verificado). miembros = [(k, if_entrada, if_salida)] en el orden de los argumentos.

    El primero es el que no recibe de otro firewall del camino; cada siguiente es el vecino de la salida del anterior."""
    if len(miembros) < 2:
        return miembros, True
    ks = {m[0] for m in miembros}
    inicio = [m for m in miembros if not vec.get((m[0], m[1]), set()) & (ks - {m[0]})]
    if len(inicio) != 1:
        return miembros, False
    por = {m[0]: m for m in miembros}
    orden = [inicio[0]]
    while len(orden) < len(miembros):
        sig = vec.get((orden[-1][0], orden[-1][2]), set()) & (ks - {m[0] for m in orden})
        if len(sig) != 1:
            return miembros, False
        orden.append(por[next(iter(sig))])
    return orden, True


def elegir_sentidos(dicts: list, n: int) -> list:
    """Sentido ('original' | 'invertido' | None) de cada conducto bidireccional, igual en todo el camino (D43).

    Se elige el primero que sea permitido en todos los firewalls que cruza; si ninguno, el original."""
    out = []
    for i in range(n):
        rs = [d["resultados"][i] for d in dicts if d["resultados"][i].get("sentidos")]
        if not rs:
            out.append(None)
            continue
        permitido = {s: all(r["sentidos"][s]["resultado"] == "permitido" for r in rs)
                     for s in ("original", "invertido")}
        out.append("invertido" if not permitido["original"] and permitido["invertido"] else "original")
    return out


def _unir_resultados(rs: list, ids_regla: list) -> dict:
    """Decision de extremo a extremo: cualquier denegado manda; luego sin regla; luego respuesta; si no, permitido."""
    if not rs:
        return {"resultado": "no_cruza", "regla": "", "regla_nombre": ""}
    orden = ("denegado_observado", "sin_regla", "respuesta", "permitido")
    res = next(x for x in orden if any(r["resultado"] == x for r in rs))
    reglas = "; ".join(f"{i}:{r['regla']}" + (f" {r['regla_nombre']}" if r.get("regla_nombre") else "")
                       for i, r in zip(ids_regla, rs) if r["regla"])
    return {"resultado": res, "regla": reglas, "regla_nombre": "",
            "l4_inferido": any(r.get("l4_inferido") for r in rs),
            "sentido": rs[0].get("sentido", "original")}


def combinar(ids: list, fws: list, dicts: list, conductos: list, assets: dict, ip_de) -> dict:
    """Parte multiple del dict de Assessment.firewall: resultados unidos, cruces con camino y topologia."""
    enl = enlaces(ids, fws)
    vec = _vecinos(enl)
    por_ip = {}
    for k, f in enumerate(fws):
        for nombre, ifc in _interfaces(f):
            por_ip.setdefault(str(ifc.ip), (k, nombre, ifc.network))
    cache_orden: dict = {}
    cache_salto: dict = {}
    combinados, caminos, filas_coh = [], [], []
    conteo = dict.fromkeys(TIPOS, 0)
    sin_fw = 0

    def d_ip(ip, red) -> bool:
        try:
            return ipaddress.ip_address(str(ip).strip()) in red
        except ValueError:
            return False

    def salto_de(k, ip):
        if (k, ip) not in cache_salto:
            r = fws[k].ruta_de(ip)
            cache_salto[(k, ip)] = por_ip.get(r.salto) if r is not None and r.salto else None
        return cache_salto[(k, ip)]

    for i, c in enumerate(conductos):
        miembros = []
        for k, d in enumerate(dicts):
            r = d["resultados"][i]
            if r["resultado"] != "no_cruza":
                miembros.append((k, r["if_origen"], r["if_destino"]))
        clave = tuple(miembros)
        if clave not in cache_orden:
            cache_orden[clave] = ordenar(miembros, vec)
        orden, verificado = cache_orden[clave]
        rs = [dicts[m[0]]["resultados"][i] for m in orden]
        camino = [{"fw": ids[m[0]], "interfaz_entrada": m[1], "interfaz_salida": m[2],
                   "resultado": r["resultado"], "regla_id": r["regla"], "regla_nombre": r.get("regla_nombre", "")}
                  for m, r in zip(orden, rs)]
        comb = _unir_resultados(rs, [ids[m[0]] for m in orden])
        if orden:
            comb["if_origen"], comb["if_destino"] = orden[0][1], orden[-1][2]
            comb["camino"], comb["orden_verificado"] = camino, verificado
        combinados.append(comb)
        caminos.append(camino)
        s, d_ = ip_de(c.get("src")), ip_de(c.get("dst"))
        if comb.get("sentido") == "invertido":
            s, d_ = d_, s
        base = {"ip_origen": str(s), "ip_destino": str(d_), "protocolo_l4": str(c.get("l4") or ""),
                "puerto": c.get("port") if c.get("port") is not None else "", "camino": camino,
                "orden_verificado": verificado, "i": i}
        if not orden:
            # solo se cuenta: son la mayoria (trafico dentro de un segmento) y llenarian la hoja de coherencia
            sin_fw += 1
            continue
        perm = [x["fw"] for x in camino if x["resultado"] == "permitido"]
        den = [x["fw"] for x in camino if x["resultado"] == "denegado_observado"]
        if perm and den:
            filas_coh.append(dict(base, tipo=T_MIXTO, a=", ".join(perm), b=", ".join(den)))
        en_camino = {m[0] for m in orden}
        for m in orden:
            sig = salto_de(m[0], d_)
            if sig is None or sig[0] in en_camino or sig[0] == m[0]:
                continue
            x, _ifx, red_enlace = sig
            if d_ip(d_, red_enlace):
                continue        # el destino esta en la red del enlace: no le toca cruzar a ese firewall
            filas_coh.append(dict(base, tipo=T_SALTO, a=ids[x], b=ids[m[0]]))
    for f in filas_coh:
        conteo[f["tipo"]] += 1
    conteo[T_SIN_FW] = sin_fw
    filas_coh.sort(key=lambda f: (TIPOS.index(f["tipo"]), f["i"]))

    det = _cr.construir(conductos, combinados, assets, ip_de)
    agregado = [dict(a, firewall=ids[k]) for k, d in enumerate(dicts) for a in d["cruces"]["agregado"]]
    det["totales"]["pares_interfaces"] = len({(a["firewall"], a["interfaz_origen"], a["interfaz_destino"])
                                              for a in agregado})
    cuenta = {x: 0 for x in ("permitido", "denegado_observado", "respuesta", "sin_regla", "no_cruza")}
    for r in combinados:
        cuenta[r["resultado"]] += 1
    cuenta["invertidos"] = sum(1 for r in combinados if r.get("sentido") == "invertido")
    claves_suma = ("reglas_sin_trafico", "permitir_con_aciertos_sin_conductos",
                   "permitir_con_conductos_sin_aciertos", "reglas", "subreglas_con_puerto_origen")
    for kk in claves_suma:
        cuenta[kk] = sum(d["resumen"][kk] for d in dicts)
    cuenta["con_contadores"] = any(d["resumen"]["con_contadores"] for d in dicts)
    cuenta["l4_inferido"] = sum(1 for r in combinados if r.get("l4_inferido"))
    avisos = [f"{ids[k]}: {a}" for k, d in enumerate(dicts) for a in d["avisos"]]
    nat = [dict(f, firewall=ids[k]) for k, d in enumerate(dicts) for f in (d.get("nat") or {}).get("filas", ())]
    return {
        **({"nat": {"filas": nat, "multiple": True,
                    "con_contadores": any((d.get("nat") or {}).get("con_contadores") for d in dicts),
                    "nota": "; ".join(f"{ids[k]}: {d['nat']['nota']}" for k, d in enumerate(dicts)
                                      if (d.get("nat") or {}).get("nota"))}} if nat else {}),
        "archivo": ", ".join(d["archivo"] for d in dicts),
        "fabricante": ", ".join(dict.fromkeys(d["fabricante"] for d in dicts)),
        "hostname": ", ".join(ids), "resultados": combinados, "resumen": cuenta, "reglas": [],
        "avisos": avisos, "rutas_estado": [], "cruces": dict(det, agregado=agregado, multiple=True),
        "sin_trafico": [dict(s, regla=f"{ids[k]}:{s['regla']}") for k, d in enumerate(dicts)
                        for s in d["sin_trafico"]],
        "firewalls": [{"id": ids[k], "archivo": d["archivo"], "fabricante": d["fabricante"],
                       "hostname": d["hostname"], "interfaces": len(fws[k].interfaces), "reglas": len(d["reglas"]),
                       "rutas": len(fws[k].rutas), "datos": d} for k, d in enumerate(dicts)],
        "topologia": {"enlaces": enl, "coherencia": {"filas": filas_coh, "conteo": conteo}}}


def es_multiple(fw) -> bool:
    return bool((fw or {}).get("firewalls"))


def texto_marca(f: dict) -> str:
    if f["tipo"] == T_MIXTO:
        return t("permitido en {a}, denegado en {b}", a=f["a"], b=f["b"])
    if f["tipo"] == T_SALTO:
        return t("salto hacia {a} sin cruce en {a} (salto de {b})", a=f["a"], b=f["b"])
    return t(T_SIN_FW)


def filas_enlaces(fw: dict) -> list:
    return [[e[c] if c != "descubierto_por" else "; ".join(t(x) for x in e[c].split("; "))
             for c in COL_ENLACES] for e in fw["topologia"]["enlaces"]]


def filas_firewalls(fw: dict) -> list:
    return [[x["id"], x["fabricante"], x["hostname"], x["interfaces"], x["reglas"], x["rutas"]]
            for x in fw["firewalls"]]


def filas_coherencia(fw: dict) -> list:
    return [[f["ip_origen"], f["ip_destino"], f["protocolo_l4"], f["puerto"],
             _cr.texto_camino(f["camino"], f["orden_verificado"]), texto_marca(f)]
            for f in fw["topologia"]["coherencia"]["filas"]]


def resumen_texto(fw: dict) -> str:
    n = fw["topologia"]["coherencia"]["conteo"]
    return t("{f} firewalls, {e} enlaces entre ellos. Marcas de coherencia: permitido en uno y denegado en "
             "otro: {m}; salto hacia un firewall que no cruza: {s}; sin firewall en el camino: {n}. "
             "Detalle en firewall_topologia.csv y firewall_coherencia.csv.",
             f=len(fw["firewalls"]), e=len(fw["topologia"]["enlaces"]), m=n[T_MIXTO], s=n[T_SALTO],
             n=n[T_SIN_FW])


def cabecera_firewalls() -> list:
    return [t("Firewall"), t("Fabricante"), t("Hostname"), t("Interfaces"), t("Reglas"), t("Rutas")]


def cabecera_enlaces() -> list:
    return [t("Firewall A"), t("Interfaz A"), t("Red"), t("Firewall B"), t("Interfaz B"), t("IP de B"),
            t("Descubierto por")]


def tablas_reporte(fw: dict) -> list:
    """[(cabecera, filas)] de la seccion 'Firewalls' de los reportes."""
    return [(cabecera_firewalls(), filas_firewalls(fw)), (cabecera_enlaces(), filas_enlaces(fw))]


def tablas(fw: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] propias de varios firewalls (el resto del reporte no cambia)."""
    from .. import rutas_firewall as _rf
    from . import integracion as _fi
    out = [("firewall_topologia.csv", HOJA_ENLACES, COL_ENLACES, filas_enlaces(fw)),
           ("firewall_coherencia.csv", HOJA_COHERENCIA, COL_COHERENCIA, filas_coherencia(fw))]
    for x in fw["firewalls"]:
        d, p, ident = x["datos"], prefijo_archivo(x["id"]), x["id"]

        def hoja(nombre, ident=ident):
            return Traducido(f"{ident} {t(nombre)}")
        out.append((f"{p}_firewall_reglas.csv", hoja("Reglas del firewall"), _fi.COL_REGLAS, _fi.filas_reglas(d)))
        if d.get("rutas_estado"):
            out.append((f"{p}_firewall_rutas.csv", hoja("Rutas del firewall"), _fi.COL_RUTAS, _fi.filas_rutas(d)))
        ri = d.get("rutas_info")
        if ri:
            out.append((f"{p}_firewall_interfaces.csv", hoja("FW interfaces"), _rf.COL_INTERFACES,
                        _rf.filas_interfaces(ri)))
            out.append((f"{p}_firewall_matriz.csv", hoja("FW matriz"), _rf.COL_MATRIZ, _rf.filas_matriz(ri)))
    return out
