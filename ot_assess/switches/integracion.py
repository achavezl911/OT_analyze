"""SW1a: integra el modelo de switch al analisis.

- ubica cada activo con MAC del inventario en su puerto y VLAN (tabla MAC); si la MAC esta en varios
  puertos gana el puerto de acceso sobre el trunk, el Port-channel o el puerto con vecino CDP;
- dice que VLAN espeja cada sesion SPAN y marca las VLAN con equipos que ninguna sesion espeja.
Solo lee el modelo ya armado por el lector (que no guarda secretos). Es evidencia pasiva de lo que
muestra la tabla MAC en el momento de la captura de la CLI, no un inventario de puertos garantizado.
"""
from __future__ import annotations

from pathlib import Path

from ..i18n import t
from . import aruba_cx, cisco_ios, snmp
from .cisco_ios import clave_if, mac_norm

TITULO = "Switches"
NOTA = ("Datos leidos de la CLI de los switches (running-config, tabla MAC, interfaces, CDP). La ubicacion de un "
        "activo es la de su MAC en la tabla MAC en ese momento. Una VLAN marcada sin espejo no esta en ninguna "
        "sesion SPAN de los switches entregados; puede capturarse por otro medio (TAP, otro switch). "
        "Un espejo por interfaz de origen cubre solo el trafico de esa interfaz y se rotula como parcial.")
COL_PUERTOS = ["switch", "puerto", "descripcion", "modo", "vlans", "estado", "macs", "fabricantes", "activos"]
COL_VLANS = ["switch", "vlan", "nombre", "puertos_acceso", "macs", "espejada_span", "sesion", "marcas"]
COL_SPAN = ["switch", "sesion", "origenes", "destino", "vlans_cubiertas", "vlans_parciales"]
MAX_MACS = 10
MARCA_SIN_ESPEJO = "VLAN sin espejo"
SI, PARCIAL, NO = "si", "parcial", "no"
DESCONOCIDO = ""        # switch SNMP o AOS-CX sin show mirror: no se sabe que espeja
_ORDEN = {NO: 0, PARCIAL: 1, SI: 2}


def comprimir(vlans) -> str:
    """[4, 31, 32, 33, 40] -> '4;31-33;40'."""
    vs = sorted(set(vlans))
    out, i = [], 0
    while i < len(vs):
        j = i
        while j + 1 < len(vs) and vs[j + 1] == vs[j] + 1:
            j += 1
        out.append(str(vs[i]) if j == i else f"{vs[i]}-{vs[j]}")
        i = j + 1
    return ";".join(out)


def cargar(archivos) -> tuple:
    """([Switch], [avisos]). Un archivo que no existe lanza ValueError (el CLI lo convierte en error)."""
    lista, avisos = [], []
    for a in archivos:
        if not Path(a).is_file():
            raise ValueError(f"--switch espera un archivo existente: '{a}'")
        if snmp.es_snmp(a):
            sw = snmp.leer_archivo(a)
        elif aruba_cx.es_aoscx(a):
            sw = aruba_cx.leer_archivo(a)
        else:
            sw = cisco_ios.leer_archivo(a)
        for adv in sw.avisos:
            avisos.append(f"{sw.archivo}: {adv}")
        if any(x.hostname == sw.hostname for x in lista):
            avisos.append(f"{sw.archivo}: el hostname {sw.hostname} ya viene en otro archivo; "
                          "se tratan como equipos distintos")
        lista.append(sw)
    return lista, avisos


def _enlace(sw, p) -> bool:
    """Puerto entre switches o agregado: trunk, Port-channel, miembro de canal o con vecino CDP."""
    k = clave_if(p.nombre)
    return (p.modo == "trunk" or k.startswith("port-channel") or p.canal is not None
            or any(clave_if(v.interfaz) == k for v in sw.cdp))


def _vlans_puerto(sw, p) -> set:
    v = set(p.vlans_trunk)
    if p.vlan_acceso is not None:
        v.add(p.vlan_acceso)
    k = clave_if(p.nombre)
    v.update(vl for vl, _m, pto in sw.mac if clave_if(pto) == k)
    return v


def _espejo(sw) -> dict:
    """{vlan: (estado, [sesiones])} de las VLAN del switch; estado = si | parcial | no."""
    if sw.origen == "snmp" or (sw.origen == "aoscx" and "espejo" not in sw.leyo):
        vs = {vl for vl, _m, _p in sw.mac} | set(sw.vlans) | {p.vlan_acceso for p in sw.puertos}
        return {v: (DESCONOCIDO, []) for v in vs if v}
    completo: dict = {}
    parcial: dict = {}
    for s in sw.span:
        for v in s.vlans_origen:
            completo.setdefault(v, []).append(s.id)
        for i in s.interfaces_origen:
            p = sw.puerto(i)
            for v in (_vlans_puerto(sw, p) if p else ()):
                parcial.setdefault(v, []).append(s.id)
    out = {}
    for v in {vl for vl, _m, _p in sw.mac} | set(sw.vlans) | {p.vlan_acceso for p in sw.puertos
                                                            if p.vlan_acceso is not None}:
        if v in completo:
            out[v] = (SI, sorted(set(completo[v])))
        elif v in parcial:
            out[v] = (PARCIAL, sorted(set(parcial[v])))
        else:
            out[v] = (NO, [])
    return out


def _ubicar(switches, assets) -> dict:
    """{clave_activo: (indice_switch, vlan, puerto)}. Gana el puerto de acceso; luego el primer switch."""
    por_mac: dict = {}
    for i, sw in enumerate(switches):
        for vlan, mac, pto in sw.mac:
            p = sw.puerto(pto)
            rango = 1 if (p is None or _enlace(sw, p)) else 0
            por_mac.setdefault(mac, []).append((rango, i, vlan, p.nombre if p else pto))
    out = {}
    for k, a in assets.items():
        mac = mac_norm(str(a.get("mac") or ""))
        if mac and mac in por_mac:
            _r, i, vlan, pto = min(por_mac[mac])
            out[k] = (i, vlan, pto)
    return out


def integrar(archivos, assets: dict) -> dict:
    """Lee los switches, ubica los activos (les escribe `switch_puerto` y `vlan`) y arma el resultado."""
    switches, avisos = cargar(archivos)
    ubic = _ubicar(switches, assets)
    for k, (i, vlan, pto) in ubic.items():
        assets[k]["switch_puerto"] = f"{switches[i].hostname}:{pto}"
        if vlan:
            assets[k]["vlan"] = str(vlan)
    espejos = [_espejo(sw) for sw in switches]
    con_mac = sum(1 for a in assets.values() if mac_norm(str(a.get("mac") or "")))
    res = {"archivos": [sw.archivo for sw in switches], "switches": switches, "espejos": espejos,
           "ubicacion": ubic, "ubicados": len(ubic), "con_mac": con_mac, "avisos": avisos,
           "nombres": {k: a.get("nombre") or k for k, a in assets.items()},
           "vendors": {mac_norm(str(a.get("mac") or "")): a.get("vendor") or ""
                       for a in assets.values() if mac_norm(str(a.get("mac") or ""))}}
    res["sin_espejo"] = sin_espejo(res)
    return res


def hay(sw: dict | None) -> bool:
    return bool(sw and sw.get("switches"))


def _macs_vlan(sw, vlan) -> int:
    return len({m for v, m, _p in sw.mac if v == vlan})


def sin_espejo(res: dict) -> list:
    """[(hostname, vlan, nombre, macs)] de las VLAN con MAC aprendidas que ninguna sesion SPAN espeja."""
    out = []
    for sw, esp in zip(res["switches"], res["espejos"]):
        for v in sorted(esp):
            n = _macs_vlan(sw, v)
            if n and esp[v][0] == NO:
                out.append((sw.hostname, v, sw.vlans.get(v, ""), n))
    return out


def espejo_por_vlan(res: dict) -> dict:
    """{vlan (texto): si | parcial | no} para las VLAN con equipos; con varios switches gana el mejor."""
    out: dict = {}
    for sw, esp in zip(res["switches"], res["espejos"]):
        for v, (est, _s) in esp.items():
            if est != DESCONOCIDO and _macs_vlan(sw, v) and _ORDEN[est] >= _ORDEN.get(out.get(str(v), NO), 0):
                out[str(v)] = est
    return out


def _lista(items) -> str:
    items = list(items)
    if len(items) > MAX_MACS:
        return ";".join(items[:MAX_MACS]) + ";" + t("y {n} mas", n=len(items) - MAX_MACS)
    return ";".join(items)


def filas_puertos(res: dict) -> list:
    en_puerto: dict = {}
    for k, (i, _v, pto) in res["ubicacion"].items():
        en_puerto.setdefault((i, clave_if(pto)), []).append(str(res["nombres"].get(k, k)))
    filas = []
    for i, sw in enumerate(res["switches"]):
        macs: dict = {}
        for _v, mac, pto in sw.mac:
            macs.setdefault(clave_if(pto), []).append(mac)
        for p in sw.puertos:
            k = clave_if(p.nombre)
            ms = sorted(set(macs.get(k, ())))
            if p.modo == "trunk":
                vl = (comprimir(p.vlans_trunk) if p.vlans_trunk else t("todas") if p.trunk_todas else "")
                if p.vlan_nativa is not None:
                    vl += (" " if vl else "") + t("(nativa {n})", n=p.vlan_nativa)
            else:
                vl = str(p.vlan_acceso) if p.vlan_acceso is not None else ""
            estado = p.estado or ("admin down" if p.apagado else "")
            vend = sorted({res["vendors"].get(m, "") for m in ms} - {""})
            filas.append([sw.hostname, p.nombre, p.descripcion, p.modo, vl, estado, _lista(ms), ";".join(vend),
                          _lista(sorted(en_puerto.get((i, k), ())))])
    return filas


def filas_vlans(res: dict) -> list:
    filas = []
    for sw, esp in zip(res["switches"], res["espejos"]):
        for v in sorted(esp):
            acc = [p.nombre for p in sw.puertos
                   if p.vlan_acceso == v and p.modo != "trunk" and not _enlace(sw, p)]
            n = _macs_vlan(sw, v)
            est, ses = esp[v]
            filas.append([sw.hostname, v, sw.vlans.get(v, ""), _lista(acc), n, t(est) if est else "",
                          ";".join(str(s) for s in ses),
                          t(MARCA_SIN_ESPEJO) if n and est == NO else ""])
    return filas


def _origenes(s) -> str:
    partes = []
    if s.vlans_origen:
        partes.append("vlan " + comprimir(s.vlans_origen))
    if s.interfaces_origen:
        partes.append("interfaces " + ";".join(s.interfaces_origen))
    return " / ".join(partes)


def filas_span(res: dict) -> list:
    filas = []
    for sw in res["switches"]:
        for s in sorted(sw.span, key=lambda x: x.id):
            parc: set = set()
            for i in s.interfaces_origen:
                p = sw.puerto(i)
                parc.update(_vlans_puerto(sw, p) if p else ())
            filas.append([sw.hostname, s.id, _origenes(s), s.destino, comprimir(s.vlans_origen),
                          comprimir(parc - set(s.vlans_origen))])
    return filas


def tablas(res: dict) -> list:
    """[(archivo, hoja, cabecera, filas)] para los CSV y el XLSX."""
    if not hay(res):
        return []
    return [("switch_puertos.csv", "Switch puertos", COL_PUERTOS, filas_puertos(res)),
            ("switch_vlans.csv", "Switch VLAN", COL_VLANS, filas_vlans(res)),
            ("switch_span.csv", "Switch SPAN", COL_SPAN, filas_span(res))]


def resumen_texto(res: dict) -> str:
    sin = res["sin_espejo"]
    txt = t("{n} switches leidos ({archivos}); {u} de {m} activos con MAC ubicados en un puerto y VLAN. "
            "Detalle en switch_puertos.csv, switch_vlans.csv y switch_span.csv.",
            n=len(res["switches"]), archivos=", ".join(res["archivos"]), u=res["ubicados"], m=res["con_mac"])
    if sin:
        txt += " " + t("VLAN con equipos y sin espejo SPAN: {lista}.",
                       lista=", ".join(f"{h}:{v}" for h, v, _n, _m in sin[:20]))
    return txt


def tablas_reporte(res: dict) -> list:
    """[(titulo, cabecera, filas)] para HTML, Markdown y Word."""
    sw_filas = []
    for sw in res["switches"]:
        ubic = sum(1 for (i, _v, _p) in res["ubicacion"].values() if res["switches"][i] is sw)
        sw_filas.append([sw.hostname, sw.modelo, sw.version, len(sw.vlans), len(sw.puertos),
                         len({m for _v, m, _p in sw.mac}), len(sw.span), ubic])
    out = [(t("Switches leidos"),
            [t(x) for x in ("Switch", "Modelo", "Version", "VLAN", "Puertos", "MAC aprendidas", "Sesiones SPAN",
                            "Activos ubicados")], sw_filas)]
    span = filas_span(res)
    if span:
        out.append((t("Sesiones SPAN"), [t(x) for x in ("Switch", "Sesion", "Origenes", "Destino", "VLAN cubiertas",
                                                         "VLAN parciales")], span))
    if res["sin_espejo"]:
        out.append((t(MARCA_SIN_ESPEJO), [t(x) for x in ("Switch", "VLAN", "Nombre", "MAC aprendidas")],
                    [list(f) for f in res["sin_espejo"]]))
    return out
