"""Tablas del reporte y su salida CSV. `tablas` arma las filas una sola vez; los CSV y el XLSX
solo las recorren."""
from __future__ import annotations

from pathlib import Path

from .. import acceso_remoto as _ar
from .. import alertas as _al
from .. import attack_cobertura as _atc
from .. import avisos_cisa as _ac
from .. import cobertura_captura as _cc
from .. import conductos_zcr as _zc
from .. import csf_tiers as _ct
from .. import csf_transicion as _cft
from .. import direccionamiento as _dr
from .. import evasion as _ev
from .. import fuentes as _fu
from .. import fuentes_log as _fl
from .. import hardening as _hd
from .. import ingenieria as _ing
from .. import inventario_normalizado as _in
from .. import inventario_presentado as _ip
from .. import linea_base_aprobada as _lba
from .. import madurez as _ma
from .. import matriz_controles as _mc
from .. import obsolescencia as _ob
from .. import periodicidad as _pe
from .. import registros_dns as _rd
from .. import remediacion as _re
from .. import riesgo as _rg
from .. import rutas_ataque as _ra
from .. import rutas_firewall as _rf
from .. import salud_red as _sr
from .. import sensores as _se
from .. import tobe as _tb
from .. import vuln_firmware as _vf
from .. import vulnerabilidades as _vu
from .. import zonas as _zo
from ..catalog import SEV_ORDER
from ..cobertura import de_corrida
from ..detail.control import detalle_visible, op_visible
from ..firewall import filas_contraste
from ..firewalls import cruces as _cr
from ..firewalls import integracion as _fi
from ..firewalls import nat as _nt
from ..firewalls import politica as _po
from ..firewalls import rutas_propuestas as _rp
from ..firewalls import topologia as _tp
from ..i18n import t
from ..model import Assessment
from ..riesgo import id_hallazgo
from ..roles import mostrar as mostrar_rol
from ..standards import ESTANDARES, traducir_refs
from ..switches import integracion as _sw
from ..util import port_info
from .common import escritor_csv

COLUMNAS_COBERTURA = ["id", "grupo", "categoria", "texto", "cobertura",
                      "hallazgos_que_lo_citan", "hallazgos_en_esta_corrida"]


def cabecera_hallazgos(estandares: list) -> list:
    return (["id", "captura", "severidad", "categoria", "titulo", "evidencia",
             "por_que_importa", "recomendacion", "mitre_ics", "mitre_ics_tacticas"] + [e.clave for e in estandares])


def fila_hallazgo(nombre_origen: str, f: dict, estandares: list) -> list:
    return ([f.get("id") or id_hallazgo(f["titulo"]), nombre_origen, t(f["severidad"]), t(f["categoria"]), t(f["titulo"]), t(f["evidencia"]),
             t(f["por_que_importa"]), t(f["recomendacion"]), f["referencias"].get("mitre-ics", ""),
             _atc.tacticas_de(f["referencias"].get("mitre-ics", ""))]
            + [traducir_refs(f["referencias"].get(e.clave, "")) for e in estandares])


def tablas(res: Assessment) -> list:
    """[(archivo_csv, hoja, cabecera, filas)]. hoja=None: la tabla no va al XLSX."""
    caps, assets, conduits = res.caps, res.assets, res.conduits
    estandares = res.estandares or [ESTANDARES["iec62443"]]
    nombres = _rd.nombre_de_ip(res)
    out = []

    filas_inv = _ip.filas(res, nombres)          # I3 (D105): una fila por IP para las MAC de enrutamiento
    con_nat = any(a.get("nat_nota") for a in filas_inv)     # D70: columna solo si hay activos marcados
    con_salto = _ip.hay_partidas(filas_inv)
    # Inventario consolidado: un renglon por equipo, no por equipo y captura.
    out.append(("inventario.csv", "Inventario",
                ["equipo", "ips", "mac", *(["mac_salto"] if con_salto else []), "fabricante", "modelo_descripcion",
                 "firmware", "rol_inferido", "zona_purdue", "vlans",
                 "base_inferencia", "puertos_servidos", "protocolos",
                 "paquetes", "bytes", "visto_en_capturas", "nombre_dns", "interfaz_firewall",
                 "zona_asignada", "origen_asignacion", *(["switch_puerto", "vlan"] if res.switches else []),
                 *(["nota_nat"] if con_nat else [])],
                [[a["nombre"], ";".join(sorted(a["ips"])), a["mac"], *([a.get("mac_salto", "")] if con_salto else []),
                  a["vendor"],
                  a.get("modelo", ""), a.get("firmware", ""), mostrar_rol(a["role"]), mostrar_rol(a["purdue"]),
                  ";".join(sorted(a["vlans"])), a["role_why"],
                  ";".join(f"{p}/{l4}" for (p, l4) in a["ports_served"]),
                  ";".join(f"{p}={n}" for p, n in a["protos"].most_common(12)),
                  a["pkts"], a["bytes"], ";".join(sorted(a["capturas"])),
                  _ip.nombre_dns(a, nombres),
                  _rf.mostrar_iface(a.get("interfaz_firewall", "")), *_zo.columnas_activo(a),
                  *([a.get("switch_puerto", ""), a.get("vlan", "")] if res.switches else []),
                  *([a.get("nat_nota", "")] if con_nat else [])]
                 for a in filas_inv]))

    out.extend(_cc.tablas(res.cobertura_captura))
    out.extend(_sr.tablas(res.salud_red))
    out.extend(_se.tablas(res.sensores))
    out.extend(_lba.tablas(res.linea_base_aprobada))
    out.extend(_in.tablas(res.inventario_normalizado))
    out.extend(_ob.tablas(res.obsolescencia))
    out.extend(_vf.tablas(res.vuln_firmware))

    out.append(("comunicaciones.csv", "Comunicaciones",
                ["origen", "origen_ip", "origen_rol", "origen_zona",
                 "destino", "destino_ip", "destino_rol", "destino_zona",
                 "servicio", "l4", "puerto", "categoria", "sentido",
                 "cruza_zona", "escrituras", "criticidad", "paquetes",
                 "bytes", "capturas", "nombre_dns", "if_origen", "if_destino", "cruza_firewall"],
                [[k["src_nombre"], k["src"], mostrar_rol(k["src_rol"]), mostrar_rol(k["src_zona"]),
                  k["dst_nombre"], k["dst"], mostrar_rol(k["dst_rol"]), mostrar_rol(k["dst_zona"]),
                  k["servicio"], k["l4"], k["port"], k["categoria"],
                  t("bidireccional") if k["bidireccional"] else t("unidireccional"),
                  t("si") if k["cruza_zona"] else t("no"), k["escrituras"],
                  t(k["criticidad"]), k["pkts"], k["bytes"], ";".join(sorted(k["capturas"])),
                  nombres.get(k["dst"], ""), _rf.mostrar_iface(k.get("if_origen", "")),
                  _rf.mostrar_iface(k.get("if_destino", "")),
                  {True: t("si"), False: t("no")}.get(k.get("cruza_firewall"), "")]
                 for k in conduits]))

    if any("fuentes" in k for k in conduits):       # M2: procedencia de cada conducto
        _arch, _hoja, cab_c, filas_c = out[-1]
        cab_c.append("fuentes")
        for fila, k in zip(filas_c, conduits):
            fila.append("; ".join(k.get("fuentes", ())))

    out.append(("activos.csv", None,
                ["captura", "mac", "fabricante", "ips", "vlans", "rol_inferido",
                 "nivel_purdue", "base_inferencia", "hostnames", "puertos_servidos",
                 "paquetes_tx", "paquetes_rx", "bytes_tx", "bytes_rx", "fingerprints",
                 "zona_asignada", "origen_asignacion"],
                [[c.name, h["mac"], h["vendor"], ";".join(sorted(h["ips"])),
                  ";".join(sorted(h["vlans"])), mostrar_rol(h.get("role", "")), mostrar_rol(h.get("purdue", "")),
                  h.get("role_why", ""), ";".join(sorted(h["hostnames"])),
                  ";".join(f"{p}/{l4}" for (p, l4) in h["ports_served"]),
                  h["tx_pkts"], h["rx_pkts"], h["tx_bytes"], h["rx_bytes"],
                  " | ".join(sorted(h["fingerprints"])), *_zo.columnas_activo(assets.get(h["mac"], {}))]
                 for c in caps for h in c.hosts.values()]))

    out.extend(_sw.tablas(res.switches))

    if _zo.hay(res.zonas):
        out.append(("zonas.csv", _zo.TITULO, _zo.COLUMNAS, _zo.filas_tabla(_zo.presentada(res.zonas, filas_inv))))
    if _zc.hay(res.zcr):
        out.append((_zc.ARCHIVO, _zc.HOJA, _zc.COLUMNAS, _zc.filas_tabla(res.zcr)))
    out.extend(_tb.tablas(res.tobe))
    out.extend(_hd.tablas(res.hardening))
    out.extend(_fl.tablas(res.fuentes_log))
    out.extend(_dr.tablas(res.direccionamiento))
    out.extend(_ra.tablas(res.rutas_ataque))
    out.extend(_mc.tablas(res.matriz_controles, res.linea_base))

    out.append(("flujos.csv", None,
                ["captura", "origen", "destino", "l4", "puerto_destino",
                 "servicio", "protocolo", "paquetes", "bytes"],
                [[c.name, f["src"], f["dst"], f["l4"], f["dport"],
                  port_info(f["dport"], f["l4"])[0], f["proto"], f["pkts"], f["bytes"]]
                 for c in caps for f in sorted(c.flows.values(), key=lambda x: -x["pkts"])]))

    out.append(("identidad.csv", "Identidad",
                ["captura", "origen_ip", "origen_mac", "tipo", "valor", "detalle"],
                [[c.name, i["ip"], i["mac"], i["tipo"], i["valor"], i["detalle"]]
                 for c in caps for i in c.identity]))

    out.append(("hallazgos.csv", "Hallazgos",
                cabecera_hallazgos(estandares),
                [fila_hallazgo(c.name, f, estandares)
                 for c in [*caps, *res.extras]
                 for f in sorted(c.findings, key=lambda x: SEV_ORDER.get(x["severidad"], 9))]))

    out.extend(_atc.tablas([f for c in [*caps, *res.extras] for f in c.findings]))
    out.extend(_cft.tablas([f for c in [*caps, *res.extras] for f in c.findings], estandares))

    out.append(("plan_remediacion.csv", "Plan de remediacion", _re.COLUMNAS, _re.tabla(res)))
    out.extend(_rg.tablas(_rg.de(res)))
    out.extend(_ma.tablas(res.madurez))
    out.extend(_ct.tablas(res.csf_tiers))

    out.append(("dns_registros.csv", "DNS registros", _rd.COL_REGISTROS, _rd.registros(res)))
    out.append(("dns_resoluciones.csv", "DNS resoluciones", _rd.COL_RESOLUCIONES, _rd.resoluciones(res)))
    out.append(("dns_servidores.csv", "DNS servidores", _rd.COL_SERVIDORES, _rd.servidores(res)))

    out.append(("periodicidad.csv", None, _pe.COLUMNAS, _pe.filas(res)))
    out.append((_ar.ARCHIVO, None, _ar.COLUMNAS, _ar.filas(res)))
    out.append((_ev.ARCHIVO, None, _ev.COLUMNAS, _ev.filas(res)))

    out.append(("control.csv", "Control",
                ["captura", "trama", "protocolo", "operacion", "origen", "destino", "detalle", "clase"],
                [[c.name, o["frame"], o["proto"], op_visible(o), o["src"], o["dst"], detalle_visible(o),
                  t(o["clase"]) if o.get("clase") else ""]
                 for c in caps for o in c.control_ops]))
    out.append((_ing.ARCHIVO, None, _ing.COLUMNAS, _ing.filas(caps)))

    if res.firewall:
        out.append(("firewall_contraste.csv", "Firewall",
                    ["origen", "origen_ip", "destino", "destino_ip", "servicio", "l4", "puerto",
                     "cruza_zona", "resultado", "regla"],
                    [[k["src_nombre"], k["src"], k["dst_nombre"], k["dst"], k["servicio"],
                      k["l4"], k["port"], t("si") if k["cruza_zona"] else t("no"), t(r["resultado"]),
                      r["regla"]] for k, r in filas_contraste(conduits, res.firewall)]))
        out.append(("firewall_reglas_sin_trafico.csv", "Reglas sin trafico",
                    ["regla", "origen", "destino", "puerto", "protocolo"],
                    [[s["regla"], s["origen"], s["destino"], s["puerto"], s["protocolo"]]
                     for s in res.firewall["sin_trafico"]]))

    if res.firewall.get("reglas"):
        out.append(("firewall_reglas.csv", "Reglas del firewall", _fi.COL_REGLAS, _fi.filas_reglas(res.firewall)))

    if res.firewall.get("rutas_estado"):
        out.append(("firewall_rutas.csv", "Rutas del firewall", _fi.COL_RUTAS, _fi.filas_rutas(res.firewall)))

    if _fu.hay(res.fuentes):
        out.append(("fuentes_resumen.csv", _fu.HOJA_RESUMEN, _fu.COL_RESUMEN, _fu.filas_resumen(res.fuentes)))
        out.append(("fuentes_cobertura.csv", _fu.HOJA_COBERTURA, _fu.COL_COBERTURA, res.fuentes["filas"]))

    if _cr.hay(res.firewall):
        out.append(("firewall_cruces.csv", _cr.HOJA_AGREGADO, _cr.columnas_agregado(res.firewall["cruces"]),
                    _cr.filas_agregado(res.firewall["cruces"])))
        out.append(("firewall_cruces_detalle.csv", _cr.HOJA_DETALLE, _cr.columnas_detalle(res.firewall["cruces"]),
                    _cr.filas_detalle(res.firewall["cruces"])))

    if _nt.hay(res.firewall):
        out.append(("firewall_nat.csv", _nt.HOJA_NAT, _nt.columnas(res.firewall["nat"]),
                    _nt.filas_tabla(res.firewall["nat"])))

    if _po.hay(res.firewall):
        out.extend(_po.tablas(res.firewall["politica"]))

    if _rp.hay(res.firewall):
        out.extend(_rp.tablas(res.firewall["rutas_propuestas"]))

    if _tp.es_multiple(res.firewall):
        out.extend(_tp.tablas(res.firewall))
    elif res.rutas:
        out.append(("firewall_interfaces.csv", "FW interfaces", _rf.COL_INTERFACES,
                    _rf.filas_interfaces(res.rutas)))
        out.append(("firewall_matriz.csv", "FW matriz", _rf.COL_MATRIZ, _rf.filas_matriz(res.rutas)))

    if res.vulnerabilidades:
        out.append(("vulnerabilidades.csv", "Vulnerabilidades", _vu.columnas(res.vulns_cruces),
                    _vu.filas_tabla(res.vulns_cruces, assets)))

    if "avisos_ics" in res.vulnerabilidades:
        filas = _ac.filas_avisos(res.vulns_cruces, assets, (getattr(res, "perfil", None) or {}).get("version_cvss", "3"))
        if filas:
            out.append(("avisos_ics.csv", "Avisos ICS", _ac.COLUMNAS_AVISOS, filas))

    if res.alertas:
        out.append(("alertas.csv", "Alertas", _al.COLUMNAS, _al.filas_tabla(res.alertas_asoc, assets)))

    # Anexo de cobertura: solo para marcos elegidos que tienen archivo de cobertura.
    for e, filas, _resum in de_corrida(res):
        out.append((f"cobertura_{e.clave}.csv", f"Cobertura {e.clave}", COLUMNAS_COBERTURA,
                    [[f["id"], f["grupo"], f["categoria"], f["texto"], t(f["cobertura"]),
                      ";".join(f["fragmentos"]), f["hallazgos"]] for f in filas]))
    return out


def cabecera_t(res: Assessment, cabecera: list) -> list:
    """Cabecera con las columnas traducidas al escribir. Las claves de los marcos (columnas de
    referencias del CSV de hallazgos) son datos y no se traducen."""
    claves = {e.clave for e in (res.estandares or [ESTANDARES["iec62443"]])}
    return [c if c in claves else t(c) for c in cabecera]


def nombre_hoja(hoja: str) -> str:
    """Nombre de hoja traducido; las hojas de cobertura llevan la clave del marco."""
    pref = "Cobertura "
    if hoja.startswith(pref) and hoja != _cc.HOJA:
        return t("Cobertura {clave}", clave=hoja[len(pref):])
    return t(hoja)


def write_csvs(res: Assessment, outdir: Path) -> None:
    for archivo, _hoja, cabecera, filas in tablas(res):
        with open(outdir / archivo, "w", newline="", encoding="utf-8-sig") as fh:
            w = escritor_csv(fh)
            w.writerow(cabecera_t(res, cabecera))
            w.writerows(filas)
