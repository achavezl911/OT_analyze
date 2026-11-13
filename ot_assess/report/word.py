"""Informe editable para el cliente (informe_ot.docx). Mismo contenido sustantivo que
reporte_ot.html; solo lee el modelo ya calculado y las tablas de csvout (D31)."""
from __future__ import annotations

import collections
from datetime import datetime
from pathlib import Path

from .. import alertas as _al
from .. import cobertura as _cobertura
from .. import cobertura_captura as _cc
from .. import conductos_zcr as _zc
from .. import csf_tiers as _ct
from .. import direccionamiento as _dr
from .. import entorno as _entorno
from .. import firewall as _firewall
from .. import fuentes as _fu
from .. import fuentes_log as _fl
from .. import hardening as _hd
from .. import inventario_normalizado as _in
from .. import inventario_presentado as _ip
from .. import linea_base as _lb
from .. import linea_base_aprobada as _lba
from .. import madurez as _ma
from .. import matriz_controles as _mc
from .. import obsolescencia as _ob
from .. import perfil as _perfil
from .. import playbooks as _pb
from .. import registro_red as _rr
from .. import registros_dns as _rd
from .. import remediacion as _rem
from .. import riesgo as _rg
from .. import rutas_acceso as _rac
from .. import rutas_ataque as _ra
from .. import rutas_firewall as _rf
from .. import salud_red as _sr
from .. import sensores as _se
from .. import tobe as _tb
from .. import trazabilidad as _tz
from .. import vuln_firmware as _vf
from .. import vulnerabilidades as _vuln
from .. import zonas as _zo
from ..firewalls import cruces as _cr
from ..firewalls import integracion as _fi
from ..firewalls import politica as _po
from ..firewalls import rutas_propuestas as _rp
from ..firewalls import topologia as _tp
from ..i18n import t
from ..model import Assessment
from ..standards import ESTANDARES
from ..standards import avisos as _avisos
from ..switches import integracion as _sw
from ..texts import client_questions
from .common import agrupar_hallazgos, filas_fuentes, referencias_visibles
from .csvout import cabecera_t, tablas
from .docx import escribir_docx

_RESULTADOS_FW = (("permitido", "Permitido por una regla"),
                  ("denegado_observado", "Denegado por una regla pero observado"),
                  ("respuesta", "Respuesta de una sesion permitida"),
                  ("sin_regla", "Trafico sin regla"),
                  ("no_cruza", "No cruza este firewall"),
                  ("reglas_sin_trafico", "Reglas de permitir sin trafico"))


def _recortada(cabecera, filas, max_rows, bloques):
    """Tabla recortada a max_rows filas, con la nota de las que quedan en el XLSX."""
    bloques.append(("tabla", cabecera, filas[:max_rows]))
    if len(filas) > max_rows:
        bloques.append(("nota", t("{n} filas mas en reporte_ot.xlsx", n=len(filas) - max_rows)))


def _flujos_fw(res: Assessment) -> list:
    """Seccion 'Flujos entre interfaces del firewall' (XD-c)."""
    s = _rf.seccion(res.rutas, res.conduits)
    b = [("h1", t("Flujos entre interfaces del firewall")), ("nota", t(_rf.NOTA)), ("p", s["resumen"])]
    b += [("nota", aviso) for aviso in s["avisos"]]
    b.append(("tabla", s["cab_matriz"], s["matriz"]))
    if s["mas"]:
        b.append(("nota", s["mas"]))
    b.append(("tabla", s["cab_interfaces"], s["interfaces"]))
    return b


def construir_bloques(res: Assessment) -> list:
    caps, conduits, args = res.caps, res.conduits, res.args
    n_activos = _ip.contar(res)      # I3 (D105): las mismas filas que inventario.csv
    estandares = res.estandares or [ESTANDARES["iec62443"]]
    b = [("titulo", args.titulo),
         ("subtitulo", f"{args.cliente} - {datetime.now().astimezone().strftime('%Y-%m-%d')}")]
    if res.perfil:
        if res.perfil.get("clasificacion"):
            b.append(("nota", f"{t('Clasificacion')}: {res.perfil['clasificacion']}"))
        if res.perfil.get("leyenda_salidas"):
            b.append(("nota", f"{t('Leyenda de salidas')}: {res.perfil['leyenda_salidas']}"))
        b += [("h1", t("Perfil del proyecto")),
              ("tabla", [t("Campo"), t("Valor")], [list(x) for x in _perfil.etiquetas(res.perfil)]),
              ("nota", t(_perfil.NOTA))]
    if _cc.hay(res.cobertura_captura):      # C1 (D80): al inicio, antes del resumen
        s = _cc.seccion(res.cobertura_captura)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", *s["tabla"]),
              ("tabla", *s["tabla_zonas"])]

    by_sev = collections.Counter(f["severidad"] for c in [*caps, *res.extras] for f in c.findings)
    b += [("h1", t("Resumen")),
          ("tabla", [t("Concepto"), t("Valor")],
           ([[t("Capturas"), len(caps)], [t("Paquetes"), sum(c.flow_packets for c in caps)]] if caps
            else [list(x) for x in filas_fuentes(res)])
           + [[t("Activos"), n_activos],
            [t("Conductos"), len(conduits)],
            [t("Conductos que cruzan zonas"), sum(1 for c in conduits if c["cruza_zona"])]]
           + [[f"{t('Hallazgos')} {t(s).lower()}", by_sev.get(s, 0)]
              for s in ("Alta", "Media", "Baja", "Informativa")])]

    b.append(("h1", t("Hallazgos")))
    avisos = _avisos(estandares)
    if avisos:
        b.append(("nota", " ".join(avisos)))
    for f in agrupar_hallazgos([*caps, *res.extras]):
        b += [("h2", f"{t(f['severidad'])} - {t(f['titulo'])} ({f['id']})"),
              ("p", f"{t('Evidencia')}: {t(f['evidencia'])}"),
              ("p", f"{t('Por que importa')}: {t(f['por_que_importa'])}"),
              ("p", f"{t('Recomendacion')}: {t(f['recomendacion'])}")]
        for n, txt in referencias_visibles(f, estandares):
            b.append(("p", f"{t('Referencias')} - {n}: {txt}"))
        b.append(("p", t("Capturas" if caps else "Fuentes") + ": " + ", ".join(sorted(set(f["capturas"])))))

    if caps:        # sin capturas no hay trafico DNS
        b.append(("h1", t("Resolucion de nombres (DNS)")))
        sd = _rd.seccion(res)
        if sd is None:
            b.append(("p", t(_rd.SIN_DNS)))
        else:
            b += [("p", sd["resumen"]), ("tabla", sd["cab_nombres"], sd["nombres"])]
            if sd["mas"]:
                b.append(("nota", t(_rd.NOTA_MAS)))
            b.append(("tabla", sd["cab_servidores"], sd["servidores"]))
    if res.rutas and not res.firewall:
        b += _flujos_fw(res)

    pr = _rem.resumen(res)
    b += [("h1", t("Plan de remediacion")), ("nota", t(_rem.NOTA))]
    if pr["filas"]:
        b += [("p", "; ".join(f"{k}: {v}" for k, v in pr["conteo"].items()) + "."),
              ("tabla", [t(c) for c in _rem.CAB_REPORTE], pr["filas"]),
              ("p", t(_rem.NOTA_ESFUERZO))]
    else:
        b.append(("p", t(_rem.SIN_PRIORIZAR)))
    if pr["playbooks"]:
        b += [("h1", t(_pb.TITULO)), ("nota", t(_pb.NOTA))]
        for pb in pr["playbooks"]:
            b.append(("h2", f"{pb['titulo']} ({pb['id']})"))
            for etiqueta, items, ordenada in pb["bloques"]:
                b += [("p", etiqueta),
                      ("lista", [f"{i}. {x}" if ordenada else x for i, x in enumerate(items, 1)])]

    s = _rg.seccion(_rg.de(res))
    b += [("h1", s["titulo"]), ("nota", s["nota"])]
    if s["vacia"]:
        b.append(("p", s["vacia"]))
    else:
        cab, filas, niveles = s["mapa"]
        b += [("p", s["resumen"]),
              ("tabla", cab, filas, [[s["colores"].get(n) for n in fila] for fila in niveles]),
              ("tabla", s["cab_top"], s["top"]), ("p", s["nota_quick"])]
        b.append(("tabla", s["cab_quick"], s["quick"]) if s["quick"] else ("p", s["sin_quick"]))
        vs = s["valoracion"]
        if vs:      # RM2b (D130)
            b += [("h2", vs["titulo"]), ("tabla", vs["cab"], vs["filas"]), ("p", vs["frase"])]
            for titulo, (cab_v, filas_v, niv_v), _texto in vs["mapas"]:
                b += [("h2", titulo), ("tabla", cab_v, filas_v, [[s["colores"].get(n) for n in fila] for fila in niv_v])]

    if _ma.hay(res.madurez):        # M7 (D84)
        s = _ma.seccion(res.madurez)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]),
              ("p", t("Origen del objetivo") + ": " + s["origen_objetivo"]), ("tabla", s["cab"], s["filas"])]
        if s["equivalencia"]:       # MAD2 (D131)
            b += [("h2", s["equivalencia"]["titulo"]), ("tabla", s["equivalencia"]["cab"], s["equivalencia"]["filas"])]

    if _ct.hay(res.csf_tiers):      # CSF2T (D110)
        s = _ct.seccion(res.csf_tiers)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]),
              ("p", t("Origen del objetivo") + ": " + s["origen_objetivo"]), ("tabla", s["cab"], s["filas"])]

    por_hoja = {hoja: (cab, filas) for _a, hoja, cab, filas in tablas(res) if hoja}
    cab, filas = por_hoja["Inventario"]
    b.append(("h1", t("Inventario de activos")))
    _recortada(cabecera_t(res, cab), filas, args.max_rows, b)
    if _zo.hay(res.zonas):
        zon = _zo.presentada(res.zonas, _ip.filas(res))
        b += [("h1", t(_zo.TITULO)), ("nota", t(_zo.NOTA))]
        if _zo.nota_partidas(zon):
            b.append(("nota", _zo.nota_partidas(zon)))
        b.append(("p", _zo.resumen_texto(zon)))
        _recortada(*_zo.tabla_reporte(zon), args.max_rows, b)
    if _in.hay(res.inventario_normalizado):
        s = _in.seccion(res.inventario_normalizado)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", *s["tabla"])]
    if _ob.hay(res.obsolescencia):
        s = _ob.seccion(res.obsolescencia)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", *s["tabla"])]
    if _zc.hay(res.zcr):
        b += [("h1", t(_zc.TITULO)), ("nota", t(_zc.NOTA)), ("p", _zc.resumen_texto(res.zcr)),
              ("tabla", *_zc.tabla_reporte(res.zcr))]
        d = res.diagrama_zcr
        if d:
            b.append(("imagen_svg", d.svg, d.slug,
                      t("Si el diagrama no se ve (Word anterior a 2016 u otro editor), abra {slug}.svg "
                        "o {slug}.drawio de la carpeta del reporte.", slug=d.slug)))
            if d.nota:
                b.append(("nota", d.nota))
    if _tb.hay(res.tobe):       # T1a (D85)
        s = _tb.seccion(res.tobe)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab_matriz"], s["matriz"]),
              ("nota", s["leyenda"]), ("tabla", s["cab"], s["filas"])]
        if s["mas"]:
            b.append(("p", s["mas"]))
        d = res.diagrama_tobe
        if d:
            b.append(("imagen_svg", d.svg, d.slug,
                      t("Si el diagrama no se ve (Word anterior a 2016 u otro editor), abra {slug}.svg "
                        "o {slug}.drawio de la carpeta del reporte.", slug=d.slug)))
            b.append(("nota", d.nota))
    elif _tb.hay_seccion(res.tobe):
        s = _tb.seccion_vacia(res.tobe)
        b += [("h1", s["titulo"]), ("p", s["texto"])]
        if s["nota"]:
            b.append(("nota", s["nota"]))
    if _rac.hay(res.rutas_acceso):       # RUTA1 (D134)
        s = _rac.seccion(res.rutas_acceso)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab"], s["filas"])]
        if s["mas"]:
            b.append(("p", s["mas"]))
    if _rr.hay(res.registro_red):       # FWLOG (D137)
        s = _rr.seccion(res.registro_red)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab"], s["filas"])]
        if s["mas"]:
            b.append(("p", s["mas"]))
    if _hd.hay(res.hardening):       # T1b (D86)
        s = _hd.seccion(res.hardening)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab_tipos"], s["tipos"])]
        if s["top"]:
            b += [("p", s["titulo_top"]), ("tabla", s["cab_top"], s["top"])]
        else:
            b.append(("p", s["sin_top"]))
    if _vf.hay(res.vuln_firmware):     # V1a (D89)
        s = _vf.seccion(res.vuln_firmware)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"])]
        if s["tabla"][1]:
            b.append(("tabla", *s["tabla"]))
        for texto in (s["mas"], s["vacio"]):
            if texto:
                b.append(("p", texto))
    if _fl.hay(res.fuentes_log):       # G1a (D87)
        s = _fl.seccion(res.fuentes_log)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab_tipos"], s["tipos"])]
        if s["colectores"]:
            b.append(("tabla", s["cab_colectores"], s["colectores"]))
        for texto in (s["mas"], s["vacio"]):
            if texto:
                b.append(("p", texto))
    if _dr.hay(res.direccionamiento):       # G1b (D88)
        s = _dr.seccion(res.direccionamiento)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", s["cab_redes"], s["redes"])]
        if s["observaciones"]:
            b.append(("tabla", s["cab_obs"], s["observaciones"]))
        if s["mas"]:
            b.append(("p", s["mas"]))
    if _lb.hay(res.linea_base):
        s = _lb.seccion(res.linea_base)
        b +=[("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", *s["pivote"]),
              ("tabla", *s["top"]), ("nota", s["nota_cota"])]
    if _mc.hay(res.matriz_controles):
        s = _mc.seccion(res.matriz_controles, res.linea_base)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"]), ("tabla", *s["tabla"])]
        if s.get("tabla_zonas"):
            b += [("tabla", *s["tabla_zonas"])]
    if _sr.hay(res.salud_red):
        s = _sr.seccion(res.salud_red)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"])]
        for titulo, cab, filas in s["tablas"]:
            b += [("p", titulo), ("tabla", cab, filas)]
    if _se.hay(res.sensores):
        s = _se.seccion(res.sensores)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"])]
        for titulo, cab, filas in s["tablas"]:
            b += [("p", titulo), ("tabla", cab, filas)]
    if _tz.hay(res):
        s = _tz.seccion(res)
        b += [("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"])]
    if _lba.hay(res.linea_base_aprobada):
        s = _lba.seccion(res.linea_base_aprobada)
        b +=[("h1", s["titulo"]), ("nota", s["nota"]), ("p", s["resumen"])]
        for titulo, cab, filas in s["tablas"]:
            b += [("p", titulo), ("tabla", cab, filas)]
    if _ra.hay(res.rutas_ataque):
        b += [("h1", t(_ra.TITULO)), ("nota", t(_ra.NOTA)), ("p", _ra.resumen_texto(res.rutas_ataque)),
              ("tabla", *_ra.tabla_caminos(res.rutas_ataque)), ("tabla", *_ra.tabla_puntos(res.rutas_ataque))]
    cab, filas = por_hoja["Comunicaciones"]
    i = cab.index("cruza_zona")
    filas = sorted(filas, key=lambda f: f[i] != "si")  # estable: conserva el orden dentro de cada grupo
    b.append(("h1", t("Matriz de comunicaciones")))
    _recortada(cabecera_t(res, cab), filas, args.max_rows, b)

    if res.diagrams:
        b.append(("h1", t("Diagramas")))
        for d in res.diagrams:
            b += [("h2", d.titulo), ("p", d.descripcion),
                  ("imagen_svg", d.svg, d.slug,
                   t("Si el diagrama no se ve (Word anterior a 2016 u otro editor), abra {slug}.svg "
                     "o {slug}.drawio de la carpeta del reporte.", slug=d.slug))]
            if d.nota:
                b.append(("nota", d.nota))

    if res.vulnerabilidades:
        vr = res.vulnerabilidades
        b += [("h1", t("Vulnerabilidades importadas")),
              ("nota", t(_vuln.NOTA)),
              ("p", t("{archivo}: {total} filas, {asoc} asociadas a un activo, {sin} sin activo "
                      "en el inventario.", archivo=vr["archivo"], total=vr["total"],
                      asoc=vr["asociadas"], sin=vr["sin_activo"])),
              ("tabla", [t("Severidad"), *(t(e) for e in _vuln._ESTADOS)],
               [[t(s), *(fila[e] for e in _vuln._ESTADOS)] for s, fila in vr["matriz"].items()])]

    if res.alertas:
        b += [("h1", t("Alertas importadas")),
              ("nota", t(_al.NOTA)),
              ("p", _al.intro(res.alertas))]
        b += [("tabla", cab, filas) for cab, filas in _al.tablas_resumen(res.alertas)]

    if _fu.hay(res.fuentes):
        b += [("h1", t(_fu.TITULO)), ("nota", t(_fu.NOTA)), ("p", _fu.resumen_texto(res.fuentes)),
              ("tabla", _fu.cabecera_resumen(), _fu.filas_resumen(res.fuentes))]

    if _sw.hay(res.switches):
        b += [("h1", t(_sw.TITULO)), ("nota", t(_sw.NOTA)), ("p", _sw.resumen_texto(res.switches))]
        for tit, cab, filas in _sw.tablas_reporte(res.switches):
            b += [("h2", tit), ("tabla", cab, filas)]

    if res.firewall:
        b += [("h1", t("Politica de firewall")),
              ("nota", t(_firewall.NOTA)),
              ("tabla", [t("Resultado"), t("Cantidad")],
               [[t(rot), res.firewall["resumen"][k]] for k, rot in _RESULTADOS_FW
                if k in res.firewall["resumen"]])]
        if res.firewall.get("reglas"):
            b.append(("p", _fi.resumen_texto(res.firewall)))
        if res.firewall.get("rutas_estado"):
            b.append(("p", _fi.resumen_rutas_texto(res.firewall)))
        if _tp.es_multiple(res.firewall):
            b += [("h1", t(_tp.TITULO)), ("nota", t(_tp.NOTA)), ("p", _tp.resumen_texto(res.firewall))]
            b += [("tabla", cab, filas) for cab, filas in _tp.tablas_reporte(res.firewall)]
        if _cr.hay(res.firewall):
            b += [("h1", t(_cr.TITULO)), ("nota", t(_cr.NOTA)),
                  ("p", _cr.resumen_texto(res.firewall["cruces"])),
                  ("tabla", _cr.cabecera_pares(), _cr.pares_top(res.firewall["cruces"]))]
        if _po.hay(res.firewall):
            b += [("h1", t(_po.TITULO)), ("nota", t(_po.NOTA)), ("p", _po.resumen_texto(res.firewall["politica"]))]
            for tit, cab, filas in _po.tablas_reporte(res.firewall["politica"]):
                b += [("h2", tit), ("tabla", cab, filas)]
        if _rp.hay(res.firewall):
            b += [("h1", t(_rp.TITULO)), ("nota", t(_rp.NOTA)),
                  ("p", _rp.resumen_texto(res.firewall["rutas_propuestas"]))]
            for tit, cab, filas in _rp.tablas_reporte(res.firewall["rutas_propuestas"]):
                b += [("h2", tit), ("tabla", cab, filas)]
        if res.rutas:
            b += _flujos_fw(res)

    for e, _filas, resum in _cobertura.de_corrida(res):
        b += [("h1", t("Cobertura de {nombre}", nombre=e.nombre)),
              ("nota", t(_cobertura.NOTA))]
        if e.clave in _cobertura.NOTAS_MARCO:
            b.append(("nota", t(_cobertura.NOTAS_MARCO[e.clave])))
        b.append(("tabla", [t(x) for x in ("Grupo", "Total", "Directa", "Apoyo", "No evidenciable")],
                  [[g, s["total"], s[_cobertura.DIRECTA], s[_cobertura.APOYO], s[_cobertura.NO_EVID]]
                   for g, s in resum.items()]))

    b += [("h1", t("Preguntas para la sesion")), ("lista", client_questions()),
          ("h1", t("Entorno de analisis")),
          ("tabla", [t("Campo"), t("Valor")], [list(x) for x in _entorno.lineas(res.entorno)])]
    return b


def write_docx(res: Assessment, outdir: Path) -> Path:
    return escribir_docx(outdir / "informe_ot.docx", construir_bloques(res))
