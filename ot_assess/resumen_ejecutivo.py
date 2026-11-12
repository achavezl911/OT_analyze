"""Resumen ejecutivo de una pagina (S5, D40): cinco riesgos principales, en HTML y Word.

Los cinco riesgos salen del registro de riesgos (riesgo.de, D83: probabilidad x impacto; D91), en su orden.
Los conteos por fase siguen saliendo del plan de remediacion (S4). Solo lee el modelo.
"""
from __future__ import annotations

import re
from datetime import datetime
from html import escape
from pathlib import Path

from . import remediacion as _rem
from . import riesgo as _rg
from .i18n import t

MAX_RIESGOS = 5
MAX_ACTIVOS = 3
MAX_RECOMENDACION = 160
NOTA = ("Resultado del trafico y los archivos analizados; no es una evaluacion de cumplimiento. "
        "El detalle esta en informe_ot.docx y en el plan de remediacion.")
ORDEN = ("Orden del registro de riesgos (probabilidad x impacto); el plan de remediacion por fases esta "
         "en el informe completo.")
_ORACION = re.compile(r"(?<=[.!?])\s")


def recortar(texto: str, maximo: int = MAX_RECOMENDACION) -> str:
    """Oraciones completas del texto mientras quepan en `maximo` caracteres; si ni la primera cabe,
    la primera recortada con '...'."""
    oraciones = _ORACION.split(texto.strip())
    s = oraciones[0]
    if len(s) > maximo:
        return s[:maximo - 3].rstrip() + "..."
    for o in oraciones[1:]:
        if len(s) + 1 + len(o) > maximo:
            break
        s += " " + o
    return s


def _activos(r: dict) -> str:
    ips = [ip for ip in r["activos"].split(";") if ip]
    if not ips:
        return "-"
    s = ", ".join(ips[:MAX_ACTIVOS])
    return s + t(" y {n} mas", n=len(ips) - MAX_ACTIVOS) if len(ips) > MAX_ACTIVOS else s


def datos(res) -> dict:
    from .report.common import agrupar_hallazgos

    args = res.args
    filas = _rem.plan(res)
    hall = agrupar_hallazgos([*res.caps, *res.extras])
    riesgos = []
    for n, r in enumerate(map(_rg._mostrar, _rg.de(res)["filas"][:MAX_RIESGOS]), 1):
        riesgos.append({"n": n, "id": r["id_riesgo"], "titulo": r["titulo"], "severidad": r["severidad"],
                        "nivel": r["nivel"],
                        "puntuacion": f"{r['probabilidad']} x {r['impacto']} = {r['puntuacion']}",
                        "activos": _activos(r), "recomendacion": recortar(r["recomendacion"])})
    return {
        "titulo": t("Resumen ejecutivo"), "proyecto": args.titulo,
        "subtitulo": f"{args.cliente} - {datetime.now().astimezone().strftime('%Y-%m-%d')}",
        "clasificacion": (res.perfil or {}).get("clasificacion", ""),
        "leyenda": (res.perfil or {}).get("leyenda_salidas", ""),
        "alcance": "; ".join(f"{t(k)}: {v}" for k, v in (
            *((("Capturas", len(res.caps)),) if res.caps else ()), ("Activos", len(res.assets)),
            ("Conductos", len(res.conduits)),
            ("Conductos que cruzan zonas", sum(1 for c in res.conduits if c["cruza_zona"])))) + ".",
        "severidades": [(t(s), sum(1 for f in hall if f["severidad"] == s))
                        for s in ("Alta", "Media", "Baja")],
        "fases": [(t(f), sum(1 for r in filas if r["fase"] == f)) for f in _rem.FASES],
        "riesgos": riesgos, "orden": t(ORDEN), "sin_riesgos": t(_rem.SIN_PRIORIZAR), "nota": t(NOTA),
    }


def _cab() -> list:
    return [t(c) for c in ("#", "ID", "Riesgo", "Severidad", "Nivel", "Puntuacion", "Activos", "Recomendacion")]


def _fila(r: dict) -> list:
    return [r["n"], r["id"], r["titulo"], r["severidad"], r["nivel"], r["puntuacion"], r["activos"],
            r["recomendacion"]]


def _conteos(titulo: str, pares) -> str:
    return f"{t(titulo)}: " + "; ".join(f"{k} {v}" for k, v in pares) + "."


_CSS = ("@page { size: letter; margin: 1.5cm }"
        "body { font-family: Arial, Helvetica, sans-serif; font-size: 10.5pt; color: #222; margin: 0 }"
        "h1 { font-size: 18pt; margin: 0 0 2pt } h2 { font-size: 12pt; margin: 12pt 0 4pt }"
        ".sub { color: #555; margin: 0 0 6pt } p { margin: 3pt 0 }"
        "table { border-collapse: collapse; width: 100%; font-size: 9.5pt }"
        "th, td { border: 1px solid #999; padding: 3pt 4pt; text-align: left; vertical-align: top }"
        "th { background: #eee } .nota { margin-top: 12pt; font-size: 9pt; color: #555; font-style: italic }")


def construir_html(d: dict) -> str:
    e = escape
    h = [(f"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{e(d['titulo'])}</title>"
          f"<style>{_CSS}</style></head><body>"),
         (f"<h1>{e(d['titulo'])}</h1><p class=\"sub\">{e(d['proyecto'])}</p>"
          f"<p class=\"sub\">{e(d['subtitulo'])}</p>")]
    if d["clasificacion"]:
        h.append(f"<p>{e(t('Clasificacion'))}: {e(d['clasificacion'])}</p>")
    if d["leyenda"]:
        h.append(f"<p>{e(t('Leyenda de salidas'))}: {e(d['leyenda'])}</p>")
    h.append(f"<h2>{e(t('Alcance'))}</h2><p>{e(d['alcance'])}</p>")
    h.append(f"<p>{e(_conteos('Hallazgos por severidad', d['severidades']))}</p>")
    h.append(f"<p>{e(_conteos('Hallazgos por fase del plan', d['fases']))}</p>")
    h.append(f"<h2>{e(t('Cinco riesgos principales'))}</h2>")
    if d["riesgos"]:
        h.append(f"<p>{e(d['orden'])}</p>")
        h.append("<table><tr>" + "".join(f"<th>{e(str(c))}</th>" for c in _cab()) + "</tr>")
        for r in d["riesgos"]:
            h.append("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in _fila(r)) + "</tr>")
        h.append("</table>")
    else:
        h.append(f"<p>{e(d['sin_riesgos'])}</p>")
    h.append(f"<p class=\"nota\">{e(d['nota'])}</p></body></html>")
    return "\n".join(h)


def construir_bloques(d: dict) -> list:
    b = [("titulo", d["titulo"]), ("subtitulo", d["proyecto"]), ("subtitulo", d["subtitulo"])]
    if d["clasificacion"]:
        b.append(("nota", f"{t('Clasificacion')}: {d['clasificacion']}"))
    if d["leyenda"]:
        b.append(("nota", f"{t('Leyenda de salidas')}: {d['leyenda']}"))
    b += [("h1", t("Alcance")), ("p", d["alcance"]),
          ("p", _conteos("Hallazgos por severidad", d["severidades"])),
          ("p", _conteos("Hallazgos por fase del plan", d["fases"])),
          ("h1", t("Cinco riesgos principales"))]
    if d["riesgos"]:
        b.append(("p", d["orden"]))
        b.append(("tabla", _cab(), [_fila(r) for r in d["riesgos"]]))
    else:
        b.append(("p", d["sin_riesgos"]))
    b.append(("nota", d["nota"]))
    return b


def write_resumen(res, outdir: Path) -> Path:
    from .report.docx import (
        escribir_docx,  # import tardio: report/__init__ importa este modulo
    )

    d = datos(res)
    ruta = Path(outdir) / "resumen_ejecutivo.html"
    ruta.write_text(construir_html(d), encoding="utf-8")
    escribir_docx(Path(outdir) / "resumen_ejecutivo.docx", construir_bloques(d))
    return ruta
