"""Ayudas compartidas por los escritores de reporte."""
from __future__ import annotations

import csv
import re
from html import escape as esc

from ..i18n import Traducido, t
from ..riesgo import id_hallazgo

_NUMERO = re.compile(r"^[-+]?\d+([.,]\d+)?$")


def filas_fuentes(res) -> list:
    """[(etiqueta, valor)] de donde salen los datos cuando no hay capturas (analisis de
    exportaciones): plataforma, archivos importados (o las fuentes de trafico) y periodo."""
    e = res.entorno or {}
    archivos = list((res.fuentes or {}).get("nombres") or []) or [x["archivo"] for x in e.get("entradas", ())]
    fechas = [k[c] for k in res.conduits for c in ("primera", "ultima") if k.get(c)]
    filas = [(t("Plataforma"), e.get("plataforma") or t("ninguno")),
             (t("Archivos importados"), ", ".join(archivos) or t("ninguno"))]
    if fechas:
        filas.append((t("Periodo"), t("{a} a {b}", a=min(fechas), b=max(fechas))))
    return filas


def celda_csv(v):
    """Neutraliza una celda que una hoja de calculo leeria como formula (SEG-02)."""
    if isinstance(v, str) and v and v[0] in "=+-@\t\r" and v != "-" and not _NUMERO.match(v):
        return "'" + v
    return v


class escritor_csv:
    """csv.writer que aplica celda_csv a cada celda."""

    def __init__(self, fh):
        self._w = csv.writer(fh)

    def writerow(self, fila):
        self._w.writerow([celda_csv(c) for c in fila])

    def writerows(self, filas):
        for f in filas:
            self.writerow(f)


def md_escape(s: str) -> str:
    s = (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s.replace("|", "\\|").replace("\n", " ")


class Numerador:
    """Numera las secciones en el orden en que se escriben: las omitidas (escritor que descarta) no
    consumen numero, asi no hay saltos. La clave de traduccion conserva su numero; aqui se reemplaza."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, clave: str, activo: bool = True) -> str:
        texto = t(clave)
        if not activo:
            return texto
        self.n += 1
        return Traducido(re.sub(r"^\d+\. ", f"{self.n}. ", texto))


def strip_tags(s: str) -> str:
    """<strong>x</strong> -> **x**, para reutilizar los textos en Markdown."""
    s = re.sub(r"</?strong>", "**", s or "")
    return re.sub(r"<[^>]+>", "", s)


def crit_tag(level: str) -> str:
    cls = {"Critica": "t-critica", "Alta": "t-alta", "Media": "t-media",
           "Baja": "t-baja", "Informativa": "t-info"}.get(level, "t-info")
    return f'<span class="tag {cls}">{esc(t(level))}</span>'


_ORIGENES = ("conductos entre zonas", "rutas de ataque", "fuentes de trafico")
_PREFIJOS_ORIGEN = ("firewall", "exportacion", "vulnerabilidades", "alertas")


def nombre_origen(nombre: str) -> str:
    """Nombre del origen de un hallazgo que no es una captura (extras) traducido; el de una captura
    real (nombre de archivo) queda igual."""
    if nombre in _ORIGENES:
        return t(nombre)
    for p in _PREFIJOS_ORIGEN:
        if nombre.startswith(p + " "):
            return t(p) + nombre[len(p):]
    return nombre


def _unir(previa: str, etiqueta: str, evidencia: str) -> str:
    """previa + etiqueta + evidencia traducida (un texto plano sin traduccion queda en FALTANTES)."""
    return Traducido(previa + etiqueta + t(evidencia))


def agrupar_hallazgos(caps: list, marca: str = "") -> list:
    """Hallazgos iguales (titulo y severidad) de varias capturas, en un solo registro con
    `capturas` y la evidencia de cada una; ordenados por severidad y titulo. `marca` envuelve
    el nombre de la captura en la evidencia ("_" para Markdown)."""
    from ..catalog import SEV_ORDER

    grouped: dict = {}
    for c in caps:
        for f in c.findings:
            origen = nombre_origen(f["captura"])
            etiqueta = f"{marca}({origen}){marca} "
            k = (f["titulo"], f["severidad"])
            if k in grouped:
                grouped[k]["capturas"].append(origen)
                grouped[k]["evidencia"] = _unir(grouped[k]["evidencia"], "\n\n" + etiqueta, f["evidencia"])
                if f.get("activos"):
                    grouped[k]["activos"] = sorted({*grouped[k].get("activos", []), *f["activos"]})
            else:
                g = dict(f)
                g["id"] = f.get("id") or id_hallazgo(f["titulo"])
                g["capturas"] = [origen]
                g["evidencia"] = _unir("", etiqueta, f["evidencia"])
                grouped[k] = g
    return sorted(grouped.values(),
                  key=lambda f: (SEV_ORDER.get(f["severidad"], 9), f["titulo"]))


def referencias_visibles(hallazgo: dict, estandares: list) -> list:
    """[(nombre del marco, texto)] para MITRE y los marcos elegidos. Vacio si no hay ninguno."""
    from ..standards import MITRE, traducir_refs

    refs = hallazgo.get("referencias", {})
    filas = [(MITRE.nombre, refs[MITRE.clave])] if refs.get(MITRE.clave) else []   # ya en ingles
    for e in estandares:
        if refs.get(e.clave):
            filas.append((e.nombre, traducir_refs(refs[e.clave])))
        elif refs or filas:
            filas.append((e.nombre, "sin referencia directa"))
    if not any(x != "sin referencia directa" for _, x in filas):
        return []
    return [(n, t(x) if x == "sin referencia directa" else x) for n, x in filas]
