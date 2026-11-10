"""Diagramas de red a partir del inventario y la matriz de comunicaciones.

Funciona igual con datos de capturas (ot_assess.consolidate) o importados de una plataforma
OT (ot_assess.importers): solo necesita `assets` y `conduits` con la forma documentada en
consolidate.py.

Para agregar una vista: un constructor de Grafo en graph.py, un render y una fila en VISTAS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from ..i18n import t
from ..standards import ESTANDARES
from .drawio import render_drawio
from .graph import Grafo, construir_activos, construir_zonas
from .mermaid import render_mermaid
from .svg import render_topologia, render_zonas


@dataclass
class Diagrama:
    slug: str            # nombre base de los archivos
    titulo: str
    descripcion: str
    svg: str             # para incrustar en una pagina: sin encabezado
    mermaid: str
    nota: str = ""
    svg_completo: str = ""   # archivo autonomo: con encabezado de titulo, cliente y fuente
    drawio: str = ""         # XML de draw.io (diagrams.net), editable


@dataclass
class Opciones:
    max_nodos: int = 40
    max_aristas: int = 60
    agrupar: str = "nivel"        # "nivel" (Purdue), "zona" (de la plataforma) o "interfaz" (del firewall)
    origen: str = "inferido"      # "inferido" (de capturas) o "plataforma" (importado)
    estandar: object = None
    titulo: str = ""              # encabezado del SVG autonomo
    cliente: str = ""
    fuente: str = ""
    fecha: str = field(default_factory=lambda: date.today().strftime("%d/%m/%Y"))


def _agrupacion(o: Opciones) -> str:
    if o.agrupar == "interfaz":
        return t("interfaz del firewall (segun su tabla de rutas)")
    if o.agrupar == "zona":
        return t("zona de seguridad definida en la plataforma")
    return t("nivel Purdue informado por la plataforma" if o.origen == "plataforma"
             else "nivel Purdue inferido")


def _encabezado(o: Opciones, titulo: str) -> dict:
    partes = [p for p in (o.cliente, o.fuente, o.estandar.nombre if o.estandar else "", o.fecha) if p]
    return {"titulo": f"{o.titulo} - {titulo}" if o.titulo else titulo, "subtitulo": "  ·  ".join(partes)}


def _zonas(assets, conduits, o: Opciones) -> Diagrama | None:
    g: Grafo = construir_zonas(assets, conduits, o.agrupar)
    if len(g.nodos) < 2:
        return None
    titulo = t("Diagrama de zonas y conductos")
    return Diagrama(
        "diagrama_zonas", titulo,
        t("Una caja por {agrupacion} y, entre cajas, los conductos que las cruzan: cuantos son, "
          "que servicios llevan y cuantos transportan escrituras. Los conductos entre cajas son los "
          "candidatos naturales a control {cruce}.", agrupacion=_agrupacion(o), cruce=t(o.estandar.cruce) if o.estandar.cruce else ""),
        render_zonas(g, "z"), render_mermaid(g), "",
        render_zonas(g, "zc", _encabezado(o, titulo)),
        render_drawio(g, titulo, "diagrama_zonas"))


def _activos(assets, conduits, o: Opciones) -> Diagrama | None:
    g: Grafo = construir_activos(assets, conduits, o.max_nodos, o.max_aristas, o.agrupar)
    if not g.aristas:
        return None
    notas = []
    if g.omitidos:
        notas.append(t("Se muestran {n} de {total} equipos: primero los "
                       "que reciben escrituras o participan en conductos de criticidad alta, luego "
                       "los de mayor volumen.", n=len(g.nodos), total=len(g.nodos) + g.omitidos))
    if g.aristas_recortadas:
        notas.append(t("Para que el diagrama siga siendo legible se dibujan los {n} trazos "
                       "de mayor criticidad y volumen; {omitidos} trazos de menor peso entre "
                       "estos equipos no se dibujan.", n=len(g.aristas), omitidos=g.aristas_recortadas))
    nota = " ".join(notas) + (" " + t("El detalle completo esta en el inventario y la matriz de comunicaciones.")
                              if notas else "")
    titulo = t("Diagrama de comunicaciones por activo")
    return Diagrama(
        "diagrama_red", titulo,
        t("Cada equipo en la banda de su {agrupacion}. Los trazos unen equipos que se comunican; "
          "el color indica la criticidad del conducto y la marca W, que el equipo recibe escrituras al "
          "proceso. Pasar el cursor sobre un trazo o equipo muestra el detalle.",
          agrupacion=_agrupacion(o)),
        render_topologia(g, "t"), render_mermaid(g), nota,
        render_topologia(g, "tc", encabezado=_encabezado(o, titulo)),
        render_drawio(g, titulo, "diagrama_red"))


VISTAS = [_zonas, _activos]


def diagrama_zcr(zcr: dict, opciones: Opciones | None = None) -> Diagrama | None:
    """Diagrama de zonas y conductos ZCR (Z1b): una caja por zona, una linea por conducto C-xx."""
    from .. import conductos_zcr as _zc

    if not _zc.hay(zcr):
        return None
    o = opciones or Opciones()
    g = _zc.grafo(zcr)
    titulo = t("Diagrama de zonas y conductos (ZCR)")
    return Diagrama(
        _zc.SLUG, titulo,
        t("Una caja por zona y, entre cajas, los conductos entre zonas C-xx de la tabla: cuantos servicios "
          "llevan y, en otro estilo, los que tienen brechas marcadas para revisar."),
        render_zonas(g, "zcr"), render_mermaid(g), _zc.nota_diagrama(zcr),
        render_zonas(g, "zcrc", _encabezado(o, titulo)), render_drawio(g, titulo, _zc.SLUG))


def diagrama_tobe(tobe: dict, opciones: Opciones | None = None) -> Diagrama | None:
    """Diagrama de segmentacion propuesta (T1a): zonas por nivel Purdue, solo permitir y por DMZ."""
    from .. import tobe as _tb

    if not _tb.hay(tobe):
        return None
    g = _tb.grafo(tobe)
    if not g.aristas:
        return None
    o = opciones or Opciones()
    titulo = t(_tb.TITULO_DIAGRAMA)
    return Diagrama(
        _tb.SLUG, titulo,
        t("Una caja por zona, de la empresa (arriba) al control (abajo), con la DMZ entre ambas. Linea continua: "
          "comunicacion a permitir; discontinua: pasa por la DMZ en dos tramos. Lo que se bloquea o se revisa no "
          "se dibuja."),
        render_zonas(g, "tb"), render_mermaid(g), _tb.nota_diagrama(tobe),
        render_zonas(g, "tbc", _encabezado(o, titulo)), render_drawio(g, titulo, _tb.SLUG))


def build_all(assets: dict, conduits: list, opciones: Opciones | None = None) -> list:
    if not conduits:
        return []
    o = opciones or Opciones()
    o.estandar = o.estandar or ESTANDARES["iec62443"]
    return [d for d in (v(assets, conduits, o) for v in VISTAS) if d]
