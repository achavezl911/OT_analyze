"""Idioma de los reportes (D39): el texto en espanol del codigo es la clave del catalogo."""
from __future__ import annotations

import json
from pathlib import Path

IDIOMAS = ("es", "en")
DIR_CATALOGOS = Path(__file__).parent / "catalogos"

FALTANTES: set = set()          # claves pedidas en ingles que el catalogo no trae
_estado = {"idioma": "es", "catalogo": {}}


def usar(idioma: str) -> None:
    """Fija el idioma del proceso y carga el catalogo una vez."""
    if idioma not in IDIOMAS:
        raise SystemExit(f"[!] Idioma '{idioma}' no valido; use uno de: {', '.join(IDIOMAS)}.")
    cat: dict = {}
    if idioma != "es":
        p = DIR_CATALOGOS / f"{idioma}.json"
        try:
            cat = json.loads(p.read_text(encoding="utf-8"))[idioma]
        except (OSError, ValueError, KeyError) as e:
            raise SystemExit(f"[!] No pude leer el catalogo de idioma '{idioma}': {e}")
    _estado["idioma"], _estado["catalogo"] = idioma, cat


_leidos: dict = {}


def catalogo(idioma: str) -> dict:
    """Catalogo es -> `idioma` leido del disco sin cambiar el idioma del proceso (vacio si no se puede leer)."""
    if idioma not in _leidos:
        try:
            _leidos[idioma] = json.loads((DIR_CATALOGOS / f"{idioma}.json").read_text(encoding="utf-8"))[idioma]
        except (OSError, ValueError, KeyError):
            _leidos[idioma] = {}
    return _leidos[idioma]


def idioma() -> str:
    return _estado["idioma"]


class Traducido(str):
    """Texto ya pasado por t(): t() no lo busca de nuevo ni lo marca como faltante."""
    __slots__ = ()


def unir(sep: str, piezas) -> str:
    """sep.join(piezas); es Traducido solo si todas las piezas lo son (si no, el reporte lo marca faltante)."""
    piezas = list(piezas)
    s = sep.join(piezas)
    return Traducido(s) if all(isinstance(p, Traducido) for p in piezas) else s


def t(texto: str, **kw) -> str:
    """Traduce `texto`; con kw aplica .format (sin kw no, hay textos con llaves).

    Siempre devuelve Traducido; un Traducido se devuelve tal cual (traducir dos veces es inofensivo).
    """
    if isinstance(texto, Traducido):
        return texto
    out = texto
    if _estado["idioma"] != "es":
        out = _estado["catalogo"].get(texto)
        if out is None:
            FALTANTES.add(texto)
            out = texto
    return Traducido(out.format(**kw) if kw else out)
