"""Archivos de diagrama: SVG autocontenido, fuente Mermaid y draw.io editables."""
from __future__ import annotations

from pathlib import Path

from ..model import Assessment


def write_diagrams(res: Assessment, outdir: Path) -> list:
    paths = []
    for d in [*res.diagrams, *([res.diagrama_zcr] if res.diagrama_zcr else []),
              *([res.diagrama_tobe] if res.diagrama_tobe else [])]:
        svg = outdir / f"{d.slug}.svg"
        svg.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + (d.svg_completo or d.svg) + "\n", encoding="utf-8")
        mmd = outdir / f"{d.slug}.mmd"
        mmd.write_text(d.mermaid, encoding="utf-8")
        paths += [svg, mmd]
        if d.drawio:
            dio = outdir / f"{d.slug}.drawio"
            dio.write_text(d.drawio, encoding="utf-8")
            paths.append(dio)
    return paths
