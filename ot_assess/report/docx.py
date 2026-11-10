"""Escritor DOCX minimo con la biblioteca estandar (D11: OOXML es ZIP con XML).

Bloques: titulo, subtitulo, h1, h2, p, nota, lista, tabla, salto, imagen_svg. Salida determinista:
mismos bloques, mismos bytes. Sin docProps (evita fechas).
"""
from __future__ import annotations

import re
import struct
import zipfile
import zlib
from xml.sax.saxutils import escape

NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CABECERA = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_ESTILOS_P = {"titulo": "Title", "subtitulo": "Subtitle", "h1": "Heading1", "h2": "Heading2"}

NS_WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
NS_PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"
NS_ASVG = "http://schemas.microsoft.com/office/drawing/2016/SVG/main"
NS_SVG = "http://www.w3.org/2000/svg"
_ANCHO_EMU = 5940000     # 16,5 cm
_ALTO_MAX_EMU = 7920000  # 22 cm


def _png_respaldo() -> bytes:
    """PNG de 8x8 gris claro (#eeeeee), RGB de 8 bits, sin dependencias."""
    def trozo(tipo, datos):
        c = zlib.crc32(tipo + datos) & 0xFFFFFFFF
        return struct.pack(">I", len(datos)) + tipo + datos + struct.pack(">I", c)
    crudo = (b"\x00" + b"\xee\xee\xee" * 8) * 8
    return (b"\x89PNG\r\n\x1a\n" + trozo(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
            + trozo(b"IDAT", zlib.compress(crudo, 9)) + trozo(b"IEND", b""))


def _dimensiones_svg(svg: str):
    # Solo se lee la etiqueta raiz con regex: no se parsea el SVG (bandit B314).
    et = re.search(r"<svg\b[^>]*>", svg)
    if not et:
        raise ValueError("SVG sin etiqueta <svg>")

    def attr(nombre):
        m = re.search(r'(?<![\w:-])' + nombre + r'\s*=\s*["\']([^"\']+)["\']', et.group(0))
        return m.group(1) if m else ""

    n = re.split(r"[\s,]+", attr("viewBox").strip())
    if len(n) == 4:
        try:
            return float(n[2]), float(n[3])
        except ValueError:
            pass
    vals = []
    for nombre in ("width", "height"):
        m = re.fullmatch(r"\s*([0-9]*\.?[0-9]+)\s*(px)?\s*", attr(nombre))
        if attr(nombre) and not m:
            raise ValueError(f"unidad de SVG no soportada en {nombre}: {attr(nombre)!r}")
        vals.append(m)
    if all(vals):
        return float(vals[0].group(1)), float(vals[1].group(1))
    raise ValueError("SVG sin viewBox ni width/height")


def _svg_autonomo(svg: str) -> str:
    svg = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", svg)
    m = re.search(r"<svg\b[^>]*>", svg)
    if m and not re.search(r'(?<![\w:])xmlns=', m.group(0)):
        svg = svg[:m.start()] + f'<svg xmlns="{NS_SVG}"' + svg[m.start() + 4:]
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + svg


def _imagen_svg(b, medios) -> str:
    if len(b) != 4:
        raise ValueError(f"bloque invalido: {b!r}")
    _t, svg_texto, nombre, pie = b
    w, h = _dimensiones_svg(svg_texto)
    if w <= 0 or h <= 0:
        raise ValueError("SVG con dimensiones no positivas")
    cx = _ANCHO_EMU
    cy = round(cx * h / w)
    if cy > _ALTO_MAX_EMU:
        cx, cy = round(cx * _ALTO_MAX_EMU / cy), _ALTO_MAX_EMU
    n = len(medios) + 1
    rpng, rsvg = f"rIdImg{2 * n - 1}", f"rIdImg{2 * n}"
    medios.append((nombre, _svg_autonomo(svg_texto), rpng, rsvg))
    dib = (
        f'<w:drawing><wp:inline xmlns:wp="{NS_WP}" distT="0" distB="0" distL="0" distR="0">'
        f'<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{n}" name="{_txt(nombre)}"/>'
        f'<a:graphic xmlns:a="{NS_A}"><a:graphicData uri="{NS_PIC}">'
        f'<pic:pic xmlns:pic="{NS_PIC}"><pic:nvPicPr><pic:cNvPr id="{n}" name="{_txt(nombre)}.png"/>'
        "<pic:cNvPicPr/></pic:nvPicPr>"
        f'<pic:blipFill><a:blip r:embed="{rpng}"><a:extLst>'
        '<a:ext uri="{96DAC541-7B7A-43D3-8B79-37D633B846F1}">'
        f'<asvg:svgBlip xmlns:asvg="{NS_ASVG}" r:embed="{rsvg}"/></a:ext></a:extLst></a:blip>'
        "<a:stretch><a:fillRect/></a:stretch></pic:blipFill>"
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
        "</a:graphicData></a:graphic></wp:inline></w:drawing>")
    return f"<w:p><w:r>{dib}</w:r></w:p>" + _par(pie, rpr='<w:i/><w:color w:val="595959"/>')


def _txt(valor) -> str:
    return escape(_CTRL.sub("", str(valor)), {'"': "&quot;", "'": "&apos;"})


def _runs(texto, rpr: str = "") -> str:
    """Texto en runs; cada salto de linea pasa a <w:br/>."""
    rp = f"<w:rPr>{rpr}</w:rPr>" if rpr else ""
    partes = _CTRL.sub("", str(texto)).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    salida = []
    for i, t in enumerate(partes):
        br = "<w:br/>" if i else ""
        salida.append(f'<w:r>{rp}{br}<w:t xml:space="preserve">{_txt(t)}</w:t></w:r>')
    return "".join(salida)


def _par(texto, estilo: str = "", rpr: str = "", extra: str = "") -> str:
    ppr = ""
    if estilo or extra:
        ppr = "<w:pPr>" + (f'<w:pStyle w:val="{estilo}"/>' if estilo else "") + extra + "</w:pPr>"
    return f"<w:p>{ppr}{_runs(texto, rpr)}</w:p>"


def _celda_txt(v) -> str:
    if v is None:
        return ""
    return v if isinstance(v, str) else str(v)


def _tabla(cabecera, filas, rellenos=None) -> str:
    """`rellenos` (opcional): color hex (p. ej. "FF5050") o None por celda de `filas`."""
    ncol = max([len(cabecera)] + [len(f) for f in filas] + [1])

    def fila(valores, es_cab, color=()):
        valores = list(valores) + [None] * (ncol - len(valores))
        trpr = "<w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>" if es_cab else "<w:trPr><w:cantSplit/></w:trPr>"
        rpr = "<w:b/>" if es_cab else ""
        celdas = []
        for i, v in enumerate(valores):
            c = "D9D9D9" if es_cab else (color[i] if i < len(color) else None)
            tcpr = f'<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="{c}"/></w:tcPr>' if c else ""
            celdas.append(f"<w:tc>{tcpr}{_par(_celda_txt(v), rpr=rpr)}</w:tc>")
        return f"<w:tr>{trpr}{''.join(celdas)}</w:tr>"

    grid = "".join('<w:gridCol w:w="%d"/>' % (9972 // ncol) for _ in range(ncol))
    cuerpo = fila(cabecera, True) + "".join(fila(f, False, rellenos[k] if rellenos else ())
                                            for k, f in enumerate(filas))
    return ('<w:tbl><w:tblPr><w:tblStyle w:val="TablaBordes"/><w:tblW w:w="5000" w:type="pct"/>'
            '<w:tblLook w:val="04A0" w:firstRow="1"/></w:tblPr>'
            f"<w:tblGrid>{grid}</w:tblGrid>{cuerpo}</w:tbl>" + "<w:p/>")


def _bloque(b, medios) -> str:
    if not isinstance(b, (tuple, list)) or not b:
        raise ValueError(f"bloque invalido: {b!r}")
    tipo = b[0]
    if tipo in _ESTILOS_P and len(b) == 2:
        return _par(b[1], _ESTILOS_P[tipo])
    if tipo == "p" and len(b) == 2:
        return _par(b[1])
    if tipo == "nota" and len(b) == 2:
        return _par(b[1], rpr='<w:i/><w:color w:val="595959"/>')
    if tipo == "lista" and len(b) == 2:
        return "".join(_par(t, "ListParagraph", extra='<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>')
                       for t in b[1])
    if tipo == "tabla" and len(b) in (3, 4):
        return _tabla(list(b[1]), [list(f) for f in b[2]], b[3] if len(b) == 4 else None)
    if tipo == "imagen_svg":
        return _imagen_svg(b, medios)
    if tipo == "salto" and len(b) == 1:
        return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    raise ValueError(f"bloque desconocido: {tipo!r}")


def _estilo_p(sid, nombre, ppr="", rpr="", base="Normal", outline=None):
    o = f'<w:outlineLvl w:val="{outline}"/>' if outline is not None else ""
    return (f'<w:style w:type="paragraph" w:styleId="{sid}"><w:name w:val="{nombre}"/>'
            f'<w:basedOn w:val="{base}"/><w:next w:val="Normal"/><w:qFormat/>'
            f"<w:pPr>{ppr}{o}</w:pPr><w:rPr>{rpr}</w:rPr></w:style>")


_ESTILOS = (
    _CABECERA + f'<w:styles xmlns:w="{NS_W}"><w:docDefaults><w:rPrDefault><w:rPr>'
    '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/><w:szCs w:val="20"/>'
    '</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120"/></w:pPr></w:pPrDefault></w:docDefaults>'
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
    + _estilo_p("Title", "Title", '<w:keepNext/><w:spacing w:before="0" w:after="240"/>',
                '<w:b/><w:sz w:val="48"/><w:szCs w:val="48"/>')
    + _estilo_p("Subtitle", "Subtitle", '<w:spacing w:after="240"/>',
                '<w:color w:val="595959"/><w:sz w:val="28"/><w:szCs w:val="28"/>')
    + _estilo_p("Heading1", "heading 1", '<w:keepNext/><w:spacing w:before="360" w:after="120"/>',
                '<w:b/><w:sz w:val="32"/><w:szCs w:val="32"/>', outline=0)
    + _estilo_p("Heading2", "heading 2", '<w:keepNext/><w:spacing w:before="240" w:after="80"/>',
                '<w:b/><w:sz w:val="26"/><w:szCs w:val="26"/>', outline=1)
    + _estilo_p("ListParagraph", "List Paragraph", '<w:spacing w:after="40"/><w:ind w:left="720"/>')
    + '<w:style w:type="table" w:styleId="TablaBordes"><w:name w:val="Tabla con bordes"/>'
      '<w:basedOn w:val="Normal"/><w:tblPr><w:tblBorders>'
    + "".join(f'<w:{l} w:val="single" w:sz="4" w:space="0" w:color="808080"/>'
              for l in ("top", "left", "bottom", "right", "insideH", "insideV"))
    + '</w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/>'
      "</w:tblCellMar></w:tblPr></w:style></w:styles>")

_NUMERACION = (
    _CABECERA + f'<w:numbering xmlns:w="{NS_W}"><w:abstractNum w:abstractNumId="0">'
    '<w:multiLevelType w:val="hybridMultilevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/>'
    '<w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/>'
    '<w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>'
    '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num></w:numbering>')

_CT = (
    _CABECERA + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
    "</Types>")

_RELS = (_CABECERA + f'<Relationships xmlns="{NS_REL}"><Relationship Id="rId1" '
         f'Type="{NS_R}/officeDocument" Target="word/document.xml"/></Relationships>')

_DOC_RELS = (_CABECERA + f'<Relationships xmlns="{NS_REL}">'
             f'<Relationship Id="rId1" Type="{NS_R}/styles" Target="styles.xml"/>'
             f'<Relationship Id="rId2" Type="{NS_R}/numbering" Target="numbering.xml"/></Relationships>')

_SECCION = ('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1134" w:right="1134" '
            'w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>')


def escribir_docx(path, bloques):
    """Escribe `bloques` (tuplas) en `path` y devuelve `path`. Bloque desconocido -> ValueError."""
    medios = []
    cuerpo = "".join(_bloque(b, medios) for b in bloques)
    doc = (_CABECERA + f'<w:document xmlns:w="{NS_W}" xmlns:r="{NS_R}"><w:body>'
           f"{cuerpo}{_SECCION}</w:body></w:document>")
    todas = [("[Content_Types].xml", _CT), ("_rels/.rels", _RELS), ("word/document.xml", doc),
             ("word/styles.xml", _ESTILOS), ("word/numbering.xml", _NUMERACION),
             ("word/_rels/document.xml.rels", _DOC_RELS)]
    if medios:
        png = _png_respaldo()
        rels = "".join(
            f'<Relationship Id="{rp}" Type="{NS_R}/image" Target="media/{n}.png"/>'
            f'<Relationship Id="{rs}" Type="{NS_R}/image" Target="media/{n}.svg"/>'
            for n, _s, rp, rs in medios)
        todas[0] = (todas[0][0], _CT.replace(
            "<Override", '<Default Extension="svg" ContentType="image/svg+xml"/>'
            '<Default Extension="png" ContentType="image/png"/><Override', 1))
        todas[5] = (todas[5][0], _DOC_RELS.replace("</Relationships>", rels + "</Relationships>"))
        for n, svg, _rp, _rs in medios:
            todas += [(f"word/media/{n}.svg", svg), (f"word/media/{n}.png", png)]
    with zipfile.ZipFile(path, "w") as z:
        for nombre, contenido in todas:
            zi = zipfile.ZipInfo(nombre, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o600 << 16
            z.writestr(zi, contenido if isinstance(contenido, bytes) else contenido.encode("utf-8"))
    return path
