"""Escritor XLSX minimo con la biblioteca estandar (D11: OOXML es ZIP con XML).

Soporta varias hojas, encabezado en negrita, filtro, primera fila fija y anchos de columna.
Salida determinista: mismas hojas, mismos bytes.

Seguridad: las cadenas se escriben como inlineStr y Excel nunca las evalua como formula,
por lo que aqui NO se aplica el apostrofo de SEG-02 (el de los CSV).
"""
from __future__ import annotations

import re
import zipfile
from xml.sax.saxutils import escape

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_INVALIDO = re.compile(r"[\[\]:*?/\\]")
_CELDA = re.compile(r"([A-Z]+)(\d+)")  # fuera de la f-string: 3.9 no admite \ dentro de {}
_MAX_CELDA = 32767
_CABECERA = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


RELLENO = {"Bajo": "2", "Medio": "3", "Alto": "4", "Muy alto": "5"}     # verde, amarillo, naranja, rojo


def _txt(valor) -> str:
    return escape(_CTRL.sub("", str(valor))[:_MAX_CELDA], {'"': "&quot;", "'": "&apos;"})


def _col(n: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _nombres(hojas) -> list:
    usados, salida = set(), []
    for nombre in (h[0] for h in hojas):
        base = _INVALIDO.sub("", _CTRL.sub("", str(nombre))).strip("'")[:31] or "Hoja"
        n, cand = 2, base
        while cand.lower() in usados:
            suf = f" {n}"
            cand = base[:31 - len(suf)] + suf
            n += 1
        usados.add(cand.lower())
        salida.append(cand)
    return salida


def _celda(ref: str, v, estilo: str = "") -> str:
    if v is None:
        return ""
    s = f' s="{estilo}"' if estilo else ""
    if isinstance(v, bool):
        v = "Si" if v else "No"
    elif isinstance(v, (int, float)):
        return f'<c r="{ref}"{s}><v>{v!r}</v></c>'
    return f'<c r="{ref}"{s} t="inlineStr"><is><t xml:space="preserve">{_txt(v)}</t></is></c>'


def _hoja(cabecera, filas, rellenos=None) -> tuple:
    """Devuelve (xml, ultima_ref o '' si no hay filas). `rellenos`: estilo (RELLENO) por celda de `filas`."""
    ncol = max([len(cabecera)] + [len(f) for f in filas])
    ncol = max(ncol, 1)
    anchos = [len(_CTRL.sub("", str(h))) for h in cabecera] + [0] * (ncol - len(cabecera))
    for f in filas:
        for i, v in enumerate(f):
            if v is not None:
                anchos[i] = max(anchos[i], len(_CTRL.sub("", str(v if not isinstance(v, bool) else "Si"))))
    ultima = f"{_col(ncol)}{len(filas) + 1}"
    p = [_CABECERA, f'<worksheet xmlns="{NS_MAIN}" xmlns:r="{NS_R}">',
         f'<dimension ref="A1:{ultima}"/>',
         '<sheetViews><sheetView workbookViewId="0">'
         '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
         '</sheetView></sheetViews><cols>']
    for i, a in enumerate(anchos, 1):
        p.append(f'<col min="{i}" max="{i}" width="{min(60, max(10, a + 2))}" customWidth="1"/>')
    p.append("</cols><sheetData>")
    for n, fila in enumerate([cabecera] + [list(f) for f in filas], 1):
        rel = rellenos[n - 2] if rellenos and n > 1 else ()
        celdas = "".join(_celda(f"{_col(i)}{n}", v, "1" if n == 1 else (rel[i - 1] if i <= len(rel) else ""))
                         for i, v in enumerate(fila, 1))
        p.append(f'<row r="{n}">{celdas}</row>')
    p.append("</sheetData>")
    if filas:
        p.append(f'<autoFilter ref="A1:{ultima}"/>')
    p.append("</worksheet>")
    return "".join(p), (ultima if filas else "")


def _estilos(extra=()) -> str:
    """styles.xml; `extra` = colores RRGGBB adicionales (niveles del proyecto, RM2) con estilos 6, 7, ..."""
    n = len(extra)
    return (
        _CABECERA + f'<styleSheet xmlns="{NS_MAIN}">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        f'<fills count="{6 + n}"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        + "".join(f'<fill><patternFill patternType="solid"><fgColor rgb="FF{c}"/><bgColor indexed="64"/></patternFill></fill>'
                  for c in ("92D050", "FFE699", "F4B183", "FF5050", *extra)) + '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        f'<cellXfs count="{6 + n}"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        + "".join(f'<xf numFmtId="0" fontId="0" fillId="{i}" borderId="0" xfId="0" applyFill="1"/>' for i in range(2, 6 + n))
        + '</cellXfs>'
        '</styleSheet>')


_ESTILOS = _estilos()


def escribir_xlsx(path, hojas):
    """Escribe `hojas` = [(nombre, cabecera, filas[, rellenos])] en `path` y devuelve `path`.
    `rellenos` (opcional) es la matriz de estilos de color de las celdas de `filas` (ver RELLENO)."""
    nombres = _nombres(hojas)
    extra: list = []        # colores RRGGBB de los niveles del proyecto (RM2): estilos 6, 7, ...

    def estilo(v):
        if isinstance(v, str) and len(v) == 6:
            if v not in extra:
                extra.append(v)
            return str(6 + extra.index(v))
        return v

    partes = [_hoja(list(h[1]), h[2], [[estilo(v) for v in f] for f in h[3]] if len(h) > 3 and h[3] else None)
              for h in hojas]
    n = len(hojas)
    ct = (_CABECERA + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
          + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                    for i in range(1, n + 1)) + "</Types>")
    rels = (_CABECERA + f'<Relationships xmlns="{NS_REL}"><Relationship Id="rId1" '
            f'Type="{NS_R}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    defs = "".join(
        f'<definedName name="_xlnm._FilterDatabase" localSheetId="{i}" hidden="1">'
        f"'{_txt(nombres[i].replace(chr(39), chr(39) * 2))}'!$A$1:${'$'.join(_CELDA.match(ult).groups())}"
        "</definedName>"
        for i, (_, ult) in enumerate(partes) if ult)
    wb = (_CABECERA + f'<workbook xmlns="{NS_MAIN}" xmlns:r="{NS_R}"><sheets>'
          + "".join(f'<sheet name="{_txt(nombres[i])}" sheetId="{i + 1}" r:id="rId{i + 1}"/>'
                    for i in range(n)) + "</sheets>"
          + (f"<definedNames>{defs}</definedNames>" if defs else "") + "</workbook>")
    wbrels = (_CABECERA + f'<Relationships xmlns="{NS_REL}">'
              + "".join(f'<Relationship Id="rId{i}" Type="{NS_R}/worksheet" Target="worksheets/sheet{i}.xml"/>'
                        for i in range(1, n + 1))
              + f'<Relationship Id="rId{n + 1}" Type="{NS_R}/styles" Target="styles.xml"/></Relationships>')
    todas = [("[Content_Types].xml", ct), ("_rels/.rels", rels), ("xl/workbook.xml", wb),
             ("xl/_rels/workbook.xml.rels", wbrels), ("xl/styles.xml", _estilos(extra) if extra else _ESTILOS)]
    todas += [(f"xl/worksheets/sheet{i}.xml", x) for i, (x, _) in enumerate(partes, 1)]
    with zipfile.ZipFile(path, "w") as z:
        for nombre, contenido in todas:
            zi = zipfile.ZipInfo(nombre, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o600 << 16
            z.writestr(zi, contenido.encode("utf-8"))
    return path
