#!/usr/bin/env python3
"""Extrae la Tabla 22 (lineas base del overlay OT) de NIST SP 800-82r3 a ot_assess/marcos/nist80082_overlay.json.

Herramienta local (D77): necesita PyMuPDF (en el 105, ~/.venv-pdf/bin/python); ot_assess nunca la importa y la CI
no la corre. SP 800-82r3 es obra del gobierno de EE. UU.: se guardan ids, titulos oficiales y marcas, nunca las
discusiones. Convenciones de la tabla (Apendice F.3): negrita = control o mejora con discusion OT; subrayado = el
overlay lo agrega a esa linea base frente a SP 800-53B; tachado = el overlay lo quita de esa linea base (no cuenta).
Subrayado y tachado no viajan en el texto: son trazos delgados que se comparan con la caja de cada id o mejora.

Uso: ~/.venv-pdf/bin/python scripts/extraer_overlay_80082.py [--pdf normas/nist/NIST.SP.800-82r3.pdf]
     [--salida ot_assess/marcos/nist80082_overlay.json]
"""
import argparse
import json
import re
import sys
from pathlib import Path

import pymupdf

FAMILIAS = {
    "AC": "Control de acceso", "AT": "Concientizacion y capacitacion", "AU": "Auditoria y rendicion de cuentas",
    "CA": "Evaluacion, autorizacion y monitoreo", "CM": "Gestion de la configuracion", "CP": "Planes de contingencia",
    "IA": "Identificacion y autenticacion", "IR": "Respuesta a incidentes", "MA": "Mantenimiento",
    "MP": "Proteccion de medios", "PE": "Proteccion fisica y ambiental", "PL": "Planeacion",
    "PM": "Gestion del programa", "PS": "Seguridad del personal",
    "PT": "Tratamiento de datos personales y transparencia", "RA": "Evaluacion de riesgos",
    "SA": "Adquisicion de sistemas y servicios", "SC": "Proteccion de sistemas y comunicaciones",
    "SI": "Integridad del sistema y de la informacion", "SR": "Gestion de riesgos de la cadena de suministro",
}
NIVELES = ("baja", "moderada", "alta")
TOKEN = re.compile(r"[A-Z]{2}-\d+|\(\d+\)")
ID = re.compile(r"^[A-Z]{2}-\d+$")


def marcas(pagina):
    """Trazos delgados y cortos (candidatos a subrayado o tachado): [(x0, x1, y)]."""
    out = []
    for d in pagina.get_drawings():
        for it in d["items"]:
            if it[0] == "l" and abs(it[1].y - it[2].y) < 0.8:
                x0, x1, y = min(it[1].x, it[2].x), max(it[1].x, it[2].x), (it[1].y + it[2].y) / 2
            elif it[0] == "re" and it[1].height < 2.0:
                x0, x1, y = it[1].x0, it[1].x1, (it[1].y0 + it[1].y1) / 2
            else:
                continue
            if 2.5 < x1 - x0 < 60:
                out.append((x0, x1, y))
    return out


def bordes_primera_columna(pagina, x_der):
    """y de los bordes horizontales de la primera columna (separan filas)."""
    ys = []
    for d in pagina.get_drawings():
        for it in d["items"]:
            if it[0] == "l" and abs(it[1].y - it[2].y) < 0.8:
                x0, x1, y = min(it[1].x, it[2].x), max(it[1].x, it[2].x), it[1].y
            elif it[0] == "re" and it[1].height < 2.0:
                x0, x1, y = it[1].x0, it[1].x1, (it[1].y0 + it[1].y1) / 2
            else:
                continue
            if x0 < 80 and abs(x1 - x_der) < 3:
                ys.append(y)
    return sorted({round(y, 1) for y in ys})


def tokens(pagina):
    """[(texto, (x0, y0, x1, y1), negrita)] de ids y mejoras, con la caja de sus caracteres.

    Se arma por linea completa: un "(5)" puede venir partido en tramos con distinto formato (parentesis normal y
    numero en negrita) y buscarlo dentro de cada tramo lo pierde."""
    out = []
    for b in pagina.get_text("rawdict")["blocks"]:
        for linea in b.get("lines", []):
            chars = [(c["c"], c["bbox"], bool(s["flags"] & 16)) for s in linea["spans"] for c in s["chars"]]
            txt = "".join(c[0] for c in chars)
            for m in TOKEN.finditer(txt):
                cs = chars[m.start():m.end()]
                caja = (min(c[1][0] for c in cs), min(c[1][1] for c in cs),
                        max(c[1][2] for c in cs), max(c[1][3] for c in cs))
                out.append((m.group(0), caja, any(c[2] for c in cs if c[0].isalnum())))
    return out


def estilo(caja, trazos):
    """('subrayado' | 'tachado' | '') segun los trazos que cruzan la caja del token."""
    x0, y0, x1, y1 = caja
    h = max(y1 - y0, 1.0)
    res = ""
    for a, b, y in trazos:
        solape = min(x1, b) - max(x0, a)
        if solape < 0.5 * min(x1 - x0, b - a):
            continue
        rel = (y - y0) / h
        if 0.3 <= rel <= 0.72:
            return "tachado"
        if 0.72 < rel and y <= y1 + 2.5:
            res = "subrayado"
    return res


def columnas(pagina):
    """Limites x: (fin de la primera columna, inicio de LOW, LOW|MOD, MOD|HIGH)."""
    cen = {}
    for w in pagina.get_text("words"):
        if w[4] in ("LOW", "MOD", "HIGH") and w[4] not in cen:
            cen[w[4]] = (w[0] + w[2]) / 2
    if len(cen) < 3:
        return None
    paso = cen["MOD"] - cen["LOW"]
    return 114.4, cen["LOW"] - paso / 2, (cen["LOW"] + cen["MOD"]) / 2, (cen["MOD"] + cen["HIGH"]) / 2


def paginas_tabla(doc):
    ini = next(i for i, p in enumerate(doc) if "Table 22. Control baselines" in p.get_text()
               and "INITIAL CONTROL" in p.get_text())
    fin = ini
    while fin + 1 < doc.page_count and "INITIAL CONTROL" in doc[fin + 1].get_text():
        fin += 1
    return list(range(ini, fin + 1))


def extraer(pdf):
    doc = pymupdf.open(pdf)
    filas, avisos, sueltos = [], [], 0
    pags = paginas_tabla(doc)
    for n in pags:
        p = doc[n]
        lim = columnas(p)
        if not lim:
            avisos.append(f"pagina {n + 1}: sin cabecera LOW/MOD/HIGH")
            continue
        x_col1, x_low, x_lm, x_mh = lim
        trazos = marcas(p)
        toks = tokens(p)
        ids = sorted([t for t in toks if ID.match(t[0]) and t[1][0] < x_col1 - 2], key=lambda t: t[1][1])
        bordes = bordes_primera_columna(p, x_col1)
        palabras = p.get_text("words")
        for k, (cid, caja, neg) in enumerate(ids):
            yc = (caja[1] + caja[3]) / 2
            arriba = [y for y in bordes if y < yc]
            abajo = [y for y in bordes if y > yc]
            if arriba and abajo:
                banda = (arriba[-1], abajo[0])
            else:   # sin bordes: punto medio con los ids vecinos
                prev = (ids[k - 1][1][3] + caja[1]) / 2 if k else caja[1] - 30
                nxt = (caja[3] + ids[k + 1][1][1]) / 2 if k + 1 < len(ids) else caja[3] + 30
                banda = (prev, nxt)
                avisos.append(f"pagina {n + 1}: {cid} sin bordes de fila; banda por punto medio")
            titulo = " ".join(w[4] for w in sorted(palabras, key=lambda w: (round(w[1]), w[0]))
                              if x_col1 < (w[0] + w[2]) / 2 < x_low and banda[0] < (w[1] + w[3]) / 2 < banda[1])
            celdas = {}
            for nivel, (a, b) in zip(NIVELES, ((x_low, x_lm), (x_lm, x_mh), (x_mh, 600))):
                celdas[nivel] = [(t, estilo(c, trazos), ng) for t, c, ng in
                                 sorted(toks, key=lambda t: (round(t[1][1]), t[1][0]))
                                 if a < (c[0] + c[2]) / 2 < b and banda[0] < (c[1] + c[3]) / 2 < banda[1]]
            # solo la columna del medio con contenido = celda combinada sobre LOW, MOD y HIGH (filas PM): un control
            # solo en MOD contradiria la regla de que HIGH contiene a MOD
            combinada = (not celdas["baja"] and not celdas["alta"] and bool(celdas["moderada"])
                         and celdas["moderada"][0][0] == cid)
            if combinada:   # celda que cubre LOW, MOD y HIGH: aplica a toda la organizacion
                tok = celdas["moderada"]
                celdas = {nv: list(tok) for nv in NIVELES}
            filas.append({"id": cid, "negrita": neg, "estilo_id": estilo(caja, trazos), "titulo": titulo,
                          "celdas": celdas, "pagina": n + 1, "organizacion": combinada})
    return filas, avisos, sueltos, [x + 1 for x in pags]


def catalogo(filas):
    ctl, avisos = {}, []

    def nuevo(cid, titulo, fam):
        return ctl.setdefault(cid, {"familia": fam, "titulo": titulo, "discusion_ot": False,
                                    "niveles": {nv: {"incluido": False, "agregado": False, "quitado": False}
                                                for nv in NIVELES}})

    for f in filas:
        fam = f["id"].split("-")[0]
        base = nuevo(f["id"], f["titulo"], fam)
        base["discusion_ot"] |= f["negrita"]
        if f.get("organizacion"):
            base["toda_la_organizacion"] = True
        for nivel, toks in f["celdas"].items():
            for t, est, neg in toks:
                if ID.match(t):
                    if t != f["id"]:
                        avisos.append(f"{f['id']}: id {t} en la celda {nivel}")
                        continue
                    ent = base
                else:
                    ent = nuevo(f"{f['id']}{t}", "", fam)
                ent["discusion_ot"] |= neg
                ent["niveles"][nivel]["agregado"] |= est == "subrayado"
                ent["niveles"][nivel]["quitado"] |= est == "tachado"
                ent["niveles"][nivel]["incluido"] |= est != "tachado"
    return ctl, avisos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf", default="normas/nist/NIST.SP.800-82r3.pdf")
    ap.add_argument("--salida", default="ot_assess/marcos/nist80082_overlay.json")
    a = ap.parse_args()
    filas, avisos, _, pags = extraer(a.pdf)
    ctl, av2 = catalogo(filas)
    avisos += av2
    conteo = {nv: {"controles": sum(1 for k, v in ctl.items() if "(" not in k and v["niveles"][nv]["incluido"]),
                   "mejoras": sum(1 for k, v in ctl.items() if "(" in k and v["niveles"][nv]["incluido"]),
                   "agregados": sorted(k for k, v in ctl.items() if v["niveles"][nv]["agregado"]),
                   "quitados": sorted(k for k, v in ctl.items() if v["niveles"][nv]["quitado"])}
              for nv in NIVELES}
    no_monotono = sorted(k for k, v in ctl.items()
                         if (v["niveles"]["baja"]["incluido"] and not v["niveles"]["moderada"]["incluido"])
                         or (v["niveles"]["moderada"]["incluido"] and not v["niveles"]["alta"]["incluido"]))
    out = {
        "fuente": "NIST SP 800-82 Rev. 3 (septiembre 2023), Apendice F.3, Tabla 22 (lineas base del overlay OT "
                  "sobre NIST SP 800-53 Rev. 5)",
        "doi": "https://doi.org/10.6028/NIST.SP.800-82r3",
        "paginas_pdf": pags,
        "convenciones": {"discusion_ot": "negrita", "agregado": "subrayado: agregado por el overlay frente a "
                         "SP 800-53B", "quitado": "tachado: quitado por el overlay; no cuenta en esa linea base"},
        "familias": {k: {"es": v} for k, v in FAMILIAS.items() if any(c["familia"] == k for c in ctl.values())},
        "conteos": {nv: {k: (len(v) if isinstance(v, list) else v) for k, v in c.items()} for nv, c in conteo.items()},
        "fuera_de_orden": no_monotono,
        "controles": dict(sorted(ctl.items(), key=lambda kv: (kv[0].split("-")[0],
                                                            [int(x) for x in re.findall(r"\d+", kv[0])]))),
    }
    Path(a.salida).write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"paginas {pags}; filas {len(filas)}; entradas {len(ctl)}")
    for nv, c in conteo.items():
        print(f"{nv}: controles {c['controles']}, mejoras {c['mejoras']}, agregados {len(c['agregados'])} "
              f"{c['agregados'][:8]}, quitados {len(c['quitados'])} {c['quitados'][:8]}")
    print("fuera de orden (baja sin moderada o moderada sin alta):", no_monotono[:12])
    for x in avisos[:15]:
        print("aviso:", x)
    return 0


if __name__ == "__main__":
    sys.exit(main())
