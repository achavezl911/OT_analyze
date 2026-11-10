#!/usr/bin/env python3
"""Herramienta LOCAL: lee los textos de ISA/IEC 62443 en normas/ y escribe
ot_assess/marcos/iec62443_niveles.json (D75).

No corre en CI: normas/ no esta en el repo (derechos de autor). De las normas se
toma solo la ESTRUCTURA (ids, listas de requisitos por nivel SL, secciones). Los
titulos los escribe scripts/titulos_62443.py con palabras propias (maximo 12
palabras, es/en); jamas se copia texto de la norma. scripts/revisar_copia_normas.py
lo comprueba.

Uso: python3 scripts/extraer_niveles_62443.py [--normas normas/isa62443/txt] [--salida ruta]
(el arnes solo admite 'python3 -c': runpy.run_path("scripts/extraer_niveles_62443.py",
run_name="__main__"))
"""
import argparse
import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import titulos_62443 as TIT

ARCH = {
    "3-3": "S_62443_3_3_pdf.txt",
    "4-2": "S_62443_4_2_pdf.txt",
    "3-2": "S_62443_3_2_2020_pdf.txt",
    "tr2-2": "ISA-TR62443-2-2-2025.txt",
}
DOCS = {
    "3-3": {"designacion": "ANSI/ISA-62443-3-3 (99.03.03)", "anio": 2013, "edicion": "2013",
            "vigente_anterior_2020": True,
            "tema": {"es": "Requisitos de seguridad del sistema y niveles de seguridad",
                     "en": "System security requirements and security levels"}},
    "4-2": {"designacion": "ANSI/ISA-62443-4-2", "anio": 2018, "edicion": "2018",
            "vigente_anterior_2020": True,
            "tema": {"es": "Requisitos tecnicos de seguridad de componentes",
                     "en": "Technical security requirements for components"}},
    "3-2": {"designacion": "ANSI/ISA-62443-3-2", "anio": 2020, "edicion": "2020",
            "tema": {"es": "Evaluacion de riesgo y diseno de zonas y conductos",
                     "en": "Security risk assessment and system design (zones and conduits)"}},
    "tr2-2": {"designacion": "ISA-TR62443-2-2", "anio": 2025, "edicion": "2025",
              "tema": {"es": "Madurez y tipos de perfil de programa de seguridad",
                       "en": "Maturity and security program rating types"}},
}
FRS = ["IAC", "UC", "SI", "DC", "RDF", "TRE", "RA"]
TIPOS = ("SR", "CR", "NDR", "SAR", "EDR", "HDR")
IDRE = r"(?:SR|CR|NDR|SAR|EDR|HDR) \d+\.\d+"
REF = IDRE + r"(?:\s*\(\d+\))*"
NOSEL = r"N\s*o\s*t\s*S\s*e\s*l\s*e\s*c\s*t\s*e\s*d"
SECLEV = (r"S\s*e\s*c\s*u\s*r\s*i\s*t\s*y\s+l\s*e\s*v\s*e\s*l\s*s\s+"
          r"T\s*h\s*e\s+r\s*e\s*q\s*u")
CABECERA_PAG = (r"12 August 2013 – \d+ – ANSI/ISA - 62443 - 3 - 3 \(99\.03\.03\) - 2013|"
                r"ANSI/ISA - 62443 - 3 - 3 \(99\.03\.03\) - 2013 – \d+ – 12 August 2013|"
                r"ANSI/ISA - 62443 - 4 - 2 - 2018 – \d+ –|– \d+ – ANSI/ISA - 62443 - 4 - 2 - 2018")


def leer(ruta):
    """Texto aplanado: sin saltos de pagina, espacios colapsados, un solo guion."""
    t = Path(ruta).read_text(encoding="utf-8")
    t = re.sub(r"\f=== pagina \d+", " ", t)
    t = t.replace("‑", "-").replace("‐", "-")
    t = re.sub(r"\s+", " ", t)
    # el texto de otros extractores (PyMuPDF) trae "SPR-T" o "62443-3-3": se lleva al formato con espacios
    t = re.sub(r"\s*-\s*", " - ", t)
    t = re.sub(r"\s*–\s*", " – ", t)
    return re.sub(CABECERA_PAG, " ", t)


def norm_ids(t):
    """Repara los ids partidos por la extraccion del PDF ('SR 1. 3', 'N D R', 'SR 1.1 2')."""
    t = re.sub(r"\b([NEH])\s?D\s?R(?= ?\d)", r"\1DR", t)
    t = re.sub(r"\bS\s?A\s?R(?= ?\d)", "SAR", t)
    t = re.sub(r"\bC R (\d)", r"CR \1", t)
    t = re.sub(r"\b(%s) (\d+)\s*\.\s*(\d+)" % "|".join(TIPOS), r"\1 \2.\3", t)
    t = re.sub(r"\(\s*(\d+)\s*\)", r"(\1)", t)
    t = re.sub(r"\bR\s*E\s*\(\s*(\d+)\s*\)", r"RE (\1)", t)
    # Numeros de dos cifras partidos: 'SR 1.1 2' (1.12), 'SR 2.1 1' (2.11).
    t = re.sub(r"\b((?:%s) 1\.1) ([0-4])\b(?![.(])" % "|".join(TIPOS), r"\g<1>\2", t)
    t = re.sub(r"\b((?:%s) 2\.1) ([0-3])\b(?![.(])" % "|".join(TIPOS), r"\g<1>\2", t)
    t = re.sub(r"\b((?:%s) 3\.1) ([0-4])\b(?![.(])" % "|".join(TIPOS), r"\g<1>\2", t)
    return t


ANOMALIAS = []


def clave(i):
    return [int(x) for x in re.findall(r"\d+", i)]


# ------------------------------------------------------------ cabeceras
def cabeceras(t, tipos):
    """{id: {sec, ini, fin_titulo}} de los apartados del cuerpo, guiado por el indice.

    El indice (lineas con puntos guia) fija id y numero de apartado; en el cuerpo se
    toma la primera aparicion posterior a la cabecera anterior.
    """
    pat = re.compile(r"(\d+\.\d+) ((?:%s) \d+\.\d+) – " % "|".join(tipos))
    toc = []
    for m in pat.finditer(t):
        if "...." in t[m.end():m.end() + 200]:
            toc.append((m.group(2), m.group(1)))
    ini = max(m.end() for m in pat.finditer(t) if "...." in t[m.end():m.end() + 200])
    out = {}
    pos = ini
    for ident, sec in toc:
        for m in pat.finditer(t, pos):
            if m.group(2) == ident and m.group(1) == sec and "...." not in t[m.end():m.end() + 200]:
                out[ident] = {"sec": sec, "ini": m.start()}
                pos = m.end()
                break
        else:
            raise SystemExit("cabecera no encontrada: %s %s" % (ident, sec))
    return out, [i for i, _ in toc]


def segmentos(t, cab, extra_cortes):
    """Recorta el texto de cada apartado hasta la siguiente cabecera o corte."""
    cortes = sorted([v["ini"] for v in cab.values()] + extra_cortes)
    seg = {}
    for ident, v in cab.items():
        sig = [c for c in cortes if c > v["ini"]]
        seg[ident] = t[v["ini"]:(sig[0] if sig else len(t))]
    return seg


# ------------------------------------------------------------ listas SL
def ids_de(cuerpo):
    """'SR 1.2 (1) (2)' -> ['SR 1.2', 'SR 1.2 RE 1', 'SR 1.2 RE 2']; 'Not selected' -> []."""
    if re.match(r"\s*" + NOSEL, cuerpo, re.IGNORECASE):
        return []
    out = []
    for r in re.findall(REF, cuerpo):
        m = re.match(r"(%s)((?:\s*\(\d+\))*)" % IDRE, r)
        base, res = m.group(1), re.findall(r"\((\d+)\)", m.group(2))
        if base not in out:
            out.append(base)
        for e in res:
            x = "%s RE %s" % (base, e)
            if x not in out:
                out.append(x)
    return out


def niveles_de(seg):
    """{1..4: [ids]} del apartado 'Security levels'; None si no tiene."""
    mi = re.search(SECLEV, seg)
    if not mi:
        return None
    bloque = seg[mi.start():]
    pat = re.compile(r"S[LR]\s*-\s*C\s*\([^)]{1,40}\)\s*([1-4])\s*:")
    ms = list(pat.finditer(bloque))
    out = {}
    for k, m in enumerate(ms):
        fin = ms[k + 1].start() if k + 1 < len(ms) else len(bloque)
        cuerpo = bloque[m.end():fin]
        mm = re.match(r"\s*(?:%s|%s(?:\s*,?\s*(?:and\s+)?%s)*)" % (NOSEL, REF, REF), cuerpo, re.IGNORECASE)
        if not mm:
            raise SystemExit("lista SL ilegible: %r" % cuerpo[:80])
        n = int(m.group(1))
        if n in out and k == 3:
            # Errata del texto: la cuarta linea de la lista lleva la etiqueta '3' repetida.
            ANOMALIAS.append("%s: la linea del SL 4 esta rotulada SL 3 en el texto; se trata como SL 4"
                             % (ids_de(mm.group(0)) or ["?"])[0].split(" RE ")[0])
            n = 4
        out[n] = ids_de(mm.group(0))
    return out


def res_definidos(seg):
    """Numeros de RE descritos en 'Requirement enhancements' (para contrastar con las listas)."""
    mi = re.search(r"Requirement\s+enhanc\s*ements", seg)
    mj = re.search(SECLEV, seg)
    if not mi:
        return []
    fin = mj.start() if mj and mj.start() > mi.start() else len(seg)
    return sorted({int(x) for x in re.findall(r"(?:^|\s)\((\d+)\)\s+[A-Z]", seg[mi.start():fin])})


# ------------------------------------------------------------ tabla B.1
def tabla_b1(t):
    """{id: marcas} de la tabla B.1: cuantas casillas de SL tiene cada fila (SR/CR y RE)."""
    marcas = "[✓✔]"
    out = {}
    for m in re.finditer(r"Table B ?\. ?1 – Mapping", t):
        if "SL 1 SL 2" not in t[m.end():m.end() + 120]:
            continue  # mencion en el indice de tablas
        ini = m.start()
        fin = t.find("BIBLIOGRAPHY", ini)
        if fin < 0:
            fin = t.find("Annex C", ini)
        if fin < 0:
            fin = len(t)
        bloque = t[ini:fin]
        bloque = re.sub(r"Table B ?\. ?1 \(cont’d\) – Mapping of SRs and REs to FR SL levels 1 - 4 "
                        r"SRs and R ?e ?s SL 1 SL 2 SL 3 SL 4", " ", bloque)
        filas = re.split(r"(?=(?:%s) \d+\.\d+ – )|(?=RE \(\d+\) )" % "|".join(TIPOS), bloque)
        actual = None
        for f in filas:
            mm = re.match(r"((?:%s) \d+\.\d+) – " % "|".join(TIPOS), f)
            if mm:
                actual = mm.group(1)
                out[actual] = len(re.findall(marcas, f))
                continue
            mr = re.match(r"RE \((\d+)\) ", f)
            if mr and actual:
                out["%s RE %s" % (actual, mr.group(1))] = len(re.findall(marcas, f))
        break  # la primera tabla basta (la 4-2 repite la misma estructura en su anexo)
    return out


def min_sl(niv, ident):
    for n in (1, 2, 3, 4):
        if ident in niv.get(n, []):
            return n
    return None


def analizar(t, tipos, extra_cortes):
    cab, orden = cabeceras(t, tipos)
    seg = segmentos(t, cab, extra_cortes)
    res = {}
    for ident in orden:
        s = seg[ident]
        niv = niveles_de(s)
        res[ident] = {"sec": cab[ident]["sec"], "niv": niv, "re_def": res_definidos(s), "texto_ini": s[:260]}
    return res, orden


def cortes_fr(t):
    return [m.start() for m in re.finditer(r"\b\d+ FR \d – |\bAnnex [A-Z]\b", t) if m.start() > 20000]


def contrastar(res, b1, etiqueta):
    """Lista de diferencias entre las listas de los apartados y la tabla B.1."""
    dif = []
    for ident, d in res.items():
        niv = d["niv"]
        if not niv:
            continue
        # SR/CR con lista propia
        for n in (1, 2, 3, 4):
            if n not in niv:
                dif.append({"id": ident, "tipo": "falta el nivel %d en el apartado" % n})
        lista_total = {x for n in niv for x in niv[n]}
        for x in sorted(lista_total, key=lambda z: (clave(z), z)):
            m = min_sl(niv, x)
            if x not in b1:
                dif.append({"id": x, "tipo": "no esta en la tabla B.1"})
                continue
            # la tabla cuenta casillas: fila presente desde SL m hasta SL 4 si es acumulativa
            presente = [n for n in (1, 2, 3, 4) if x in niv.get(n, [])]
            if b1[x] != len(presente) or presente != list(range(m, 5)):
                dif.append({"id": x, "tipo": "casillas de la tabla %d; niveles del apartado %s"
                            % (b1[x], presente)})
        for e in d["re_def"]:
            rid = "%s RE %d" % (ident, e)
            if rid not in lista_total:
                dif.append({"id": rid, "tipo": "RE descrito en el texto y no citado en ninguna lista SL"})
        # restos
    for x, n in b1.items():
        base = x.split(" RE ")[0]
        if base in res and res[base]["niv"] and not any(x in res[base]["niv"][k] for k in (1, 2, 3, 4)):
            dif.append({"id": x, "tipo": "esta en la tabla B.1 (%d casillas) y no en las listas" % n})
    return dif


def tt(par):
    return {"es": par[0], "en": par[1]}


def num_de(ident):
    return ident.split()[1]


def sl_json(niv):
    return {str(n): niv[n] for n in (1, 2, 3, 4)}


def re_titulo(tabla, ident):
    """'SR 1.1 RE 2' -> titulo de la tabla por clave '1.1.2'."""
    base, n = ident.split(" RE ")
    k = "%s.%s" % (num_de(base), n)
    if k not in tabla:
        raise SystemExit("falta titulo propio del RE %s (clave %s)" % (ident, k))
    return tt(tabla[k])


def reunir_re(res, tabla_titulos, sec_de):
    """Catalogo de RE a partir de las listas SL de cada requisito."""
    out = {}
    for ident, d in res.items():
        niv = d["niv"]
        if not niv:
            continue
        citados = sorted({x for n in niv for x in niv[n] if " RE " in x}, key=clave)
        for x in citados:
            out[x] = {"requisito": ident, "titulo": re_titulo(tabla_titulos, x),
                      "sl_minimo": min_sl(niv, x), "seccion": sec_de(d["sec"])}
    return out


def zcr_de(t):
    """ZCR 1-7 y subrequisitos de la 3-2: {id: seccion}, de los encabezados del cuerpo y del indice."""
    t = re.sub(r"Z\s?C\s?R\s*(\d)", r"ZCR \1", t)
    t = re.sub(r"ZCR (\d+)\s*\.\s*(\d+)", r"ZCR \1.\2", t)
    cuerpo = {}
    for m in re.finditer(r"(4(?:\.\s?\d+)+) (ZCR \d+(?:\.\d+)?): ", t):
        if m.start() > 14000:
            cuerpo.setdefault(m.group(2), re.sub(r"\s", "", m.group(1)))
    indice = {}
    for m in re.finditer(r"(\d(?:\.\s?\d+)+) (ZCR \d+(?:\.\d+)?): [^.]{3,120}?\.{3}", t[:14000]):
        indice.setdefault(m.group(2), re.sub(r"\s", "", m.group(1)))
    out = {}
    for ident in sorted(set(cuerpo) | set(indice), key=clave):
        out[ident] = cuerpo.get(ident) or indice[ident]
    return out


def verificar_tr(t):
    """El TR debe contener lo que el catalogo afirma (ML 1-4, SPR-T/I/O, regla de agregacion)."""
    for k in ("ML 1:", "ML 2:", "ML 3:", "ML 4:", "SPR - T", "SPR - I", "SPR - O", "minimum level"):
        if k not in t:
            raise SystemExit("el TR 2-2 no contiene %r" % k)
    if "SPR - A" in t:
        raise SystemExit("el TR 2-2 define SPR-A: revisar el catalogo")


MADUREZ = {
    "ML 1": {"titulo": ("Inicial: se hace sin documentar", "Initial: done without documentation"),
             "descripcion": ("Las practicas son ad hoc, sin registro; no se puede mostrar constancia en el tiempo.",
                             "Practices are ad hoc and unrecorded; consistency over time cannot be shown.")},
    "ML 2": {"titulo": ("Documentado: existe el procedimiento", "Documented: a procedure exists"),
             "descripcion": ("Hay procedimientos o capacitacion escritos, pero puede haber retraso entre definir y ejecutar.",
                             "Written procedures or training exist, but definition and execution may lag apart.")},
    "ML 3": {"titulo": ("Practicado: se ejecuta de forma repetible", "Practiced: executed repeatably"),
             "descripcion": ("Es un proceso ML 2 que ya se practica en la planta y se puede mostrar repetible.",
                             "A level 2 process that is already practiced on site and shown to be repeatable.")},
    "ML 4": {"titulo": ("Mejorado: se mide y se mejora", "Improving: measured and refined"),
             "descripcion": ("Con metricas se demuestra eficacia y el programa mejora el proceso con cambios.",
                             "Metrics show effectiveness and the program improves the process through changes.")},
}
SPR = {
    "SPR-T": {"nombre": ("SPR objetivo de la zona", "Target SPR of the zone"),
              "descripcion": ("Nivel de requisitos que el propietario del activo quiere cumplir en operacion, incluyendo sostener los procesos.",
                              "Requirement level the asset owner wants met in operation, including keeping the processes going."),
              "fuente": "TR 2-2:2025 6.7.3"},
    "SPR-I": {"nombre": ("SPR implementado (previsto)", "Implemented (predicted) SPR"),
              "descripcion": ("Estimacion, desde el diseno validado, de lo que se cumplira en operacion si los procesos se ejecutan de forma repetible.",
                              "Estimate from the validated design of what will be met in operation if processes run repeatably."),
              "fuente": "TR 2-2:2025 6.7.3 y 8.5.4"},
    "SPR-O": {"nombre": ("SPR operado (logrado)", "Operated (achieved) SPR"),
              "descripcion": ("Nivel de requisitos cumplido en un momento de la operacion, con repetibilidad y eficacia demostradas.",
                              "Requirement level actually met at a point in operation, with repeatability and effectiveness shown."),
              "fuente": "TR 2-2:2025 6.7.3",
              "alias_del_brief": "SPR-A"},
}
SL_TIPOS = {
    "SL-T": {"nombre": ("Nivel de seguridad objetivo", "Target security level"),
             "fuente": "3-2:2020 ZCR 5.6"},
    "SL-C": {"nombre": ("Nivel de seguridad de capacidad", "Capability security level"),
             "fuente": "3-3:2013 y 4-2:2018"},
    "SL-A": {"nombre": ("Nivel de seguridad logrado", "Achieved security level"),
             "fuente": "3-3:2013 clausula 1"},
}
NIVELES_SL = {
    "1": ("Proteccion contra uso indebido casual o fortuito", "Protection against casual or coincidental misuse"),
    "2": ("Contra un atacante con medios simples, pocos recursos y poca motivacion",
          "Against an attacker with simple means, low resources and low motivation"),
    "3": ("Contra medios sofisticados, recursos moderados y habilidades especificas",
          "Against sophisticated means, moderate resources and IACS specific skills"),
    "4": ("Contra medios sofisticados, muchos recursos y alta motivacion",
          "Against sophisticated means, extended resources and high motivation"),
}
NO_USADOS = [
    {"documento": "ISA-62443-1-1:2007", "motivo": {"es": "Solo terminologia y modelos; edicion anterior a 2020",
                                                    "en": "Terminology and models only; edition before 2020"}},
    {"documento": "ISA-62443-4-1:2018", "motivo": {"es": "Ciclo de desarrollo del fabricante, fuera del alcance de la linea base de planta",
                                                    "en": "Supplier development lifecycle, outside plant baseline scope"}},
    {"documento": "ISA-TR62443-2-3:2015", "motivo": {"es": "Gestion de parches; ya cubierto por el flujo de vulnerabilidades",
                                                      "en": "Patch management; already covered by the vulnerability flow"}},
    {"documento": "ISA-TR99.00.01:2007", "motivo": {"es": "Obsoleto", "en": "Obsolete"}},
    {"documento": "ISA/IEC 62443-2-1:2024", "motivo": {"es": "Solo identificadores, titulos propios y correspondencias publicadas (iec62443_2_1.json); su texto no se usa",
                                                        "en": "Identifiers, own titles and published mappings only (iec62443_2_1.json); its text is not used"}},
]


def construir(carpeta):
    c = Path(carpeta)
    # ---------- 3-3
    t33 = norm_ids(leer(c / ARCH["3-3"]))
    res33, orden33 = analizar(t33, ("SR",), cortes_fr(t33))
    b133 = tabla_b1(t33)
    # ---------- 4-2
    t42 = norm_ids(leer(c / ARCH["4-2"]))
    res42, orden42 = analizar(t42, TIPOS, cortes_fr(t42))
    b142 = tabla_b1(t42)
    # ---------- 3-2 y TR 2-2
    z = zcr_de(leer(c / ARCH["3-2"]))
    ttr = leer(c / ARCH["tr2-2"])
    verificar_tr(ttr)

    fr = {}
    for k, (ab, es, en) in TIT.FR.items():
        fr[k] = {"abreviatura": ab, "titulo": {"es": es, "en": en}, "apartado_33": "%d" % (4 + int(k[2:]))}
    sr = {}
    for ident in orden33:
        d = res33[ident]
        niv = d["niv"]
        if not niv or sorted(niv) != [1, 2, 3, 4]:
            raise SystemExit("%s: listas SL incompletas" % ident)
        familia = int(num_de(ident).split(".")[0])
        sr[ident] = {
            "fr": "FR%d" % familia, "titulo": tt(TIT.BASE[num_de(ident)]), "seccion": "3-3 " + d["sec"],
            "sl": sl_json(niv),
            "sl_minimo": min(n for n in niv if niv[n]),
            "re": sorted({x for n in niv for x in niv[n] if " RE " in x}, key=clave),
            "cr": ("CR " + num_de(ident)) if ("CR " + num_de(ident)) in res42 else None,
        }
    re33 = reunir_re(res33, TIT.RE_SR, lambda s: "3-3 " + s)

    comp = {}
    for ident in orden42:
        d = res42[ident]
        tipo = ident.split()[0]
        num = num_de(ident)
        rec = {"tipo": tipo, "fr": "FR%s" % num.split(".")[0], "titulo": tt(TIT.BASE[num]),
               "seccion": "4-2 " + d["sec"], "sr": ("SR " + num) if ("SR " + num) in sr else None}
        if d["niv"]:
            if sorted(d["niv"]) != [1, 2, 3, 4]:
                raise SystemExit("%s: listas SL incompletas" % ident)
            rec["clase"] = "propio"
            rec["sl"] = sl_json(d["niv"])
            rec["sl_minimo"] = min(n for n in d["niv"] if d["niv"][n])
            rec["re"] = sorted({x for n in d["niv"] for x in d["niv"][n] if " RE " in x}, key=clave)
        elif re.search(r"no c\s*omponent\s+lev", d["texto_ini"]):
            rec["clase"] = "sin_requisito_de_componente"
        else:
            rec["clase"] = "remite_a_tipo_de_dispositivo"
            rec["tipos"] = [t for t in ("SAR", "EDR", "HDR", "NDR") if "%s %s" % (t, num) in res42]
        comp[ident] = rec
    re42 = reunir_re(res42, TIT.RE_COMP, lambda s: "4-2 " + s)

    zcr = {}
    for ident, sec in z.items():
        if ident not in TIT.ZCR:
            raise SystemExit("falta titulo propio de %s" % ident)
        zcr[ident] = {"titulo": tt(TIT.ZCR[ident]), "seccion": "3-2 " + sec,
                      "padre": ident.split(".")[0] if "." in ident else None}
    faltan = sorted(set(TIT.ZCR) - set(zcr), key=clave)
    if faltan:
        raise SystemExit("ZCR con titulo y sin apartado en la 3-2: %s" % faltan)

    docs = {}
    for k, v in DOCS.items():
        d = dict(v)
        d["tema"] = dict(d["tema"])
        docs[k] = d
    out = {
        "catalogo": {
            "version": 1,
            "generado_por": "scripts/extraer_niveles_62443.py (lee normas/, que no se versiona)",
            "decision": "D75",
            "aviso": {"es": "Estructura e identificadores; titulos propios. Sin texto de las normas. No afirma cumplimiento.",
                      "en": "Structure and identifiers; own titles. No text from the standards. Makes no compliance claim."},
        },
        "documentos": docs,
        "documentos_no_usados": NO_USADOS,
        "tipos_sl": {k: {"nombre": tt(v["nombre"]), "fuente": v["fuente"]} for k, v in SL_TIPOS.items()},
        "niveles_sl": {k: tt(v) for k, v in NIVELES_SL.items()},
        "fr": fr,
        "sr": sr,
        "re_sr": re33,
        "componente": comp,
        "re_componente": re42,
        "zcr": zcr,
        "madurez": {k: {"titulo": tt(v["titulo"]), "descripcion": tt(v["descripcion"]),
                        "seccion": "TR 2-2:2025 6.2"} for k, v in MADUREZ.items()},
        "umbral_repetible": {"entre": ["ML 2", "ML 3"],
                             "descripcion": {"es": "Se considera repetible desde ML 3; por debajo el SPR no se define.",
                                             "en": "Repeatable from ML 3; below that the SPR is not defined."},
                             "seccion": "TR 2-2:2025 6.2"},
        "spr": {k: {"nombre": tt(v["nombre"]), "descripcion": tt(v["descripcion"]), "fuente": v["fuente"],
                    **({"alias_del_brief": v["alias_del_brief"]} if "alias_del_brief" in v else {})}
                for k, v in SPR.items()},
        "agregacion": {"regla": "minimo",
                       "descripcion": {"es": "El valor de una zona o conducto es el minimo de los requisitos cumplidos del grupo.",
                                       "en": "A zone or conduit value is the minimum over the met requirements of the group."},
                       "fuente": "TR 2-2:2025 8.5.4 (ejemplo del propio TR, no regla obligatoria)"},
        "contraste_tabla_b1": {
            "3-3": {"filas": len(b133), "diferencias": contrastar(res33, b133, "3-3")},
            "4-2": {"filas": len(b142), "diferencias": contrastar(res42, b142, "4-2")},
            "limite": "la extraccion pierde la columna de cada casilla: se compara el numero de casillas "
                      "y que sean contiguas hasta SL 4",
        },
        "anomalias_del_texto": sorted(ANOMALIAS),
    }
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--normas", default=str(RAIZ / "normas/isa62443/txt"))
    ap.add_argument("--salida", default=str(RAIZ / "ot_assess/marcos/iec62443_niveles.json"))
    a = ap.parse_args()
    datos = construir(a.normas)
    Path(a.salida).write_text(json.dumps(datos, indent=1, ensure_ascii=False, sort_keys=False) + "\n",
                              encoding="utf-8")
    print("escrito", a.salida)
    for k, v in datos["contraste_tabla_b1"].items():
        if isinstance(v, dict):
            print("tabla B.1 vs apartados %s: %d filas, %d diferencias" % (k, v["filas"], len(v["diferencias"])))
            for d in v["diferencias"]:
                print("  ", d)
    for x in datos["anomalias_del_texto"]:
        print("anomalia:", x)
