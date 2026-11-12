"""Entregables del proyecto (ENT1, D126): catalogo declarado en el perfil y mapeo requisito -> entregables.

El perfil trae {"catalogo": [{id, nombre, salidas}], "mapeo": {"marco:requisito": [ids]}}. Con ese mapeo,
hallazgos, cobertura por marco y matriz de controles llevan la columna "entregables" y sale entregables.csv
con el aporte de cada salida. Solo ids de requisito, sin textos de normas. Sin la clave, nada cambia.
Es trazabilidad documental: no dictamina cumplimiento.
"""
from __future__ import annotations

import fnmatch
import re
import sys
from functools import cache

from .i18n import t

CLAVE = "entregables"
ARCHIVO = "entregables.csv"
COLUMNAS = ["id_entregable", "nombre", "requisitos_mapeados", "hallazgos", "filas_cobertura", "filas_matriz",
            "salidas_presentes", "salidas_ausentes"]
MARCOS = ("iec62443", "nerc-cip", "nist-800-82", "nist-csf", "tsa-sd-1580-82", "mitre-ics", "nist-800-53", "cis")
# Columna "marco" de matriz_controles.csv -> claves del mapeo (nist-800-82 usa controles de 800-53).
EQUIVALENCIA_MATRIZ = {
    "ISA/IEC 62443": ("iec62443",),
    "ISA/IEC 62443-2-1:2024": ("iec62443",),
    "NIST SP 800-82r3": ("nist-800-82", "nist-800-53"),
    "NIST SP 800-53": ("nist-800-53",),
    "CIS Controls v8.1": ("cis",),
    "CSF 2.0": ("nist-csf",),
    "TSA SD 1580/82-2022-01E": ("tsa-sd-1580-82",),
}
_ID = re.compile(r"[A-Za-z0-9._-]{1,20}")
_MITRE = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?!\d)")
_PAREN = re.compile(r"\s\([^)]*\)")


def norm(s: str) -> str:
    return " ".join(str(s).split()).casefold()


def validar(v, fallo) -> dict:
    """Perfil -> {"catalogo": [...], "mapeo": {"marco:requisito": [ids]}}; `fallo(msg)` termina con error de perfil."""
    if not isinstance(v, dict) or set(v) != {"catalogo", "mapeo"}:
        fallo("'entregables' debe ser un objeto con 'catalogo' y 'mapeo'.")
    cat = v["catalogo"]
    if not isinstance(cat, list) or not 1 <= len(cat) <= 100:
        fallo("'entregables.catalogo' debe ser una lista de 1 a 100 objetos.")
    catalogo, ids = [], set()
    for e in cat:
        if not isinstance(e, dict) or not {"id", "nombre"} <= set(e) <= {"id", "nombre", "salidas"}:
            fallo("cada entregable necesita 'id' y 'nombre' (opcional 'salidas').")
        i, n = e["id"], e["nombre"]
        if not isinstance(i, str) or not _ID.fullmatch(i):
            fallo(f"entregables: id {i!r} invalido (1 a 20 caracteres de A-Z, a-z, 0-9, punto, guion y guion bajo).")
        if i in ids:
            fallo(f"entregables: id repetido '{i}'.")
        if (not isinstance(n, str) or not n.strip() or len(n) > 120 or "\n" in n or "\r" in n):
            fallo(f"entregables.{i}: 'nombre' admite 1 a 120 caracteres sin saltos de linea.")
        sal = e.get("salidas", [])
        if (not isinstance(sal, list) or len(sal) > 50
                or not all(isinstance(x, str) and x.strip() and "/" not in x and "\n" not in x for x in sal)):
            fallo(f"entregables.{i}: 'salidas' debe ser una lista de 0 a 50 nombres de archivo.")
        ids.add(i)
        catalogo.append({"id": i, "nombre": n, "salidas": list(sal)})
    mp = v["mapeo"]
    if not isinstance(mp, dict) or not 1 <= len(mp) <= 2000:
        fallo("'entregables.mapeo' debe ser un objeto de 1 a 2000 entradas.")
    mapeo: dict = {}
    for k, lst in mp.items():
        marco, sep, req = str(k).partition(":")
        marco = marco.strip().lower()
        if not sep or not " ".join(req.split()):
            fallo(f"entregables.mapeo: '{k}' debe ser 'marco:requisito'.")
        if marco not in MARCOS:
            fallo(f"entregables.mapeo: marco desconocido '{marco}' (marcos: {', '.join(MARCOS)}).")
        if not isinstance(lst, list) or not 1 <= len(lst) <= 20 or not all(isinstance(x, str) for x in lst):
            fallo(f"entregables.mapeo['{k}']: debe ser una lista de 1 a 20 ids del catalogo.")
        for x in lst:
            if x not in ids:
                fallo(f"entregables.mapeo['{k}']: '{x}' no esta en el catalogo.")
        clave = marco + ":" + " ".join(req.split())
        mapeo[clave] = sorted(set(mapeo.get(clave, [])) | set(lst))
    return {"catalogo": catalogo, "mapeo": mapeo}


@cache
def _vigentes_csf() -> frozenset:
    from . import cobertura
    ids = {r["id"] for r in cobertura.cargar("nist-csf")["requisitos"]}
    out = set(ids)
    for i in ids:
        out.add(i.split("-")[0])
        out.add(i.split(".")[0])
    return frozenset(norm(x) for x in out)


@cache
def _ids_cobertura(clave: str) -> frozenset:
    from . import cobertura
    cob = cobertura.cargar(clave)
    return frozenset(norm(r["id"]) for r in cob["requisitos"]) if cob else frozenset()


def _evaluar(marco: str, req: str):
    """(estado, motivo, sustituto): estado 'vigente', 'excluido' o 'no_reconocido'."""
    if marco == "nist-csf":
        if norm(req) in _vigentes_csf():
            return "vigente", "", ""
        from . import csf_transicion
        filas = [f for f in csf_transicion.cargar()["filas"] if norm(f["id_11"]) == norm(req)]
        if filas:
            return ("excluido", "CSF 1.1 retirada o reubicada",
                    "; ".join(dict.fromkeys(f["id_20"] for f in filas if f["id_20"])))
        return "no_reconocido", "", ""
    if marco == "mitre-ics":
        from . import attack_ics
        cat = attack_ics.cargar()
        tid = req.strip().upper()
        if tid in cat["revocadas"]:
            return "excluido", "tecnica revocada", attack_ics.reemplazo(tid)
        if tid in cat["obsoletas"]:
            return "excluido", "obsoleta", ""
        return ("vigente" if tid in cat["tecnicas"] else "no_reconocido"), "", ""
    if marco == "iec62443":
        return ("vigente" if norm(req) in _ids_cobertura("iec62443") else "no_reconocido"), "", ""
    return "vigente", "", ""


def plan(perfil):
    """Plan resuelto del perfil, o None sin la clave. Los requisitos retirados quedan fuera del indice."""
    e = (perfil or {}).get(CLAVE)
    if not e:
        return None
    orden = {c["id"]: n for n, c in enumerate(e["catalogo"])}
    exactos: dict = {}
    prefijos: dict = {}
    vigentes: dict = {}
    excluidos, no_rec = [], 0
    for k, ids in e["mapeo"].items():
        marco, _, req = k.partition(":")
        exacto = not req.endswith("*")
        estado, motivo, sust = _evaluar(marco, req) if exacto else ("vigente", "", "")
        if estado == "excluido":
            excluidos.append({"clave": k, "motivo": motivo, "sustituto": sust})
            continue
        if estado == "no_reconocido":
            no_rec += 1
        vigentes[k] = ids
        if exacto:
            exactos.setdefault((marco, norm(req)), set()).update(ids)
        else:
            prefijos.setdefault(marco, []).append((norm(req[:-1]), ids))
    return {"catalogo": e["catalogo"], "orden": orden, "exactos": exactos, "prefijos": prefijos,
            "vigentes": vigentes, "excluidos": excluidos, "no_reconocidos": no_rec}


def avisos(perfil) -> None:
    """Aviso en consola por cada requisito excluido y por los no reconocidos."""
    p = plan(perfil)
    if not p:
        return
    for x in p["excluidos"]:
        extra = f"; sustituto: {x['sustituto']}" if x["sustituto"] else ""
        print(f"[!] entregables: '{x['clave']}' excluido ({x['motivo']}{extra}).", file=sys.stderr)
    if p["no_reconocidos"]:
        print(f"[!] entregables: {p['no_reconocidos']} requisito(s) del mapeo no se reconocen en ningun catalogo "
              "(se conservan).", file=sys.stderr)


def resolver(p: dict, marco: str, ids) -> list:
    """Ids de entregable (orden del catalogo, sin repetir) para los ids de requisito citados de `marco`."""
    out: set = set()
    for i in ids:
        n = norm(i)
        if not n:
            continue
        out.update(p["exactos"].get((marco, n), ()))
        base = n.split("(")[0].strip()
        for pref, lst in p["prefijos"].get(marco, ()):
            if n.startswith(pref) or base.startswith(pref):
                out.update(lst)
    return sorted(out, key=p["orden"].get)


def _ids_texto(marco: str, texto: str) -> list:
    if marco == "mitre-ics":
        return _MITRE.findall(texto or "")
    from . import cobertura
    cob = cobertura.cargar(marco)
    if cob is not None:
        return sorted(cobertura.ids_citados(texto, cob))
    return [x.strip() for x in re.split(r"[,;]", _PAREN.sub("", texto or "")) if x.strip()]


def de_hallazgo(p: dict, f: dict) -> list:
    out: set = set()
    for marco, texto in f["referencias"].items():
        if marco in MARCOS:
            out.update(resolver(p, marco, _ids_texto(marco, texto)))
    return sorted(out, key=p["orden"].get)


def texto_hallazgo(p: dict, f: dict) -> str:
    return "; ".join(de_hallazgo(p, f))


def texto_fila(p: dict, marco: str, id_: str) -> str:
    claves = EQUIVALENCIA_MATRIZ.get(marco, ()) if marco not in MARCOS else (marco,)
    out: set = set()
    for c in claves:
        out.update(resolver(p, c, [id_]))
    return "; ".join(sorted(out, key=p["orden"].get))


def agregar_columna(res, archivo: str, cabecera: list, filas: list):
    """(cabecera, filas) con la columna 'entregables' al final para las tablas que la llevan; si no, igual."""
    p = plan(getattr(res, "perfil", None))
    if not p:
        return cabecera, filas
    if archivo == "matriz_controles.csv":
        i_m, i_i = cabecera.index("marco"), cabecera.index("id")
        extra = [texto_fila(p, f[i_m], f[i_i]) for f in filas]
    elif archivo.startswith("cobertura_") and archivo.endswith(".csv") and cabecera and cabecera[0] == "id":
        marco = archivo[len("cobertura_"):-len(".csv")]
        extra = [texto_fila(p, marco, f[0]) for f in filas]
    else:
        return cabecera, filas
    return [*cabecera, CLAVE], [[*f, e] for f, e in zip(filas, extra)]


def _conteos(res, p: dict) -> tuple:
    """(hallazgos, cobertura, matriz): {id_entregable: n} contando filas de hallazgos.csv, cobertura y matriz."""
    from . import cobertura
    from . import matriz_controles as mc
    h: dict = {}
    for c in [*res.caps, *res.extras]:
        for f in c.findings:
            for i in de_hallazgo(p, f):
                h[i] = h.get(i, 0) + 1
    cb: dict = {}
    for e, filas, _r in cobertura.de_corrida(res):
        for f in filas:
            for i in texto_fila(p, e.clave, f["id"]).split("; "):
                if i:
                    cb[i] = cb.get(i, 0) + 1
    mt: dict = {}
    if mc.hay(res.matriz_controles):
        for archivo, _h, cab, filas in mc.tablas(res.matriz_controles, res.linea_base):
            if archivo != mc.ARCHIVO:
                continue
            im, ii = cab.index("marco"), cab.index("id")
            for f in filas:
                for i in texto_fila(p, f[im], f[ii]).split("; "):
                    if i:
                        mt[i] = mt.get(i, 0) + 1
    return h, cb, mt


def para_json(res):
    """Bloque 'entregables' de resultado.json, o None sin la clave."""
    p = plan(getattr(res, "perfil", None))
    if not p:
        return None
    h, _cb, _mt = _conteos(res, p)
    return {"catalogo": len(p["catalogo"]), "mapeo": len(p["vigentes"]), "excluidos": p["excluidos"],
            "no_reconocidos": p["no_reconocidos"],
            "hallazgos_con_entregable": sum(
                1 for c in [*res.caps, *res.extras] for f in c.findings if de_hallazgo(p, f)),
            "por_entregable": {c["id"]: h.get(c["id"], 0) for c in p["catalogo"]}}


def write_entregables(res, outdir) -> None:
    """Escribe entregables.csv despues de todos los escritores (ve los archivos ya presentes). Sin la clave, nada."""
    p = plan(getattr(res, "perfil", None))
    if not p:
        return
    from .report.common import escritor_csv
    h, cb, mt = _conteos(res, p)
    archivos = sorted({x.name for x in outdir.iterdir() if x.is_file()} | {ARCHIVO})      # incluye este archivo
    filas = []
    for c in p["catalogo"]:
        reqs = [k for k, ids in p["vigentes"].items() if c["id"] in ids]
        pres = sorted({a for pat in c["salidas"] for a in archivos if fnmatch.fnmatchcase(a, pat)})
        aus = [pat for pat in c["salidas"] if not any(fnmatch.fnmatchcase(a, pat) for a in archivos)]
        filas.append([c["id"], c["nombre"], "; ".join(reqs), h.get(c["id"], 0), cb.get(c["id"], 0),
                      mt.get(c["id"], 0), "; ".join(pres), "; ".join(aus)])
    with open(outdir / ARCHIVO, "w", newline="", encoding="utf-8-sig") as fh:
        w = escritor_csv(fh)
        w.writerow([t(x) for x in COLUMNAS])
        w.writerows(filas)
