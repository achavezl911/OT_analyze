"""Catalogo de elementos del programa de seguridad de ISA/IEC 62443-2-1:2024 (D104).

Lee `marcos/iec62443_2_1.json`: 8 SPE, 16 sub-SPE y 87 requisitos con identificadores de la norma, titulos
propios del propietario (es/en), evidencia propuesta y las correspondencias publicadas con 3-3 (SR), 4-2 (CR)
y 2-4 (SP). Las referencias se guardan tal como se publicaron; aqui se normalizan solo para cruzarlas con
`niveles62443`. Una correspondencia no es equivalencia ni prueba de cumplimiento. No importa `linea_base`.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

RUTA = Path(__file__).parent / "marcos" / "iec62443_2_1.json"
T_SPE, T_SUB, T_REQ = "SPE", "sub-SPE", "requisito"
_REF = re.compile(r"(SR|CR) (\d+)\.(\d+)(?: (?:BR|RE\((\d+)\)))?")


@lru_cache(maxsize=1)
def cargar() -> dict:
    return json.loads(RUTA.read_text(encoding="utf-8"))


def normalizar(ref: str):
    """('SR'|'CR', id del catalogo de niveles62443) o ('SP', ref tal cual); None si no se reconoce.

    'SR 1.02' -> 'SR 1.2'; 'SR 5.1 BR' y 'SR 5.1' -> 'SR 5.1'; 'SR 5.1 RE(2)' -> 'SR 5.1 RE 2'.
    """
    ref = ref.strip()
    m = _REF.fullmatch(ref)
    if m:
        base = f"{m.group(1)} {int(m.group(2))}.{int(m.group(3))}"
        return m.group(1), base + (f" RE {int(m.group(4))}" if m.group(4) else "")
    return ("SP", ref) if ref.startswith("SP.") else None


def _orden(ident: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", ident))


def _unicos(refs, tipo: str) -> list:
    out = {n[1] for n in (normalizar(r) for r in refs) if n and n[0] == tipo}
    return sorted(out, key=_orden)


def sr(req: dict) -> list:
    """SR de 3-3 (y sus RE) que cita el requisito, normalizados, sin repetir, en orden de id."""
    return _unicos(req.get("refs", ()), "SR")


def cr(req: dict) -> list:
    """CR de 4-2 (y sus RE) que cita el requisito, normalizados, sin repetir, en orden de id."""
    return _unicos(req.get("refs", ()), "CR")


def sp(req: dict) -> list:
    """SP de 2-4 tal cual se publicaron (el proyecto no tiene la 2-4, no se cruzan)."""
    return [r.strip() for r in req.get("refs", ()) if r.strip().startswith("SP.")]


def jerarquia() -> list:
    """Elementos en orden: cada SPE, sus sub-SPE y bajo cada sub-SPE sus requisitos."""
    el = cargar()["elementos"]
    hijos: dict = {}
    for e in el:
        hijos.setdefault(e["pertenece_a"], []).append(e)
    out: list = []
    for spe in hijos.get("", ()):
        out.append(spe)
        for sub in hijos.get(spe["id"], ()):
            out.append(sub)
            out.extend(hijos.get(sub["id"], ()))
    return out


def conjuntos() -> dict:
    """id de cada elemento -> conjunto de SR/RE normalizados (sub-SPE y SPE: union de sus hijos)."""
    el = cargar()["elementos"]
    out = {e["id"]: set(sr(e)) for e in el if e["tipo"] == T_REQ}
    for tipo in (T_SUB, T_SPE):
        for e in el:
            if e["tipo"] == tipo:
                out[e["id"]] = set().union(*(out[h["id"]] for h in el if h["pertenece_a"] == e["id"]))
    return out
