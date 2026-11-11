"""Marco derivado "tsa-sd-1580-82": medidas de la seccion III de la TSA SD 1580/82 por hallazgo (D118).

No hay mapeo escrito a mano: la referencia de cada hallazgo se DERIVA de dos mapeos propios que ya existen,
hallazgo -> controles SP 800-53 (marcos/nist-800-82.json) y medida TSA -> controles SP 800-53
(marcos/tsa_sd_1580_82.json). Una medida se cita si es de tipo "tecnico" y su lista de controles incluye el
control base de alguno de los controles que cita el hallazgo (SC-7(3) cuenta como SC-7). Las medidas documentales
no se citan: no se evidencian con trafico (misma regla que la matriz de controles, D109).
"""
from __future__ import annotations

import json
from pathlib import Path

CLAVE = "tsa-sd-1580-82"
RUTA = Path(__file__).parent / "marcos" / "tsa_sd_1580_82.json"
ALCANCE = ("Referencias derivadas de dos mapeos propios sin revisar (hallazgo a controles de NIST SP 800-53 y medida de "
           "la TSA a controles de NIST SP 800-53). Una referencia no es equivalencia ni prueba de cumplimiento; las "
           "medidas documentales de la directiva no se citan.")
FUENTE = "TSA SD 1580/82-2022-01E, seccion III (ids y titulos propios)"
CONTROL_CRUCE = "SC-7"


def _base(control: str) -> str:
    return control.split("(")[0].strip()


def _medidas() -> tuple:
    d = json.loads(RUTA.read_text(encoding="utf-8"))
    return d["edicion"], [r for r in d["requisitos"] if r["tipo"] == "tecnico"]


def derivar(refs_nist: dict, medidas: list) -> dict:
    """{fragmento: 'III.B.1.a (titulo); ...'} desde las referencias NIST; sin medidas, el fragmento no se incluye."""
    out = {}
    for frag, txt in refs_nist.items():
        bases = {_base(p.split(" (")[0]) for p in txt.split("; ") if p.strip()}
        piezas = [f"{m['id']} ({m['titulo']})" for m in medidas if bases & {_base(c) for c in m["sp800_53"]}]
        if piezas:
            out[frag] = "; ".join(piezas)
    return out


def construir(nist):
    """Estandar derivado a partir del Estandar de nist-800-82."""
    from .standards import Estandar
    edicion, medidas = _medidas()
    primera = next((m for m in medidas if CONTROL_CRUCE in {_base(c) for c in m["sp800_53"]}), None)
    cruce = ("en la frontera entre zonas (medida {id} de la TSA SD 1580/82, que cita {ctl} de NIST SP 800-53)"
             .format(id=primera["id"], ctl=CONTROL_CRUCE)) if primera else ""
    return Estandar(CLAVE, "TSA SD 1580/82-2022-01E (seccion III)", cruce, ALCANCE, derivar(nist.refs, medidas),
                    FUENTE, f"TSA SD 1580/82-2022-{edicion}; SP 800-53 Rev. 5", {"estado": "sin revisar"})
