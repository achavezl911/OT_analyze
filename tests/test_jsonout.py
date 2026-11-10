"""resultado.json determinista: objetos y conjuntos por contenido, no por repr (J1)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess.firewalls.politica import _Lado
from ot_assess.model import Assessment
from ot_assess.report.jsonout import write_json


def _res():
    lado = _Lado()
    lado.nombres, lado.tam, lado.just = ["PLC-1", "HMI-2"], 2, ["x"]
    fw = {"politica": {"firewalls": [{"reglas": [{"origen": lado, "destino": lado,
                                                 "etiquetas": {"zeta", "alfa", "medio", "beta"}}]}]}}
    return Assessment(caps=[], assets={}, conduits=[], args=None, firewall=fw)


def _escribir():
    with tempfile.TemporaryDirectory() as d:
        write_json(_res(), Path(d))
        return (Path(d) / "resultado.json").read_bytes()


class JsonDeterminista(unittest.TestCase):
    def test_objeto_con_slots_por_contenido(self):
        txt = _escribir().decode("utf-8")
        self.assertNotIn("object at 0x", txt)
        regla = json.loads(txt)["firewall"]["politica"]["firewalls"][0]["reglas"][0]
        self.assertEqual(regla["origen"]["nombres"], ["PLC-1", "HMI-2"])
        self.assertEqual(regla["etiquetas"], ["alfa", "beta", "medio", "zeta"])

    def test_bytes_identicos(self):
        self.assertEqual(_escribir(), _escribir())


if __name__ == "__main__":
    unittest.main()
