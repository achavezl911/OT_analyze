"""Pruebas del exportador draw.io. Solo Python estandar: no requieren tshark ni scapy."""
from __future__ import annotations

import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess.diagram.drawio import render_drawio  # noqa: E402
from ot_assess.diagram.graph import Arista, Grafo, Nodo  # noqa: E402
from ot_assess.diagram.svg import CRIT  # noqa: E402


def grafo() -> Grafo:
    nodos = [Nodo("a", 'PLC <1> & "x"', "10.0.0.1", "Nivel 1", "controlador"),
             Nodo("b", "HMI", "10.0.0.2", "Nivel 2", "supervision"),
             Nodo("c", "8.8.8.8", "", "Externo", "externo")]
    aristas = [Arista("a", "b", fwd=True, back=False, crit="Critica",
                      servicios={"s1": 10, "s2": 40, "s3": 30, "s4": 20, "s5": 1}),
               Arista("b", "c", fwd=False, back=True, crit="Baja", servicios={"dns": 3})]
    return Grafo(nodos, aristas, ["Externo", "Nivel 2", "Nivel 1"])


def celdas(xml: str) -> list:
    return list(ET.fromstring(xml).iter("mxCell"))


class TestDrawio(unittest.TestCase):
    def setUp(self):
        self.xml = render_drawio(grafo(), "Titulo", "diagrama_x")

    def test_bien_formado_y_conteos(self):
        raiz = ET.fromstring(self.xml)
        self.assertEqual(raiz.tag, "mxfile")
        self.assertEqual(raiz.find("diagram").get("name"), "Titulo")
        cs = celdas(self.xml)
        self.assertEqual(sum(c.get("vertex") == "1" for c in cs), 3 + 3)   # bandas + nodos
        self.assertEqual(sum(c.get("edge") == "1" for c in cs), 2)

    def test_aristas_apuntan_a_ids_existentes(self):
        cs = celdas(self.xml)
        vertices = {c.get("id") for c in cs if c.get("vertex") == "1"}
        for e in (c for c in cs if c.get("edge") == "1"):
            self.assertIn(e.get("source"), vertices)
            self.assertIn(e.get("target"), vertices)
            self.assertTrue(e.get("source").startswith("n"))
        self.assertEqual(len({c.get("id") for c in cs}), len(cs))

    def test_flechas_y_color(self):
        e0, e1 = [c for c in celdas(self.xml) if c.get("edge") == "1"]
        self.assertIn("endArrow=classic", e0.get("style"))
        self.assertIn("startArrow=none", e0.get("style"))
        self.assertIn("startArrow=classic", e1.get("style"))
        self.assertIn("endArrow=none", e1.get("style"))
        self.assertIn("strokeColor=" + CRIT["Critica"], e0.get("style"))
        self.assertIn("strokeColor=" + CRIT["Baja"], e1.get("style"))

    def test_servicios_top3(self):
        e0 = next(c for c in celdas(self.xml) if c.get("edge") == "1")
        self.assertEqual(e0.get("value"), "s2, s3, s4 +2")

    def test_escape_y_salto_de_linea(self):
        n0 = next(c for c in celdas(self.xml) if c.get("id") == "n0")
        self.assertEqual(n0.get("value"), 'PLC <1> & "x"\n10.0.0.1')
        self.assertIn("&amp;", self.xml)
        self.assertIn("&#10;", self.xml)
        self.assertNotIn('"x"\n', self.xml)

    def test_punteado_solo_externo(self):
        por_id = {c.get("id"): c.get("style") for c in celdas(self.xml)}
        self.assertNotIn("dashed=1", por_id["n0"])
        self.assertIn("dashed=1", por_id["n2"])

    def test_determinista(self):
        self.assertEqual(self.xml, render_drawio(grafo(), "Titulo", "diagrama_x"))


if __name__ == "__main__":
    unittest.main()
