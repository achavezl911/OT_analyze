"""CV4: calculadora CVSS v4.0 portada de FIRST (D113). Pares vector/puntuacion publicados por CISA (dominio publico)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import cvss4

_P = "CVSS:4.0/"
_PARES = """
AV:A/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N 6.9
AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N 5.1
AV:A/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.3
AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 6.7
AV:L/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.0
AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:L/SC:H/SI:H/SA:H 7.2
AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 8.5
AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 6.8
AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N 6.8
AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.0
AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N 2.4
AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 8.4
AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L 4.6
AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N 8.5
AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N 7.2
AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 8.2
AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.5
AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 9.2
AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N 8.2
AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.7
AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 8.6
AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N 6.9
AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N 7.1
AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 7.1
AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N 5.3
AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N 5.3
AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N 5.1
AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H 10.0
AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 9.3
AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 8.7
AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N 8.8
AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N 6.9
AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N 8.7
AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N 6.9
AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N 6.9
AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N 8.7
AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N 6.9
AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N 8.7
AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 7.5
AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N 5.3
AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N 7.5
AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N 5.9
"""
PARES = [(_P + v, float(p)) for v, p in (ln.split() for ln in _PARES.strip().splitlines())]

_DISCREPANTE = _P + "AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
# vector con impacto, usado en los casos limite
_BASE = _P + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class TestCvss4(unittest.TestCase):
    def test_42_pares_de_cisa(self):
        self.assertEqual(len(PARES), 42)
        for vector, esperado in PARES:
            if vector == _DISCREPANTE:
                continue
            with self.subTest(vector=vector):
                self.assertEqual(cvss4.puntuar(vector), esperado)

    def test_par_discrepante_de_cisa(self):
        # CISA publico 7.5 para UI:P, pero el algoritmo oficial lo pone en el mismo macrovector que
        # PR:L/UI:N (CISA: 7.1) y con distancia cero en ambos: los dos vectores solo pueden dar lo mismo.
        # El 7.5 de CISA no sale de la calculadora de FIRST (macrovector 101200 vale 7.2 como maximo).
        gemelo = _DISCREPANTE.replace("PR:N/UI:P", "PR:L/UI:N")
        self.assertEqual(dict(PARES)[gemelo], 7.1)
        self.assertEqual(cvss4.puntuar(gemelo), 7.1)
        self.assertEqual(cvss4.puntuar(_DISCREPANTE), 7.1)
        self.assertEqual(dict(PARES)[_DISCREPANTE], 7.5)

    def test_severidad_sale_de_la_puntuacion(self):
        self.assertEqual(cvss4.severidad(cvss4.puntuar(
            _P + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N")), "Media")    # 6.9, CISA lo rotula High
        casos = [(0.0, "Ninguna"), (0.1, "Baja"), (3.9, "Baja"), (4.0, "Media"), (6.9, "Media"),
                 (7.0, "Alta"), (8.9, "Alta"), (9.0, "Critica"), (10.0, "Critica")]
        for p, s in casos:
            self.assertEqual(cvss4.severidad(p), s)

    def test_sin_impacto_es_cero(self):
        self.assertEqual(cvss4.puntuar(_P + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"), 0.0)

    def test_todo_en_x_igual_a_solo_base(self):
        extra = "/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"
        self.assertEqual(cvss4.puntuar(_BASE + extra), cvss4.puntuar(_BASE))

    def test_threat_y_modificadas_mueven_la_puntuacion(self):
        base = cvss4.puntuar(_BASE)
        self.assertLess(cvss4.puntuar(_BASE + "/E:U"), cvss4.puntuar(_BASE + "/E:X"))
        self.assertEqual(cvss4.puntuar(_BASE + "/E:A"), base)       # X equivale al peor caso (A)
        fisico = _P + "AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        self.assertGreater(cvss4.puntuar(fisico + "/MAV:N"), cvss4.puntuar(fisico))
        self.assertEqual(cvss4.puntuar(fisico + "/MAV:N"), cvss4.puntuar(_BASE))

    def test_supplemental_no_cambia_nada(self):
        self.assertEqual(cvss4.puntuar(_BASE + "/S:P/AU:Y/R:I/V:C/RE:H/U:Red"), cvss4.puntuar(_BASE))

    def test_orden_libre(self):
        v = "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"
        self.assertEqual(cvss4.puntuar(v), cvss4.puntuar(_BASE))

    def test_nomenclatura(self):
        self.assertEqual(cvss4.nomenclatura(_BASE), "CVSS-B")
        self.assertEqual(cvss4.nomenclatura(_BASE + "/S:P"), "CVSS-B")
        self.assertEqual(cvss4.nomenclatura(_BASE + "/E:P"), "CVSS-BT")
        self.assertEqual(cvss4.nomenclatura(_BASE + "/CR:L"), "CVSS-BE")
        self.assertEqual(cvss4.nomenclatura(_BASE + "/MAV:A"), "CVSS-BE")
        self.assertEqual(cvss4.nomenclatura(_BASE + "/E:P/MAV:A"), "CVSS-BTE")

    def test_vectores_invalidos(self):
        malos = [_BASE.replace("4.0", "3.1"),
                 _P + "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",       # base incompleta
                 _BASE.replace("AV:N", "AV:Z"),                                    # valor fuera de lista
                 _BASE + "/AV:N",                                                  # metrica repetida
                 _BASE + "/ZZ:N", _BASE + "/E", "", None, "AV:N/AC:L"]
        for v in malos:
            with self.subTest(v=v), self.assertRaises(ValueError):
                cvss4.puntuar(v)

    def test_redondeo_mitad_hacia_arriba(self):
        # round() de Python da 0.2 (par) para 0.25 y 0.4 para 0.35 (por flotante); el JS sube siempre la mitad exacta
        self.assertEqual(cvss4._redondear(0.25), 0.3)
        self.assertEqual(cvss4._redondear(2.5), 2.5)
        self.assertEqual(cvss4._redondear(0.45), 0.5)
        self.assertEqual(cvss4._redondear(6.85), 6.9)
        self.assertEqual(round(0.25, 1), 0.2)           # lo que haria round(): esta prueba lo detecta


if __name__ == "__main__":
    unittest.main()
