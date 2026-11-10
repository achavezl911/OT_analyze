"""Pruebas del perfil de proyecto (sin tshark)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import perfil  # noqa: E402


def base() -> dict:
    return {"version": 1, "cliente": "Cliente Ejemplo", "sitio": "Planta Norte",
            "marcos": [{"clave": "iec62443", "edicion": "2018", "partes": ["3-3", "2-1"]},
                       {"clave": "nist-800-82", "edicion": "Rev. 3"}],
            "regulacion": ["Texto declarado"], "captura": {"ventana": "24 h", "punto": "SPAN"},
            "engagement": {"tipo": "pasivo", "exclusiones": ["sin pentesting"]},
            "sl_objetivo": {"Zona A": "SL2"}}


class PerfilTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def cargar(self, d):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return perfil.cargar(p)

    def test_ejemplo_del_repositorio_es_valido(self):
        p = perfil.cargar(RAIZ / "docs" / "ejemplos" / "perfil.json")
        self.assertEqual(p["cliente"], "Cliente Ejemplo")

    def falla(self, d, fragmento=""):
        with self.assertRaises(SystemExit) as cm:
            self.cargar(d)
        self.assertIn("perfil.json", str(cm.exception))
        self.assertNotIn(str(self.tmp), str(cm.exception))
        self.assertIn(fragmento, str(cm.exception))

    def test_valido_normalizado(self):
        p = self.cargar(base())
        self.assertEqual(p["idioma"], "es")
        self.assertEqual(p["marcos"][0]["partes"], ["3-3", "2-1"])
        self.assertEqual(p["sl_objetivo"], {"Zona A": "SL2"})
        self.assertIn(("Marco nist-800-82", "edicion Rev. 3; mapeo basado en SP 800-53 Rev. 5; "
                       "SP 800-82 Rev. 3 (sin revisar)"), perfil.etiquetas(p))

    def test_minimo_y_edicion_no_declarada(self):
        p = self.cargar({"version": 1, "cliente": "C", "marcos": [{"clave": "nerc-cip"}]})
        valor = dict(perfil.etiquetas(p))["Marco nerc-cip"]
        self.assertTrue(valor.startswith("edicion no declarada; mapeo basado en sin declarar"), valor)

    def test_errores(self):
        d = base(); d["extra"] = 1; self.falla(d, "extra")
        d = base(); d["marcos"][0]["extra"] = 1; self.falla(d, "extra")
        d = base(); del d["cliente"]; self.falla(d, "cliente")
        d = base(); d["marcos"] = []; self.falla(d, "marcos")
        d = base(); d["marcos"][1]["partes"] = ["3-3"]; self.falla(d, "partes")
        d = base(); d["marcos"][0]["partes"] = ["5-1"]; self.falla(d, "5-1")
        d = base(); d["idioma"] = "fr"; self.falla(d, "'es' o 'en'")
        d = base(); d["sl_objetivo"] = {"Z": "SL5"}; self.falla(d, "SL5")
        d = base(); d["version"] = 2; self.falla(d, "version")
        d = base(); d["sitio"] = 5; self.falla(d, "sitio")
        d = base(); d["cliente"] = "  "; self.falla(d, "cliente")


if __name__ == "__main__":
    unittest.main()
