"""CSFT (D116): transicion oficial de NIST CSF 1.1 a 2.0 (catalogo, script y hoja de la corrida)."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports

from ot_assess import csf_transicion as cft
from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.importers.lector import leer_xlsx_hojas
from ot_assess.report.xlsx import escribir_xlsx
from ot_assess.standards import ESTANDARES
from scripts import actualizar_csf_transicion as act

REFS = json.loads((RAIZ / "ot_assess" / "marcos" / "csf2_referencias.json").read_text(encoding="utf-8"))["subcategorias"]
CAB = ["CSF 1.1 Identifier", "CSF 1.1 Description", "CSF 1.1 SORT-ID", "Relocation", "Noteworthy Modifications",
       "CSF 2.0 Identifier", "CSF 2.0 Description", "New in CSF 2.0", "CSF 2.0 SORT-ID", "Implementation Examples"]
DATOS = [
    ["ID.AM-1", " Inventario fisico ", "v11-001", "Y (moved to)", "mod", "ID.AM-01", "Desc A", "N", "s1", "ejemplo"],
    ["ID.AM-1", "Inventario fisico", "v11-001", "Y (moved to)", "", "ID.AM-08", "Desc B", "N", "s2", "ejemplo"],
    ["", "", "", "N/A", "", "GV.OC-01", "Nueva", "Y", "s3", "ejemplo"],
    ["", "", "", "", "", "", "", "", "", ""],
]


def _h(titulo, nist, sev="Alta"):
    return {"titulo": titulo, "severidad": sev, "categoria": "c", "evidencia": "e", "por_que_importa": "p",
            "recomendacion": "r", "referencias": {"nist-csf": nist}}


def _xlsx(ruta, cab=CAB, datos=DATOS, hoja=act.HOJA):
    escribir_xlsx(ruta, [("Spreadsheet Overview", ["a"], [["x"]]), (hoja, cab, datos)])


class ScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_sintetico_determinista_y_check(self):
        x = self.tmp / "t.xlsx"
        _xlsx(x)
        salida = self.tmp / "s.json"
        self.assertEqual(act.main([str(x), "--salida", str(salida)]), 0)
        primero = salida.read_bytes()
        self.assertEqual(act.main([str(x), "--salida", str(salida)]), 0)
        self.assertEqual(salida.read_bytes(), primero)
        cat = json.loads(primero)
        self.assertEqual(cat["fecha"], "2024-09-19")
        self.assertEqual([f["id_20"] for f in cat["filas"]], ["ID.AM-01", "ID.AM-08", "GV.OC-01"])
        self.assertEqual(cat["filas"][0]["descripcion_11"], "Inventario fisico")      # recorta extremos
        self.assertEqual(cat["filas"][2], {"id_11": "", "descripcion_11": "", "reubicacion": "N/A",
                                           "modificaciones": "", "id_20": "GV.OC-01",
                                           "descripcion_20": "Nueva", "nueva_en_20": "Y"})
        self.assertNotIn("ejemplo", primero.decode("utf-8"))
        self.assertEqual(act.main([str(x), "--salida", str(salida), "--check"]), 0)
        salida.write_text("{}\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(act.main([str(x), "--salida", str(salida), "--check"]), 1)
        self.assertEqual(salida.read_text(encoding="utf-8"), "{}\n")                      # --check no escribe

    def test_hoja_faltante(self):
        x = self.tmp / "t.xlsx"
        _xlsx(x, hoja="Otra")
        with self.assertRaises(SystemExit) as e:
            act.main([str(x), "--salida", str(self.tmp / "s.json")])
        self.assertIn(act.HOJA, str(e.exception))

    def test_columna_faltante(self):
        x = self.tmp / "t.xlsx"
        _xlsx(x, cab=[c for c in CAB if c != "Relocation"], datos=[[c for i, c in enumerate(r) if i != 3] for r in DATOS])
        with self.assertRaises(SystemExit) as e:
            act.main([str(x), "--salida", str(self.tmp / "s.json")])
        self.assertIn("Relocation", str(e.exception))
        self.assertFalse((self.tmp / "s.json").exists())


class CatalogoTest(unittest.TestCase):
    def test_catalogo_del_repo(self):
        filas = cft.cargar()["filas"]
        self.assertEqual(len(filas), 211)
        self.assertEqual(sum(1 for f in filas if f["nueva_en_20"] == "Y" and not f["id_11"]), 12)
        self.assertEqual({f["reubicacion"] for f in filas}, {"Y (incorporated into)", "Y (moved to)", "N", "N/A"})
        for f in filas:
            if "-" in f["id_20"]:
                self.assertIn(f["id_20"], REFS)
            self.assertFalse("-" in f["id_20"] and f["id_20"].count(".") == 0)
        self.assertGreater(len(cft.pasos("ID.AM-1")), 0)
        self.assertEqual(cft.pasos("XX.YY-9"), [])
        repetidos = [i for i in {f["id_11"] for f in filas if f["id_11"]} if len(cft.pasos(i)) > 1]
        self.assertTrue(repetidos)
        self.assertEqual(sum(len(cft.pasos(i)) for i in repetidos),
                         sum(1 for f in filas if f["id_11"] in repetidos))

    def test_cuenta_exacta_agrupada(self):
        hall = [_h("Uno", "PR.AA-05 Acceso"), _h("Dos", "PR.AA-05; DE.CM-01"),
                _h("Dos", "PR.AA-05; DE.CM-01"),                      # repetido: una vez
                _h("Tres", "GV.OC Contexto")]                         # categoria, no subcategoria
        filas = cft.filas(hall)
        col = cft.COLUMNAS.index
        por = {f[col("csf20")]: f for f in filas}
        aa = por["PR.AA-05"]
        self.assertEqual((aa[col("hallazgos_en_esta_corrida")], aa[col("titulos")]), (2, "Dos; Uno"))
        self.assertEqual(por["GV.OC-01"][col("hallazgos_en_esta_corrida")], 0)
        self.assertEqual(por["GV.OC"][col("hallazgos_en_esta_corrida")], 1)
        self.assertEqual(por["GV.OC"][col("titulos")], "Tres")
        self.assertEqual(len(filas), len(cft.cargar()["filas"]))
        self.assertTrue(all(len(f) == len(cft.COLUMNAS) for f in filas))

    def test_solo_con_nist_csf(self):
        self.assertEqual(cft.tablas([], [ESTANDARES["iec62443"]]), [])
        self.assertEqual(cft.tablas([], [ESTANDARES["iec62443"], ESTANDARES["nist-csf"]])[0][0], cft.ARCHIVO)


class CorridaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        cls.sin = cls.correr("sin")
        cls.con = cls.correr("con", "--estandar", "iec62443,nist-csf")
        cls.en = cls.correr("en", "--estandar", "nist-csf", "--idioma", "en")
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, destino, *extra):
        out = cls.tmp / destino
        with contextlib.redirect_stdout(io.StringIO()):
            assert main([*cls.args, "-o", str(out), *extra]) == 0
        return out

    @staticmethod
    def hojas(carpeta):
        return dict(leer_xlsx_hojas((carpeta / "reporte_ot.xlsx").read_bytes()))

    def test_sin_nist_csf_nada(self):
        self.assertFalse((self.sin / cft.ARCHIVO).exists())
        self.assertNotIn(cft.HOJA, self.hojas(self.sin))

    def test_con_nist_csf_archivo_y_hoja(self):
        with open(self.con / cft.ARCHIVO, newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.reader(fh))
        self.assertEqual(filas[0], cft.COLUMNAS)
        self.assertEqual(len(filas) - 1, 211)
        hoja = self.hojas(self.con)[cft.HOJA]
        self.assertEqual(hoja[0], cft.COLUMNAS)
        self.assertEqual(len(hoja) - 1, 211)

    def test_ingles(self):
        with open(self.en / cft.ARCHIVO, newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.reader(fh))
        self.assertEqual(filas[0][0], "csf_1_1")
        self.assertEqual(filas[0][2], "relocation")
        self.assertEqual(filas[1][2], cft.cargar()["filas"][0]["reubicacion"])           # valores oficiales sin traducir
        self.assertIn("CSF 1.1 to 2.0", self.hojas(self.en))


if __name__ == "__main__":
    unittest.main()
