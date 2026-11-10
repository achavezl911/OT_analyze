"""S1a: escritor XLSX minimo."""
from __future__ import annotations

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess.importers.lector import leer_xlsx
from ot_assess.report.xlsx import _col, escribir_xlsx

M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


class TestXlsx(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def _escribir(self, hojas, nombre="a.xlsx"):
        return Path(escribir_xlsx(Path(self.d.name) / nombre, hojas))

    def test_ida_y_vuelta(self):
        p = self._escribir([("H", ["Nombre", "Valor", "Nota"], [
            ["a & b <c> \"d\" 'e'", 5, "acentos: canon ñ é"],
            ["x", None, "n"],
            ["y", True, False]])])
        filas = leer_xlsx(p.read_bytes())
        self.assertEqual(filas[0], {"Nombre": "a & b <c> \"d\" 'e'", "Valor": "5",
                                    "Nota": "acentos: canon ñ é"})
        self.assertEqual(filas[1], {"Nombre": "x", "Valor": "", "Nota": "n"})
        p = self._escribir([("H", ["a", "b"], [["x", 2.5]])])
        self.assertEqual(leer_xlsx(p.read_bytes()), [{"a": "x", "b": "2.5"}])
        self.assertEqual(filas[2], {"Nombre": "y", "Valor": "Si", "Nota": "No"})

    def test_columnas(self):
        self.assertEqual([_col(n) for n in (1, 26, 27, 52, 703)], ["A", "Z", "AA", "AZ", "AAA"])

    def test_nombres_saneados_y_unicos(self):
        p = self._escribir([("a[b]:c*d?e/f\\g" + "x" * 40, ["h"], []), ("Dup", ["h"], []),
                            ("dup", ["h"], [])])
        with zipfile.ZipFile(p) as z:
            hojas = [s.get("name") for s in ET.fromstring(z.read("xl/workbook.xml")).iter(f"{M}sheet")]
        self.assertEqual(hojas[0], ("abcdefg" + "x" * 40)[:31])
        self.assertEqual(hojas[1:], ["Dup", "dup 2"])

    def test_control_eliminados(self):
        p = self._escribir([("H", ["a", "b"], [["x\x00y\x0bz\x1f", "ok\tn"]])])
        self.assertEqual(leer_xlsx(p.read_bytes())[0]["a"], "xyz")

    def test_trunca(self):
        p = self._escribir([("H", ["a", "b"], [["x" * 40000, "y"]])])
        self.assertEqual(len(leer_xlsx(p.read_bytes())[0]["a"]), 32767)

    def test_determinista(self):
        h = [("H", ["a", "b"], [["x", 1], ["y", None]]), ("I", ["c"], [])]
        self.assertEqual(self._escribir(h, "1.xlsx").read_bytes(),
                         self._escribir(h, "2.xlsx").read_bytes())

    def test_estructura(self):
        p = self._escribir([("H", ["a", "b"], [["x", 1]]), ("Vacia", ["c"], [])])
        with zipfile.ZipFile(p) as z:
            self.assertEqual(z.namelist(), [
                "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels", "xl/styles.xml",
                "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"])
            raices = {n: ET.fromstring(z.read(n)) for n in z.namelist()}
            ct = z.read("[Content_Types].xml").decode()
            self.assertIn("/xl/worksheets/sheet1.xml", ct)
            self.assertIn("/xl/worksheets/sheet2.xml", ct)
            wb = z.read("xl/workbook.xml").decode()
        self.assertEqual(wb.count("_xlnm._FilterDatabase"), 1)
        self.assertIn("'H'!$A$1:$B$2", wb)
        h1, h2 = raices["xl/worksheets/sheet1.xml"], raices["xl/worksheets/sheet2.xml"]
        self.assertEqual([c.tag[len(M):] for c in h1],
                         ["dimension", "sheetViews", "cols", "sheetData", "autoFilter"])
        self.assertEqual(h1.find(f"{M}autoFilter").get("ref"), "A1:B2")
        self.assertEqual(h1.find(f"{M}sheetViews/{M}sheetView/{M}pane").get("state"), "frozen")
        self.assertIsNone(h2.find(f"{M}autoFilter"))
        self.assertEqual(h1.find(f"{M}sheetData/{M}row/{M}c").get("s"), "1")
        for col in h1.iter(f"{M}col"):
            self.assertEqual(col.get("width"), "10")


if __name__ == "__main__":
    unittest.main()
