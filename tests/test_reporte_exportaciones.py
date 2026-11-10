"""Z2: el subcomando diagrama produce los mismos entregables que el analisis de capturas."""
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

from ot_assess import i18n
from ot_assess.cli import main

EJEMPLOS = RAIZ / "docs" / "ejemplos"
FW = ("FW1# show running-config\n"
      "access-list CSM_FW_ACL_ advanced permit ip ifc superv any ifc campo any rule-id 1\n"
      "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n"
      "FW1# show route\nCodes: L - local, C - connected, S - static\n"
      "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
      "C   10.20.1.0 255.255.255.0 is directly connected, campo\n"
      "C   10.20.2.0 255.255.255.0 is directly connected, superv\n"
      "FW1# show nameif\nInterface Name Security\nGigabitEthernet0/0 outside 0\n")
ENTREGABLES = ("reporte_ot.html", "reporte_ot.md", "reporte_ot.xlsx", "informe_ot.docx",
               "resumen_ejecutivo.html", "resumen_ejecutivo.docx", "plan_remediacion.csv",
               "hallazgos.csv", "diagramas.html")


class ReporteExportacionesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.fw = cls.tmp / "fw.txt"
        cls.fw.write_text(FW, encoding="utf-8")
        cls.vul = cls.tmp / "vul.csv"       # una vulnerabilidad grave sobre un PLC del inventario importado
        cls.vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                           "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware PLC ficticio,1.0,Escaner\n",
                           encoding="utf-8")
        cls.sin_fw = cls.correr("sin_fw")
        cls.completo = cls.correr("completo", "--firewall", str(cls.fw), "--vulnerabilidades", str(cls.vul),
                                  "--alertas", str(EJEMPLOS / "alertas.csv"))

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, destino, *extra):
        out = cls.tmp / destino
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(cls.est["activos"]),
                       "--enlaces", str(cls.est["enlaces"]), "-o", str(out), *extra])
        assert rc == 0
        return out

    def test_entregables(self):
        for n in ENTREGABLES:
            self.assertTrue((self.completo / n).is_file(), n)
        self.assertTrue(any(self.completo.glob("cobertura_*.csv")))

    def test_html_con_hallazgos_zonas_y_firewall(self):
        html = (self.completo / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("exportacion", html)          # hallazgos de inventario importado
        self.assertIn("Zonas", html)
        self.assertIn("firewall", html.lower())
        self.assertIn("Fuentes", html)
        self.assertNotIn('<div class="l">Capturas</div>', html)      # sin capturas no hay ese KPI
        self.assertNotIn("Resolucion de nombres", html)
        md = (self.completo / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("Fuentes", md)

    def test_plan_con_hallazgo_importado_y_criticidad_de_plc(self):
        with open(self.completo / "plan_remediacion.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertTrue(any(f["capturas"].startswith("exportacion") for f in filas))
        self.assertTrue(any(f["capturas"].startswith("vulnerabilidades") for f in filas))
        # sin firewall la ruta de ataque nombra al PLC importado: criticidad inferida de su tipo
        with open(self.sin_fw / "plan_remediacion.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertTrue(any(f["criticidad"] == "Critica" and f["origen_criticidad"] == "inferida"
                            and "10.20.1.11" in f["activos"].split(";") for f in filas), filas)

    def test_secciones_numeradas_sin_saltos(self):
        import re
        html = (self.completo / "reporte_ot.html").read_text(encoding="utf-8")
        md = (self.completo / "reporte_ot.md").read_text(encoding="utf-8")
        num_html = [int(n) for n in re.findall(r"<h2>(\d+)\. ", html)]
        num_md = [int(n) for n in re.findall(r"^## (\d+)\. ", md, re.MULTILINE)]
        self.assertGreaterEqual(len(num_html), 5)
        self.assertEqual(num_html, list(range(1, len(num_html) + 1)))
        self.assertGreaterEqual(len(num_md), 4)
        self.assertEqual(num_md, list(range(1, len(num_md) + 1)))

    def test_solo_diagramas_no_genera_reporte(self):
        out = self.correr("solo", "--solo-diagramas")
        self.assertTrue((out / "diagramas.html").is_file())
        for n in ("reporte_ot.html", "reporte_ot.xlsx", "informe_ot.docx", "plan_remediacion.csv"):
            self.assertFalse((out / n).exists(), n)

    def test_ingles_sin_faltantes(self):
        i18n.FALTANTES.clear()
        out = self.correr("en", "--idioma", "en", "--firewall", str(self.fw))
        faltantes = set(i18n.FALTANTES)
        i18n.usar("es")
        self.assertEqual(faltantes, set())
        html = (out / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn('lang="en"', html)
        self.assertNotIn("Hallazgos", html)
        from test_i18n import _espanol_en, _visible_html
        self.assertEqual(_espanol_en(_visible_html(html)), [])
        self.assertEqual(_espanol_en((out / "reporte_ot.md").read_text(encoding="utf-8")), [])

    def test_resultado_json_valido(self):
        datos = json.loads((self.completo / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(datos["capturas"], [])
        self.assertEqual(datos["entorno"]["modo"], "exportacion")


if __name__ == "__main__":
    unittest.main()
