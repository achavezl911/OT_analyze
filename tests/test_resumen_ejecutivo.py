"""Pruebas del resumen ejecutivo de una pagina (S5). Sin tshark."""
from __future__ import annotations

import csv
import io
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import i18n, remediacion, riesgo
from ot_assess import resumen_ejecutivo as rx
from ot_assess.report import ESCRITORES, write_all

PLC = "Controlador / dispositivo de campo (PLC, RTU, IED)"
LARGA = "Aislar el segmento " + "x" * 200 + ". Segunda oracion."


def hallazgo(titulo, sev, ev, rec="Rec corta. Otra oracion."):
    return {"titulo": titulo, "severidad": sev, "evidencia": ev, "captura": "a.pcap", "categoria": "Higiene",
            "recomendacion": rec}


def corrida(hallazgos, ips=("10.0.0.1",), perfil=None, zonas=None):
    cap = SimpleNamespace(findings=hallazgos, flow_packets=1)
    assets = {i: {"ips": {ip}, "role": PLC, "zona_asignada": (zonas or {}).get(ip, "")}
              for i, ip in enumerate(ips)}
    return SimpleNamespace(caps=[cap], extras=[], assets=assets, perfil=perfil or {},
                           rutas_ataque={}, riesgos={},
                           conduits=[{"cruza_zona": True}, {"cruza_zona": False}],
                           args=SimpleNamespace(titulo="Proyecto <X>", cliente="Cli"))


def siete():
    # puntuaciones distintas para fijar el orden: Alta/PLC=9 ... Baja/PLC=3
    sevs = ["Baja", "Media", "Alta", "Baja", "Media", "Alta", "Baja"]
    return [hallazgo(f"T{i}", s, "ip 10.0.0.1" if i % 2 else "sin ip") for i, s in enumerate(sevs)]


def texto_docx(ruta):
    with zipfile.ZipFile(ruta) as z:
        x = z.read("word/document.xml").decode("utf-8")
    return " ".join(re.findall(r"(?s)<w:t(?: [^>]*)?>(.*?)</w:t>", x))


class ResumenTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def escribir(self, res):
        rx.write_resumen(res, self.tmp)
        return ((self.tmp / "resumen_ejecutivo.html").read_text(encoding="utf-8"),
                texto_docx(self.tmp / "resumen_ejecutivo.docx"))

    def _dos_zonas(self, **perfil_extra):
        # A: Alta en zona de impacto 1; B: Media en zona de impacto 5
        perfil = {"zonas": [{"nombre": "Z1", "impacto": {"seguridad": 1}},
                                {"nombre": "Z5", "impacto": {"seguridad": 5}}], **perfil_extra}
        hs = [hallazgo("HA", "Alta", "ip 10.0.0.1"), hallazgo("HB", "Media", "ip 10.0.0.2")]
        return corrida(hs, ips=("10.0.0.1", "10.0.0.2"), perfil=perfil,
                       zonas={"10.0.0.1": "Z1", "10.0.0.2": "Z5"})

    def test_registro_y_plan_ordenan_distinto_y_gana_el_registro(self):
        res = self._dos_zonas()
        self.assertEqual([f["titulo"] for f in remediacion.plan(res)], ["HA", "HB"])
        d = rx.datos(res)
        self.assertEqual([r["titulo"] for r in d["riesgos"]], ["HB", "HA"])
        self.assertEqual(d["riesgos"][0]["puntuacion"], "3 x 5 = 15")
        self.assertEqual(d["riesgos"][0]["nivel"], "Alto")
        self.assertEqual(d["riesgos"][0]["id"], riesgo.de(res)["filas"][0]["id_riesgo"])
        html, docx = self.escribir(res)
        for texto in (html, docx):
            self.assertLess(texto.find("HB"), texto.find("HA"))
            self.assertNotIn("Criticidad", texto)
        self.assertIn("3 x 5 = 15", html)

    def test_ids_del_resumen_son_los_primeros_de_riesgos_csv(self):
        res = corrida(siete())
        r = riesgo.de(res)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(riesgo.COLUMNAS)
        w.writerows(riesgo.tabla(r))
        csv_ids = [x["id_riesgo"] for x in csv.DictReader(io.StringIO(buf.getvalue()))]
        self.assertEqual([x["id"] for x in rx.datos(res)["riesgos"]], csv_ids[:5])

    def test_ajuste_del_analista_sube_al_primer_lugar(self):
        hid = riesgo.id_hallazgo("HA")
        res = self._dos_zonas(ajustes_riesgo={hid: {"probabilidad": 5, "impacto": 5, "justificacion": "Expuesto"}})
        self.assertEqual(rx.datos(self._dos_zonas())["riesgos"][0]["titulo"], "HB")
        d = rx.datos(res)
        self.assertEqual(d["riesgos"][0]["titulo"], "HA")
        self.assertEqual(d["riesgos"][0]["puntuacion"], "5 x 5 = 25")

    def test_plan_de_remediacion_no_cambia(self):
        res = self._dos_zonas()
        antes = [(f["titulo"], f["fase"], f["criticidad"]) for f in remediacion.plan(res)]
        rx.datos(res)
        self.assertEqual([(f["titulo"], f["fase"], f["criticidad"]) for f in remediacion.plan(res)], antes)
        self.assertEqual([a[0] for a in antes], ["HA", "HB"])
        self.assertEqual(sum(n for _f, n in rx.datos(res)["fases"]), 2)

    def test_solo_cinco_riesgos_en_el_orden_del_registro(self):
        res = corrida(siete())
        orden = [f["titulo"] for f in riesgo.de(res)["filas"]]
        self.assertEqual(len(orden), 7)
        d = rx.datos(res)
        self.assertEqual([r["titulo"] for r in d["riesgos"]], orden[:5])
        html, docx = self.escribir(res)
        for texto in (html, docx):
            pos = [texto.find(t) for t in orden[:5]]
            self.assertTrue(all(p >= 0 for p in pos))
            self.assertEqual(pos, sorted(pos))
            for t in orden[5:]:
                self.assertNotIn(t, texto)
            self.assertIn("Orden del registro de riesgos (probabilidad x impacto)", texto)
        self.assertEqual(html.count("<tr>"), 6)

    def test_recomendacion_recortada(self):
        res = corrida([hallazgo("H", "Alta", "ip 10.0.0.1", LARGA)])
        rec = rx.datos(res)["riesgos"][0]["recomendacion"]
        self.assertLessEqual(len(rec), 160)
        self.assertTrue(rec.endswith("..."))
        self.assertNotIn("Segunda", rec)
        self.assertEqual(rx.recortar("Rec corta. Otra oracion."), "Rec corta. Otra oracion.")
        self.assertEqual(rx.recortar("Atribuir el origen. " + "y" * 150 + "."), "Atribuir el origen.")

    def test_activos_maximo_tres(self):
        ips = [f"10.0.0.{i}" for i in range(1, 6)]
        res = corrida([hallazgo("H", "Alta", " ".join(ips))], ips=ips)
        act = rx.datos(res)["riesgos"][0]["activos"]
        self.assertEqual(act, "10.0.0.1, 10.0.0.2, 10.0.0.3 y 2 mas")

    def test_sin_hallazgos_priorizables(self):
        res = corrida([hallazgo("I", "Informativa", "x")])
        html, docx = self.escribir(res)
        for texto in (html, docx):
            self.assertIn("Sin hallazgos que priorizar.", texto)
        self.assertNotIn("<table", html)

    def test_texto_escapado_y_sin_cumplimiento(self):
        res = corrida([hallazgo("<script>alert(1)</script>", "Alta", "ip 10.0.0.1")])
        html, _ = self.escribir(res)
        self.assertNotIn("<script", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Proyecto &lt;X&gt;", html)
        self.assertIn("@page { size: letter; margin: 1.5cm }", html)
        self.assertNotRegex(html.lower(), r"\bcumple\b|no cumple")
        self.assertIn("no es una evaluacion de cumplimiento", html)

    def test_conteos(self):
        d = rx.datos(corrida(siete()))
        self.assertEqual(d["severidades"], [("Alta", 2), ("Media", 2), ("Baja", 3)])
        self.assertEqual(sum(n for _f, n in d["fases"]), 7)
        self.assertIn("Conductos que cruzan zonas: 1", d["alcance"])

    def test_write_all_genera_los_dos_archivos(self):
        self.assertIn("resumen", [n for n, _f in ESCRITORES])
        mod = sys.modules["ot_assess.report"]
        solo = [("resumen", rx.write_resumen)]
        orig = mod.ESCRITORES
        mod.ESCRITORES = solo
        try:
            r = write_all(corrida(siete()), self.tmp)
        finally:
            mod.ESCRITORES = orig
        self.assertEqual(r["resumen"], self.tmp / "resumen_ejecutivo.html")
        self.assertTrue((self.tmp / "resumen_ejecutivo.docx").exists())

    def test_ingles_sin_palabras_en_espanol(self):
        from test_i18n import _espanol_en, _visible_html
        self.addCleanup(i18n.usar, "es")
        i18n.usar("en")
        i18n.FALTANTES.clear()
        # titulo y recomendacion son claves del catalogo (texto del hallazgo traducido)
        res = corrida([hallazgo("Capturas", "Alta", "Capturas", "Activos")],
                      perfil={"clasificacion": "Confidencial"})
        html, docx = self.escribir(res)
        self.assertEqual(i18n.FALTANTES, set())
        self.assertIn("Executive summary", html)
        for texto in (html, docx):
            self.assertIn("Order of the risk register (probability x impact)", texto)
            self.assertIn("Score", texto)
            self.assertIn("Level", texto)
        for texto in (_visible_html(html), docx):
            self.assertEqual(_espanol_en(texto), [])


if __name__ == "__main__":
    unittest.main()
