"""SALP1 (D121): restricciones de alcance por proyecto (sin tshark)."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_resumen_ejecutivo as tre
import test_solicitud_cambio as tsc

from ot_assess import cli, cli_politica, i18n, perfil
from ot_assess import resumen_ejecutivo as rx
from ot_assess.consolidate import build_conduits, merge_assets
from ot_assess.model import Assessment, Capture
from ot_assess.report import html, md, word
from ot_assess.report.jsonout import write_json

LEYENDA = "Insumo de trabajo; no es entregable"
MSG = "deshabilitado por el perfil del proyecto: clave subcomandos_deshabilitados"


def _perfil(tmp, **extra):
    d = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}
    p = Path(tmp) / "perfil.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    return p


def _res(per):
    cap = Capture(Path("p.pcap"))
    h = cap.host("aa:bb:cc:00:00:01")
    h["ips"] |= {"198.51.100.5"}
    assets, idx = merge_assets([cap])
    args = SimpleNamespace(max_rows=500, titulo="t", cliente="C", max_packets=0)
    res = Assessment([cap], assets, build_conduits([cap], idx), args)
    res.entorno = {"max_packets": 0, "ot_assess": "x", "commit": "", "tshark": "", "estandares": "iec62443",
                   "campos_ignorados": [], "capturas": []}
    res.perfil = per
    return res


class TestPerfil(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_valores_validos(self):
        p = perfil.cargar(_perfil(self.tmp, subcomandos_deshabilitados=["solicitud-cambio", "politica-fmc"],
                                  leyenda_salidas=LEYENDA))
        self.assertEqual(p["subcomandos_deshabilitados"], ["politica-fmc", "solicitud-cambio"])
        self.assertEqual(p["leyenda_salidas"], LEYENDA)

    def test_invalidos(self):
        for extra in ({"subcomandos_deshabilitados": ["otro"]}, {"subcomandos_deshabilitados": "politica-fmc"},
                      {"subcomandos_deshabilitados": [1]}, {"leyenda_salidas": ""}, {"leyenda_salidas": "a\nb"},
                      {"leyenda_salidas": "x" * 201}, {"leyenda_salidas": 5}):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as cm:
                perfil.cargar(_perfil(self.tmp, **extra))
            self.assertIn("[!]", str(cm.exception))


class TestRestricciones(tsc.Base):
    def _resultado(self, per):
        write_json(_res(per), self.d)

    def _sin_archivos_nuevos(self, rc, err, carpeta):
        self.assertEqual(rc, 2)
        self.assertIn(MSG, err)
        self.assertFalse(carpeta.exists())

    def test_resultado_json_lleva_restricciones(self):
        self._resultado({"cliente": "A", "subcomandos_deshabilitados": ["politica-fmc"]})
        r = json.loads((self.d / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(r["restricciones"], {"subcomandos_deshabilitados": ["politica-fmc"]})

    def test_sin_clave_resultado_json_no_cambia(self):
        self._resultado({"cliente": "A"})
        r = json.loads((self.d / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("restricciones", r)
        self.assertEqual(r["perfil"], {"cliente": "A"})

    def test_politica_fmc_y_solicitud_deshabilitadas(self):
        self._resultado({"cliente": "A", "subcomandos_deshabilitados": ["politica-fmc", "solicitud-cambio"]})
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = cli_politica.main(["--propuesta", self.prop, "--objetos", self.objs, "-o", str(self.d / "f")])
        self._sin_archivos_nuevos(rc, err.getvalue(), self.d / "f")
        rc, err, out = self.correr()
        self._sin_archivos_nuevos(rc, err, out)

    def test_solo_una_deshabilitada(self):
        self._resultado({"cliente": "A", "subcomandos_deshabilitados": ["politica-fmc"]})
        rc, err, _ = self.correr()
        self.assertEqual(rc, 0, err)

    def test_solicitud_con_perfil_que_lo_declara(self):
        p = _perfil(self.d, subcomandos_deshabilitados=["solicitud-cambio"])
        rc, err, out = self.correr("--perfil", str(p))
        self._sin_archivos_nuevos(rc, err, out)

    def test_sin_clave_funcionan_como_hoy(self):
        self._resultado({"cliente": "A"})
        rc, err, _ = self.correr("--perfil", str(_perfil(self.d)))
        self.assertEqual(rc, 0, err)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli_politica.main(["--propuesta", self.prop, "--objetos", self.objs, "-o", str(self.d / "f")])
        self.assertEqual(rc, 0)

    def test_perfil_invalido_en_solicitud_es_error_controlado(self):
        p = _perfil(self.d, subcomandos_deshabilitados=["x"])
        rc, _, out = self.correr("--perfil", str(p))
        self.assertEqual(rc, 2)
        self.assertFalse(out.exists())


class TestLeyenda(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _salidas(self, per):
        res = _res(per)
        return (html.write_html(res, self.tmp).read_text(encoding="utf-8"),
                md.write_md(res, self.tmp).read_text(encoding="utf-8"),
                json.dumps(word.construir_bloques(res), ensure_ascii=False))

    def test_aparece_en_html_md_word(self):
        base = {"cliente": "A", "marcos": [{"clave": "iec62443"}], "clasificacion": "Confidencial"}
        for salida in self._salidas({**base, "leyenda_salidas": LEYENDA}):
            self.assertIn(LEYENDA, salida)
        for salida in self._salidas(base):
            self.assertNotIn(LEYENDA, salida)
            self.assertNotIn("Leyenda de salidas", salida)

    def test_resumen_ejecutivo(self):
        res = tre.corrida(tre.siete(), perfil={"clasificacion": "Conf", "leyenda_salidas": LEYENDA})
        rx.write_resumen(res, self.tmp)
        self.assertIn(LEYENDA, (self.tmp / "resumen_ejecutivo.html").read_text(encoding="utf-8"))
        self.assertIn(LEYENDA, tre.texto_docx(self.tmp / "resumen_ejecutivo.docx"))
        self.assertTrue(any(b[0] == "nota" and LEYENDA in b[1] for b in rx.construir_bloques(rx.datos(res))))
        res.perfil = {"clasificacion": "Conf"}
        self.assertFalse(any(LEYENDA in str(b) for b in rx.construir_bloques(rx.datos(res))))


class TestSitios(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")
        for n in ("a", "b"):
            (self.tmp / n).mkdir()

    def _cli(self, *args):
        o, e = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            rc = cli.main(["sitios", *map(str, args)])
        return rc, o.getvalue(), e.getvalue()

    def test_salida_dentro_o_igual_a_un_sitio(self):
        for o in (self.tmp / "a", self.tmp / "a" / "consolidado", self.tmp / "b" / "x" / "y"):
            with self.subTest(o=str(o)):
                antes = sorted(self.tmp.rglob("*"))
                rc, _, err = self._cli(self.tmp / "a", self.tmp / "b", "-o", o)
                self.assertEqual(rc, 2)
                self.assertIn("el consolidado mezcla sitios", err)
                self.assertEqual(sorted(self.tmp.rglob("*")), antes)

    def test_salida_fuera_lleva_uso(self):
        rc, out, err = self._cli(self.tmp / "a", self.tmp / "b", "-o", self.tmp / "fuera")
        self.assertEqual(rc, 0, err)
        self.assertIn("interno (consolida varios sitios; no se entrega a un sitio)", out)
        js = json.loads((self.tmp / "fuera" / "consolidado_sitios.json").read_text(encoding="utf-8"))
        self.assertEqual(js["uso"], "interno (consolida varios sitios; no se entrega a un sitio)")


if __name__ == "__main__":
    unittest.main()
