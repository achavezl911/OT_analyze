"""CSF2T (D110): Tiers de NIST CSF 2.0 por funcion, meta del perfil, tier declarado y evidencia de la matriz."""
from __future__ import annotations

import contextlib
import csv
import io
import json
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

import gen_exports

from ot_assess import csf_tiers as ct
from ot_assess import i18n, perfil
from ot_assess import matriz_controles as mc
from ot_assess.cli import main

REFS = json.loads((RAIZ / "ot_assess" / "marcos" / "csf2_referencias.json").read_text(encoding="utf-8"))["subcategorias"]
T_SC7 = "Conductos entre zonas sin firewall observado en el camino"
OBJETIVOS = {"GV": "Repetible", "ID": "Adaptive", "PR": 3, "DE": "3", "RS": 4, "RC": "repeatable"}


def hallazgo(titulo, sev, nist):
    return {"titulo": titulo, "severidad": sev, "categoria": "Higiene", "evidencia": "x 10.0.0.1",
            "captura": "a.pcap", "recomendacion": "Rec", "activos": ["10.0.0.1"],
            "referencias": {mc.CLAVE_NIST: nist}}


def corrida(hallazgos=(), perf=None):
    hs = list(hallazgos)
    return SimpleNamespace(caps=[SimpleNamespace(findings=hs)], extras=[], perfil=perf or {},
                           matriz_controles=mc.construir({}, {}, {}, hs, perf))


def fun(m, clave):
    return next(x for x in m["funciones"] if x["clave"] == clave)


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        i18n.usar("es")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def csv(self, texto):
        p = self.tmp / "csf_tiers.csv"
        p.write_text(texto, encoding="utf-8")
        return p

    def perfil(self, valor):
        pf = self.tmp / "perfil.json"
        pf.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                  "csf_tiers_objetivo": valor}), encoding="utf-8")
        return perfil.cargar(pf)


class TierTest(Base):
    def test_tier_de_acepta_numero_texto_y_nombres(self):
        def malo(m):
            raise ValueError(m)
        for v, n in ((1, 1), ("2", 2), (" 3 ", 3), ("Repetible", 3), ("ADAPTIVE", 4), ("risk informed", 2),
                     ("Informado  por el riesgo", 2), ("partial", 1), ("parcial", 1)):
            self.assertEqual(ct.tier_de(v, malo), n, v)
        for v in (0, 5, "7", "", True, 2.5, None, "Optimo"):
            with self.assertRaises(ValueError, msg=str(v)):
                ct.tier_de(v, malo)

    def test_perfil_valido_e_invalido(self):
        self.assertEqual(self.perfil(OBJETIVOS)["csf_tiers_objetivo"],
                         {"GV": 3, "ID": 4, "PR": 3, "DE": 3, "RS": 4, "RC": 3})
        for malo in ({"XX": 2}, {"GV": 5}, {"GV": "mucho"}, {"GV": True}, ["GV"], {"gv": 2}):
            with self.assertRaises(SystemExit, msg=str(malo)):
                self.perfil(malo)


class EvidenciaTest(Base):
    def test_sin_perfil_ni_archivo_no_hay_seccion(self):
        m = ct.construir(corrida(), None)
        self.assertEqual(m, {})
        self.assertFalse(ct.hay(m))
        self.assertEqual(ct.tablas(m), [])
        self.assertEqual(ct.para_json(m), {})

    def test_metas_del_perfil_y_propuesta(self):
        m = ct.construir(corrida(perf=self.perfil({"GV": "Repetible", "ID": 4})))
        self.assertEqual([x["clave"] for x in m["funciones"]], list(ct.FUNCIONES))
        self.assertEqual((fun(m, "GV")["objetivo"], fun(m, "ID")["objetivo"], fun(m, "PR")["objetivo"]), (3, 4, 2))
        self.assertEqual(fun(m, "GV")["origen_objetivo"], ct.ORIGEN_PERFIL)
        self.assertEqual(fun(m, "PR")["origen_objetivo"], ct.ORIGEN_PROPUESTO)
        self.assertTrue(all(x["actual"] is None and x["brecha"] is None for x in m["funciones"]))

    def test_conteos_igualan_un_calculo_independiente(self):
        res = corrida([hallazgo(T_SC7, "Media", "SC-7")], perf={"csf_tiers_objetivo": {}})
        m = ct.construir(res)
        filas = res.matriz_controles["nist"]["filas"]
        pr = fun(m, "PR")["evidencia"]
        self.assertGreater(pr["brecha"], 0)
        for f in ct.FUNCIONES:
            ctl = set()
            for sub, d in REFS.items():
                if sub.startswith(f + "."):
                    ctl |= {c.split("(")[0] for c in d["sp800_53"]}
            esperado = [r for r in filas if r["id"].split("(")[0] in ctl]
            e = fun(m, f)["evidencia"]
            self.assertEqual(e["brecha"], sum(r["estado"] == "brecha con evidencia" for r in esperado), f)
            self.assertEqual(e["observado"], sum(r["estado"] == "control observado" for r in esperado), f)
            self.assertEqual(e["sin_evidencia"], sum(r["estado"].startswith("sin evidencia") for r in esperado), f)
            self.assertEqual(e["no_evaluable"], sum(r["estado"].startswith("no evaluable") for r in esperado), f)
            self.assertEqual(e["subcategorias"], sum(1 for s in REFS if s.startswith(f + ".")))
            self.assertGreater(e["subcategorias"], 0)

    def test_brecha_y_revision(self):
        res = corrida([hallazgo(T_SC7, "Alta", "SC-7")], perf=self.perfil({"GV": 3, "RS": 4, "PR": 3}))
        decl = {"GV": {"tier_actual": 2}, "RS": {"tier_actual": 4}, "PR": {"tier_actual": 3}}
        m = ct.construir(res, decl)
        self.assertEqual(fun(m, "GV")["brecha"], 1)
        self.assertEqual(fun(m, "RS")["brecha"], 0)
        self.assertIn(T_SC7, fun(m, "PR")["revision"])
        self.assertTrue(fun(m, "PR")["revision"].startswith("revisar:"))
        self.assertEqual(fun(m, "PR")["actual"], 3)         # la revision no cambia el tier
        self.assertEqual(fun(m, "RS")["revision"], "")      # sin hallazgo Alta en sus filas
        self.assertIsNone(fun(m, "DE")["actual"])
        # tier 2 con el mismo hallazgo: no se revisa; hallazgo Media con tier 3: tampoco
        self.assertEqual(fun(ct.construir(res, {"PR": {"tier_actual": 2}}), "PR")["revision"], "")
        media = corrida([hallazgo(T_SC7, "Media", "SC-7")])
        self.assertEqual(fun(ct.construir(media, {"PR": {"tier_actual": 3}}), "PR")["revision"], "")


class LecturaTest(Base):
    def test_lee_nombres_numeros_y_vacios(self):
        p = self.csv("﻿funcion;tier_actual;comentario\nGV;Repetible;ok\nid;2;\nPR;;\n")
        d = ct.leer(p)
        self.assertEqual((d["GV"]["tier_actual"], d["ID"]["tier_actual"], d["PR"]["tier_actual"]), (3, 2, None))
        self.assertEqual(d["GV"]["comentario"], "ok")

    def test_errores_con_numero_de_linea(self):
        for texto, linea in (("funcion,tier_actual\nGV,2\nGV,3\n", "linea 3"), ("funcion,tier_actual\nGV,7\n", "linea 2"),
                             ("funcion,tier_actual\nGV,2\nXX,2\n", "linea 3"), ("funcion,x\nGV,2\n", "linea 1")):
            with self.assertRaises(ct.ErrorCsfTiers) as e:
                ct.leer(self.csv(texto))
            self.assertIn(linea, str(e.exception), texto)

    def test_el_cli_falla_antes_de_analizar_y_no_escribe_nada(self):
        p = self.csv("funcion,tier_actual\nGV,2\nGV,3\n")
        out = self.tmp / "salida"
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as e:
            main(["diagrama", "--activos", "no.csv", "--enlaces", "no.csv", "--csf-tiers", str(p), "-o", str(out)])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("linea 3", err.getvalue())
        self.assertFalse(out.exists())


class ReporteTest(unittest.TestCase):
    """`diagrama` de punta a punta: sin nada, solo perfil, con --csf-tiers e ingles."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        pf = cls.tmp / "perfil.json"
        pf.write_text(json.dumps({"version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}],
                                  "csf_tiers_objetivo": OBJETIVOS}), encoding="utf-8")
        cls.pf = pf
        tiers = cls.tmp / "tiers.csv"
        tiers.write_text("funcion,tier_actual,entrevistado\nGV,2,Ana\nRS,4,\n", encoding="utf-8")
        cls.sin = cls.correr("sin")
        cls.solo = cls.correr("solo", "--perfil", str(pf))
        cls.con = cls.correr("con", "--perfil", str(pf), "--csf-tiers", str(tiers))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--perfil", str(pf), "--csf-tiers", str(tiers), "--idioma", "en")
        cls.faltantes = set(i18n.FALTANTES)
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, destino, *extra):
        out = cls.tmp / destino
        with contextlib.redirect_stdout(io.StringIO()):
            assert main([*cls.args, "-o", str(out), *extra]) == 0
        return out

    @staticmethod
    def leer(ruta):
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def test_sin_perfil_ni_opcion_nada_nuevo(self):
        self.assertFalse((self.sin / "csf_tiers.csv").exists())
        self.assertNotIn("csf_tiers", json.loads((self.sin / "resultado.json").read_text(encoding="utf-8")))
        for nombre in ("reporte_ot.html", "reporte_ot.md"):
            self.assertNotIn("Tiers) de NIST CSF", (self.sin / nombre).read_text(encoding="utf-8"))

    def test_solo_perfil_hoja_de_trabajo(self):
        filas = self.leer(self.solo / "csf_tiers.csv")
        self.assertEqual([f["funcion"] for f in filas], list(ct.FUNCIONES))
        self.assertEqual(list(filas[0]), ct.COLUMNAS)
        self.assertEqual([f["tier_objetivo"] for f in filas],
                         ["Repetible", "Adaptativo", "Repetible", "Repetible", "Adaptativo", "Repetible"])
        self.assertTrue(all(f["origen_objetivo"] == ct.ORIGEN_PERFIL for f in filas))
        self.assertTrue(all(f["tier_actual"] == "" and f["brecha"] == "" for f in filas))
        md = (self.solo / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("## " + ct.TITULO, md)
        self.assertIn("--csf-tiers ARCHIVO", md)

    def test_con_archivo_brecha_y_salidas(self):
        filas = {f["funcion"]: f for f in self.leer(self.con / "csf_tiers.csv")}
        self.assertEqual((filas["GV"]["tier_actual"], filas["GV"]["brecha"]), ("Informado por el riesgo", "1"))
        self.assertEqual((filas["RS"]["tier_actual"], filas["RS"]["brecha"]), ("Adaptativo", "0"))
        self.assertEqual(filas["GV"]["entrevistado"], "Ana")
        self.assertEqual(filas["ID"]["brecha"], "")
        datos = json.loads((self.con / "resultado.json").read_text(encoding="utf-8"))["csf_tiers"]
        self.assertTrue(datos["con_archivo"])
        self.assertEqual(len(datos["funciones"]), 6)
        md = (self.con / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("| GV Gobernar | Informado por el riesgo | Repetible | 1 |", md)
        self.assertIn("Tier actual declarado en 2 de 6 funciones; 1 con brecha", md)
        self.assertIn(ct.TITULO, (self.con / "reporte_ot.html").read_text(encoding="utf-8"))
        with zipfile.ZipFile(self.con / "informe_ot.docx") as z:
            self.assertIn(ct.TITULO, z.read("word/document.xml").decode("utf-8"))

    def test_nunca_cumple_ni_no_cumple(self):
        for d in (self.solo, self.con):
            md = (d / "reporte_ot.md").read_text(encoding="utf-8").lower()
            seccion = md.split("## " + ct.TITULO.lower())[1].split("\n## ")[0]
            self.assertNotIn("no cumple", seccion)
            self.assertNotRegex(seccion, r"\bcumple\b")

    def test_ingles(self):
        self.assertEqual(self.faltantes, set())
        filas = self.leer(self.en / "csf_tiers.csv")
        self.assertIn("current_tier", filas[0])
        self.assertEqual(filas[0]["function"], "GV")
        self.assertEqual((filas[0]["name"] if "name" in filas[0] else filas[0]["nombre"]), "Govern")
        self.assertEqual(filas[1]["target_tier"], "Adaptive")
        self.assertEqual(filas[0]["current_tier"], "Risk Informed")
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("NIST CSF 2.0 Tiers by function", html)
        self.assertIn("Current tier", html)
        # el archivo escrito en ingles se puede volver a entregar
        d = ct.leer(self.en / "csf_tiers.csv")
        self.assertEqual(d["GV"]["tier_actual"], 2)


if __name__ == "__main__":
    unittest.main()
