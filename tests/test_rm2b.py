"""RM2b (D130): valoracion inherente, residual actual y residual objetivo con plantilla e importacion. Sin tshark."""
from __future__ import annotations

import argparse
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_riesgo import PLC, WIN, activo, corrida, hallazgo
from test_rm1 import _error, _perfil
from test_rm2 import ETQ4, ETQ6, NIV3

from ot_assess import i18n, riesgo
from ot_assess import valoraciones_riesgo as val
from ot_assess.cli import main


def _plan(perfil_riesgo=None, previos=None):
    cfg = _perfil({"riesgo": perfil_riesgo})["riesgo"].get("valoraciones") if perfil_riesgo else None
    return val.Plan(cfg or val.defecto(), previos or {})


def _construir(perfil_riesgo, previos=None, activa=True):
    """Tres riesgos (Alta, Media, Baja) con el perfil dado y, si `activa`, el plan de valoraciones."""
    perf = _perfil({"riesgo": perfil_riesgo} if perfil_riesgo else {})
    hs = [hallazgo("Alta uno", "Alta", "10.0.0.1"), hallazgo("Media dos", "Media", "10.0.0.2"),
          hallazgo("Baja tres", "Baja", "10.0.0.3")]
    res = corrida([activo("10.0.0.1", PLC), activo("10.0.0.2", WIN), activo("10.0.0.3", WIN)], hs, perf)
    res.args = argparse.Namespace(valoraciones_plan=_plan(perfil_riesgo, previos) if activa else None)
    return riesgo.construir(res)


def _id(titulo):
    return "R-" + riesgo.id_hallazgo(titulo)[2:]


def _csv(ruta: Path, filas: list, sep=",", bom=False):
    buf = io.StringIO()
    csv.writer(buf, delimiter=sep).writerows(filas)
    ruta.write_bytes((b"\xef\xbb\xbf" if bom else b"") + buf.getvalue().encode("utf-8"))
    return ruta


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class ValidacionTest(Base):
    def malo(self, v, fragmento, extra=None):
        msg = _error({"riesgo": {"valoraciones": v, **(extra or {})}})
        self.assertIn(fragmento, msg, msg)

    def test_validos(self):
        self.assertEqual(_perfil({"riesgo": {"valoraciones": {}}})["riesgo"]["valoraciones"], val.defecto())
        p = _perfil({"riesgo": {"valoraciones": {"tratamientos": ["a", "b"], "nivel_aceptable": "Medio"}}})
        self.assertEqual(p["riesgo"]["valoraciones"], {"tratamientos": ["a", "b"], "nivel_aceptable": "Medio"})
        p = _perfil({"riesgo": {"niveles": NIV3, "valoraciones": {"nivel_aceptable": "Atencion"}}})
        self.assertEqual(p["riesgo"]["valoraciones"]["nivel_aceptable"], "Atencion")

    def test_invalidos(self):
        self.malo([], "debe ser un objeto")
        self.malo({"otra": 1}, "clave desconocida")
        self.malo({"tratamientos": ["a"]}, "2 a 8")
        self.malo({"tratamientos": [str(i) for i in range(9)]}, "2 a 8")
        self.malo({"tratamientos": ["a", "a"]}, "repetidos")
        self.malo({"tratamientos": ["a", ""]}, "1 a 30")
        self.malo({"tratamientos": ["a", "x" * 31]}, "1 a 30")
        self.malo({"tratamientos": ["a", 3]}, "1 a 30")
        self.malo({"nivel_aceptable": "Inexistente"}, "nivel_aceptable")
        self.malo({"nivel_aceptable": "Medio"}, "nivel_aceptable", {"niveles": NIV3})   # nombres propios de RM2
        self.malo({"nivel_aceptable": 3}, "nivel_aceptable")


class LecturaTest(Base):
    M = riesgo.metodo({})
    CAB = ["id_riesgo", "probabilidad_inherente", "impacto_inherente", "tratamiento", "fecha_objetivo", "responsable"]

    def leer(self, filas, cab=None, **kw):
        return val.leer(_csv(self.tmp / "v.csv", [cab or self.CAB, *filas], **kw), self.M, val.TRATAMIENTOS_DEFECTO)

    def malo(self, filas, fragmento, cab=None):
        with self.assertRaises(ValueError) as cm:
            self.leer(filas, cab)
        self.assertIn(fragmento, str(cm.exception))

    def test_formatos(self):
        fila = ["R-aaaaaa", "3", "4", "mitigar", "2027-02-28", "Ana"]
        esperado = {"R-aaaaaa": {"probabilidad_inherente": 3, "impacto_inherente": 4, "controles_existentes": "",
                                 "tratamiento": "mitigar", "controles_planeados": "", "probabilidad_objetivo": "",
                                 "impacto_objetivo": "", "responsable": "Ana", "fecha_objetivo": "2027-02-28",
                                 "justificacion": ""}}
        self.assertEqual(self.leer([fila]), esperado)
        self.assertEqual(self.leer([fila], sep=";"), esperado)
        self.assertEqual(self.leer([fila], bom=True), esperado)
        self.assertEqual(self.leer([fila], sep=";", bom=True), esperado)
        en = ["id_riesgo", "likelihood_inherent", "impact_inherent", "treatment", "target_date", "owner"]
        self.assertEqual(self.leer([["R-aaaaaa", "3", "4", "mitigate", "2027-02-28", "Ana"]], en), esperado)
        self.assertEqual(self.leer([["H-AAAAAA", "3", "4", "mitigar", "2027-02-28", "Ana"]],
                                   ["id_hallazgo", *self.CAB[1:]]), esperado)

    def test_errores(self):
        ok = ["R-aaaaaa", "3", "4", "mitigar", "2027-02-28", "Ana"]
        self.malo([ok], "id_riesgo ni id_hallazgo", ["probabilidad_inherente"])
        self.malo([ok, ["H-aaaaaa", "1", "1", "", "", ""]], "repetido")      # H-x y R-x: el mismo riesgo
        self.malo([["R-aaaaaa", "6", "4", "", "", ""]], "fuera de 1 a 5")
        self.malo([["R-aaaaaa", "0", "4", "", "", ""]], "fuera de 1 a 5")
        self.malo([["R-aaaaaa", "x", "4", "", "", ""]], "fuera de 1 a 5")
        self.malo([["R-aaaaaa", "3", "4", "ignorar", "", ""]], "Tratamiento no permitido")
        for malo in ("2027-02-30", "28/02/2027", "2027-2-28", "20270228", "2027-13-01"):
            self.malo([["R-aaaaaa", "3", "4", "", malo, ""]], "AAAA-MM-DD")
        self.malo([["R-aaaaaa", "3", "4", "", "", "x" * 501]], "500 caracteres")
        with self.assertRaises(ValueError):
            val.leer(self.tmp / "no_existe.csv", self.M, val.TRATAMIENTOS_DEFECTO)

    def test_escala_propia(self):
        m = riesgo.metodo(_perfil({"riesgo": {"escala": {"probabilidad": ETQ4, "impacto": ETQ6}}}))
        ruta = _csv(self.tmp / "e.csv", [self.CAB, ["R-aaaaaa", "4", "6", "", "", ""]])
        self.assertEqual(val.leer(ruta, m, ["x", "y"])["R-aaaaaa"]["impacto_inherente"], 6)
        ruta = _csv(self.tmp / "e.csv", [self.CAB, ["R-aaaaaa", "5", "6", "", "", ""]])
        with self.assertRaises(ValueError):
            val.leer(ruta, m, ["x", "y"])
        ruta = _csv(self.tmp / "e.csv", [self.CAB, ["R-aaaaaa", "4", "7", "", "", ""]])
        with self.assertRaises(ValueError):
            val.leer(ruta, m, ["x", "y"])

    def test_tratamientos_del_perfil(self):
        ruta = _csv(self.tmp / "t.csv", [self.CAB, ["R-aaaaaa", "", "", "reducir", "", ""]])
        self.assertEqual(val.leer(ruta, self.M, ["reducir", "retener"])["R-aaaaaa"]["tratamiento"], "reducir")
        with self.assertRaises(ValueError):
            val.leer(ruta, self.M, val.TRATAMIENTOS_DEFECTO)


class CalculoTest(Base):
    def fila(self, r, titulo):
        return r["valoraciones"]["por_id"][_id(titulo)]

    def previo(self, titulo, **kw):
        base = {c: "" for c in val.COL_EQUIPO}
        return {_id(titulo): {**base, **kw}}

    def test_sin_archivo_es_la_plantilla(self):
        r = _construir(None)
        filas = r["valoraciones"]["filas"]
        self.assertEqual([f["id_riesgo"] for f in filas], [x["id_riesgo"] for x in r["filas"]])
        for f, x in zip(filas, r["filas"]):
            self.assertEqual((f["probabilidad_actual"], f["impacto_actual"], f["puntuacion_actual"],
                              f["nivel_actual"], f["titulo"], f["id_hallazgo"]),
                             (x["probabilidad"], x["impacto"], x["puntuacion"], x["nivel"], x["titulo"],
                              x["id_hallazgo"]))
            self.assertTrue(all(f[c] == "" for c in val.COL_EQUIPO + val.COL_CALCULADAS))
        self.assertEqual(val.COLUMNAS[:7] + val.COLUMNAS[7:17] + val.COLUMNAS[17:],
                         val.COL_HERRAMIENTA + val.COL_EQUIPO + val.COL_CALCULADAS)

    def test_calculo_escala_5(self):
        prev = self.previo("Alta uno", probabilidad_inherente=5, impacto_inherente=5, tratamiento="mitigar",
                           probabilidad_objetivo=2, impacto_objetivo=3)
        f = self.fila(_construir({"valoraciones": {}}, prev), "Alta uno")
        self.assertEqual((f["puntuacion_inherente"], f["nivel_inherente"]), (25, "Muy alto"))
        self.assertEqual((f["puntuacion_objetivo"], f["nivel_objetivo"]), (6, "Medio"))
        self.assertEqual(f["dentro_de_apetito"], "")          # sin nivel_aceptable
        self.assertEqual(f["observaciones"], "")

    def test_escala_4_por_6_y_niveles_propios(self):
        rp = {"escala": {"probabilidad": ETQ4, "impacto": ETQ6}, "niveles": NIV3,
              "valoraciones": {"nivel_aceptable": "Atencion"}}
        prev = self.previo("Alta uno", probabilidad_inherente=4, impacto_inherente=6, probabilidad_objetivo=3,
                           impacto_objetivo=5, tratamiento="aceptar")
        r = _construir(rp, prev)
        f = self.fila(r, "Alta uno")
        self.assertEqual((f["puntuacion_inherente"], f["nivel_inherente"]), (24, "Critico"))
        self.assertEqual((f["puntuacion_objetivo"], f["nivel_objetivo"], f["dentro_de_apetito"]),
                         (15, "Atencion", "si"))
        self.assertEqual(set(r["valoraciones"]["por_nivel"]["inherente"]), {"Tolerable", "Atencion", "Critico",
                                                                          val.SIN_VALORAR})

    def test_par_incompleto(self):
        prev = self.previo("Alta uno", probabilidad_inherente=3, impacto_objetivo=2, tratamiento="mitigar")
        f = self.fila(_construir(None, prev), "Alta uno")
        self.assertEqual((f["puntuacion_inherente"], f["nivel_inherente"]), ("", ""))
        self.assertEqual((f["puntuacion_objetivo"], f["nivel_objetivo"]), ("", ""))
        self.assertIn("valoracion incompleta (inherente)", f["observaciones"])
        self.assertIn("valoracion incompleta (objetivo)", f["observaciones"])

    def test_observaciones(self):
        r0 = _construir(None)
        actual = self.fila(r0, "Media dos")["puntuacion_actual"]
        self.assertTrue(1 < actual < 25)
        # inherente menor que la actual y objetivo mayor que la actual, sin tratamiento
        prev = self.previo("Media dos", probabilidad_inherente=1, impacto_inherente=1, probabilidad_objetivo=5,
                           impacto_objetivo=5)
        f = self.fila(_construir({"valoraciones": {"nivel_aceptable": "Medio"}}, prev), "Media dos")
        obs = f["observaciones"].split("; ")
        self.assertEqual(obs, ["inherente menor que la actual", "objetivo mayor que la actual",
                               "objetivo sin tratamiento", "fuera de apetito"])
        self.assertEqual(f["dentro_de_apetito"], "no")

    def test_apetito_niveles_por_defecto_y_propios(self):
        prev = {**self.previo("Alta uno", probabilidad_objetivo=2, impacto_objetivo=5, tratamiento="mitigar"),
                **self.previo("Baja tres", probabilidad_objetivo=1, impacto_objetivo=2, tratamiento="mitigar")}
        r = _construir({"valoraciones": {"nivel_aceptable": "Alto"}}, prev)
        self.assertEqual(self.fila(r, "Alta uno")["nivel_objetivo"], "Alto")
        self.assertEqual(self.fila(r, "Alta uno")["dentro_de_apetito"], "si")
        r = _construir({"valoraciones": {"nivel_aceptable": "Medio"}}, prev)
        self.assertEqual(self.fila(r, "Alta uno")["dentro_de_apetito"], "no")
        self.assertEqual(self.fila(r, "Baja tres")["dentro_de_apetito"], "si")
        self.assertEqual(r["valoraciones"]["fuera_de_apetito"], 1)
        r = _construir({"niveles": NIV3, "valoraciones": {"nivel_aceptable": "Tolerable"}}, prev)
        self.assertEqual(self.fila(r, "Alta uno")["nivel_objetivo"], "Atencion")
        self.assertEqual(self.fila(r, "Alta uno")["dentro_de_apetito"], "no")

    def test_filas_no_presentes_se_conservan(self):
        prev = {**self.previo("Alta uno", probabilidad_inherente=2, impacto_inherente=2),
                "R-ffffff": {**{c: "" for c in val.COL_EQUIPO}, "responsable": "Luis", "probabilidad_objetivo": 2,
                             "impacto_objetivo": 2}}
        r = _construir(None, prev)
        v = r["valoraciones"]
        self.assertEqual(len(v["filas"]), 4)
        ultima = v["filas"][-1]
        self.assertEqual((ultima["id_riesgo"], ultima["responsable"]), ("R-ffffff", "Luis"))
        self.assertIn("no aparece en esta corrida", ultima["observaciones"])
        self.assertEqual(v["no_presentes"], 1)
        self.assertTrue(any("1 id" in a for a in r["avisos"]))
        self.assertEqual(v["valoradas"], {"inherente": 1, "objetivo": 0})      # los no presentes no cuentan

    def test_candidatos(self):
        prev = self.previo("Alta uno", probabilidad_inherente=4, impacto_inherente=4, probabilidad_objetivo=2,
                           impacto_objetivo=2, tratamiento="mitigar")
        r = _construir({"modo": "candidatos", "valoraciones": {"nivel_aceptable": "Medio"}}, prev)
        f = self.fila(r, "Alta uno")
        self.assertEqual(f["puntuacion_actual"], "")
        self.assertEqual((f["puntuacion_inherente"], f["puntuacion_objetivo"]), (16, 4))
        self.assertEqual(f["observaciones"], "")          # sin actual no se compara
        self.assertEqual(r["valoraciones"]["por_nivel"]["actual"][val.SIN_VALORAR], 3)

    def test_registro_y_json(self):
        prev = self.previo("Alta uno", probabilidad_inherente=5, impacto_inherente=5, tratamiento="mitigar",
                           probabilidad_objetivo=1, impacto_objetivo=1)
        r = _construir({"valoraciones": {"nivel_aceptable": "Medio"}}, prev)
        self.assertEqual(riesgo.columnas(r)[-6:], val.COL_REGISTRO)
        fila = dict(zip(riesgo.columnas(r), riesgo.tabla(r)[[x["titulo"] for x in r["filas"]].index("Alta uno")]))
        self.assertEqual((fila["puntuacion_inherente"], fila["nivel_inherente"], fila["puntuacion_objetivo"],
                          fila["nivel_objetivo"], fila["tratamiento"], fila["dentro_de_apetito"]),
                         (25, "Muy alto", 1, "Bajo", "mitigar", "si"))
        j = riesgo.para_json(r)["valoraciones"]
        self.assertEqual(j["valoradas"], {"inherente": 1, "objetivo": 1})
        self.assertEqual(j["fuera_de_apetito"], 0)
        self.assertEqual(j["no_presentes"], 0)
        self.assertEqual(set(j["por_nivel"]), {"inherente", "actual", "objetivo"})
        self.assertEqual(j["por_nivel"]["inherente"]["Muy alto"], 1)
        self.assertEqual(sum(j["por_nivel"]["actual"].values()), 3)

    def test_sin_funcion_activa_nada_cambia(self):
        r = _construir(None, activa=False)
        self.assertNotIn("valoraciones", r)
        self.assertEqual(riesgo.columnas(r), riesgo.COLUMNAS)
        self.assertEqual(set(riesgo.para_json(r)), {"registro", "mapa", "quick_wins", "nota"})
        self.assertIsNone(riesgo.seccion(r)["valoracion"])
        self.assertEqual([t[0] for t in riesgo.tablas(r)], [riesgo.ARCHIVO_REGISTRO, riesgo.ARCHIVO_MAPA])


def _leer(ruta):
    with open(ruta, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


class ExtremoAExtremoTest(unittest.TestCase):
    """Camino `diagrama` de punta a punta, en espanol e ingles."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        vul = cls.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                       "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware PLC ficticio,1.0,Escaner\n",
                       encoding="utf-8")
        cls.perfil = cls.tmp / "perfil.json"
        cls.perfil.write_text(json.dumps({
            "version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}],
            "riesgo": {"valoraciones": {"nivel_aceptable": "Medio"}}}), encoding="utf-8")
        cls.sin = cls.tmp / "sin_perfil.json"
        cls.sin.write_text(json.dumps({"version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}]}),
                           encoding="utf-8")
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                    "--vulnerabilidades", str(vul)]
        cls.es = cls.correr("es", "--perfil", str(cls.perfil))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--perfil", str(cls.perfil), "--idioma", "en")
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

    def test_plantilla_sin_archivo(self):
        reg = _leer(self.es / "riesgos.csv")
        pl = _leer(self.es / "valoraciones_riesgo.csv")
        self.assertGreaterEqual(len(reg), 1)
        self.assertEqual(list(pl[0]), val.COLUMNAS)
        self.assertEqual([f["id_riesgo"] for f in pl], [f["id_riesgo"] for f in reg])
        self.assertEqual([(f["probabilidad_actual"], f["puntuacion_actual"], f["nivel_actual"]) for f in pl],
                         [(f["probabilidad"], f["puntuacion"], f["nivel"]) for f in reg])
        self.assertTrue(all(f[c] == "" for f in pl for c in val.COL_EQUIPO))
        self.assertEqual(list(reg[0])[-6:], val.COL_REGISTRO)
        self.assertEqual(list(_leer(self.en / "valoraciones_riesgo.csv")[0])[7],
                         "likelihood_inherent")

    def test_ida_y_vuelta_y_reportes(self):
        pl = _leer(self.es / "valoraciones_riesgo.csv")
        pl[0].update(probabilidad_inherente="5", impacto_inherente="5", tratamiento="mitigar",
                     probabilidad_objetivo="1", impacto_objetivo="2", responsable="Ana",
                     fecha_objetivo="2027-03-31", justificacion="x")
        pl.append({**{c: "" for c in val.COLUMNAS}, "id_riesgo": "R-ffffff", "responsable": "Luis"})
        ruta = _csv(self.tmp / "lleno.csv", [val.COLUMNAS, *[[f[c] for c in val.COLUMNAS] for f in pl]], sep=";")
        o1 = self.correr("r1", "--perfil", str(self.perfil), "--valoraciones-riesgo", str(ruta))
        p1 = _leer(o1 / "valoraciones_riesgo.csv")
        self.assertEqual(p1[0]["puntuacion_inherente"], "25")
        self.assertEqual(p1[0]["nivel_inherente"], "Muy alto")
        self.assertEqual(p1[0]["nivel_objetivo"], "Bajo")
        self.assertEqual(p1[0]["dentro_de_apetito"], "si")
        self.assertEqual((p1[0]["responsable"], p1[0]["fecha_objetivo"]), ("Ana", "2027-03-31"))
        self.assertEqual(p1[-1]["id_riesgo"], "R-ffffff")
        self.assertEqual(p1[-1]["observaciones"], "no aparece en esta corrida")
        o2 = self.correr("r2", "--perfil", str(self.perfil), "--valoraciones-riesgo", str(o1 / "valoraciones_riesgo.csv"))
        self.assertEqual(_leer(o2 / "valoraciones_riesgo.csv"), p1)          # ida y vuelta
        # sin la subclave del perfil, solo con la opcion: la funcion se activa con los valores por defecto
        o3 = self.correr("r3", "--perfil", str(self.sin), "--valoraciones-riesgo", str(ruta))
        p3 = _leer(o3 / "valoraciones_riesgo.csv")
        self.assertEqual(p3[0]["puntuacion_objetivo"], "2")
        self.assertEqual(p3[0]["dentro_de_apetito"], "")
        # reportes
        html = (o1 / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("<h3>Valoracion del riesgo</h3>", html)
        self.assertIn("Mapa de calor: riesgo inherente", html)
        self.assertIn("Mapa de calor: riesgo residual objetivo", html)
        self.assertEqual(html.count('<table class="mapa-calor">'), 3)
        md = (o1 / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("### Valoracion del riesgo", md)
        self.assertIn("| Residual objetivo |", md)
        self.assertIn("Sin valorar", md)
        self.assertIn("Fuera de apetito (nivel aceptable: Medio): 0 de 1 riesgos con valoracion objetivo.", md)
        with zipfile.ZipFile(o1 / "informe_ot.docx") as z:
            doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("Mapa de calor: riesgo inherente", doc)
        with zipfile.ZipFile(o1 / "reporte_ot.xlsx") as z:
            libro = z.read("xl/workbook.xml").decode("utf-8")
        for hoja in ("Valoracion de riesgos", "Valoracion del riesgo", "Mapa de riesgo inherente",
                     "Mapa de riesgo objetivo"):
            self.assertIn(hoja, libro)
        j = json.loads((o1 / "resultado.json").read_text(encoding="utf-8"))["riesgos"]["valoraciones"]
        self.assertEqual(j["valoradas"], {"inherente": 1, "objetivo": 1})
        self.assertEqual(j["no_presentes"], 1)
        # sin valoracion completa no hay mapas extra
        self.assertEqual((self.es / "reporte_ot.html").read_text(encoding="utf-8").count('<table class="mapa-calor">'), 1)
        env = json.loads((o1 / "resultado.json").read_text(encoding="utf-8"))["entorno"]
        self.assertEqual(env["valoraciones_riesgo"]["archivo"], "lleno.csv")
        self.assertEqual(len(env["valoraciones_riesgo"]["sha256"]), 64)

    def test_plantilla_en_ingles_se_vuelve_a_leer(self):
        pl = _leer(self.en / "valoraciones_riesgo.csv")
        cab = list(pl[0])
        pl[0]["likelihood_inherent"], pl[0]["impact_inherent"], pl[0]["treatment"] = "3", "3", "mitigate"
        ruta = _csv(self.tmp / "en.csv", [cab, *[[f[c] for c in cab] for f in pl]])
        o = self.correr("r_en", "--perfil", str(self.perfil), "--valoraciones-riesgo", str(ruta))
        p = _leer(o / "valoraciones_riesgo.csv")
        self.assertEqual((p[0]["puntuacion_inherente"], p[0]["tratamiento"]), ("9", "mitigar"))

    def test_en_ingles_sin_faltantes(self):
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Risk assessment", html)
        self.assertEqual(self.faltantes, set())

    def test_errores_dan_codigo_2_sin_salidas(self):
        casos = {
            "no_existe.csv": None,
            "sin_llave.csv": [["probabilidad_inherente"], ["3"]],
            "repetido.csv": [["id_riesgo", "probabilidad_inherente"], ["R-aaaaaa", "1"], ["H-aaaaaa", "2"]],
            "fuera.csv": [["id_riesgo", "probabilidad_inherente"], ["R-aaaaaa", "9"]],
            "trat.csv": [["id_riesgo", "tratamiento"], ["R-aaaaaa", "nada"]],
            "fecha.csv": [["id_riesgo", "fecha_objetivo"], ["R-aaaaaa", "2027-02-30"]],
            "largo.csv": [["id_riesgo", "justificacion"], ["R-aaaaaa", "x" * 501]],
        }
        for nombre, filas in casos.items():
            ruta = self.tmp / nombre
            if filas is not None:
                _csv(ruta, filas)
            out = self.tmp / ("err_" + nombre)
            with self.subTest(nombre), contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    main([*self.args, "-o", str(out), "--perfil", str(self.perfil), "--valoraciones-riesgo",
                          str(ruta)])
            self.assertEqual(cm.exception.code, 2)
            self.assertFalse(out.exists() and any(out.iterdir()))

    def test_sin_subclave_ni_opcion_salidas_de_hoy(self):
        o = self.correr("hoy", "--perfil", str(self.sin))
        self.assertFalse((o / "valoraciones_riesgo.csv").exists())
        self.assertEqual(list(_leer(o / "riesgos.csv")[0]), riesgo.COLUMNAS)
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("valoraciones", j["riesgos"])
        self.assertNotIn("valoraciones_riesgo", j["entorno"])
        html = (o / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertNotIn("Valoracion del riesgo", html)
        self.assertEqual(html.count('<table class="mapa-calor">'), 1)
        self.assertEqual((o / "mapa_calor_riesgo.csv").read_bytes(),
                         (self.es / "mapa_calor_riesgo.csv").read_bytes())
        # el resto de riesgos.csv es identico al de la corrida con la funcion (columnas extra al final)
        a, b = _leer(o / "riesgos.csv"), _leer(self.es / "riesgos.csv")
        self.assertEqual([{k: f[k] for k in riesgo.COLUMNAS} for f in b], a)


if __name__ == "__main__":
    unittest.main()
