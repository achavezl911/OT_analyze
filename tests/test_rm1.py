"""RM1 (D123): registro de riesgos en modo candidatos y dimensiones de impacto del perfil. Sin tshark."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_riesgo import PLC, WIN, activo, corrida, desde_internet, hallazgo

from ot_assess import i18n, perfil, resumen_ejecutivo, riesgo
from ot_assess import sitios as st
from ot_assess.cli import main

T_KEV = "Vulnerabilidades en KEV"
CAND = {"riesgo": {"modo": "candidatos"}}
VACIOS = ("probabilidad", "impacto", "puntuacion", "nivel", "quick_win")


def _perfil(extra: dict):
    d = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "perfil.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return perfil.cargar(p)


def _error(extra: dict) -> str:
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            _perfil(extra)
        except SystemExit as e:
            return str(e)
    return ""


def _corrida(perf, hallazgos=None, rutas=None):
    activos = [activo("10.0.0.1", PLC, "Control"), activo("10.0.0.2", WIN, "Corp"), activo("10.0.0.3", WIN)]
    hs = hallazgos or [hallazgo("Alta uno", "Alta", "10.0.0.1"), hallazgo("Media dos", "Media", "10.0.0.2"),
                       hallazgo("Baja tres", "Baja", "10.0.0.3"), hallazgo("Alta " + T_KEV, "Alta", "10.0.0.2")]
    return corrida(activos, hs, perf, rutas or desde_internet("10.0.0.1"))


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")


class CandidatosTest(Base):
    def test_filas_sin_puntos_y_factores(self):
        r = riesgo.construir(_corrida(_perfil(CAND)))
        self.assertEqual(r["modo"], "candidatos")
        self.assertEqual(len(r["filas"]), 4)
        for f in r["filas"]:
            for c in VACIOS:
                self.assertEqual(f[c], "", c)
            self.assertEqual(f["origen"], "candidato")
            self.assertNotRegex(f["motivo_probabilidad"], r"\(\d\)|\(\+1\)")
        por = {f["titulo"]: f for f in r["filas"]}
        self.assertEqual(por["Alta uno"]["motivo_probabilidad"], "severidad Alta; alcanzable desde Internet")
        self.assertEqual(por["Alta " + T_KEV]["motivo_probabilidad"], "severidad Alta")
        self.assertEqual(r["quick_wins"], [])
        self.assertTrue(all(c["riesgos"] == 0 for c in r["mapa"]))
        self.assertIn("criticidad", por["Alta uno"]["motivo_impacto"])
        self.assertNotRegex(por["Alta uno"]["motivo_impacto"], r"\(\d\)|inferido")
        self.assertEqual(por["Alta uno"]["dimension_impacto"], "produccion (inferida)")

    def test_kev_y_orden(self):
        from ot_assess.avisos_cisa import TITULO_KEV
        hs = [hallazgo("Alta A", "Alta", "10.0.0.2"), hallazgo("Alta B " + TITULO_KEV, "Alta", "10.0.0.1"),
              hallazgo("Media dos", "Media", "10.0.0.2"), hallazgo("Baja tres", "Baja", "10.0.0.3")]
        r = riesgo.construir(_corrida(_perfil(CAND), hs))
        self.assertEqual(r["filas"][1]["titulo"], "Alta A")      # mismo nivel de severidad: mas factores primero
        self.assertEqual(r["filas"][2]["titulo"], "Media dos")
        self.assertEqual(r["filas"][3]["titulo"], "Baja tres")
        kev = next(f for f in r["filas"] if TITULO_KEV in f["titulo"])
        self.assertEqual(kev["motivo_probabilidad"],
                         "severidad Alta; alcanzable desde Internet; CVE explotada (KEV)")
        self.assertEqual(r["filas"][0], kev)

    def test_mismo_id_y_columnas_que_puntuado(self):
        a = riesgo.construir(_corrida(_perfil({})))
        b = riesgo.construir(_corrida(_perfil(CAND)))
        self.assertEqual({f["id_riesgo"] for f in a["filas"]}, {f["id_riesgo"] for f in b["filas"]})
        self.assertEqual(riesgo.tablas(b)[0][2], riesgo.COLUMNAS)

    def test_ajuste_completo_puntua_y_va_primero(self):
        hid = riesgo.id_hallazgo("Baja tres")
        p = _perfil({**CAND, "ajustes_riesgo": {hid: {"probabilidad": 5, "impacto": 5, "justificacion": "j"}}})
        r = riesgo.construir(_corrida(p))
        f = r["filas"][0]
        self.assertEqual((f["titulo"], f["puntuacion"], f["nivel"], f["origen"]), ("Baja tres", 25, "Muy alto", "analista"))
        self.assertIn(f["quick_win"], ("si", "no"))
        self.assertEqual(sum(c["riesgos"] for c in r["mapa"]), 1)
        self.assertTrue(all(x["puntuacion"] == "" for x in r["filas"][1:]))
        self.assertEqual(riesgo.seccion(r)["top"][0][1], "Baja tres")

    def test_ajuste_parcial_muestra_solo_ese_valor(self):
        hid = riesgo.id_hallazgo("Media dos")
        p = _perfil({**CAND, "ajustes_riesgo": {hid: {"impacto": 4, "justificacion": "j"}}})
        f = next(x for x in riesgo.construir(_corrida(p))["filas"] if x["titulo"] == "Media dos")
        self.assertEqual((f["impacto"], f["probabilidad"], f["puntuacion"], f["nivel"], f["origen"]),
                         (4, "", "", "", "candidato"))

    def test_seccion_resumen_ejecutivo_y_json(self):
        res = _corrida(_perfil(CAND))
        res.riesgos = riesgo.construir(res)
        s = riesgo.seccion(res.riesgos)
        self.assertIn("modo candidatos: la herramienta no puntua", s["resumen"].lower())
        self.assertIn("Candidatos: 4; puntuados por el analista: 0.", s["resumen"])
        self.assertEqual(s["cab_top"], ["ID", "Riesgo", "Severidad", "Factores", "Zonas", "Esfuerzo estimado"])
        self.assertEqual(len(s["top"][0]), 6)
        self.assertEqual(s["quick"], [])
        self.assertEqual(riesgo.para_json(res.riesgos)["modo"], "candidatos")
        res.args = type("A", (), {"titulo": "T", "cliente": "C"})()
        res.assets = {}
        res.conduits = []
        res.rutas_ataque = {}
        d = resumen_ejecutivo.datos(res)
        self.assertEqual(d["riesgos"][0]["nivel"], "candidato sin puntuar")
        self.assertEqual(d["riesgos"][0]["puntuacion"], "")
        i18n.usar("en")
        self.assertIn("unscored candidate", resumen_ejecutivo.datos(res)["riesgos"][0]["nivel"])
        self.assertIn("Candidates mode", riesgo.seccion(res.riesgos)["resumen"])

    def test_sin_clave_o_puntuado_explicito_es_igual(self):
        a = riesgo.construir(_corrida(_perfil({})))
        b = riesgo.construir(_corrida(_perfil({"riesgo": {"modo": "puntuado"}})))
        self.assertEqual(a, b)
        self.assertNotIn("modo", riesgo.para_json(a))
        self.assertEqual([f["puntuacion"] for f in a["filas"]], sorted((f["puntuacion"] for f in a["filas"]),
                                                                        reverse=True))
        self.assertTrue(all(isinstance(f["puntuacion"], int) and f["origen"] == "inferido" for f in a["filas"]))


class DimensionesTest(Base):
    DIMS = ("personas", "produccion", "calidad", "inocuidad", "financiero_cumplimiento", "reputacion")

    def _fila(self, extra, zonas=None):
        z = {"nombre": "Control", "redes": ["10.0.0.0/24"]}
        if zonas is not None:
            z["impacto"] = zonas
        return riesgo.construir(_corrida(_perfil({**extra, "zonas": [z]}), [hallazgo("H", "Media", "10.0.0.1")])
                                )["filas"][0]

    def test_zona_acepta_dimensiones_del_perfil_y_rechaza_las_otras(self):
        rg = {"riesgo": {"dimensiones_impacto": self.DIMS}}
        f = self._fila(rg, {"calidad": 4, "personas": 4})
        self.assertEqual((f["impacto"], f["dimension_impacto"]), (4, "personas"))   # desempate por el orden de la lista
        self.assertIn("personas", f["motivo_impacto"])
        zona = {"nombre": "Control", "redes": ["10.0.0.0/24"], "impacto": {"seguridad": 3}}
        self.assertIn("clave desconocida 'seguridad'", _error({**rg, "zonas": [zona]}))

    def test_inferida(self):
        self.assertEqual(self._fila({"riesgo": {"dimensiones_impacto": self.DIMS}})["dimension_impacto"],
                         "produccion (inferida)")
        self.assertEqual(self._fila({"riesgo": {"dimensiones_impacto": ["calidad", "personas"]}})
                         ["dimension_impacto"], "calidad (inferida)")
        f = self._fila({"riesgo": {"dimensiones_impacto": self.DIMS, "dimension_inferida": "inocuidad"}})
        self.assertEqual(f["dimension_impacto"], "inocuidad (inferida)")
        self.assertEqual(self._fila({"riesgo": {"dimension_inferida": "ambiente"}})["dimension_impacto"],
                         "ambiente (inferida)")

    def test_dimensiones_del_perfil_no_se_traducen_y_las_de_hoy_si(self):
        i18n.usar("en")
        rg = {"riesgo": {"dimensiones_impacto": ["calidad", "seguridad"], "dimension_inferida": "calidad"}}
        r = riesgo.construir(_corrida(_perfil(rg), [hallazgo("H", "Media", "10.0.0.1")]))
        self.assertEqual(riesgo.tabla(r)[0][riesgo.COLUMNAS.index("dimension_impacto")], "calidad (inferred)")
        r["filas"][0]["dimension_impacto"] = "seguridad"
        self.assertEqual(riesgo.tabla(r)[0][riesgo.COLUMNAS.index("dimension_impacto")], "safety")


class InvalidosTest(Base):
    def test_invalidos(self):
        malos = [{"modo": "otro"}, {"modo": 1}, {"dimensiones_impacto": []},
                 {"dimensiones_impacto": [f"d{i}" for i in range(9)]}, {"dimensiones_impacto": ["a", "a"]},
                 {"dimensiones_impacto": ["Mayus"]}, {"dimensiones_impacto": ["a" * 31]},
                 {"dimensiones_impacto": ["a b"]}, {"dimensiones_impacto": "a"}, {"dimensiones_impacto": [1]},
                 {"dimensiones_impacto": ["a"], "dimension_inferida": "b"}, {"dimension_inferida": "otra"},
                 {"otra": 1}]
        for m in malos:
            self.assertIn("[!]", _error({"riesgo": m}), m)
        self.assertIn("[!]", _error({"riesgo": []}))

    def test_validos(self):
        self.assertEqual(_perfil({"riesgo": {"dimensiones_impacto": ["a" * 30] * 1, "modo": "puntuado"}})["riesgo"],
                         {"modo": "puntuado", "dimensiones_impacto": ["a" * 30]})
        self.assertEqual(_error({"riesgo": {"dimensiones_impacto": [f"d{i}" for i in range(8)]}}), "")


class SitiosTest(Base):
    def test_candidatos_y_puntuado_mezclados(self):
        import test_sitios as ts
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            ts._sitio(raiz, "a", "Norte", [("H1", "Alta")], [("R1", 10)])
            c = ts._sitio(raiz, "c", "Centro", [("H1", "Alta")], [])
            ts._csv(c, "riesgos.csv", ts.RIESGO, [["R-1", "H-1", "T", "Seg", "Alta", "", "", "", "", "", "", "", "R"]])
            out = raiz / "out"
            o = io.StringIO()
            with contextlib.redirect_stdout(o), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["sitios", str(raiz / "a"), str(c), "-o", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("R-1", (out / "riesgos_sitios.csv").read_text(encoding="utf-8-sig"))
            self.assertTrue(st.NIVELES)


if __name__ == "__main__":
    unittest.main()
