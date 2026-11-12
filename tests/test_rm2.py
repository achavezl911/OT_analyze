"""RM2 (D129): metodo de riesgo del proyecto (escalas, niveles, elevacion, quick win) en el perfil. Sin tshark."""
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_riesgo import (
    PLC,
    T_ANY,
    T_VULN,
    WIN,
    activo,
    corrida,
    desde_internet,
    hallazgo,
)
from test_rm1 import _error, _perfil

from ot_assess import i18n, riesgo
from ot_assess.avisos_cisa import TITULO_KEV
from ot_assess.cli import main
from ot_assess.report.xlsx import escribir_xlsx

NIV3 = [{"nombre": "Tolerable", "desde": 1}, {"nombre": "Atencion", "desde": 6, "color": "00aaff"},
        {"nombre": "Critico", "desde": 16}]
ETQ6 = ["Rara", "Poco probable", "Posible", "Probable", "Casi segura", "Segura"]
ETQ4 = ["Baja", "Media", "Alta", "Muy alta"]


def _construir(extra, hallazgos, activos, rutas=None):
    perf = _perfil(extra)
    return riesgo.construir(corrida(activos, hallazgos, perf, rutas))


def _una(riesgo_perfil, sev="Media", titulo="H", activos=None, rutas=None, extra=None):
    r = _construir({"riesgo": riesgo_perfil, **(extra or {})}, [hallazgo(titulo, sev)],
                   activos or [activo("10.0.0.1", PLC)], rutas)
    assert len(r["filas"]) == 1
    return r["filas"][0], r


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")


class ValidacionTest(Base):
    def malo(self, riesgo_perfil, fragmento, extra=None):
        msg = _error({"riesgo": riesgo_perfil, **(extra or {})})
        self.assertIn(fragmento, msg, msg)

    def test_perfil_valido(self):
        p = _perfil({"riesgo": {"escala": {"probabilidad": ETQ4, "impacto": ETQ6}, "niveles": NIV3,
                                "elevacion": [{"condicion": "kev", "nivel_minimo": "Critico"},
                                              {"condicion": "dimension:seguridad>=5", "nivel_minimo": "Atencion"}],
                                "quick_win": {"niveles": ["Critico"], "esfuerzo": ["bajo", "medio"]}}})
        self.assertEqual(p["riesgo"]["niveles"][1]["color"], "00AAFF")
        self.assertEqual(riesgo.metodo(p)["np"], 4)
        self.assertEqual(riesgo.metodo(p)["ni"], 6)

    def test_escala_invalida(self):
        self.malo({"escala": {"probabilidad": ["a", "b", "a"]}}, "repetidas")
        self.malo({"escala": {"probabilidad": ["a", "b"]}}, "3 a 10")
        self.malo({"escala": {"impacto": [str(i) for i in range(11)]}}, "3 a 10")
        self.malo({"escala": {"impacto": ["a", "b", ""]}}, "1 a 40")
        self.malo({"escala": {"impacto": ["a", "b", "x" * 41]}}, "1 a 40")
        self.malo({"escala": {"impacto": ["a", "b", "c\nd"]}}, "saltos")
        self.malo({"escala": {}}, "indique")

    def test_niveles_invalidos(self):
        n = lambda *d: [{"nombre": f"N{i}", "desde": v} for i, v in enumerate(d)]
        self.malo({"niveles": n(1, 5, 5)}, "creciente")
        self.malo({"niveles": n(1, 9, 5)}, "creciente")
        self.malo({"niveles": n(2, 5)}, "empezar")
        self.malo({"niveles": n(1, 26)}, "supera")
        self.malo({"niveles": n(1)}, "2 a 6")
        self.malo({"niveles": n(1, 2, 3, 4, 5, 6, 7)}, "2 a 6")
        self.malo({"niveles": [{"nombre": "A", "desde": 1}, {"nombre": "A", "desde": 5}]}, "repetido")
        self.malo({"niveles": [{"nombre": "A", "desde": 1}, {"nombre": "B", "desde": 5, "color": "XYZ123"}]}, "RRGGBB")
        self.malo({"niveles": [{"nombre": "A", "desde": 1}, {"nombre": "B", "desde": 5, "color": "FFF"}]}, "RRGGBB")
        # el maximo depende de la escala: 4 x 4 = 16
        esc = {"probabilidad": ETQ4, "impacto": ETQ4}
        self.malo({"escala": esc, "niveles": n(1, 17)}, "supera")
        self.assertTrue(_perfil({"riesgo": {"escala": esc, "niveles": n(1, 16)}}))

    def test_elevacion_invalida(self):
        r = lambda c, m="Alto": {"elevacion": [{"condicion": c, "nivel_minimo": m}]}
        self.malo(r("internet"), "desconocida")
        self.malo(r("dimension:calidad>=3"), "calidad")
        self.malo(r("dimension:seguridad>=6"), "fuera de la escala")
        self.malo(r("dimension:seguridad>=0"), "fuera de la escala")
        self.malo(r("kev", "Catastrofico"), "no existe")
        self.malo({"elevacion": [{"condicion": "kev", "nivel_minimo": "Alto"}] * 11}, "0 a 10")
        self.malo({"elevacion": [{"condicion": "kev"}]}, "necesita")
        # la dimension se valida contra las del perfil
        self.assertTrue(_perfil({"riesgo": {"dimensiones_impacto": ["calidad"], **r("dimension:calidad>=3")}}))
        self.malo({"dimensiones_impacto": ["calidad"], **r("dimension:seguridad>=3")}, "seguridad")

    def test_quick_win_invalido(self):
        self.malo({"quick_win": {"niveles": ["Nunca"]}}, "quick_win.niveles")
        self.malo({"quick_win": {"esfuerzo": ["enorme"]}}, "quick_win.esfuerzo")
        self.malo({"quick_win": {"esfuerzo": []}}, "quick_win.esfuerzo")

    def test_ajustes_y_zonas_se_validan_contra_la_escala(self):
        hid = riesgo.id_hallazgo("H")
        esc = {"escala": {"probabilidad": ETQ4, "impacto": ETQ6}}
        aj = lambda k, v: {"ajustes_riesgo": {hid: {k: v, "justificacion": "x"}}}
        self.assertIn("1 a 4", _error({"riesgo": esc, **aj("probabilidad", 5)}))
        self.assertIn("1 a 6", _error({"riesgo": esc, **aj("impacto", 7)}))
        self.assertEqual(_error({"riesgo": esc, **aj("impacto", 6)}), "")
        self.assertEqual(_error({"riesgo": esc, **aj("probabilidad", 4)}), "")
        zona = lambda v: {"zonas": [{"nombre": "Z", "redes": ["10.0.0.0/24"], "impacto": {"seguridad": v}}]}
        self.assertIn("1 a 6", _error({"riesgo": esc, **zona(7)}))
        self.assertEqual(_error({"riesgo": esc, **zona(6)}), "")
        self.assertIn("1 a 5", _error(zona(6)))         # sin escala propia, como hoy


class EscalaTest(Base):
    def test_reescalado_casos_1_3_5(self):
        self.assertEqual([riesgo._reescalar(v, 4) for v in (1, 3, 5)], [1, 3, 4])
        self.assertEqual([riesgo._reescalar(v, 6) for v in (1, 3, 5)], [1, 4, 6])
        self.assertEqual([riesgo._reescalar(v, 5) for v in range(1, 6)], [1, 2, 3, 4, 5])
        self.assertEqual([riesgo._reescalar(v, 3) for v in range(1, 6)], [1, 2, 2, 3, 3])      # .5 hacia arriba

    def test_escala_1_4_en_probabilidad(self):
        f, r = _una({"escala": {"probabilidad": ETQ4}})
        self.assertEqual((f["probabilidad"], f["impacto"], f["puntuacion"]), (3, 5, 15))     # 3 -> 3; impacto en 1-5
        self.assertIn("reescalado de 1-5 a 1-4", f["motivo_probabilidad"])
        self.assertNotIn("reescalado", f["motivo_impacto"])
        f, _ = _una({"escala": {"probabilidad": ETQ4}}, rutas=desde_internet("10.0.0.1"))      # base 3 + 1 = 4 -> 1 + 11//4
        self.assertEqual(f["probabilidad"], 3)

    def test_escala_1_6_en_ambos_ejes_etiquetas_y_mapa(self):
        f, r = _una({"escala": {"probabilidad": ETQ6, "impacto": ETQ6}})
        self.assertEqual((f["probabilidad"], f["impacto"], f["puntuacion"]), (4, 6, 24))
        self.assertIn("reescalado de 1-5 a 1-6", f["motivo_impacto"])
        self.assertEqual((f["probabilidad_etiqueta"], f["impacto_etiqueta"]), ("Probable", "Segura"))
        self.assertEqual(len(r["mapa"]), 36)
        self.assertEqual(sum(c["riesgos"] for c in r["mapa"]), 1)
        cab, filas, niveles = riesgo.cuadricula(r)
        self.assertEqual(cab[1:], [f"{k} - {e}" for k, e in enumerate(ETQ6, 1)])
        self.assertEqual(filas[0][0], "6 - Segura")
        self.assertEqual(len(filas), 6)

    def test_mapa_no_cuadrado_en_csv(self):
        f, r = _una({"escala": {"probabilidad": ETQ4, "impacto": ETQ6}})
        self.assertEqual(len(r["mapa"]), 24)
        archivos = {a: (cab, filas) for a, _h, cab, filas in riesgo.tablas(r)}
        cab, filas = archivos[riesgo.ARCHIVO_MAPA]
        self.assertEqual(cab, riesgo.COL_MAPA)
        self.assertEqual(len(filas), 24)
        self.assertEqual({fila[0] for fila in filas}, set(range(1, 7)))
        self.assertEqual({fila[1] for fila in filas}, set(range(1, 5)))
        cab, filas = archivos[riesgo.ARCHIVO_REGISTRO]
        self.assertEqual(cab, riesgo.COLUMNAS + ["probabilidad_etiqueta", "impacto_etiqueta"])
        self.assertEqual(filas[0][-2:], ["Alta", "Segura"])

    def test_ajuste_del_analista_no_se_reescala(self):
        hid = riesgo.id_hallazgo("H")
        extra = {"ajustes_riesgo": {hid: {"probabilidad": 6, "impacto": 2, "justificacion": "Decidido"}}}
        f, _ = _una({"escala": {"probabilidad": ETQ6, "impacto": ETQ6}}, extra=extra)
        self.assertEqual((f["probabilidad"], f["impacto"], f["origen"]), (6, 2, "analista"))
        self.assertEqual(f["motivo_probabilidad"], "ajustado por el analista: Decidido")
        self.assertNotIn("reescalado", f["motivo_impacto"])

    def test_impacto_de_zona_no_se_reescala(self):
        z = {"zonas": [{"nombre": "Control", "redes": ["10.0.0.0/24"], "impacto": {"seguridad": 3}}]}
        f, _ = _una({"escala": {"impacto": ETQ6}}, activos=[activo("10.0.0.1", PLC, "Control")], extra=z)
        self.assertEqual(f["impacto"], 3)
        self.assertNotIn("reescalado", f["motivo_impacto"])

    def test_escala_5_no_cambia_nada(self):
        e5 = ["a", "b", "c", "d", "e"]
        f, _ = _una({"escala": {"probabilidad": e5, "impacto": e5}})
        g, _ = _una({})
        self.assertEqual((f["probabilidad"], f["impacto"], f["motivo_probabilidad"], f["motivo_impacto"]),
                         (g["probabilidad"], g["impacto"], g["motivo_probabilidad"], g["motivo_impacto"]))


class NivelesTest(Base):
    def test_bordes_de_cada_umbral(self):
        m = riesgo.metodo(_perfil({"riesgo": {"niveles": NIV3}}))
        got = [riesgo.nivel(p, m) for p in (1, 5, 6, 15, 16, 25)]
        self.assertEqual(got, ["Tolerable", "Tolerable", "Atencion", "Atencion", "Critico", "Critico"])
        self.assertEqual([c for _, _, c in m["niveles"]], ["92D050", "00AAFF", "FF5050"])    # sin color: paleta

    def test_paleta_de_cuatro_niveles_es_la_actual(self):
        niv = [{"nombre": n, "desde": d} for n, d in (("A", 1), ("B", 5), ("C", 10), ("D", 20))]
        m = riesgo.metodo(_perfil({"riesgo": {"niveles": niv}}))
        self.assertEqual([c for _, _, c in m["niveles"]], [c for _, _, c in riesgo.NIVELES_DEF])

    def test_registro_resumen_y_mapa(self):
        f, r = _una({"niveles": NIV3})           # 3 x 5 = 15
        self.assertEqual((f["puntuacion"], f["nivel"]), (15, "Atencion"))
        self.assertEqual({c["nivel"] for c in r["mapa"]}, {"Tolerable", "Atencion", "Critico"})
        s = riesgo.seccion(r)
        self.assertEqual(s["resumen"], "Tolerable: 0; Atencion: 1; Critico: 0.")
        self.assertEqual(s["colores"]["Atencion"], "00AAFF")
        self.assertTrue(s["propio"])
        self.assertEqual(s["mapa"][2][0][-1], "Critico")
        self.assertIn("(Critico)", s["mapa_texto"][1][0][-1])

    def test_nombres_del_proyecto_no_se_traducen(self):
        niv = [{"nombre": "Bajo", "desde": 1}, {"nombre": "Alto", "desde": 9}]
        i18n.usar("en")
        f, r = _una({"niveles": niv})
        s = riesgo.seccion(r)
        self.assertEqual(s["top"][0][6], "Alto")
        self.assertEqual(riesgo.tabla(r)[0][riesgo.COLUMNAS.index("nivel")], "Alto")
        self.assertEqual(s["resumen"], "Bajo: 0; Alto: 1.")

    def test_xlsx_usa_el_color_del_proyecto(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = escribir_xlsx(Path(tmp) / "a.xlsx", [("H", ["x", "y"], [[1, 2]], [["", "00AAFF"]]),
                                                       ("I", ["x"], [[1]], [["2"]])])
            with zipfile.ZipFile(ruta) as z:
                self.assertIsNone(z.testzip())
                estilos = z.read("xl/styles.xml").decode("utf-8")
                hoja = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
                hoja2 = z.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertIn('<fills count="7">', estilos)
        self.assertIn("FF00AAFF", estilos)
        self.assertIn('<cellXfs count="7">', estilos)
        self.assertIn('s="6"', hoja)
        self.assertIn('s="2"', hoja2)


class ElevacionTest(Base):
    def test_kev_eleva_el_nivel_no_la_puntuacion(self):
        reglas = {"elevacion": [{"condicion": "kev", "nivel_minimo": "Muy alto"}]}
        f, _ = _una(reglas, "Baja", "Baja " + TITULO_KEV, [activo("10.0.0.1", WIN)])
        # Baja 2 + KEV 1 = 3; WIN impacto 3 -> 9 (Medio) -> Muy alto por la regla
        self.assertEqual((f["puntuacion"], f["nivel"]), (9, "Muy alto"))
        self.assertEqual(f["elevacion"], "kev -> Muy alto")
        g, _ = _una({}, "Baja", "Baja " + TITULO_KEV, [activo("10.0.0.1", WIN)])
        self.assertEqual((g["puntuacion"], g["nivel"]), (9, "Medio"))
        self.assertNotIn("elevacion", g)

    def test_exposicion_eleva(self):
        reglas = {"elevacion": [{"condicion": "exposicion", "nivel_minimo": "Alto"}]}
        f, _ = _una(reglas, "Baja", activos=[activo("10.0.0.1", WIN)], rutas=desde_internet("10.0.0.1"))
        self.assertEqual((f["puntuacion"], f["nivel"], f["elevacion"]), (9, "Alto", "exposicion -> Alto"))

    def test_dimension_eleva_si_la_zona_la_declara(self):
        z = {"zonas": [{"nombre": "Corp", "redes": ["10.0.0.0/24"], "impacto": {"seguridad": 4}}]}
        act = [activo("10.0.0.1", WIN, "Corp")]
        reglas = {"elevacion": [{"condicion": "dimension:seguridad>=4", "nivel_minimo": "Alto"}]}
        f, _ = _una(reglas, "Baja", activos=act, extra=z)
        self.assertEqual((f["puntuacion"], f["nivel"], f["elevacion"]),
                         (8, "Alto", "dimension:seguridad>=4 -> Alto"))

    def test_regla_que_no_aplica_no_cambia_nada(self):
        z = {"zonas": [{"nombre": "Corp", "redes": ["10.0.0.0/24"], "impacto": {"seguridad": 4}}]}
        act = [activo("10.0.0.1", WIN, "Corp")]
        reglas = {"elevacion": [{"condicion": "dimension:seguridad>=5", "nivel_minimo": "Muy alto"},
                                {"condicion": "kev", "nivel_minimo": "Muy alto"},
                                {"condicion": "exposicion", "nivel_minimo": "Muy alto"}]}
        f, _ = _una(reglas, "Baja", activos=act, extra=z)
        g, _ = _una({}, "Baja", activos=act, extra=z)
        self.assertEqual((f["puntuacion"], f["nivel"], f["elevacion"]), (g["puntuacion"], g["nivel"], ""))

    def test_nunca_baja_el_nivel(self):
        reglas = {"elevacion": [{"condicion": "kev", "nivel_minimo": "Bajo"}]}
        f, _ = _una(reglas, "Media", "Media " + TITULO_KEV, [activo("10.0.0.1", PLC)])
        self.assertEqual(f["nivel"], "Muy alto")      # 4 x 5 = 20
        self.assertEqual(f["elevacion"], "kev -> Bajo")

    def test_varias_reglas_gana_la_mas_alta(self):
        reglas = {"elevacion": [{"condicion": "exposicion", "nivel_minimo": "Alto"},
                                {"condicion": "kev", "nivel_minimo": "Muy alto"}]}
        f, _ = _una(reglas, "Baja", "Baja " + TITULO_KEV, [activo("10.0.0.1", WIN)],
                    rutas=desde_internet("10.0.0.1"))
        self.assertEqual(f["nivel"], "Muy alto")
        self.assertEqual(f["elevacion"], "exposicion -> Alto; kev -> Muy alto")

    def test_columna_elevacion_solo_con_la_subclave(self):
        f, r = _una({"elevacion": []})
        self.assertEqual(f["elevacion"], "")
        self.assertEqual(riesgo.columnas(r)[-1], "elevacion")
        _, r0 = _una({})
        self.assertEqual(riesgo.columnas(r0), riesgo.COLUMNAS)


class QuickWinTest(Base):
    def test_por_defecto_es_el_de_hoy(self):
        f, r = _una({}, titulo=T_ANY)
        self.assertEqual((f["nivel"], f["esfuerzo_estimado"], f["quick_win"]), ("Alto", "bajo", "si"))
        self.assertEqual(riesgo.seccion(r)["nota_quick"], riesgo.NOTA_QUICK)

    def test_niveles_propios(self):
        f, r = _una({"quick_win": {"niveles": ["Muy alto"]}}, titulo=T_ANY)
        self.assertEqual(f["quick_win"], "no")
        self.assertEqual(r["quick_wins"], [])
        f, _ = _una({"quick_win": {"niveles": ["Medio", "Alto"]}}, titulo=T_ANY)
        self.assertEqual(f["quick_win"], "si")

    def test_esfuerzos_propios_y_nota(self):
        f, r = _una({"quick_win": {"esfuerzo": ["bajo", "medio"]}}, titulo=T_VULN)
        self.assertEqual((f["esfuerzo_estimado"], f["quick_win"]), ("medio", "si"))
        self.assertEqual(riesgo.seccion(r)["nota_quick"],
                         "Quick win: riesgo de nivel Alto, Muy alto cuyo playbook tiene esfuerzo estimado bajo, medio.")
        g, _ = _una({"quick_win": {"esfuerzo": ["bajo"]}}, titulo=T_VULN)
        self.assertEqual(g["quick_win"], "no")

    def test_niveles_del_proyecto_por_defecto_los_dos_mas_altos(self):
        f, r = _una({"niveles": NIV3}, titulo=T_ANY)      # Atencion (15) es el segundo mas alto
        self.assertEqual(f["quick_win"], "si")
        self.assertIn("nivel Atencion, Critico", riesgo.seccion(r)["nota_quick"])
        g, _ = _una({"niveles": NIV3, "quick_win": {"niveles": ["Critico"]}}, titulo=T_ANY)
        self.assertEqual(g["quick_win"], "no")

    def test_la_elevacion_cuenta_para_el_quick_win(self):
        reglas = {"elevacion": [{"condicion": "exposicion", "nivel_minimo": "Alto"}],
                  "quick_win": {"niveles": ["Alto"]}}
        f, _ = _una(reglas, "Baja", T_ANY, [activo("10.0.0.1", WIN)], rutas=desde_internet("10.0.0.1"))
        self.assertEqual((f["puntuacion"], f["nivel"], f["quick_win"]), (9, "Alto", "si"))


class CandidatosTest(Base):
    def test_solo_las_filas_del_analista_llevan_nivel(self):
        hid = riesgo.id_hallazgo("Alta uno")
        extra = {"riesgo": {"modo": "candidatos", "niveles": NIV3,
                            "elevacion": [{"condicion": "exposicion", "nivel_minimo": "Critico"}]},
                 "ajustes_riesgo": {hid: {"probabilidad": 2, "impacto": 3, "justificacion": "Equipo"}}}
        hs = [hallazgo("Alta uno", "Alta", "10.0.0.1"), hallazgo("Media dos", "Media", "10.0.0.2")]
        act = [activo("10.0.0.1", PLC), activo("10.0.0.2", WIN)]
        r = _construir(extra, hs, act, desde_internet("10.0.0.1"))
        por = {f["titulo"]: f for f in r["filas"]}
        self.assertEqual((por["Alta uno"]["puntuacion"], por["Alta uno"]["nivel"]), (6, "Critico"))     # 6 -> Atencion, elevado
        self.assertEqual(por["Alta uno"]["elevacion"], "exposicion -> Critico")
        for c in ("probabilidad", "impacto", "puntuacion", "nivel", "quick_win", "elevacion"):
            self.assertEqual(por["Media dos"][c], "", c)
        s = riesgo.seccion(r)
        self.assertIn("Candidatos: 1; puntuados por el analista: 1.", s["resumen"])
        self.assertTrue(s["resumen"].endswith("Tolerable: 0; Atencion: 0; Critico: 1."))
        self.assertEqual(sum(c["riesgos"] for c in r["mapa"]), 1)


class SinSubclavesTest(Base):
    def test_declarar_el_metodo_por_defecto_da_lo_mismo(self):
        hs = [hallazgo("Alta uno", "Alta", "10.0.0.1"), hallazgo("Media " + TITULO_KEV, "Media", "10.0.0.2"),
              hallazgo(T_ANY, "Baja", "10.0.0.2")]
        act = [activo("10.0.0.1", PLC), activo("10.0.0.2", WIN)]
        r0 = _construir({}, hs, act, desde_internet("10.0.0.1"))
        niv = [{"nombre": n, "desde": d, "color": c} for n, d, c in riesgo.NIVELES_DEF]
        r1 = _construir({"riesgo": {"niveles": niv, "elevacion": [],
                                    "quick_win": {"niveles": ["Alto", "Muy alto"], "esfuerzo": ["bajo"]}}},
                        hs, act, desde_internet("10.0.0.1"))
        quitar = lambda f: {k: v for k, v in f.items() if k != "elevacion"}
        self.assertEqual([quitar(f) for f in r1["filas"]], r0["filas"])
        self.assertEqual(r1["mapa"], r0["mapa"])
        self.assertEqual(len(r1["quick_wins"]), len(r0["quick_wins"]))

    def test_sin_subclaves_la_forma_es_la_de_hoy(self):
        f, r = _una({})
        self.assertNotIn("elevacion", f)
        self.assertNotIn("probabilidad_etiqueta", f)
        self.assertEqual(riesgo.columnas(r), riesgo.COLUMNAS)
        self.assertEqual(len(r["mapa"]), 25)
        self.assertEqual(set(riesgo.para_json(r)), {"registro", "mapa", "quick_wins", "nota"})
        self.assertEqual(r["nota"], i18n.t(riesgo.NOTA))
        self.assertFalse(riesgo.seccion(r)["propio"])

    def test_json_con_metodo(self):
        _, r = _una({"escala": {"probabilidad": ETQ4}, "niveles": NIV3,
                     "elevacion": [{"condicion": "kev", "nivel_minimo": "Critico"}],
                     "quick_win": {"esfuerzo": ["bajo", "medio"]}})
        m = riesgo.para_json(r)["metodo"]
        self.assertEqual(m, {"escala": {"probabilidad": 4, "impacto": 5},
                             "niveles": [{"nombre": "Tolerable", "desde": 1}, {"nombre": "Atencion", "desde": 6},
                                         {"nombre": "Critico", "desde": 16}],
                             "elevacion": 1,
                             "quick_win": {"niveles": ["Atencion", "Critico"], "esfuerzo": ["bajo", "medio"]}})


class ReporteTest(unittest.TestCase):
    """Camino `diagrama` de punta a punta con un metodo de proyecto, en espanol e ingles."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        vul = cls.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                       "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware PLC ficticio,1.0,Escaner\n",
                       encoding="utf-8")
        pf = cls.tmp / "perfil.json"
        pf.write_text(json.dumps({
            "version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}],
            "riesgo": {"escala": {"probabilidad": ETQ4, "impacto": ETQ6}, "niveles": NIV3,
                       "elevacion": [{"condicion": "dimension:produccion>=1", "nivel_minimo": "Critico"}],
                       "quick_win": {"niveles": ["Critico"], "esfuerzo": ["bajo", "medio"]}}}),
            encoding="utf-8")
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                    "--vulnerabilidades", str(vul)]
        cls.es = cls.correr("es", "--perfil", str(pf))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--perfil", str(pf), "--idioma", "en")
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

    def test_csv(self):
        filas = self.leer(self.es / "riesgos.csv")
        self.assertEqual(list(filas[0]), riesgo.COLUMNAS + ["probabilidad_etiqueta", "impacto_etiqueta", "elevacion"])
        self.assertTrue(all(f["probabilidad_etiqueta"] in ETQ4 and f["impacto_etiqueta"] in ETQ6 for f in filas))
        self.assertTrue(all(int(f["probabilidad"]) <= 4 and int(f["impacto"]) <= 6 for f in filas))
        mapa = self.leer(self.es / "mapa_calor_riesgo.csv")
        self.assertEqual(len(mapa), 24)
        self.assertEqual({f["nivel"] for f in mapa}, {"Tolerable", "Atencion", "Critico"})
        en = self.leer(self.en / "riesgos.csv")
        self.assertIn("escalation", list(en[0]))
        self.assertIn("impact_label", list(en[0]))

    def test_html_docx_xlsx_md_json(self):
        html = (self.es / "reporte_ot.html").read_text(encoding="utf-8")
        cuerpo = html.split('<table class="mapa-calor">')[1].split("</table>")[0]
        self.assertIn('style="background:#00AAFF"', cuerpo)
        self.assertNotIn("mc-", cuerpo)
        self.assertIn("1 - Baja", cuerpo)
        self.assertIn("6 - Segura", cuerpo)
        with zipfile.ZipFile(self.es / "informe_ot.docx") as z:
            doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn('w:fill="00AAFF"', doc)
        with zipfile.ZipFile(self.es / "reporte_ot.xlsx") as z:
            self.assertIsNone(z.testzip())
            estilos = z.read("xl/styles.xml").decode("utf-8")
        self.assertIn("FF00AAFF", estilos)
        md = (self.es / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertRegex(md, r"\| \d+ \((Tolerable|Atencion|Critico)\) \|")
        self.assertIn("Quick win: riesgo de nivel Critico cuyo playbook tiene esfuerzo estimado bajo, medio.", md)
        datos = json.loads((self.es / "resultado.json").read_text(encoding="utf-8"))["riesgos"]
        self.assertEqual(datos["metodo"]["escala"], {"probabilidad": 4, "impacto": 6})
        self.assertEqual(datos["metodo"]["elevacion"], 1)
        self.assertEqual(len(datos["mapa"]), 24)

    def test_ingles_sin_faltantes(self):
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Risk register and heat map", html)
        self.assertIn("Critico", html)          # el nombre del nivel es del proyecto: no se traduce
        self.assertEqual(self.faltantes, set())


if __name__ == "__main__":
    unittest.main()


class TestSitiosNivelesProyecto(unittest.TestCase):
    """El consolidado multisitio cuenta los riesgos con los niveles del metodo del proyecto (RM2, D129)."""

    def _carpeta(self, raiz, nombre, niveles, valores):
        import csv as _csv
        import json as _json
        c = raiz / nombre
        c.mkdir()
        j = {"perfil": {"cliente": "ACME", "sitio": nombre, "idioma": "es"}, "entorno": {"ot_assess": "0.78.0"}}
        if niveles:
            j["riesgos"] = {"metodo": {"niveles": [{"nombre": n, "desde": k + 1} for k, n in enumerate(niveles)]}}
        (c / "resultado.json").write_text(_json.dumps(j), encoding="utf-8")
        with open(c / "hallazgos.csv", "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["id", "captura", "severidad", "categoria", "titulo"])
            w.writerow(["H1", "x", "Alta", "Segmentacion", "T"])
        with open(c / "riesgos.csv", "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["id_riesgo", "puntuacion", "nivel"])
            for k, v in enumerate(valores):
                w.writerow([f"R-{k}", 3, v])
        return c

    def test_niveles_del_proyecto_y_por_defecto(self):
        import csv as _csv
        import tempfile
        from pathlib import Path as _P

        from ot_assess import sitios as st
        with tempfile.TemporaryDirectory() as d:
            raiz = _P(d)
            a = self._carpeta(raiz, "A", ("Bajo", "Moderado", "Critico"), ["Critico", "Critico", "Moderado"])
            b = self._carpeta(raiz, "B", (), ["Alto", "Bajo"])
            r = st.consolidar([a, b])
            self.assertEqual(r["niveles"], ["Bajo", "Moderado", "Critico", "Medio", "Alto", "Muy alto"])
            self.assertTrue(any("niveles de riesgo distintos" in x for x in r["avisos"]))
            st.escribir(raiz / "out", r, "es")
            with open(raiz / "out" / "sitios.csv", encoding="utf-8-sig") as fh:
                filas = {f["sitio"]: f for f in _csv.DictReader(fh)}
            self.assertEqual((filas["A"]["riesgos_critico"], filas["A"]["riesgos_moderado"]), ("2", "1"))
            self.assertEqual((filas["B"]["riesgos_alto"], filas["B"]["riesgos_bajo"], filas["B"]["riesgos_critico"]),
                             ("1", "1", "0"))

    def test_sin_metodo_cabecera_de_siempre(self):
        import tempfile
        from pathlib import Path as _P

        from ot_assess import sitios as st
        with tempfile.TemporaryDirectory() as d:
            raiz = _P(d)
            a = self._carpeta(raiz, "A", (), ["Alto"])
            b = self._carpeta(raiz, "B", (), ["Muy alto", "Bajo"])
            r = st.consolidar([a, b])
            self.assertEqual(r["niveles"], list(st.NIVELES))
            self.assertFalse(any("niveles de riesgo distintos" in x for x in r["avisos"]))
            self.assertEqual(st.cab_sitios(r["niveles"]), st.CAB_SITIOS)
