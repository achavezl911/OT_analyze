"""MAD2 (D131): escala de madurez del proyecto (niveles, descriptores y equivalencia con la 0-4). Sin tshark."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import re
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
from test_madurez import corrida, dom, hallazgo, respuestas

from ot_assess import i18n, madurez, perfil, sitios
from ot_assess.cli import main

T_SEG = "Conductos entre zonas sin firewall observado en el camino"

NOMBRES5 = ["Inicial", "Repetible", "Definido", "Gestionado", "Optimizado"]


def niveles(desde=1, n=5):
    return [{"valor": desde + i, "nombre": f"Nivel {desde + i} propio", "descripcion": f"Descripcion {desde + i}"}
            for i in range(n)]


def escala5():
    return [{"valor": i + 1, "nombre": NOMBRES5[i], "descripcion": f"Desc de {NOMBRES5[i]}"} for i in range(5)]


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")
        self.addCleanup(i18n.FALTANTES.clear)

    def perfil(self, **extra):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], **extra}),
                     encoding="utf-8")
        return p

    def cargar(self, **extra):
        return perfil.cargar(self.perfil(**extra))


class ValidacionTest(Base):
    def test_escala_valida_y_equivalencia_por_defecto(self):
        p = self.cargar(escala_madurez={"niveles": escala5()})
        self.assertEqual([n["valor"] for n in p["escala_madurez"]["niveles"]], [1, 2, 3, 4, 5])
        self.assertEqual(p["escala_madurez"]["equivalencia"], {"0": 1, "1": 2, "2": 3, "3": 4, "4": 5})

    def test_equivalencia_por_defecto_en_varias_escalas(self):
        for desde, n, esperado in ((1, 5, [1, 2, 3, 4, 5]), (0, 5, [0, 1, 2, 3, 4]), (1, 3, [1, 2, 2, 3, 3]),
                                   (1, 7, [1, 3, 4, 6, 7])):
            eq = self.cargar(escala_madurez={"niveles": niveles(desde, n)})["escala_madurez"]["equivalencia"]
            self.assertEqual([eq[str(k)] for k in range(5)], esperado, (desde, n))
            self.assertEqual(list(madurez.equivalencia_defecto(desde, desde + n - 1).values()), esperado)

    def test_equivalencia_declarada(self):
        eq = {"0": 1, "1": 1, "2": 3, "3": 4, "4": 5}
        p = self.cargar(escala_madurez={"niveles": escala5(), "equivalencia": eq})
        self.assertEqual(p["escala_madurez"]["equivalencia"], eq)

    def test_errores_de_la_escala(self):
        malos = {
            "dos niveles": {"niveles": niveles(1, 2)},
            "ocho niveles": {"niveles": niveles(1, 8)},
            "no es lista": {"niveles": "x"},
            "salto": {"niveles": [{"valor": 1, "nombre": "a"}, {"valor": 3, "nombre": "b"},
                                  {"valor": 4, "nombre": "c"}]},
            "desordenados": {"niveles": [{"valor": 3, "nombre": "a"}, {"valor": 2, "nombre": "b"},
                                         {"valor": 1, "nombre": "c"}]},
            "valor no entero": {"niveles": [{"valor": 1.5, "nombre": "a"}, {"valor": 2.5, "nombre": "b"},
                                            {"valor": 3.5, "nombre": "c"}]},
            "nombre repetido": {"niveles": [{"valor": 1, "nombre": "a"}, {"valor": 2, "nombre": "a"},
                                            {"valor": 3, "nombre": "c"}]},
            "nombre vacio": {"niveles": [{"valor": 1, "nombre": ""}, {"valor": 2, "nombre": "b"},
                                         {"valor": 3, "nombre": "c"}]},
            "nombre largo": {"niveles": [{"valor": 1, "nombre": "x" * 41}, {"valor": 2, "nombre": "b"},
                                         {"valor": 3, "nombre": "c"}]},
            "nombre con salto": {"niveles": [{"valor": 1, "nombre": "a\nb"}, {"valor": 2, "nombre": "b"},
                                             {"valor": 3, "nombre": "c"}]},
            "descripcion larga": {"niveles": [{"valor": 1, "nombre": "a", "descripcion": "x" * 301},
                                              {"valor": 2, "nombre": "b"}, {"valor": 3, "nombre": "c"}]},
            "clave desconocida": {"niveles": niveles(1, 3), "otra": 1},
            "equivalencia incompleta": {"niveles": escala5(), "equivalencia": {"0": 1, "1": 2, "2": 3, "3": 4}},
            "equivalencia fuera de escala": {"niveles": escala5(),
                                             "equivalencia": {"0": 0, "1": 2, "2": 3, "3": 4, "4": 5}},
            "equivalencia decreciente": {"niveles": escala5(),
                                         "equivalencia": {"0": 1, "1": 3, "2": 2, "3": 4, "4": 5}},
            "equivalencia con texto": {"niveles": escala5(),
                                       "equivalencia": {"0": "1", "1": 2, "2": 3, "3": 4, "4": 5}},
        }
        for nombre, valor in malos.items():
            with self.assertRaises(SystemExit, msg=nombre):
                self.cargar(escala_madurez=valor)
        with self.assertRaises(SystemExit):
            self.cargar(escala_madurez=[])

    def test_madurez_objetivo_se_valida_contra_la_escala_del_perfil(self):
        esc = {"niveles": escala5()}
        self.assertEqual(self.cargar(escala_madurez=esc, madurez_objetivo={"segmentacion": 5})["madurez_objetivo"],
                         {"segmentacion": 5})
        self.assertEqual(self.cargar(madurez_objetivo={"segmentacion": 0})["madurez_objetivo"], {"segmentacion": 0})
        with self.assertRaises(SystemExit):
            self.cargar(escala_madurez=esc, madurez_objetivo={"segmentacion": 0})
        with self.assertRaises(SystemExit):
            self.cargar(escala_madurez=esc, madurez_objetivo={"segmentacion": 6})
        with self.assertRaises(SystemExit):
            self.cargar(madurez_objetivo={"segmentacion": 5})


class CuestionarioTest(Base):
    def plantilla(self, *extra):
        ruta = self.tmp / "q.csv"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["madurez", "cuestionario", "-o", str(ruta), *extra]), 0)
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            return ruta, list(csv.DictReader(fh))

    def test_plantilla_con_la_escala_del_proyecto(self):
        pf = self.perfil(escala_madurez={"niveles": escala5()})
        _ruta, filas = self.plantilla("--perfil", str(pf))
        self.assertEqual(len(filas), 32)
        esc = filas[0]["escala"]
        self.assertTrue(esc.startswith("1 = Inicial: Desc de Inicial; 2 = Repetible"), esc)
        self.assertTrue(esc.endswith("5 = Optimizado: Desc de Optimizado"), esc)
        self.assertNotIn("0 = ", esc)

    def test_plantilla_sin_la_clave_es_la_de_hoy(self):
        _r, base = self.plantilla()
        _r, con_perfil = self.plantilla("--perfil", str(self.perfil()))
        self.assertEqual(base, con_perfil)
        self.assertEqual(base[0]["escala"], madurez.texto_escala())
        self.assertTrue(base[0]["escala"].startswith("0 = "))

    def test_leer_con_escala_1_a_5(self):
        esc = madurez.escala_de(self.cargar(escala_madurez={"niveles": escala5()}))
        q = self.tmp / "r.csv"
        q.write_text("id,respuesta\nSEG-01,5\nSEG-02,1\nSEG-03,N/A\nSEG-04,\n", encoding="utf-8")
        out = madurez.leer(q, esc)
        self.assertEqual([out[i]["respuesta"] for i in ("SEG-01", "SEG-02", "SEG-03", "SEG-04")],
                         ["5", "1", "N/A", ""])
        q.write_text("id,respuesta\nSEG-01,0\n", encoding="utf-8")
        with self.assertRaises(madurez.ErrorMadurez) as e:
            madurez.leer(q, esc)
        self.assertIn("linea 2", str(e.exception))
        self.assertIn("use 1 a 5", str(e.exception))
        q.write_text("id,respuesta\nSEG-01,6\n", encoding="utf-8")
        with self.assertRaises(madurez.ErrorMadurez):
            madurez.leer(q, esc)

    def test_leer_sin_escala_sigue_siendo_0_a_4(self):
        q = self.tmp / "r.csv"
        q.write_text("id,respuesta\nSEG-01,4\nSEG-02,0\n", encoding="utf-8")
        self.assertEqual(madurez.leer(q)["SEG-01"]["respuesta"], "4")
        q.write_text("id,respuesta\nSEG-01,5\n", encoding="utf-8")
        with self.assertRaises(madurez.ErrorMadurez) as e:
            madurez.leer(q)
        self.assertIn("use 0 a 4", str(e.exception))

    def test_el_cli_de_analisis_lee_con_la_escala_del_perfil(self):
        pf = self.perfil(escala_madurez={"niveles": escala5()})
        q = self.tmp / "r.csv"
        q.write_text("id,respuesta\nSEG-01,0\n", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as e:
            main(["diagrama", "--activos", "no.csv", "--enlaces", "no.csv", "--madurez", str(q),
                  "--perfil", str(pf), "-o", str(self.tmp / "s")])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("use 1 a 5", err.getvalue())


class CalculoTest(Base):
    def construir(self, resp, hallazgos=(), **extra):
        p = self.cargar(**extra)
        m = madurez.construir(corrida(hallazgos, p), resp)
        return m, p

    def test_nivel_objetivo_por_dominio_brecha_y_nombres(self):
        m, _ = self.construir(respuestas(SEG=[2, 3, 3, 4]), escala_madurez={"niveles": escala5()},
                              madurez_objetivo={"segmentacion": 5})
        d = dom(m, "segmentacion")
        self.assertEqual((d["nivel"], d["objetivo"], d["brecha"]), (3.0, 5, 2.0))
        self.assertEqual(madurez.nombre_nivel(m["escala"], d["nivel"]), "Definido")
        self.assertEqual(madurez.nombre_nivel(m["escala"], d["objetivo"]), "Optimizado")
        self.assertEqual(madurez.nombre_nivel(m["escala"], 3.9), "Definido")
        self.assertEqual(madurez.nombre_nivel(m["escala"], None), "")
        self.assertEqual(madurez.nombre_nivel(m["escala"], 0.5), "")

    def test_objetivo_por_ml_y_por_defecto(self):
        m, _ = self.construir(respuestas(SEG=[2, 2, 2, 2]), escala_madurez={"niveles": escala5()},
                              ml_objetivo="ML4")
        self.assertEqual(dom(m, "segmentacion")["objetivo"], 5)
        self.assertEqual(dom(m, "segmentacion")["brecha"], 3.0)
        m, _ = self.construir(respuestas(SEG=[2, 2, 2, 2]), escala_madurez={"niveles": escala5()}, ml_objetivo="ML1")
        self.assertEqual(dom(m, "segmentacion")["objetivo"], 2)
        m, _ = self.construir(respuestas(SEG=[2, 2, 2, 2]), escala_madurez={"niveles": escala5()})
        self.assertEqual(dom(m, "segmentacion")["objetivo"], 3)          # equivalencia["2"]
        self.assertEqual(dom(m, "segmentacion")["brecha"], 1.0)
        m, _ = self.construir(respuestas(SEG=[2, 2, 2, 2]),
                              escala_madurez={"niveles": escala5(),
                                              "equivalencia": {"0": 1, "1": 1, "2": 2, "3": 4, "4": 5}},
                              ml_objetivo="ML3")
        self.assertEqual(dom(m, "segmentacion")["objetivo"], 4)

    def test_sin_la_clave_el_calculo_es_el_de_hoy(self):
        m, _ = self.construir(respuestas(SEG=[2, 3, 3, 4]), ml_objetivo="ML3")
        d = dom(m, "segmentacion")
        self.assertEqual((d["nivel"], d["objetivo"], d["brecha"]), (3.0, 3, 0.0))
        self.assertFalse(m["escala"]["proyecto"])

    def test_insuficiente_igual_en_la_escala_del_proyecto(self):
        m, _ = self.construir(respuestas(SEG=[3]), escala_madurez={"niveles": escala5()})
        self.assertIsNone(dom(m, "segmentacion")["nivel"])
        self.assertEqual(dom(m, "segmentacion")["estado"], madurez.INSUFICIENTE)

    def test_contradiccion_con_el_umbral_de_la_escala(self):
        hs = [hallazgo(T_SEG, "Alta")]
        esc = {"niveles": escala5()}
        m, _ = self.construir(respuestas(SEG=[3, 3, 3, 4]), hs, escala_madurez=esc)       # 3.25 -> 3.3 < 4
        self.assertEqual(dom(m, "segmentacion")["contradiccion"], "")
        m, _ = self.construir(respuestas(SEG=[4, 4, 4, 4]), hs, escala_madurez=esc)
        self.assertIn("revisar", dom(m, "segmentacion")["contradiccion"])
        # sin la clave el umbral sigue en 3
        m, _ = self.construir(respuestas(SEG=[3, 3, 3, 3]), hs)
        self.assertIn("revisar", dom(m, "segmentacion")["contradiccion"])

    def test_tablas_columnas_y_hoja_de_equivalencia(self):
        m, _ = self.construir(respuestas(SEG=[2, 3, 3, 4]), escala_madurez={"niveles": escala5()})
        tabs = madurez.tablas(m)
        self.assertEqual(tabs[0][2], madurez.COLUMNAS + ["nombre_nivel_actual", "nombre_nivel_objetivo"])
        fila = next(f for f in tabs[0][3] if f[0] == "Segmentacion de red")
        self.assertEqual(fila[-2:], ["Definido", "Definido"])
        archivo, hoja, _cab, filas = tabs[2]
        self.assertIsNone(archivo)
        self.assertEqual(hoja, "Equivalencia de escalas")
        self.assertEqual(len(filas), 5)
        self.assertEqual(filas[0][:2], [1, "Inicial"])
        self.assertIn("0 = ", filas[0][3])
        m, _ = self.construir(respuestas(SEG=[2, 3, 3, 4]))
        tabs = madurez.tablas(m)
        self.assertEqual(len(tabs), 2)
        self.assertEqual(tabs[0][2], madurez.COLUMNAS)

    def test_equivalencia_muestra_varios_niveles_de_la_herramienta_en_un_valor(self):
        m, _ = self.construir(None, escala_madurez={"niveles": niveles(1, 3)})
        filas = madurez.seccion(m)["equivalencia"]["filas"]
        self.assertEqual(len(filas), 3)
        self.assertTrue(filas[1][3].startswith("1 = ") and "; 2 = " in filas[1][3], filas[1][3])
        self.assertEqual(sum(1 for f in filas for _ in re.findall(r"\d = ", f[3])), 5)


class SitiosTest(Base):
    def carpeta(self, nombre, escala=None):
        c = self.tmp / nombre
        c.mkdir()
        j = {"perfil": {"cliente": "C", "sitio": nombre}}
        if escala:
            j["madurez"] = {"escala": escala}
        (c / "resultado.json").write_text(json.dumps(j), encoding="utf-8")
        return c

    def avisos(self, *carpetas):
        _s, avisos = sitios.leer_sitios(list(carpetas), {})
        return [a for a in avisos if "escalas de madurez" in a]

    def test_aviso_si_las_escalas_difieren(self):
        e1 = {"niveles": [{"valor": 1, "nombre": "a"}], "equivalencia": {"0": 1}}
        e2 = {"niveles": [{"valor": 0, "nombre": "a"}], "equivalencia": {"0": 0}}
        a, b = self.carpeta("a", e1), self.carpeta("b", e2)
        self.assertEqual(self.avisos(a, b),
                         ["las carpetas usan escalas de madurez distintas: los promedios no son comparables"])
        self.assertEqual(len(self.avisos(a, self.carpeta("c"))), 1)         # una con escala del proyecto y otra sin

    def test_sin_diferencia_no_hay_aviso(self):
        e1 = {"niveles": [{"valor": 1, "nombre": "a"}], "equivalencia": {"0": 1}}
        self.assertEqual(self.avisos(self.carpeta("a", e1), self.carpeta("b", dict(e1))), [])
        self.assertEqual(self.avisos(self.carpeta("c"), self.carpeta("d")), [])


class ReporteTest(unittest.TestCase):
    """`diagrama` de punta a punta: sin la clave y con ella, en espanol e ingles."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        base = {"version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}]}
        cls.escala = {"niveles": escala5()}
        q = cls.tmp / "q.csv"
        q.write_text("id,respuesta\n" + "".join(f"{p['id']},4\n" for p in madurez.preguntas()), encoding="utf-8")
        q0 = cls.tmp / "q0.csv"
        q0.write_text("id,respuesta\n" + "".join(f"{p['id']},3\n" for p in madurez.preguntas()), encoding="utf-8")
        sin = cls.tmp / "sin.json"
        sin.write_text(json.dumps(base), encoding="utf-8")
        con = cls.tmp / "con.json"
        con.write_text(json.dumps({**base, "escala_madurez": cls.escala, "madurez_objetivo": {"segmentacion": 5}}),
                       encoding="utf-8")
        cls.sin = cls.correr("sin", "--madurez", str(q0), "--perfil", str(sin))
        cls.con = cls.correr("con", "--madurez", str(q), "--perfil", str(con))
        cls.sin_q = cls.correr("sinq", "--perfil", str(con))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--madurez", str(q), "--perfil", str(con), "--idioma", "en")
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

    def test_sin_la_clave_las_salidas_son_las_de_hoy(self):
        filas = self.leer(self.sin / "madurez.csv")
        self.assertEqual(list(filas[0]), madurez.COLUMNAS)
        self.assertEqual(list(self.leer(self.sin / "cuestionario_madurez.csv")[0])[3], "escala")
        self.assertTrue(all(r["escala"].startswith("0 = ") for r in self.leer(self.sin / "cuestionario_madurez.csv")))
        datos = json.loads((self.sin / "resultado.json").read_text(encoding="utf-8"))["madurez"]
        self.assertNotIn("escala", datos)
        self.assertIn("escala 0 a 4", datos["nota"])
        html = (self.sin / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertNotIn("Equivalencia de escalas", html)
        self.assertIn("Promedio declarado 3.0 de 4", html)
        self.assertNotIn("Equivalencia de escalas", (self.sin / "reporte_ot.md").read_text(encoding="utf-8"))
        with zipfile.ZipFile(self.sin / "reporte_ot.xlsx") as z:
            self.assertNotIn("Equivalencia de escalas", z.read("xl/workbook.xml").decode("utf-8"))
        self.assertFalse(list(self.sin.glob("*equivalencia*")))

    def test_csv_y_json_con_la_escala_del_proyecto(self):
        filas = {f["dominio"]: f for f in self.leer(self.con / "madurez.csv")}
        self.assertEqual(list(next(iter(filas.values())))[-2:], ["nombre_nivel_actual", "nombre_nivel_objetivo"])
        seg = filas["Segmentacion de red"]
        self.assertEqual((seg["nivel_actual"], seg["nivel_objetivo"], seg["brecha"]), ("4.0", "5", "1.0"))
        self.assertEqual((seg["nombre_nivel_actual"], seg["nombre_nivel_objetivo"]), ("Gestionado", "Optimizado"))
        ctl = filas["Control de acceso"]
        self.assertEqual((ctl["nivel_objetivo"], ctl["brecha"]), ("3", "0.0"))      # equivalencia["2"] = 3
        esc = self.leer(self.con / "cuestionario_madurez.csv")[0]["escala"]
        self.assertTrue(esc.startswith("1 = Inicial: Desc de Inicial"), esc)
        datos = json.loads((self.con / "resultado.json").read_text(encoding="utf-8"))["madurez"]
        self.assertEqual(datos["escala"]["niveles"][0], {"valor": 1, "nombre": "Inicial"})
        self.assertEqual(datos["escala"]["equivalencia"], {"0": 1, "1": 2, "2": 3, "3": 4, "4": 5})
        self.assertNotIn("0 a 4", datos["nota"])

    def test_html_md_word_xlsx_con_la_tabla_de_equivalencia(self):
        html = (self.con / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Equivalencia de escalas", html)
        self.assertIn("Desc de Gestionado", html)
        self.assertIn("escala del proyecto (1 a 5)", html)
        self.assertNotIn("escala 0 a 4", html)
        md = (self.con / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("### Equivalencia de escalas", md)
        self.assertIn("| 4 | Gestionado | Desc de Gestionado |", md)
        with zipfile.ZipFile(self.con / "informe_ot.docx") as z:
            doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("Equivalencia de escalas", doc)
        self.assertIn("Optimizado", doc)
        with zipfile.ZipFile(self.con / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Equivalencia de escalas", hojas)
        self.assertFalse(list(self.con.glob("*equivalencia*")))

    def test_sin_cuestionario_objetivo_en_la_escala_del_proyecto_y_tabla(self):
        filas = self.leer(self.sin_q / "madurez.csv")
        seg = next(f for f in filas if f["dominio"] == "Segmentacion de red")
        self.assertEqual(seg["nivel_objetivo"], "5")
        self.assertEqual((seg["nivel_actual"], seg["nombre_nivel_actual"]), ("", ""))
        self.assertEqual(seg["nombre_nivel_objetivo"], "Optimizado")
        self.assertTrue(all(f["nivel_objetivo"] == "3" for f in filas if f is not seg))
        self.assertIn("Equivalencia de escalas", (self.sin_q / "reporte_ot.html").read_text(encoding="utf-8"))

    def test_ingles_sin_traducir_los_nombres_del_proyecto(self):
        self.assertEqual(self.faltantes, set())
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Scale equivalence", html)
        self.assertIn("Tool levels (0 to 4)", html)
        self.assertIn("Gestionado", html)
        self.assertIn("Desc de Gestionado", html)
        self.assertIn("on the project scale (1 to 5)", html)
        filas = self.leer(self.en / "madurez.csv")
        self.assertEqual(list(filas[0])[-2:], ["current_level_name", "target_level_name"])
        self.assertIn("Gestionado", {f["current_level_name"] for f in filas})
        self.assertTrue(self.leer(self.en / "cuestionario_madurez.csv")[0]["scale"].startswith("1 = Inicial"))


if __name__ == "__main__":
    unittest.main()
