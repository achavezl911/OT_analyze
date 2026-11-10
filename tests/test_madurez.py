"""M7 (D84): madurez por dominio, cuestionario de entrevista, senales tecnicas y contradicciones. Sin tshark."""
from __future__ import annotations

import ast
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
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports

from ot_assess import i18n, madurez, perfil, playbooks
from ot_assess.cli import main

T_SEG = "Conductos entre zonas sin firewall observado en el camino"      # segmentacion
T_ACC = "Credenciales o administracion en texto claro"                     # acceso
NIVELES = json.loads((RAIZ / "ot_assess" / "marcos" / "iec62443_niveles.json").read_text(encoding="utf-8"))
CSF = json.loads((RAIZ / "ot_assess" / "marcos" / "nist-csf.json").read_text(encoding="utf-8"))


def hallazgo(titulo, sev):
    return {"titulo": titulo, "severidad": sev, "categoria": "Higiene", "evidencia": "x 10.0.0.1",
            "captura": "a.pcap", "recomendacion": "Rec", "activos": ["10.0.0.1"], "referencias": {}}


def corrida(hallazgos=(), perf=None, **extra):
    return SimpleNamespace(caps=[SimpleNamespace(findings=list(hallazgos))], extras=[], perfil=perf or {}, **extra)


def respuestas(**por_dominio):
    """{id: {"respuesta": r}} con la lista de respuestas de cada dominio (por prefijo: ACT, SEG...)."""
    out = {}
    for pref, lista in por_dominio.items():
        for i, r in enumerate(lista, 1):
            out[f"{pref}-{i:02d}"] = {"respuesta": str(r)}
    return out


def dom(m, clave):
    return next(x for x in m["dominios"] if x["clave"] == clave)


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def tearDown(self):
        i18n.usar("es")
        i18n.FALTANTES.clear()


class DatosTest(Base):
    def test_ocho_dominios_cuatro_preguntas_ids_y_mapeos(self):
        self.assertEqual(madurez.claves(), ("activos", "segmentacion", "acceso", "parches", "monitoreo",
                                            "incidentes", "suministro", "riesgo"))
        ps = madurez.preguntas()
        self.assertEqual(len(ps), 32)
        self.assertEqual(len({p["id"] for p in ps}), 32)
        for p in ps:
            self.assertRegex(p["id"], r"^[A-Z]{3}-0[1-4]$")
            self.assertRegex(p["csf"], r"^[A-Z]{2}\.[A-Z]{2}$")
            self.assertTrue(p["iec62443"] in NIVELES["fr"] or p["iec62443"] in NIVELES["sr"], p["iec62443"])
            self.assertTrue(p["texto"].isascii() and p["texto"].endswith("?"))
        self.assertEqual(madurez.datos()["validacion"]["estado"], "sin revisar")
        existentes = set(re.findall(r"[A-Z]{2}\.[A-Z]{2}", " ".join(CSF["referencias"].values())))
        for p in ps:        # categorias del marco ya mapeado; GV.SC, GV.RM, RS.MA, RC.RP e ID.IM son de CSF 2.0 y no estan
            self.assertTrue(p["csf"] in existentes or p["csf"] in
                            ("GV.SC", "GV.RM", "RS.MA", "RC.RP", "ID.IM"), p["csf"])

    def test_cada_titulo_conocido_tiene_exactamente_un_dominio(self):
        titulos = {pb["hallazgo"] for pb in playbooks.cargar().values()}
        arboles = [ast.parse(p.read_text(encoding="utf-8")) for p in sorted((RAIZ / "ot_assess").rglob("*.py"))]

        def valor(nodo, consts):
            """Texto de una constante, un nombre o una suma de ambos; None si no es resoluble."""
            if isinstance(nodo, ast.Constant) and isinstance(nodo.value, str):
                return nodo.value
            if isinstance(nodo, ast.Name):
                return consts.get(nodo.id)
            if isinstance(nodo, ast.BinOp) and isinstance(nodo.op, ast.Add):
                a, b = valor(nodo.left, consts), valor(nodo.right, consts)
                return a + b if a is not None and b is not None else None
            return None

        def constantes(arbol):
            out = {}
            for n in arbol.body:
                if isinstance(n, ast.Assign):
                    v = valor(n.value, out)
                    if v is not None:
                        out.update({getattr(x, "id", ""): v for x in n.targets})
            return out
        globales = {k: v for arbol in arboles for k, v in constantes(arbol).items() if k.startswith("TIT_")}
        for arbol in arboles:
            consts = {**globales, **constantes(arbol)}      # una constante importada de otro modulo (TIT_*)
            for n in ast.walk(arbol):
                if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "finding" and len(n.args) > 2:
                    v = valor(n.args[2], consts)
                    if v is not None:
                        titulos.add(v)
                    else:       # f-string o expresion: no se puede resolver; que no pase en silencio
                        self.assertNotIsInstance(n.args[2], ast.Name, ast.dump(n.args[2]))
        self.assertGreater(len(titulos), 100)
        for tit in sorted(titulos):
            self.assertEqual(len(madurez.dominios_de(tit)), 1, tit)

    def test_fragmentos_con_dominio_valido_y_sin_repetir(self):
        asign = madurez.datos()["asignacion_titulos"]
        self.assertEqual(set(asign), set(madurez.claves()))
        todos = [f for frags in asign.values() for f in frags]
        self.assertEqual(len(todos), len(set(todos)))
        self.assertTrue(all(f == f.lower() and f.isascii() for f in todos))


class CuestionarioTest(Base):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def plantilla(self, *extra):
        ruta = self.tmp / "q.csv"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["madurez", "cuestionario", "-o", str(ruta), *extra]), 0)
        return ruta

    def test_plantilla_32_preguntas_8_dominios_y_respuestas_vacias(self):
        ruta = self.plantilla()
        self.assertTrue(ruta.read_bytes().startswith(b"\xef\xbb\xbf"))
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), madurez.COL_CUESTIONARIO)
        self.assertEqual(len(filas), 32)
        self.assertEqual(len({f["dominio"] for f in filas}), 8)
        for f in filas:
            for c in ("respuesta", "evidencia_presentada", "entrevistado", "fecha", "comentario"):
                self.assertEqual(f[c], "")
            self.assertIn("0 = No existe", f["escala"])
            self.assertIn("4 = Mejora continua", f["escala"])
        self.assertEqual(filas[0]["id"], "ACT-01")
        self.assertEqual(filas[-1]["id"], "RIE-04")

    def test_plantilla_en_ingles_con_el_catalogo(self):
        i18n.FALTANTES.clear()
        ruta = self.plantilla("--idioma", "en")
        with open(ruta, newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(i18n.FALTANTES, set())
        self.assertIn("question", filas[0])
        self.assertEqual(filas[0]["domain"], "Asset management")
        self.assertEqual(filas[0]["answer"], "")
        self.assertIn("0 = Does not exist", filas[0]["scale"])
        self.assertTrue(all(f["question"].isascii() for f in filas))

    def test_el_leer_acepta_la_plantilla_contestada_y_el_separador_punto_y_coma(self):
        ruta = self.plantilla()
        texto = ruta.read_text(encoding="utf-8-sig").splitlines()
        self.assertEqual(madurez.leer(ruta), {p["id"]: {"respuesta": "", "evidencia_presentada": "",
                                                        "entrevistado": "", "fecha": "", "comentario": ""}
                                              for p in madurez.preguntas()})
        pc = self.tmp / "pc.csv"
        pc.write_text("id;respuesta;comentario\nSEG-01;3;ok\nseg-02; n/a ;\n", encoding="utf-8")
        r = madurez.leer(pc)
        self.assertEqual((r["SEG-01"]["respuesta"], r["SEG-02"]["respuesta"]), ("3", "N/A"))
        self.assertEqual(len(texto), 33)


class CalculoTest(Base):
    def test_promedio_objetivo_del_perfil_brecha_y_general(self):
        perf = {"madurez_objetivo": {"segmentacion": 3}}
        r = respuestas(SEG=[3, 3, 2, "N/A"], ACT=[4, 4, 4, 4], ACC=[2, 2, 2, 2])
        m = madurez.construir(corrida(perf=perf), r)
        s = dom(m, "segmentacion")
        self.assertEqual((s["nivel"], s["objetivo"], s["brecha"]), (2.7, 3, 0.3))
        self.assertEqual((s["contestadas"], s["total"], s["na"]), (4, 4, 1))
        self.assertIn("madurez_objetivo", s["origen_objetivo"])
        a = dom(m, "activos")
        self.assertEqual((a["nivel"], a["objetivo"], a["brecha"]), (4.0, 2, 0.0))   # brecha minima 0
        self.assertEqual(a["origen_objetivo"], "propuesto por la herramienta; lo fija el cliente")
        self.assertEqual(m["general"], {"dominios_con_nivel": 3, "nivel": 2.9, "objetivo": 2.3, "brecha": 0.1})

    def test_objetivo_desde_ml_objetivo_del_perfil(self):
        m = madurez.construir(corrida(perf={"ml_objetivo": "ML3"}), respuestas(ACC=[1, 1, 1, 1]))
        x = dom(m, "acceso")
        self.assertEqual((x["objetivo"], x["brecha"]), (3, 2.0))
        self.assertIn("ml_objetivo", x["origen_objetivo"])

    def test_menos_de_la_mitad_contestadas_es_insuficiente(self):
        m = madurez.construir(corrida(), respuestas(ACC=[3, "", "", ""], SEG=[3, 3, "", ""]))
        a, s = dom(m, "acceso"), dom(m, "segmentacion")
        self.assertEqual((a["nivel"], a["brecha"], a["estado"]), (None, None, "insuficiente"))
        self.assertEqual((s["nivel"], s["estado"]), (3.0, "medido"))      # justo la mitad
        self.assertEqual(m["general"]["dominios_con_nivel"], 1)
        self.assertEqual(dom(madurez.construir(corrida(), respuestas(ACC=["N/A"] * 4)), "acceso")["estado"],
                         "insuficiente")

    def test_sin_cuestionario_no_hay_niveles(self):
        m = madurez.construir(corrida())
        self.assertFalse(m["con_cuestionario"])
        self.assertTrue(all(x["nivel"] is None and x["estado"] == "sin cuestionario" for x in m["dominios"]))
        self.assertIsNone(m["general"]["nivel"])


class ErroresTest(Base):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def csv(self, texto):
        p = self.tmp / "q.csv"
        p.write_text(texto, encoding="utf-8")
        return p

    def test_respuesta_fuera_de_rango_o_id_desconocido_dan_error_con_la_linea(self):
        p = self.csv("id,respuesta\nSEG-01,3\nSEG-02,5\nXXX-01,2\nSEG-03,tres\n")
        with self.assertRaises(madurez.ErrorMadurez) as e:
            madurez.leer(p)
        msg = str(e.exception)
        self.assertIn("linea 3", msg)
        self.assertIn("'5'", msg)
        self.assertIn("linea 4", msg)
        self.assertIn("XXX-01", msg)
        self.assertIn("linea 5", msg)

    def test_columnas_faltantes_y_repetidos(self):
        with self.assertRaises(madurez.ErrorMadurez) as e:
            madurez.leer(self.csv("id,comentario\nSEG-01,x\n"))
        self.assertIn("linea 1", str(e.exception))
        with self.assertRaises(madurez.ErrorMadurez) as e:
            madurez.leer(self.csv("id,respuesta\nSEG-01,1\nSEG-01,2\n"))
        self.assertIn("linea 3", str(e.exception))

    def test_el_cli_falla_antes_de_analizar_y_no_escribe_nada(self):
        p = self.csv("id,respuesta\nSEG-01,9\n")
        out = self.tmp / "salida"
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as e:
            main(["diagrama", "--activos", "no.csv", "--enlaces", "no.csv", "--madurez", str(p), "-o", str(out)])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("linea 2", err.getvalue())
        self.assertFalse(out.exists())

    def test_perfil_madurez_objetivo_invalido(self):
        def cargar(valor):
            pf = self.tmp / "perfil.json"
            pf.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                      "madurez_objetivo": valor}), encoding="utf-8")
            return perfil.cargar(pf)
        self.assertEqual(cargar({"segmentacion": 3, "riesgo": 0})["madurez_objetivo"], {"segmentacion": 3, "riesgo": 0})
        for malo in ({"red": 3}, {"segmentacion": 5}, {"segmentacion": "3"}, {"segmentacion": True},
                     {"segmentacion": 2.5}, ["segmentacion"]):
            with self.assertRaises(SystemExit, msg=str(malo)):
                cargar(malo)


class ContradiccionTest(Base):
    def test_nivel_3_con_hallazgo_alta_del_dominio_se_marca(self):
        r = respuestas(SEG=[3, 3, 3, 3])
        m = madurez.construir(corrida([hallazgo(T_SEG, "Alta")]), r)
        s = dom(m, "segmentacion")
        self.assertIn("la evidencia de red no respalda el nivel declarado", s["contradiccion"])
        self.assertIn(T_SEG, s["contradiccion"])
        self.assertEqual(s["nivel"], 3.0)       # solo marca; no cambia el nivel
        self.assertEqual(s["hallazgos"], {"Alta": 1, "Media": 0, "Baja": 0})

    def test_sin_alta_en_el_dominio_o_nivel_menor_no_se_marca(self):
        r = respuestas(SEG=[3, 3, 3, 3])
        self.assertEqual(dom(madurez.construir(corrida([hallazgo(T_SEG, "Media")]), r), "segmentacion")
                         ["contradiccion"], "")
        self.assertEqual(dom(madurez.construir(corrida([hallazgo(T_ACC, "Alta")]), r), "segmentacion")
                         ["contradiccion"], "")
        bajo = respuestas(SEG=[2, 3, 3, 2])      # 2.5 < 3
        self.assertEqual(dom(madurez.construir(corrida([hallazgo(T_SEG, "Alta")]), bajo), "segmentacion")
                         ["contradiccion"], "")

    def test_las_senales_cuentan_hallazgos_por_severidad_y_dominio(self):
        hs = [hallazgo(T_SEG, "Alta"), hallazgo(T_ACC, "Media"), hallazgo(T_ACC + " (otro)", "Baja"),
              hallazgo("Titulo desconocido", "Alta"), hallazgo(T_ACC, "Informativa")]
        m = madurez.construir(corrida(hs))
        self.assertEqual(dom(m, "acceso")["hallazgos"], {"Alta": 0, "Media": 1, "Baja": 1})
        self.assertEqual(m["sin_asignar"], ["Titulo desconocido"])

    def test_senales_de_datos_existentes(self):
        campos = lambda f, m, fw: {"campos": {"fabricante": {"valor": f}, "modelo": {"valor": m},
                                              "firmware": {"valor": fw}}}
        res = corrida(
            inventario_normalizado={"filas": [campos("A", "B", "1"), campos("A", "", "1")]},
            obsolescencia={"filas": [{"id": "x", "estado": "fuera de soporte"},
                                     {"id": "x", "estado": "fuera de soporte"},
                                     {"id": "y", "estado": "con soporte"}]},
            vulns_cruces=[{"activo": "k1", "kev": "si", "vuln": {"estado": "abierta"}},
                          {"activo": "k2", "kev": "no", "vuln": {"estado": "abierta"}}],
            cobertura_captura={"puntos": [1], "resumen": {"apta": 1, "apta con limitaciones": 2, "no apta": 0}})
        m = madurez.construir(res)
        self.assertEqual(dom(m, "activos")["senales"],
                         ["50% de 2 activos del inventario normalizado con fabricante, modelo y firmware"])
        self.assertEqual(dom(m, "parches")["senales"],
                         ["1 activos fuera de soporte (reporte de obsolescencia)",
                          "1 activos con CVE en el catalogo KEV (abiertas)"])
        self.assertIn("1 puntos aptos, 2 aptos con limitaciones, 0 no aptos", dom(m, "monitoreo")["senales"][0])
        for k in ("incidentes", "riesgo"):
            self.assertIn("no evaluable con datos de red", dom(m, k)["senales"][0])


class ReporteTest(unittest.TestCase):
    """`diagrama` de punta a punta: sin y con --madurez, en espanol e ingles."""

    @classmethod
    def setUpClass(cls):
        i18n.usar("es")
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.args = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        q = cls.tmp / "q.csv"
        q.write_text("id,respuesta\n" + "".join(f"{p['id']},3\n" for p in madurez.preguntas()), encoding="utf-8")
        pf = cls.tmp / "perfil.json"
        pf.write_text(json.dumps({"version": 1, "cliente": "Prueba", "marcos": [{"clave": "iec62443"}],
                                  "madurez_objetivo": {"segmentacion": 4}}), encoding="utf-8")
        cls.sin = cls.correr("sin")
        cls.con = cls.correr("con", "--madurez", str(q), "--perfil", str(pf))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--madurez", str(q), "--perfil", str(pf), "--idioma", "en")
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

    def test_sin_cuestionario_senales_sin_niveles_ni_radar(self):
        filas = self.leer(self.sin / "madurez.csv")
        self.assertEqual(len(filas), 8)
        self.assertEqual(list(filas[0]), madurez.COLUMNAS)
        self.assertTrue(all(f["nivel_actual"] == "" and f["brecha"] == "" for f in filas))
        self.assertTrue(all(f["nivel_objetivo"] == "2" for f in filas))
        self.assertTrue(all(f["referencias_csf"] and f["referencias_62443"] for f in filas))
        self.assertEqual(len(self.leer(self.sin / "cuestionario_madurez.csv")), 32)
        html = (self.sin / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Madurez por dominio", html)
        self.assertIn("El nivel actual se mide con la entrevista", html)
        self.assertNotIn('class="radar"', html)
        datos = json.loads((self.sin / "resultado.json").read_text(encoding="utf-8"))["madurez"]
        self.assertFalse(datos["con_cuestionario"])
        self.assertEqual(len(datos["dominios"]), 8)

    def test_con_cuestionario_niveles_objetivo_del_perfil_y_radar(self):
        filas = {f["dominio"]: f for f in self.leer(self.con / "madurez.csv")}
        self.assertEqual(filas["Segmentacion de red"]["nivel_actual"], "3.0")
        self.assertEqual(filas["Segmentacion de red"]["nivel_objetivo"], "4")
        self.assertEqual(filas["Segmentacion de red"]["brecha"], "1.0")
        self.assertEqual(filas["Control de acceso"]["brecha"], "0.0")      # objetivo 2 propuesto, actual 3
        self.assertEqual(filas["Control de acceso"]["contestadas"], "4")
        resp = self.leer(self.con / "cuestionario_madurez.csv")
        self.assertTrue(all(r["respuesta"] == "3" for r in resp))
        html = (self.con / "reporte_ot.html").read_text(encoding="utf-8")
        radar = html.split('<div class="radar">')[1].split("</div>")[0]
        self.assertTrue(radar.startswith("<svg"))
        self.assertNotIn("<script", radar)
        self.assertEqual(radar.count("<polygon"), 6)        # 4 anillos, objetivo y actual
        self.assertIn("Promedio declarado 3.0 de 4", html)

    def test_md_word_xlsx(self):
        md = (self.con / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("## Madurez por dominio", md)
        self.assertIn("| Segmentacion de red | 3.0 | 4 | 1.0 |", md)
        with zipfile.ZipFile(self.con / "informe_ot.docx") as z:
            self.assertIsNone(z.testzip())
            self.assertIn("Madurez por dominio", z.read("word/document.xml").decode("utf-8"))
        with zipfile.ZipFile(self.con / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Madurez por dominio", hojas)
        self.assertIn("Cuestionario de madurez", hojas)

    def test_nunca_cumple_ni_no_cumple(self):
        for d in (self.sin, self.con):
            texto = (d / "reporte_ot.md").read_text(encoding="utf-8").lower()
            seccion = texto.split("## madurez por dominio")[1].split("\n## ")[0]
            self.assertNotIn("no cumple", seccion)
            self.assertNotRegex(seccion, r"\bcumple\b")

    def test_ingles(self):
        self.assertEqual(self.faltantes, set())
        html = (self.en / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("Maturity by domain", html)
        filas = self.leer(self.en / "madurez.csv")
        self.assertIn("current_level", filas[0])
        self.assertEqual(self.leer(self.en / "cuestionario_madurez.csv")[0]["domain"], "Asset management")


class CatalogoInglesTest(Base):
    def test_todo_el_cuestionario_esta_traducido(self):
        cat = json.loads((RAIZ / "ot_assess" / "catalogos" / "en.json").read_text(encoding="utf-8"))["en"]
        d = madurez.datos()
        textos = list(d["escala"].values()) + [x["nombre"] for x in d["dominios"]] \
            + [p["texto"] for x in d["dominios"] for p in x["preguntas"]]
        faltan = [x for x in textos if x not in cat]
        self.assertEqual(faltan, [])


if __name__ == "__main__":
    unittest.main()
