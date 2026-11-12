"""NBZ1 (D132): linea base NIST SP 800-82r3 por zona en la matriz de controles. Datos sinteticos."""
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

from ot_assess import i18n
from ot_assess import linea_base as lb
from ot_assess import matriz_controles as mc
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama

ZONAS = [{"nombre": "Z1", "linea_base_nist": "alta"}, {"nombre": "Z2", "linea_base_nist": "baja"},
         {"nombre": "Z3"}]
ACTIVOS = {"a": {"ips": ["10.0.0.1"], "zona_asignada": "Z1"}, "b": {"ips": ["10.0.0.2"], "zona_asignada": "Z2"}}


def _hall(nist, activos=None, titulo="Hallazgo de ejemplo"):
    f = {"titulo": titulo, "severidad": "Alta", "referencias": {"nist-800-82": nist}}
    if activos is not None:
        f["activos"] = activos
    return f


def _c(findings=(), zonas=ZONAS, **perfil):
    return mc.construir(ACTIVOS, {}, {}, list(findings), {"zonas": zonas, **perfil})["nist"]


def _filas(n, ident):
    return {f["zona"]: f for f in n["filas"] if f["id"] == ident}


def _solo(nivel_a, nivel_b, alcance):
    """Ids de alcance dado en la linea base `nivel_a` y no en `nivel_b`."""
    cat = mc.cargar()["controles"]
    return [i for i in mc.controles_de(nivel_a) if i not in mc.controles_de(nivel_b)
            and (alcance == mc.ALC_ORG) == bool(cat[i].get("toda_la_organizacion")
                                                or cat.get(mc.base_de(i), {}).get("toda_la_organizacion"))]


class PerfilTest(unittest.TestCase):
    def test_valor_invalido_es_error_de_perfil(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        p = tmp / "p.json"
        base = {"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}]}
        p.write_text(json.dumps({**base, "zonas": [{"nombre": "Z1", "redes": ["10.0.0.0/24"],
                                                    "linea_base_nist": "critica"}]}), encoding="utf-8")
        with self.assertRaises(SystemExit) as cm:
            pf.cargar(p)
        self.assertIn("linea_base_nist", str(cm.exception))
        p.write_text(json.dumps({**base, "zonas": [{"nombre": "Z1", "redes": ["10.0.0.0/24"],
                                                    "linea_base_nist": "alta"}]}), encoding="utf-8")
        self.assertEqual(pf.cargar(p)["zonas"][0]["linea_base_nist"], "alta")


class FilasTest(unittest.TestCase):
    def test_controles_de_cada_linea_base_y_organizacion_una_vez(self):
        n = _c()
        solo_alta = _solo("alta", "moderada", mc.ALC_SITIO)[0]
        self.assertEqual(list(_filas(n, solo_alta)), ["Z1"])       # Z2 baja y Z3 moderada no lo incluyen
        sitio_moderada = _solo("moderada", "baja", mc.ALC_SITIO)[0]
        self.assertEqual(sorted(_filas(n, sitio_moderada)), ["Z1", "Z3"])
        self.assertEqual(sorted(_filas(n, "SC-7")), ["Z1", "Z2", "Z3"])
        f = _filas(n, "PM-1")                                       # alcance organizacion: una sola fila
        self.assertEqual(list(f), [""])
        self.assertEqual((f[""]["linea_base"], f[""]["origen"]), ("alta", "declarado en el perfil"))
        baja_y_heredada = _c(zonas=[{"nombre": "Z1", "linea_base_nist": "baja"}, {"nombre": "Z2"}])
        self.assertEqual(_filas(baja_y_heredada, "PM-1")[""]["linea_base"], "moderada")
        z3 = _filas(n, "SC-7")["Z3"]
        self.assertEqual((z3["linea_base"], z3["origen"]), ("moderada", mc.ORIGEN_ZONA_PROPUESTA))
        z3 = _filas(_c(linea_base_nist="baja"), "SC-7")["Z3"]
        self.assertEqual((z3["linea_base"], z3["origen"]), ("baja", mc.ORIGEN_ZONA_HEREDADA))

    def test_orden_y_prioridad(self):
        n = _c([_hall("CM-7 (funcionalidad minima)", ["10.0.0.1"])])
        self.assertEqual([f["prioridad"] for f in n["filas"]], list(range(1, len(n["filas"]) + 1)))
        claves = [(lb.ESTADOS.index(f["estado"]), f["sev"], mc._orden(f["id"]), f["zona"]) for f in n["filas"]]
        self.assertEqual(claves, sorted(claves))


class EstadoPorZonaTest(unittest.TestCase):
    def test_hallazgo_con_activos_de_z1_marca_brecha_solo_en_z1(self):
        f = _filas(_c([_hall("CM-7 (funcionalidad minima)", ["10.0.0.1"])]), "CM-7")
        self.assertEqual(f["Z1"]["estado"], lb.E_BRECHA)
        self.assertNotEqual(f["Z2"]["estado"], lb.E_BRECHA)
        self.assertNotEqual(f["Z3"]["estado"], lb.E_BRECHA)

    def test_hallazgo_sin_activos_marca_brecha_en_todas(self):
        f = _filas(_c([_hall("CM-7 (funcionalidad minima)")]), "CM-7")
        self.assertEqual({z: r["estado"] for z, r in f.items()}, {z: lb.E_BRECHA for z in ("Z1", "Z2", "Z3")})

    def test_hallazgo_con_activo_en_zona_sin_linea_base_propia_no_toca_otras(self):
        f = _filas(_c([_hall("CM-7 (funcionalidad minima)", ["10.0.0.2"])]), "CM-7")
        self.assertEqual([z for z, r in f.items() if r["estado"] == lb.E_BRECHA], ["Z2"])


class TablaTest(unittest.TestCase):
    def test_conteos_suman_filas_y_zona_sin_activos(self):
        r = mc.construir(ACTIVOS, {}, {}, [_hall("CM-7 (funcionalidad minima)", ["10.0.0.1"])], {"zonas": ZONAS})
        filas = mc.filas_zonas(r)
        self.assertEqual(filas[-1][0], "organizacion")
        self.assertEqual(sum(sum(f[6:]) for f in filas), len(r["nist"]["filas"]))
        z3 = next(f for f in filas if f[0] == "Z3")
        self.assertEqual(z3[5], 0)                                   # sin activos, igual lleva filas
        self.assertGreater(sum(z3[6:]), 0)
        z1 = next(f for f in filas if f[0] == "Z1")
        z2 = next(f for f in filas if f[0] == "Z2")
        self.assertEqual((z1[5], z2[5]), (1, 1))
        self.assertGreater(z1[6], 0)                                 # brecha de CM-7 solo en Z1
        self.assertEqual(z2[6], 0)
        self.assertEqual([x["zona"] for x in r["nist"]["por_zona"]], ["Z1", "Z2", "Z3"])
        self.assertEqual(set(r["nist"]["por_zona"][0]), {"zona", "linea_base", "origen", "controles", "mejoras",
                                                          "activos"})
        s = mc.seccion(r, {})
        self.assertIn("Z1 alta", s["resumen"])
        self.assertIn("Z3 moderada (propuesta)", s["resumen"])
        self.assertIn("sin activos observados en esta corrida: Z3", s["resumen"])
        nombres = [a for a, _h, _c, _f in mc.tablas(r, {})]
        self.assertIn(mc.ARCHIVO_ZONAS, nombres)

    def test_ingles(self):
        r = mc.construir(ACTIVOS, {}, {}, [], {"zonas": ZONAS, "linea_base_nist": "baja"})
        i18n.FALTANTES.clear()
        i18n.usar("en")
        try:
            s = mc.seccion(r, {})
            mc.filas_matriz(r, {})
            mc.filas_general(r)
            mc.tablas(r, {})
            self.assertIn("Z3 moderate (inherited)".replace("moderate", "low"), s["resumen"])
            self.assertEqual(s["tabla_zonas"][0][1], "baseline")
            self.assertEqual(i18n.FALTANTES, set())
        finally:
            i18n.usar("es")
            i18n.FALTANTES.clear()


class SinClaveTest(unittest.TestCase):
    def test_zonas_sin_clave_dan_lo_mismo_que_sin_zonas(self):
        a = mc.construir(ACTIVOS, {}, {}, [_hall("CM-7 (x)", ["10.0.0.1"])], {"zonas": [{"nombre": "Z1"}]})
        b = mc.construir(ACTIVOS, {}, {}, [_hall("CM-7 (x)", ["10.0.0.1"])], {})
        self.assertEqual(a, b)
        self.assertNotIn("zona", a["nist"]["filas"][0])
        self.assertFalse(mc.por_zona(a))
        self.assertNotIn(mc.ARCHIVO_ZONAS, [x[0] for x in mc.tablas(a, {})])


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        (cls.tmp / "a.csv").write_text(
            "id,name,ip,type,level,zone\n1,HMI-1,10.0.0.1,Windows XP SP3,2,Z\n2,PLC-1,10.0.0.2,PLC,1,Z\n",
            encoding="utf-8")
        (cls.tmp / "e.csv").write_text("from,to,protocol,port\n1,2,telnet,23\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _correr(self, nombre, zonas, extra=None):
        p = self.tmp / (nombre + ".json")
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                 "zonas": zonas, **(extra or {})}), encoding="utf-8")
        out = self.tmp / nombre
        args = ["--activos", str(self.tmp / "a.csv"), "--enlaces", str(self.tmp / "e.csv"), "-o", str(out),
                "--perfil", str(p)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama(args), 0)
        return out

    def test_salidas_con_modo_por_zona_y_sin_clave(self):
        z = [{"nombre": "Alta", "redes": ["10.0.0.0/32"], "linea_base_nist": "alta"},
             {"nombre": "Vacia", "redes": ["10.9.0.0/24"]}]
        out = self._correr("con", z)
        with open(out / mc.ARCHIVO_ZONAS, encoding="utf-8-sig") as fh:
            tabla = list(csv.DictReader(fh))
        self.assertEqual(list(tabla[0]), mc.COL_ZONAS)
        self.assertEqual([t["zona"] for t in tabla], ["Alta", "Vacia", "organizacion"])
        self.assertEqual(tabla[1]["activos"], "0")
        with open(out / mc.ARCHIVO, encoding="utf-8-sig") as fh:
            filas = [f for f in csv.DictReader(fh) if f["marco"] == mc.M_NIST]
        self.assertEqual({f["zona_o_conducto"] for f in filas}, {"", "Alta", "Vacia"})
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as zf:
            self.assertIn("Linea base NIST por zona", zf.read("xl/workbook.xml").decode("utf-8"))
        for n in ("reporte_ot.html", "reporte_ot.md"):
            txt = (out / n).read_text(encoding="utf-8")
            self.assertIn("Linea base NIST SP 800-82r3 por zona: Alta alta, Vacia moderada (propuesta)", txt)
            self.assertIn("organizacion", txt)
        self.assertTrue((out / "informe_ot.docx").exists())
        d = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual([x["zona"] for x in d["matriz_controles"]["nist"]["por_zona"]], ["Alta", "Vacia"])

        sin = self._correr("sin", [{"nombre": "Alta", "redes": ["10.0.0.0/32"]},
                                   {"nombre": "Vacia", "redes": ["10.9.0.0/24"]}])
        self.assertFalse((sin / mc.ARCHIVO_ZONAS).exists())
        with open(sin / mc.ARCHIVO, encoding="utf-8-sig") as fh:
            self.assertEqual({f["zona_o_conducto"] for f in csv.DictReader(fh) if f["marco"] == mc.M_NIST}, {""})
        self.assertNotIn("por_zona", (sin / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("Linea base NIST SP 800-82r3 por zona", (sin / "reporte_ot.html").read_text(encoding="utf-8"))

    def test_entregables_en_filas_por_zona(self):
        ent = {"catalogo": [{"id": "D-01", "nombre": "Matriz", "salidas": ["matriz_controles.csv"]}],
               "mapeo": {"nist-800-82:SC-7": ["D-01"]}}
        out = self._correr("ent", [{"nombre": "Alta", "redes": ["10.0.0.0/32"], "linea_base_nist": "alta"},
                                   {"nombre": "Baja", "redes": ["10.9.0.0/24"], "linea_base_nist": "baja"}],
                           {"entregables": ent})
        with open(out / mc.ARCHIVO, encoding="utf-8-sig") as fh:
            sc7 = [f for f in csv.DictReader(fh) if f["marco"] == mc.M_NIST and f["id"] == "SC-7"]
        self.assertEqual(sorted(f["zona_o_conducto"] for f in sc7), ["Alta", "Baja"])
        self.assertEqual({f["entregables"] for f in sc7}, {"D-01"})


if __name__ == "__main__":
    unittest.main()
