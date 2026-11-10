"""B7c (D77): matriz de controles 62443 + NIST SP 800-82r3. Corridas sinteticas (IP de documentacion)."""
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
from test_linea_base import _lb
from test_zonas import _inventario_xdome

from ot_assess import i18n
from ot_assess import linea_base as lb
from ot_assess import matriz_controles as mc
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.switches.higiene import TIT_HORA


def _hall(titulo, nist, sev="Media"):
    return {"titulo": titulo, "severidad": sev, "referencias": {"nist-800-82": nist}}


def _nist(findings=(), perfil=None, assets=None, zcr=None, firewall=None):
    return mc.construir(assets or {}, zcr or {}, firewall or {}, list(findings), perfil)


def _fila(r, ident):
    return next(f for f in r["nist"]["filas"] if f["id"] == ident)


class CatalogoTest(unittest.TestCase):
    def test_conteos_de_las_tres_lineas_base(self):
        self.assertEqual([mc.conteo(n)[0] for n in mc.LINEAS_BASE], [169, 215, 227])
        self.assertEqual([mc.conteo(n)[1] for n in mc.LINEAS_BASE], [25, 123, 194])
        for n in mc.LINEAS_BASE:
            self.assertEqual(mc.conteo(n), (mc.cargar()["conteos"][n]["controles"], mc.cargar()["conteos"][n]["mejoras"]))

    def test_sc10_quitado_no_esta_en_moderada_ni_alta_ni_en_baja(self):
        for n in mc.LINEAS_BASE:
            self.assertNotIn("SC-10", mc.controles_de(n), n)
            self.assertNotIn("SC-10", [f["id"] for f in _nist(perfil={"linea_base_nist": n})["nist"]["filas"]], n)
        self.assertIn("SC-7", mc.controles_de("baja"))

    def test_las_pm_van_con_alcance_organizacion(self):
        r = _nist()
        self.assertEqual(_fila(r, "PM-1")["alcance"], mc.ALC_ORG)
        self.assertEqual(_fila(r, "SC-7")["alcance"], mc.ALC_SITIO)

    def test_contraste_con_las_referencias_del_marco(self):
        # todo control citado existe en el catalogo salvo los de 800-53r5 sin linea base OT (D77)
        self.assertEqual(mc.contraste_refs(), ["SC-32"])


class EstadoTest(unittest.TestCase):
    def test_hallazgo_que_cita_sc7_da_brecha_y_la_mejora_hereda_solo_si_no_se_distingue(self):
        r = _nist([_hall("Hallazgo de ejemplo", "SC-7 (proteccion de frontera)")])
        self.assertEqual(_fila(r, "SC-7")["estado"], lb.E_BRECHA)
        self.assertEqual(_fila(r, "SC-7(3)")["estado"], lb.E_BRECHA)        # hereda del control base
        r2 = _nist([_hall("Hallazgo de ejemplo", "SC-7 (frontera); SC-7(5) (denegar por defecto)")])
        self.assertEqual(_fila(r2, "SC-7(5)")["estado"], lb.E_BRECHA)
        self.assertNotEqual(_fila(r2, "SC-7(3)")["estado"], lb.E_BRECHA)    # el hallazgo distingue la mejora
        self.assertEqual(_fila(r2, "SC-7")["estado"], lb.E_BRECHA)

    def test_sin_evidencia_y_no_evaluable(self):
        r = _nist()
        self.assertEqual(_fila(r, "AU-8")["estado"], lb.E_SIN)       # citado por un fragmento del marco
        self.assertEqual(_fila(r, "PM-1")["estado"], lb.E_NOEVAL)
        self.assertNotIn(lb.E_BRECHA, {f["estado"] for f in r["nist"]["filas"]})

    def test_au8_control_observado_con_switch_y_brecha_con_el_hallazgo_de_hora(self):
        assets = {"a": {"switch_puerto": "SW1:Gi0/1"}}
        self.assertEqual(_fila(_nist(assets=assets), "AU-8")["estado"], lb.E_CONTROL)
        r = _nist([_hall(TIT_HORA, "AU-8 (marcas de tiempo)")], assets=assets)
        self.assertEqual(_fila(r, "AU-8")["estado"], lb.E_BRECHA)
        self.assertEqual(_fila(r, "AU-8")["playbooks"] != [], True)

    def test_sc7_control_observado_solo_si_todos_los_conductos_cruzan_firewall(self):
        def fila(fw, ids):
            return {"firewalls": fw, "reglas_ids": ids}
        marcas = {("", "7"): ""}
        antes = lb._marcas_reglas
        lb._marcas_reglas = lambda _fw: marcas
        try:
            ok = _nist(zcr={"filas": [fila(["fw"], [["", "7"]])]})
            self.assertEqual(_fila(ok, "SC-7")["estado"], lb.E_CONTROL)
            self.assertEqual(_fila(ok, "SC-7(3)")["estado"], lb.E_SIN)     # la mejora no hereda el control
            sin = _nist(zcr={"filas": [fila(["fw"], [["", "7"]]), fila([], [])]})
            self.assertNotEqual(_fila(sin, "SC-7")["estado"], lb.E_CONTROL)
            marcas[("", "7")] = "any-any"
            amplia = _nist(zcr={"filas": [fila(["fw"], [["", "7"]])]})
            self.assertNotEqual(_fila(amplia, "SC-7")["estado"], lb.E_CONTROL)
        finally:
            lb._marcas_reglas = antes

    def test_prioridad_brecha_primero(self):
        r = _nist([_hall("Hallazgo de ejemplo", "CM-7 (funcionalidad minima)")])
        filas = sorted(r["nist"]["filas"], key=lambda f: f["prioridad"])
        self.assertEqual(filas[0]["estado"], lb.E_BRECHA)
        self.assertEqual([f["prioridad"] for f in filas], list(range(1, len(filas) + 1)))


class LineaBaseElegidaTest(unittest.TestCase):
    def test_sin_perfil_es_moderada_propuesta(self):
        n = _nist()["nist"]
        self.assertEqual((n["linea_base"], len(n["filas"])), ("moderada", 215 + 123))
        self.assertTrue(n["origen"].startswith("propuesto por la herramienta"))

    def test_alta_trae_mas_filas_y_origen_del_perfil(self):
        n = _nist(perfil={"linea_base_nist": "alta"})["nist"]
        self.assertEqual(len(n["filas"]), 227 + 194)
        self.assertEqual(n["origen"], mc.ORIGEN_BASE_PERFIL)

    def test_perfil_valida_linea_base_nist(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            def cargar(v):
                p = tmp / "p.json"
                p.write_text(json.dumps({"version": 1, "cliente": "Cliente X", "marcos": [{"clave": "iec62443"}],
                                         "linea_base_nist": v}), encoding="utf-8")
                return pf.cargar(str(p))
            self.assertEqual(cargar("alta")["linea_base_nist"], "alta")
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                cargar("critica")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class MatrizTest(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")

    def _datos(self):
        h = {"titulo": "Texto claro de ejemplo", "severidad": "Media",
             "referencias": {"iec62443": "SR 1.1 Identificacion", "nist-800-82": "IA-5 (autenticadores)"},
             "activos": ["192.0.2.5"]}
        r = _lb(findings=[h])
        return r, _nist([h])

    def _matriz(self, r, m):
        return mc.filas_matriz(m, r)

    def test_filas_62443_son_las_de_linea_base(self):
        r, m = self._datos()
        n_lb = sum(len(x["filas"]) for k in ("zonas", "conductos") for x in r[k])
        filas = [f for f in self._matriz(r, m) if f[0] == mc.M_62443]
        self.assertEqual(len(filas), n_lb)
        self.assertEqual(len([f for f in self._matriz(r, m) if f[0] == mc.M_NIST]), 215 + 123)
        self.assertEqual(len(mc.COLUMNAS), len(filas[0]))

    def test_columnas_de_validacion_vacias(self):
        r, m = self._datos()
        self.assertEqual(mc.COLUMNAS[-6:], ["estado_validado", "fuente_validacion", "validado_por", "revisado_por",
                                            "fecha_validacion", "comentario"])
        for f in self._matriz(r, m):
            self.assertEqual(f[-6:], [""] * 6)

    def test_nunca_cumple_ni_no_cumple(self):
        r, m = self._datos()
        for idioma, prohibido in (("es", "cumple"), ("en", "compliant")):
            i18n.usar(idioma)
            tablas = mc.tablas(m, r)
            s = mc.seccion(m, r)
            txt = [str(c) for _a, hoja, cab, filas in tablas for c in [hoja, *cab, *[x for f in filas for x in f]]]
            txt += [s["titulo"], s["nota"], s["resumen"], *s["tabla"][0], *[str(c) for f in s["tabla"][1] for c in f]]
            self.assertNotIn(prohibido, "\n".join(txt).lower(), idioma)

    def test_ingles_sin_textos_faltantes(self):
        r, m = self._datos()
        i18n.FALTANTES.clear()
        i18n.usar("en")
        mc.tablas(m, r)
        mc.seccion(m, r)
        for c in mc.COLUMNAS:
            i18n.t(c)
        self.assertEqual(i18n.FALTANTES - {"Texto claro de ejemplo"}, set())
        i18n.FALTANTES.clear()

    def test_general_agrega_una_fila_por_familia(self):
        r, m = self._datos()
        gen = next(f for a, _h, _c, f in mc.tablas(m, r) if a == lb.ARCHIVO_GEN)
        fams = [f for f in gen if f[0] == "NIST SP 800-53"]
        self.assertEqual(len(fams), len({x["familia"] for x in m["nist"]["filas"]}))
        ia = next(f for f in fams if f[1] == "IA")
        self.assertGreaterEqual(ia[6], 1)                       # con_brecha: IA-5 citado
        self.assertTrue(all(len(f) == len(lb.COL_GEN) for f in gen))

    def test_sin_zonas_igual_hay_matriz_nist(self):
        m = _nist()
        tablas = {a: f for a, _h, _c, f in mc.tablas(m, {})}
        self.assertIn(mc.ARCHIVO, tablas)
        self.assertIn(lb.ARCHIVO_GEN, tablas)

    def test_seccion_por_marco_y_familia(self):
        r, m = self._datos()
        cab, filas = mc.seccion(m, r)["tabla"]
        self.assertEqual(len(cab), 2 + 4 + 1)
        self.assertEqual({f[0] for f in filas}, {mc.M_62443, mc.M_NIST})
        self.assertEqual(sum(f[-1] for f in filas if f[0] == mc.M_NIST), 215 + 123)


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        com = gen_exports.xd_escribir_comunicaciones(cls.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI",
                                tipo_b="PLC")])
        inv = _inventario_xdome(cls.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                      ("PLC-1", "10.10.2.20", "Campo")])
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome",
                                    "-o", str(cls.out)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_archivos_y_secciones(self):
        self.assertEqual(self.rc, 0)
        with open(self.out / mc.ARCHIVO, encoding="utf-8-sig") as fh:
            filas = list(csv.reader(fh))
        self.assertEqual(filas[0], mc.COLUMNAS)
        self.assertGreater(len(filas), 215 + 123)
        for n in ("reporte_ot.html", "reporte_ot.md"):
            self.assertIn("Matriz de controles (ISA/IEC 62443 y NIST SP 800-82r3)",
                          (self.out / n).read_text(encoding="utf-8"))
        self.assertTrue((self.out / "informe_ot.docx").exists())
        self.assertTrue((self.out / "reporte_ot.xlsx").exists())
        d = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(d["matriz_controles"]["nist"]["linea_base"], "moderada")


if __name__ == "__main__":
    unittest.main()
