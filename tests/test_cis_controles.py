"""CIS1 (D108): filas de CIS Controls v8.1 en la matriz de controles, leidas de un archivo del analista.

Los archivos y titulos son sinteticos ("Salvaguarda de prueba N"): el repo no distribuye texto de CIS.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_matriz_controles import _hall

from ot_assess import cis_controles as cc
from ot_assess import i18n
from ot_assess import linea_base as lb
from ot_assess import matriz_controles as mc

CAB = ["CIS Control", "CIS Safeguard", "Asset Class", "Security Function", "Title", "Description", "IG1", "IG2", "IG3"]
# Texto del xlsx real de CIS para el id del control 4 y numeros que Excel guarda con ruido de coma flotante.
IDS_CELDA_4 = ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.0999999999999996", "4.11", "4.12"]


def _archivo_filas() -> list:
    filas = [CAB, ["4\xa0", "", "", "", "Control de prueba 4", "descripcion de prueba", "", "", ""]]
    for i, celda in enumerate(IDS_CELDA_4, 1):
        filas.append(["4", celda, "Devices", "Protect", f"Salvaguarda de prueba {i}", "descripcion de prueba",
                      "x" if i <= 2 else "", "x" if i <= 5 else "", "x"])
    return filas


def _sal(ident, ig=("ig1", "ig2", "ig3"), clase="Devices", funcion="Protect"):
    return {"id": ident, "control": ident.split(".")[0], "clase": clase, "funcion": funcion,
            "titulo": f"Salvaguarda de prueba {ident}", "ig1": "ig1" in ig, "ig2": "ig2" in ig, "ig3": "ig3" in ig}


def _mc(findings=(), perfil=None, cis=None):
    return mc.construir({}, {}, {}, list(findings), perfil, cis)


def _fila_cis(m, ident):
    return next(f for f in m["cis"]["filas"] if f["id"] == ident)


class CargaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_xlsx_con_ids_numericos_que_chocan(self):
        p = self.dir / "cis.xlsx"
        gen_exports.escribir_xlsx(p, _archivo_filas())
        r = cc.cargar(p)
        self.assertEqual([x["id"] for x in r], [f"4.{i}" for i in range(1, 13)])
        self.assertEqual(r[9]["titulo"], "Salvaguarda de prueba 10")
        self.assertEqual([x["ig1"] for x in r][:3], [True, True, False])
        self.assertEqual(sum(x["ig2"] for x in r), 5)
        self.assertNotIn("descripcion de prueba", json.dumps(r))      # la Description no sale

    def test_id_que_no_cuadra_con_su_ordinal(self):
        filas = _archivo_filas()
        filas[5][1] = "4.7"
        p = self.dir / "mal.xlsx"
        gen_exports.escribir_xlsx(p, filas)
        with self.assertRaises(SystemExit) as e:
            cc.cargar(p)
        self.assertIn("no coincide", str(e.exception))

    def test_csv_con_las_mismas_columnas(self):
        p = self.dir / "cis.csv"
        with p.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(_archivo_filas())
        self.assertEqual(len(cc.cargar(p)), 12)

    def test_archivos_invalidos(self):
        p = self.dir / "otro.csv"
        p.write_text("a,b\n1,2\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            cc.cargar(p)
        with self.assertRaises(SystemExit):
            cc.cargar(self.dir / "no_existe.xlsx")


class ReferenciasTest(unittest.TestCase):
    def test_json_de_referencias(self):
        d = json.loads(mc.RUTA_CSF.read_text(encoding="utf-8"))["subcategorias"]
        self.assertEqual(len(d), 185)
        self.assertEqual(len({s for v in d.values() for s in v["cis_v8_1"]}), 49)
        ctl = {c for v in d.values() for c in v["sp800_53"]}
        self.assertIn("AC-2", ctl)
        self.assertFalse([c for c in ctl if "-0" in c or "(0" in c], "ids de 800-53 sin ceros a la izquierda")

    def test_check_no_falla_con_o_sin_normas(self):
        r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "extraer_csf_referencias.py"), "--check"],
                           check=False, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class FilasCisTest(unittest.TestCase):
    def setUp(self):
        self.cis = [_sal("14.1"), _sal("99.1", clase="Documentation", funcion="Govern"), _sal("99.2"),
                    _sal("98.1", clase="Documentation", funcion="Protect"), _sal("15.2", ig=("ig3",)),
                    _sal("97.1", ig=("ig1", "ig2", "ig3"), funcion="Govern", clase="Devices")]

    def test_brecha_en_un_control_alcanzado_por_la_salvaguarda(self):
        m = _mc([_hall("Hallazgo de ejemplo", "PM-2 (ejemplo)")], cis=self.cis)
        f = _fila_cis(m, "14.1")
        self.assertEqual(f["estado"], lb.E_BRECHA)
        self.assertIn("PM-2", f["controles"])
        self.assertEqual(f["hallazgos"], ["Hallazgo de ejemplo"])
        self.assertEqual(m["cis"]["filas"][0]["id"], "14.1")                # brecha primero
        fila = next(x for x in mc.filas_matriz(m, {}) if x[0] == mc.M_CIS and x[3] == "14.1")
        self.assertIn("CSF 2.0: GV.RR-01; PR.AT-01; SP 800-53 en la linea base:", fila[8])
        self.assertIn("1 con brecha", fila[8])
        self.assertEqual(fila[4], "Salvaguarda de prueba 14.1")
        self.assertEqual(fila[9], "Hallazgo de ejemplo")

    def test_sin_correspondencia_documental_y_de_dispositivos(self):
        m = _mc(cis=self.cis)
        self.assertEqual(_fila_cis(m, "99.1")["estado"], lb.E_NOEVAL)        # Govern sin correspondencia
        self.assertEqual(_fila_cis(m, "98.1")["estado"], lb.E_NOEVAL)        # Documentation sin correspondencia
        self.assertEqual(_fila_cis(m, "99.2")["estado"], lb.E_SIN)
        fila = next(x for x in mc.filas_matriz(m, {}) if x[3] == "99.2")
        self.assertIn("revisar a mano", fila[8])

    def test_salvaguarda_citada_sin_filas_nist_es_sin_evidencia(self):
        falso = {"X.Y-01": {"cis_v8_1": ["96.1"], "sp800_53": ["ZZ-9"]}}      # control que ninguna linea base trae
        with mock.patch.dict(mc._cache, {"csf": falso}):
            m = _mc(cis=[_sal("96.1", clase="Documentation", funcion="Govern")])
        self.assertEqual(m["cis"]["filas"][0]["estado"], lb.E_SIN)           # citada: sin evidencia aunque sea Govern
        fila = next(x for x in mc.filas_matriz(m, {}) if x[0] == mc.M_CIS)
        self.assertEqual(fila[8], "CSF 2.0: X.Y-01; ningun control SP 800-53 correspondiente esta en la linea "
                                  "base NIST elegida")

    def test_orden_prioridad_y_validacion_vacia(self):
        m = _mc([_hall("Hallazgo de ejemplo", "PM-2 (ejemplo)")], cis=self.cis)
        filas = mc.filas_matriz(m, {})
        nist = [x for x in filas if x[0] == mc.M_NIST]
        cis = [x for x in filas if x[0] == mc.M_CIS]
        self.assertEqual(filas[-len(cis):], cis)                              # al final, despues de las NIST
        self.assertEqual(filas[-len(cis) - len(nist):-len(cis)], nist)
        self.assertEqual(len(cis), 5)                                         # IG2 por defecto: todas menos 15.2
        self.assertEqual([x[11] for x in cis], list(range(1, len(cis) + 1)))
        self.assertTrue(all(x[-mc.N_VALIDACION:] == [""] * mc.N_VALIDACION for x in cis))
        self.assertTrue(all(x[1] == "organizacion" and x[2] == "" for x in cis))

    def test_grupo_por_defecto_y_del_perfil(self):
        m = _mc(cis=self.cis)
        self.assertEqual(m["cis"]["grupo"], "IG2")
        self.assertEqual(m["cis"]["origen"], mc.ORIGEN_BASE_PROPUESTA)
        self.assertNotIn("15.2", [f["id"] for f in m["cis"]["filas"]])        # solo IG3
        m1 = _mc(perfil={"cis_ig": "IG1"}, cis=[_sal("1.1"), _sal("1.2", ig=("ig2", "ig3"))])
        self.assertEqual([f["id"] for f in m1["cis"]["filas"]], ["1.1"])
        self.assertEqual(m1["cis"]["origen"], mc.ORIGEN_BASE_PERFIL)
        fila = next(x for x in mc.filas_matriz(m1, {}) if x[0] == mc.M_CIS)
        self.assertEqual((fila[5], fila[6]), ("IG1", mc.ORIGEN_BASE_PERFIL))
        m3 = _mc(perfil={"cis_ig": "IG3"}, cis=self.cis)
        self.assertIn("15.2", [f["id"] for f in m3["cis"]["filas"]])

    def test_sin_cis_todo_queda_igual(self):
        sin = _mc()
        self.assertNotIn("cis", sin)
        self.assertEqual(mc.filas_matriz(sin, {}), mc.filas_matriz(_mc(cis=[]), {}))
        self.assertFalse([x for x in mc.filas_matriz(sin, {}) if x[0] == mc.M_CIS])
        self.assertNotIn("CIS", mc.seccion(sin, {})["nota"])

    def test_seccion_una_fila_por_control_y_suma_el_total(self):
        m = _mc(cis=self.cis)
        s = mc.seccion(m, {})
        filas = [f for f in s["tabla"][1] if f[0] == mc.M_CIS]
        self.assertEqual([f[1] for f in filas], ["CIS 14", "CIS 97", "CIS 98", "CIS 99"])
        self.assertEqual(sum(f[-1] for f in filas), len(m["cis"]["filas"]))
        for f in filas:
            self.assertEqual(sum(f[2:-1]), f[-1])
        self.assertIn("www.cisecurity.org/controls/", s["nota"])
        self.assertNotIn("Salvaguarda de prueba", json.dumps(s))               # sin titulos de CIS en la seccion

    def test_ingles(self):
        m = _mc([_hall("Hallazgo de ejemplo", "PM-2 (ejemplo)")], cis=self.cis)
        i18n.usar("en")
        try:
            filas = [x for x in mc.filas_matriz(m, {}) if x[0] == mc.M_CIS]
            nota = mc.seccion(m, {})["nota"]
        finally:
            i18n.usar("es")
        self.assertEqual(filas[0][1], "organization")
        self.assertIn("NIST rows", filas[0][8])
        self.assertIn("review by hand", next(x for x in filas if x[3] == "99.2")[8])
        self.assertIn("not an equivalence", nota)
        self.assertEqual(filas[0][4], "Salvaguarda de prueba 14.1")              # el titulo de CIS no se traduce


if __name__ == "__main__":
    unittest.main()
