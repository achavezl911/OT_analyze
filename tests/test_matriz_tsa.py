"""TSA1 (D109): filas de la Security Directive TSA SD 1580/82-2022-01E (seccion III) en la matriz de controles."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_matriz_controles import _hall

from ot_assess import i18n, perfil
from ot_assess import linea_base as lb
from ot_assess import matriz_controles as mc

PERFIL = {"tsa_sd": "01E"}


def _mc(findings=(), perfil_=None, cis=None):
    return mc.construir({}, {}, {}, list(findings), PERFIL if perfil_ is None else perfil_, cis)


def _tsa(m):
    return [x for x in mc.filas_matriz(m, {}) if x[0] == mc.M_TSA]


def _fila(m, ident):
    return next(x for x in _tsa(m) if x[3] == ident)


class FilasTsaTest(unittest.TestCase):
    def test_treinta_y_ocho_filas_al_final_con_prioridad_y_validacion_vacia(self):
        m = _mc()
        filas = mc.filas_matriz(m, {})
        tsa = _tsa(m)
        self.assertEqual(len(tsa), 38)
        self.assertEqual(filas[-38:], tsa)
        self.assertEqual([x[3] for x in tsa], [r["id"] for r in mc.tsa()["requisitos"]])
        self.assertEqual(sorted(x[11] for x in tsa), list(range(1, 39)))
        self.assertTrue(all(x[-mc.N_VALIDACION:] == [""] * mc.N_VALIDACION for x in tsa))
        self.assertTrue(all(x[1] == "organizacion" and x[2] == "" and x[5] == "" and x[6] == "" for x in tsa))

    def test_edicion_desconocida_falla_con_la_conocida(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "perfil.json"
            base = {"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}]}
            p.write_text(json.dumps({**base, "tsa_sd": "01D"}), encoding="utf-8")
            with self.assertRaises(SystemExit) as cm:
                perfil.cargar(p)
            self.assertIn("01E", str(cm.exception))
            p.write_text(json.dumps({**base, "tsa_sd": "01E"}), encoding="utf-8")
            self.assertEqual(perfil.cargar(p)["tsa_sd"], "01E")

    def test_brecha_en_sc7_y_documental_no_evaluable(self):
        m = _mc([_hall("Hallazgo de ejemplo", "SC-7 (ejemplo)")])
        f = _fila(m, "III.B.2.a")
        self.assertEqual(f[7], lb.E_BRECHA)
        self.assertRegex(f[8], r"Filas NIST: [1-9]\d* con brecha")
        self.assertIn("SC-7", f[8])
        self.assertEqual(f[9], "Hallazgo de ejemplo")
        d = _fila(m, "III.C.1.a")
        self.assertEqual(d[7], lb.E_NOEVAL)
        self.assertEqual(d[8], "Documental: se evalua por entrevista o documentos")
        self.assertEqual(d[9], "")

    def test_sin_filas_nist_es_sin_evidencia(self):
        casi = mc._construir_tsa([], PERFIL)
        self.assertEqual(next(r for r in casi["filas"] if r["id"] == "III.B.2.a")["estado"], lb.E_SIN)
        self.assertEqual(next(r for r in casi["filas"] if r["id"] == "III.C.1.a")["estado"], lb.E_NOEVAL)

    def test_sin_tsa_todo_queda_igual(self):
        sin = _mc(perfil_={})
        self.assertNotIn("tsa", sin)
        self.assertFalse(_tsa(sin))
        self.assertEqual(mc.filas_matriz(sin, {}), mc.filas_matriz(mc.construir({}, {}, {}, [], None), {}))
        self.assertNotIn("TSA", mc.seccion(sin, {})["nota"])
        self.assertFalse([f for f in mc.seccion(sin, {})["tabla"][1] if f[0] == mc.M_TSA])

    def test_seccion_seis_letras_y_suma_el_total(self):
        s = mc.seccion(_mc(), {})
        filas = [f for f in s["tabla"][1] if f[0] == mc.M_TSA]
        self.assertEqual([f[1] for f in filas], [f"TSA III.{x}" for x in "ABCDEF"])
        self.assertEqual(sum(f[-1] for f in filas), 38)
        for f in filas:
            self.assertEqual(sum(f[2:-1]), f[-1])
        self.assertIn("CIP", s["nota"])

    def test_con_cis_las_filas_cis_no_cambian(self):
        cis = [{"id": "4.1", "control": "4", "clase": "Devices", "funcion": "Protect", "titulo": "Salvaguarda de prueba",
                "ig1": True, "ig2": True, "ig3": True}]
        h = [_hall("Hallazgo de ejemplo", "SC-7 (ejemplo)")]
        solo = mc.filas_matriz(_mc(h, {}, cis), {})
        junto = mc.filas_matriz(_mc(h, PERFIL, cis), {})
        self.assertEqual(junto[:len(solo)], solo)
        self.assertEqual(len(junto), len(solo) + 38)
        self.assertEqual(_mc(h, {}, cis)["cis"], _mc(h, PERFIL, cis)["cis"])

    def test_controles_del_json_estan_en_el_catalogo_del_overlay(self):
        cat = mc.cargar()["controles"]
        for r in mc.tsa()["requisitos"]:
            for c in r["sp800_53"]:
                self.assertIn(c, cat, f"{r['id']}: {c}")
                self.assertTrue(any(cat[c]["niveles"][n]["incluido"] for n in mc.LINEAS_BASE), f"{r['id']}: {c}")

    def test_json_del_marco(self):
        d = mc.tsa()
        self.assertEqual((d["clave"], d["edicion"]), ("tsa-sd-1580-82", "01E"))
        self.assertEqual(d["validacion"], {"estado": "sin revisar"})
        self.assertEqual(d["vigencia"], {"desde": "2026-05-03", "hasta": "2027-05-02"})
        self.assertTrue(all(r["tipo"] in ("tecnico", "documental") for r in d["requisitos"]))

    def test_ingles(self):
        m = _mc([_hall("Hallazgo de ejemplo", "SC-7 (ejemplo)")])
        i18n.usar("en")
        try:
            tsa = _tsa(m)
            nota = mc.seccion(m, {})["nota"]
        finally:
            i18n.usar("es")
        self.assertEqual(tsa[0][1], "organization")
        self.assertEqual(tsa[0][4], "Identify the critical cyber systems")
        self.assertIn("NIST rows", next(x for x in tsa if x[3] == "III.B.2.a")[8])
        self.assertEqual(next(x for x in tsa if x[3] == "III.C.1.a")[8], "Documentary: assessed by interview or documents")
        self.assertIn("not equivalence", nota)
        for x in tsa:
            self.assertNotEqual(x[4], next(r["titulo"] for r in mc.tsa()["requisitos"] if r["id"] == x[3]))


if __name__ == "__main__":
    unittest.main()
