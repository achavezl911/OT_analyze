"""SPE1 (D104): elementos del programa de ISA/IEC 62443-2-1:2024 y su linea base por requisito."""
from __future__ import annotations

import collections
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_linea_base import ZONAS, _hallazgo, _lb

from ot_assess import i18n
from ot_assess import linea_base as lb
from ot_assess import niveles62443 as nv
from ot_assess import spe62443 as sp

C = {c: i for i, c in enumerate(lb.COL_21)}


def _fila(r, ident):
    return next(f for f in lb.filas_2_1(r) if f[C["id"]] == ident)


def _n(f, col):
    return f[C[col]]


class CatalogoTest(unittest.TestCase):
    def test_conteos_ids_y_pertenencia(self):
        el = sp.cargar()["elementos"]
        self.assertEqual(collections.Counter(e["tipo"] for e in el), {"SPE": 8, "sub-SPE": 16, "requisito": 87})
        ids = [e["id"] for e in el]
        self.assertEqual(len(set(ids)), 111)
        self.assertTrue(all(e["pertenece_a"] in ids for e in el if e["pertenece_a"]))
        self.assertTrue(all(e["titulo"]["es"] and e["titulo"]["en"] for e in el))
        self.assertTrue(all("nivel_madurez" not in e for e in el))
        req = [e for e in el if e["tipo"] == "requisito"]
        self.assertEqual({e["evidencia_propuesta"] for e in req}, {"red", "configuracion", "documental"})
        self.assertIn("aviso", sp.cargar()["catalogo"])

    def test_refs_se_guardan_tal_como_se_publicaron(self):
        por_id = {e["id"]: e for e in sp.cargar()["elementos"]}
        self.assertIn("SR 1.02 BR", por_id["USER 1.19"]["refs"])
        self.assertIn("SR 2.03 RE(1)", por_id["USER 1.19"]["refs"])
        self.assertTrue({"SR 7.3", "SR 7.3 BR"} <= set(por_id["AVAIL 2.1"]["refs"]))
        self.assertEqual(por_id["ORG 1.1"]["refs"], [])
        self.assertEqual(por_id["USER 1.7"]["refs"], [])

    def test_titulos_de_casos_conocidos(self):
        por_id = {e["id"]: e for e in sp.cargar()["elementos"]}
        self.assertEqual(por_id["NET 1"]["titulo"]["en"], "Separation and control between zones")
        self.assertEqual(por_id["USER 1.7"]["titulo"]["es"], "Impedir que cuentas de servicios abran sesiones interactivas")

    def test_jerarquia_en_orden(self):
        j = [e["id"] for e in sp.jerarquia()]
        self.assertEqual(len(j), 111)
        self.assertEqual(j[:6], ["SPE 1", "ORG 1", "ORG 1.1", "ORG 1.2", "ORG 1.3", "ORG 1.4"])
        self.assertLess(j.index("ORG 3.1"), j.index("SPE 2"))


class NormalizacionTest(unittest.TestCase):
    def test_formatos(self):
        n = sp.normalizar
        self.assertEqual(n("SR 1.02"), ("SR", "SR 1.2"))
        self.assertEqual(n("SR 5.1 BR"), ("SR", "SR 5.1"))
        self.assertEqual(n("SR 5.1"), ("SR", "SR 5.1"))
        self.assertEqual(n("SR 5.1 RE(2)"), ("SR", "SR 5.1 RE 2"))
        self.assertEqual(n("CR 2.03 RE(1)"), ("CR", "CR 2.3 RE 1"))
        self.assertEqual(n("SP.03.02 RE(1)"), ("SP", "SP.03.02 RE(1)"))
        self.assertIsNone(n("XX 1.1"))

    def test_toda_ref_sr_y_cr_existe_en_el_catalogo(self):
        cat = nv.cargar()
        sr_ids = set(cat["sr"]) | set(cat["re_sr"])
        cr_ids = set(cat["componente"]) | set(cat["re_componente"])
        vistos = {"SR": set(), "CR": set()}
        for e in sp.cargar()["elementos"]:
            for ref in e.get("refs", ()):
                n = sp.normalizar(ref)
                self.assertIsNotNone(n, ref)
                if n[0] != "SP":
                    vistos[n[0]].add(n[1])
        self.assertLessEqual(vistos["SR"], sr_ids)
        self.assertLessEqual(vistos["CR"], cr_ids)

    def test_sr_sin_requisito_de_la_2_1(self):
        usados = {x for e in sp.cargar()["elementos"] if e["tipo"] == "requisito" for x in sp.sr(e)}
        sin = {s for s in nv.cargar()["sr"] if s not in usados and not any(u.startswith(s + " ") for u in usados)}
        self.assertEqual(sin, {"SR 1.8", "SR 1.9", "SR 1.10", "SR 1.12", "SR 3.5", "SR 3.7"})

    def test_ceros_y_calificadores(self):
        por_id = {e["id"]: e for e in sp.cargar()["elementos"]}
        u = sp.sr(por_id["USER 1.19"])
        self.assertIn("SR 1.2", u)
        self.assertIn("SR 2.3 RE 1", u)
        self.assertNotIn("SR 1.02", u)
        self.assertEqual(sp.sr(por_id["AVAIL 2.1"]), ["SR 7.3", "SR 7.3 RE 1", "SR 7.3 RE 2"])
        self.assertEqual(sp.sr(por_id["ORG 1.1"]), [])

    def test_sp_tal_cual_y_sin_cruzar(self):
        por_id = {e["id"]: e for e in sp.cargar()["elementos"]}
        self.assertEqual(sp.sp(por_id["ORG 1.2"]), ["SP.01.04 BR", "SP.01.04 RE(1)"])
        todas = {x for e in sp.cargar()["elementos"] if e["tipo"] == "requisito" for x in sp.sp(e)}
        self.assertEqual(len(todas), 114)


class LineaBase21Test(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")

    def test_tabla_solo_con_linea_base(self):
        self.assertEqual(lb.tablas({}), [])
        r = _lb()
        self.assertEqual([t[0] for t in lb.tablas(r)], ["linea_base_especifica.csv", "linea_base_conductos.csv",
                                                       "linea_base_general.csv", "linea_base_2_1.csv"])
        filas = lb.filas_2_1(r)
        self.assertEqual(len(filas), 111)
        self.assertTrue(all(len(f) == len(lb.COL_21) for f in filas))

    def test_brecha_en_sr_5_1(self):
        r = _lb(findings=[_hallazgo("Segmentacion ausente", "SR 5.1 Segmentacion", ["192.0.2.5"])])
        net11 = _fila(r, "NET 1.1")
        self.assertGreaterEqual(_n(net11, "con_brecha"), 1)
        self.assertIn("SR 5.1", _n(net11, "sr_con_brecha").split("; "))
        self.assertEqual(_n(_fila(r, "NET 1.7"), "con_brecha"), 0)
        self.assertEqual(_n(_fila(r, "NET 1"), "con_brecha"), _n(net11, "con_brecha"))
        self.assertEqual(_n(_fila(r, "SPE 3"), "con_brecha"), _n(net11, "con_brecha"))
        self.assertEqual(_n(_fila(r, "NET 1.2"), "con_brecha"), "")
        self.assertEqual(_n(net11, "sr_referenciados").split("; ")[:2], ["SR 5.1", "SR 5.1 RE 1"])

    def test_varios_requisitos_citan_la_misma_sr_y_cuenta_una_vez(self):
        r = _lb(findings=[_hallazgo("Limite abierto", "SR 5.2 Proteccion de limites", ["192.0.2.5"])])
        net1, spe3 = _fila(r, "NET 1"), _fila(r, "SPE 3")
        ids = _n(net1, "sr_con_brecha").split("; ")
        for ident in ("NET 1.1", "NET 1.6", "NET 2.2"):
            self.assertIn("SR 5.2", _n(_fila(r, ident), "sr_con_brecha").split("; "))
        self.assertEqual(_n(net1, "con_brecha"), len(ids))      # una zona: cada fila una sola vez
        self.assertEqual(_n(spe3, "con_brecha"), len(ids))

    def test_re_solo_cuenta_donde_se_cita(self):
        zonas = [dict(ZONAS[0], sl_t="SL4"), ZONAS[1]]
        r = _lb(zonas=zonas, findings=[_hallazgo("Solo la RE", "SR 5.1 RE 2 Segmentacion", ["192.0.2.5"])])
        self.assertEqual(_n(_fila(r, "NET 1.1"), "sr_con_brecha"), "SR 5.1 RE 2")
        self.assertEqual(_n(_fila(r, "NET 1.1"), "con_brecha"), 1)
        self.assertEqual(_n(_fila(r, "NET 1.8"), "con_brecha"), 0)     # no cita SR 5.1

    def test_notas_documental_y_a_mano(self):
        r = _lb()
        org = _fila(r, "ORG 1.1")
        self.assertEqual(org[C["con_brecha"]:C["sr_con_brecha"] + 1], [""] * 5)
        self.assertEqual(_n(org, "nota"), "Documental: se evalua por entrevista")
        user = _fila(r, "USER 1.7")
        self.assertEqual(_n(user, "nota"), "Sin requisito de 3-3 asociado: esta corrida no lo evalua; revisar a mano")
        self.assertEqual(_n(_fila(r, "NET 1.1"), "nota"), "")
        self.assertEqual(_n(_fila(r, "NET 1"), "nota"), "")

    def test_ingles(self):
        r = _lb()
        i18n.FALTANTES.clear()
        i18n.usar("en")
        filas = lb.filas_2_1(r)
        por_id = {f[1]: f for f in filas}
        self.assertEqual(por_id["NET 1"][C["nombre"]], "Separation and control between zones")
        self.assertEqual(por_id["ORG 1.1"][C["nota"]], "Documentary: assessed by interview")
        self.assertTrue(por_id["USER 1.7"][C["nota"]].startswith("No associated 3-3"))
        self.assertEqual(por_id["NET 1.1"][C["evidencia_propuesta"]], "network")
        tabla = next(t for t in lb.tablas(r) if t[0] == lb.ARCHIVO_21)
        self.assertEqual(i18n.t(tabla[1]), "Baseline 2-1")
        self.assertEqual([i18n.t(c) for c in tabla[2]][3:5], ["name", "proposed_evidence"])
        self.assertIn("linea_base_2_1.csv", lb.seccion(r)["resumen"])
        self.assertEqual(i18n.FALTANTES, set())
        self.assertIn("linea_base_2_1.csv", lb.seccion(r)["nota"])
        self.assertNotIn("pending", lb.seccion(r)["nota"])

    def test_json_de_niveles_ya_no_tiene_pendiente(self):
        self.assertNotIn("pendiente", nv.cargar())
        d = json.loads((RAIZ / "ot_assess" / "marcos" / "iec62443_2_1.json").read_text(encoding="utf-8"))
        self.assertEqual(len(d["elementos"]), 111)


if __name__ == "__main__":
    unittest.main()
