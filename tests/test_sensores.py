"""S1 (D96): plan de ubicacion de sensores. Todo sintetico y sin tshark: cobertura, capturas y conductos falsos."""
from __future__ import annotations

import csv
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import i18n
from ot_assess import sensores as se


def cond(n, categoria="ot"):
    """Conducto sintetico n: 192.0.2.n -> 198.51.100.n por TCP/502."""
    return {"src": f"192.0.2.{n}", "dst": f"198.51.100.{n}", "l4": "tcp", "port": 502, "categoria": categoria}


def cap(ruta, ns):
    flows = {i: {"src": f"192.0.2.{n}", "dst": f"198.51.100.{n}", "l4": "tcp", "dport": 502, "bytes": 10, "pkts": 1}
             for i, n in enumerate(ns)}
    return SimpleNamespace(path=Path(ruta), flows=flows)


def punto(nombre, veredicto="apta", p95=1.5, mx=3.0):
    return {"punto": nombre, "paths": [f"/x/{nombre}.pcap"], "veredicto": veredicto,
            "m": {"industriales": ["Modbus/TCP"], "mbps_p95": p95, "mbps_max": mx}}


def escenario(conjuntos, veredictos=None, categorias=None):
    veredictos = veredictos or {}
    cob = {"puntos": [punto(n, veredictos.get(n, "apta")) for n in conjuntos], "zonas": []}
    caps = [cap(f"/x/{n}.pcap", ns) for n, ns in conjuntos.items()]
    todos = sorted({n for ns in conjuntos.values() for n in ns})
    categorias = categorias or {}
    return cob, caps, [cond(n, categorias.get(n, "ot")) for n in todos]


def por_nombre(rep):
    return {p["punto"]: p for p in rep["puntos"]}


class VorazTest(unittest.TestCase):
    def test_tres_puntos(self):
        rep = se.construir(*escenario({"A": [1, 2, 3], "B": [3, 4], "C": [3]}))
        p = por_nombre(rep)
        self.assertEqual((p["A"]["orden_cobertura"], p["A"]["cobertura_acumulada_pct"]), (1, 75.0))
        self.assertEqual((p["B"]["orden_cobertura"], p["B"]["cobertura_acumulada_pct"]), (2, 100.0))
        self.assertIsNone(p["C"]["orden_cobertura"])
        self.assertEqual(p["C"]["recomendacion"], se.R_REDUNDANTE)
        self.assertEqual([p[x]["conductos_ot_unicos"] for x in "ABC"], [2, 1, 0])
        self.assertEqual(p["A"]["recomendacion"], se.R_CANDIDATO)
        self.assertEqual(rep["resumen"], {"puntos": 3, "elegidos": 2, "conductos_ot": 4, "redundantes": 1,
                                          "brechas": 0})
        self.assertEqual([x["punto"] for x in rep["puntos"]], ["A", "B", "C"])

    def test_empate_por_nombre_y_determinista(self):
        esc = escenario({"B": [1, 2], "A": [1, 2]})
        r1, r2 = se.construir(*esc), se.construir(*esc)
        self.assertEqual(r1, r2)
        p = por_nombre(r1)
        self.assertEqual(p["A"]["orden_cobertura"], 1)
        self.assertEqual(p["B"]["recomendacion"], se.R_REDUNDANTE)

    def test_no_apta_elegido_dice_corregir_y_sus_conductos_cuentan(self):
        rep = se.construir(*escenario({"A": [1, 2, 3], "B": [3]}, veredictos={"A": "no apta"}))
        p = por_nombre(rep)
        self.assertEqual(p["A"]["recomendacion"], se.R_CORREGIR)
        self.assertEqual(p["A"]["orden_cobertura"], 1)
        self.assertEqual(p["A"]["conductos_ot"], 3)
        self.assertEqual(rep["resumen"]["conductos_ot"], 3)

    def test_sin_ot_y_categoria_distinta(self):
        rep = se.construir(*escenario({"A": [1, 2], "B": [5]}, categorias={5: "it"}))
        p = por_nombre(rep)
        self.assertEqual(p["B"]["recomendacion"], se.R_SIN_OT)
        self.assertEqual(p["B"]["conductos_ot"], 0)
        self.assertEqual(p["A"]["conductos_ot"], 2)
        self.assertEqual(rep["resumen"]["conductos_ot"], 2)


class BrechasTest(unittest.TestCase):
    def zona(self, punto_, nombre, estado, activos=1):
        return {"punto": punto_, "tipo": "zona", "nombre": nombre, "redes": "10.1.0.0/24", "activos": activos,
                "paquetes": 1, "estado": estado}

    def rep(self, zonas, switches=None, fuentes=None):
        cob, caps, conds = escenario({"A": [1], "B": [2]})
        cob["zonas"] = zonas
        return se.construir(cob, caps, conds, switches, fuentes)

    def test_zonas(self):
        z = [self.zona("A", "Z1", "sin trafico"), self.zona("B", "Z1", "sin trafico"),
             self.zona("A", "Z2", "sin trafico"), self.zona("B", "Z2", "vista"),
             self.zona("A", "Z3", "solo difusion", 4), self.zona("B", "Z3", "solo difusion", 2),
             {**self.zona("A", "10.9.0.0/24", "sin trafico"), "tipo": "subred inferida"}]
        rep = self.rep(z)
        self.assertEqual([(b["tipo"], b["nombre"], b["recomendacion"]) for b in rep["brechas"]],
                         [("zona", "Z1", se.R_ZONA_SIN), ("zona", "Z3", se.R_ZONA_DIF)])
        self.assertEqual(rep["brechas"][0]["detalle"], "10.1.0.0/24")
        self.assertEqual(rep["brechas"][1]["activos"], 4)
        self.assertEqual(por_nombre(rep)["B"]["zonas_vistas"], "Z2")
        self.assertEqual(rep["resumen"]["brechas"], 2)

    def test_vlan_y_segmento(self):
        sw = {"sin_espejo": [("SW1", 20, "PLANTA", 7)]}
        rep = self.rep([], sw, {"sin_cobertura": ["10.5.0.0/24"]})
        self.assertEqual([(b["tipo"], b["nombre"], b["detalle"], b["activos"]) for b in rep["brechas"]],
                         [("segmento", "10.5.0.0/24", "", None), ("vlan", "VLAN 20", "SW1 PLANTA", 7)])


class SalidasTest(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")

    def test_sin_cobertura_nada_nuevo(self):
        for cob in ({}, {"puntos": []}):
            rep = se.construir(cob, [], [cond(1)])
            self.assertEqual(rep, {})
            self.assertFalse(se.hay(rep))
            self.assertEqual(se.tablas(rep), [])
            self.assertEqual(se.para_json(rep), {})

    def csv_bytes(self):
        rep = se.construir(*escenario({"A": [1, 2, 3], "B": [3, 4], "C": [3]}))
        salida = []
        for _a, _h, cab, filas in se.tablas(rep):
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow(cab)
            w.writerows(filas)
            salida.append(buf.getvalue())
        return salida

    def test_csv_identicos(self):
        self.assertEqual(self.csv_bytes(), self.csv_bytes())
        self.assertEqual(self.csv_bytes()[0].splitlines()[1].split(",")[9:11], ["1", "75.0"])

    def test_idioma_en(self):
        rep = se.construir(*escenario({"A": [1, 2, 3], "C": [3]}))
        self.assertEqual(se.seccion(rep)["titulo"], "Ubicacion de sensores")
        i18n.usar("en")
        s = se.seccion(rep)
        self.assertEqual(s["titulo"], "Sensor placement")
        self.assertIn("1 of 2 points", s["resumen"])
        filas = se.tablas(rep)[0][3]
        self.assertEqual(filas[0][-1], "candidate for a permanent sensor")
        self.assertEqual(filas[1][-1], "redundant: other points see its OT conduits")
        self.assertEqual(s["tablas"][0][1][0], "point")


if __name__ == "__main__":
    unittest.main()
