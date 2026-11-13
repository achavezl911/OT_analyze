"""Pruebas de la matriz de cobertura. Sin tshark."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import cobertura as cb
from ot_assess import standards as st


def _base():
    return json.loads((cb.DIR_COBERTURA / "nist-csf.json").read_text(encoding="utf-8"))


class CargaTest(unittest.TestCase):
    def test_carga(self):
        self.assertEqual(len(cb.cargar("nist-csf")["requisitos"]), 106)
        self.assertEqual(len(cb.cargar("iec62443")["requisitos"]), 51)

    def test_patron_invalido(self):
        d = _base()
        d["patron"] = "(GV"
        with self.assertRaises(SystemExit):
            cb.validar(d, "x")

    def test_grupo_inexistente(self):
        d = json.loads((cb.DIR_COBERTURA / "iec62443.json").read_text(encoding="utf-8"))
        d["requisitos"][0]["grupo"] = "FR9"
        with self.assertRaises(SystemExit):
            cb.validar(d, "x")

    def test_id_duplicado(self):
        d = _base()
        d["requisitos"].append(copy.deepcopy(d["requisitos"][0]))
        with self.assertRaises(SystemExit):
            cb.validar(d, "x")

    def test_apoyo_inexistente(self):
        d = _base()
        d["apoyo"]["XX.YY-99"] = "nada"
        with self.assertRaises(SystemExit):
            cb.validar(d, "x")

    def test_clave_desconocida(self):
        d = _base()
        d["extra"] = 1
        with self.assertRaises(SystemExit):
            cb.validar(d, "x")


class ClasificacionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.filas = cb.clasificar(cb.cargar("nist-csf"), st.ESTANDARES["nist-csf"])
        cls.por_id = {f["id"]: f for f in cls.filas}

    def test_clases(self):
        self.assertEqual(self.por_id["PR.IR-01"]["cobertura"], cb.DIRECTA)
        self.assertIn("ip publicas", self.por_id["PR.IR-01"]["fragmentos"])
        self.assertEqual(self.por_id["ID.AM-02"]["cobertura"], cb.APOYO)
        self.assertTrue(self.por_id["ID.AM-02"]["apoyo"])
        self.assertEqual(self.por_id["GV.OC-01"]["cobertura"], cb.NO_EVID)
        self.assertEqual(self.por_id["GV.OC-01"]["apoyo"], cb.TEXTO_NO_EVID)

    def test_cifras_actuales(self):
        r = cb.resumen(self.filas)
        self.assertEqual(sum(s["total"] for s in r.values()), 106)
        self.assertEqual(sum(s[cb.DIRECTA] for s in r.values()), 19)         # ID.RA-04 (A1); PR.PS-04 y DE.AE-03 por la hora del switch (T10c)
        self.assertEqual(sum(s[cb.APOYO] for s in r.values()), 1)
        self.assertEqual(sum(s[cb.NO_EVID] for s in r.values()), 86)

    def test_cifras_iec(self):
        filas = cb.clasificar(cb.cargar("iec62443"), st.ESTANDARES["iec62443"])
        r = cb.resumen(filas)
        self.assertEqual([sum(s[k] for s in r.values()) for k in ("total", cb.DIRECTA, cb.APOYO, cb.NO_EVID)],
                         [51, 19, 0, 32])                     # SR 1.2 y SR 1.5 (SW1b); SR 2.11 por la hora (T10c); SR 7.2 (L1); SR 6.1 (FWLOG)
        directas = {f["id"] for f in filas if f["cobertura"] == cb.DIRECTA}
        self.assertEqual(directas, {"SR 1.1", "SR 1.2", "SR 1.5", "SR 1.13", "SR 2.1", "SR 2.11", "SR 2.8", "SR 3.1", "SR 4.1", "SR 4.3", "SR 5.1", "SR 5.2",
                                    "SR 6.1", "SR 6.2", "SR 7.1", "SR 7.2", "SR 7.6", "SR 7.7", "SR 7.8"})
        f = {f["id"]: f for f in filas}["SR 5.2"]
        self.assertEqual((f["grupo"], f["categoria"]), ("FR5", "Flujo de datos restringido (RDF)"))
        self.assertEqual(self.por_id["PR.IR-01"]["grupo"], "PR")

    def test_integridad_de_ids_del_marco(self):
        """Una errata en un mapeo (id que no existe en el marco) falla aqui."""
        for clave in ("nist-csf", "iec62443"):
            cob = cb.cargar(clave)
            existentes = {r["id"] for r in cob["requisitos"]}
            for frag, txt in st.ESTANDARES[clave].refs.items():
                citados = cb.ids_citados(txt, cob)
                self.assertLessEqual(citados, existentes, f"{clave}: {frag}")

    def test_errata_se_detecta(self):
        cob = cb.cargar("iec62443")
        self.assertEqual(cb.ids_citados("SR 9.9 (x); IEC 62443-2-3 (parches)", cob), {"SR 9.9"})

    def test_conteo_por_corrida_agrupa_como_el_reporte(self):
        cob = cb.cargar("nist-csf")
        refs = {"nist-csf": "PR.IR-01 (x); ID.AM-03 (y)"}
        f = [{"titulo": "A", "severidad": "Alta", "referencias": refs},
             {"titulo": "A", "severidad": "Alta", "referencias": refs},     # otra captura: mismo grupo
             {"titulo": "B", "severidad": "Baja", "referencias": {}}]
        self.assertEqual(cb.hallazgos_por_id(f, "nist-csf", cob), {"PR.IR-01": 1, "ID.AM-03": 1})


if __name__ == "__main__":
    unittest.main()
