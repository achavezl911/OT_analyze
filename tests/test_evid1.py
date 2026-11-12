"""EVID1 (D122): clases de evidencia del proyecto en el inventario normalizado. Datos sinteticos."""
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

from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import perfil as pf
from ot_assess.cli_diagrama import main as main_diagrama
from tests.test_inventario_normalizado import (
    M_HMI,
    M_PLC,
    _escribir,
    _plataforma,
    _registros_plat,
)


def _perfil(extra=None):
    d = {"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}]}
    d.update(extra or {})
    return d


class _Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def perfil(self, extra):
        p = self.tmp / "p.json"
        p.write_text(json.dumps(_perfil(extra)), encoding="utf-8")
        return pf.cargar(p)

    def falla(self, me):
        with self.assertRaises(SystemExit) as cm:
            self.perfil({"modelo_evidencia": me})
        self.assertIn("modelo_evidencia", str(cm.exception))


class PerfilTest(_Base):
    def test_vacio_y_validos(self):
        self.assertEqual(self.perfil({"modelo_evidencia": {}})["modelo_evidencia"], {})
        p = self.perfil({"modelo_evidencia": {"clases": {"declarado": "DOC", "sin dato": "N/E"},
                                              "por_fuente": {"manual": "DOC", "Plataforma:nozomi": "DOC"}}})
        self.assertEqual(p["modelo_evidencia"]["clases"]["declarado"], "DOC")

    def test_invalidos(self):
        for me in ([], "x", {"otra": 1}, {"clases": []}, {"clases": {"raro": "X"}}, {"clases": {"declarado": ""}},
                   {"clases": {"declarado": "A" * 21}}, {"clases": {"declarado": "A\nB"}},
                   {"clases": {"declarado": 3}}, {"por_fuente": {"nube": "X"}}, {"por_fuente": {"plataforma:": "X"}},
                   {"por_fuente": {"manual": " "}}, {"por_fuente": []}):
            with self.subTest(me=me):
                self.falla(me)


class ModeloTest(_Base):
    def datos(self, perfil):
        imp = _plataforma(self.tmp, [["PLC-1", "192.0.2.10", M_PLC, "Acme", "Modelo-X", "2.0.0", "PLC", "1", ""],
                                     ["HMI-1", "192.0.2.20", M_HMI, "Acme", "", "", "HMI", "2", ""]])
        man, _av = inv.cargar_manual(_escribir(self.tmp / "m.csv", ("Hostname", "IP Address", "Firmware"),
                                               [["PLC-1", "192.0.2.10", "1.0.0"]]))
        return inv.construir(_registros_plat(imp) + man, perfil, True)

    def test_sin_clave_igual_que_antes(self):
        r = self.datos(None)
        self.assertNotIn("modelo", r)
        self.assertNotIn("por_clase", r["resumen"])
        self.assertEqual(inv.columnas(r), list(inv.COLUMNAS))
        self.assertTrue(all(len(f) == len(inv.COLUMNAS) for f in inv.filas_tabla(r)))
        self.assertEqual({len(x) for x in r["procedencia"]}, {6})
        self.assertEqual(inv.tablas(r)[1][2], inv.COL_PROCEDENCIA)
        self.assertFalse(any(f[0] == "clase de evidencia" for f in inv.seccion(r)["tabla"][1]))

    def test_tabla_por_defecto(self):
        r = self.datos(self.perfil({"modelo_evidencia": {}}))
        cols = inv.columnas(r)
        self.assertEqual(len(cols), len(inv.COLUMNAS) + len(inv.CAMPOS))
        for c in inv.CAMPOS:
            self.assertEqual(cols.index(c + "_clase"), cols.index(c + "_estado") + 1)
        plc = next(f for f in r["filas"] if "192.0.2.10" in f["campos"]["ips"]["valor"])
        self.assertEqual(plc["campos"]["firmware"]["clase"], "DISCREPANCIA")     # manual 1.0.0 vs plataforma 2.0.0
        self.assertEqual(plc["campos"]["nombre"]["clase"], "DEC")
        self.assertEqual(plc["campos"]["ips"]["clase"], "DEC")
        hmi = next(f for f in r["filas"] if "192.0.2.20" in f["campos"]["ips"]["valor"])
        self.assertEqual(hmi["campos"]["nombre"]["clase"], "OBS")
        filas = inv.filas_tabla(r)
        self.assertTrue(all(len(f) == len(cols) for f in filas))
        fila = filas[[f["id"] for f in r["filas"]].index(hmi["id"])]
        self.assertEqual(fila[cols.index("firmware_clase")], "N/E")
        self.assertEqual(fila[cols.index("firmware_estado")], "")
        self.assertEqual({len(x) for x in inv.filas_procedencia(r)}, {7})
        self.assertEqual(inv.tablas(r)[1][2][-1], "clase")
        self.assertIn("DISCREPANCIA", {x[6] for x in inv.filas_procedencia(r)})
        pc = r["resumen"]["por_clase"]
        self.assertEqual(sum(pc.values()), len(r["filas"]) * len(inv.CAMPOS))
        self.assertGreaterEqual(pc["DISCREPANCIA"], 1)
        self.assertGreater(pc["N/E"], 0)
        s = inv.seccion(r)
        self.assertIn(["clase de evidencia", "DISCREPANCIA", pc["DISCREPANCIA"]], s["tabla"][1])
        self.assertIn("sin revisar", s["nota"])

    def test_clases_y_por_fuente_del_perfil(self):
        me = {"clases": {"declarado": "DEC2"},
              "por_fuente": {"manual": "DOC", "plataforma:nozomi": "DOC", "plataforma": "OBS"}}
        r = self.datos(self.perfil({"modelo_evidencia": me}))
        plc = next(f for f in r["filas"] if "192.0.2.10" in f["campos"]["ips"]["valor"])
        self.assertEqual(plc["campos"]["nombre"]["clase"], "DOC")             # manual
        hmi = next(f for f in r["filas"] if "192.0.2.20" in f["campos"]["ips"]["valor"])
        self.assertEqual(hmi["campos"]["nombre"]["clase"], "DOC")             # plataforma:nozomi
        m = r["modelo"]
        self.assertEqual(inv.clase_de(m, "importado", "plataforma:otra"), "OBS")
        self.assertEqual(inv.clase_de(m, "importado", "PLATAFORMA:Nozomi"), "DOC")
        self.assertEqual(inv.clase_de(m, "observado", "captura:a.pcap"), "OBS")
        self.assertEqual(inv.clase_de(m, "declarado", "perfil"), "DEC2")
        self.assertEqual(inv.clase_de(m, "en conflicto", "manual"), "DISCREPANCIA")
        self.assertIn("perfil del proyecto", inv.seccion(r)["nota"])

    def test_por_fuente_no_confunde_prefijos_de_tipo(self):
        m = inv.modelo_de({"modelo_evidencia": {"por_fuente": {"plat": "X"}}})
        self.assertEqual(inv.clase_de(m, "importado", "plataforma:n"), "OBS")


class SalidasTest(_Base):
    def correr(self, extra, nombre):
        a = _escribir(self.tmp / "a.csv", ["Name", "IP", "MAC", "Vendor", "Firmware", "Type", "Level"],
                      [["PLC-1", "10.10.2.20", M_PLC, "Acme", "1.0", "PLC", "1"]])
        e = _escribir(self.tmp / "e.csv", ["Source", "Destination", "Port", "Protocol", "Packets"],
                      [["10.10.1.10", "10.10.2.20", "502", "Modbus", "100"]])
        p = self.tmp / (nombre + ".json")
        p.write_text(json.dumps(_perfil(extra)), encoding="utf-8")
        out = self.tmp / nombre
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico", "--perfil", str(p),
                                "-o", str(out)])
        self.assertEqual(rc, 0)
        return out

    def test_csv_y_json_con_y_sin_clave(self):
        sin = self.correr({}, "sin")
        con = self.correr({"modelo_evidencia": {}}, "con")
        def cab(d, n):
            return next(csv.reader((d / n).read_text(encoding="utf-8-sig").splitlines()))
        self.assertEqual(cab(sin, "inventario_normalizado.csv"), inv.COLUMNAS)
        c = cab(con, "inventario_normalizado.csv")
        self.assertEqual(len(c), 16 * 4 + 1 + 3 + len(inv.QA))
        self.assertEqual(cab(sin, "inventario_procedencia.csv"), inv.COL_PROCEDENCIA)
        self.assertEqual(cab(con, "inventario_procedencia.csv")[-1], "clase")
        rs = json.loads((sin / "resultado.json").read_text(encoding="utf-8"))["inventario_normalizado"]
        rc = json.loads((con / "resultado.json").read_text(encoding="utf-8"))["inventario_normalizado"]
        self.assertNotIn("por_clase", rs)
        self.assertIn("por_clase", rc)


if __name__ == "__main__":
    unittest.main()
