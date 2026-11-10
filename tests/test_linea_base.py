"""B7b (D76): linea base ISA/IEC 62443 as-is / to-be. Corridas sinteticas (IP de documentacion, zonas inventadas)."""
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
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_conductos_zcr import _armar, _k
from test_firewalls_integracion import _contraste
from test_firewalls_topologia import _cadena
from test_zonas import _activo, _inventario_xdome

from ot_assess import conductos_zcr as zc
from ot_assess import i18n
from ot_assess import linea_base as lb
from ot_assess import zonas as zo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.firewalls import integracion as fi
from ot_assess.switches.higiene import TIT_HORA

ZONAS: ClassVar[list] = [{"nombre": "A", "redes": ["192.0.2.0/24"], "sl_t": "SL2"},
                         {"nombre": "B", "redes": ["198.51.100.0/24"]}]
IPS: ClassVar[dict] = {"a1": ("192.0.2.5", ""), "b1": ("198.51.100.5", "")}


def _hallazgo(titulo, refs, activos=None, sev="Media"):
    h = {"titulo": titulo, "severidad": sev, "referencias": {"iec62443": refs}}
    if activos:
        h["activos"] = activos
    return h


def _lb(zonas=ZONAS, ips=IPS, cond=(), firewall=None, switches=None, findings=(), perfil=None, asset_extra=None):
    assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
    for n, extra in (asset_extra or {}).items():
        assets[n].update(extra)
    zon = zo.asignar(assets, {"zonas": zonas}, None, firewall, None)
    zcr = zc.construir(assets, list(cond), zon, firewall)
    return lb.construir(assets, zon, zcr, firewall or {}, switches or {}, list(findings), perfil)


def _zona(r, nombre):
    return next(z for z in r["zonas"] if z["zona"] == nombre)


def _est(z, req):
    return next(f["estado"] for f in z["filas"] if f["requisito"] == req)


class ZonaTest(unittest.TestCase):
    def test_hallazgo_en_activo_de_a_da_brecha_en_sr_y_re_y_cota_cero(self):
        h = _hallazgo("Texto claro de ejemplo", "SR 1.1 Identificacion y autenticacion de usuarios humanos",
                      ["192.0.2.5"])
        r = _lb(findings=[h])
        a, b = _zona(r, "A"), _zona(r, "B")
        self.assertEqual(a["sl_t"], 2)
        self.assertEqual(_est(a, "SR 1.1"), lb.E_BRECHA)
        self.assertEqual(_est(a, "SR 1.1 RE 1"), lb.E_BRECHA)      # la RE hereda la cita de su SR
        self.assertEqual((a["fr"]["FR1"]["cota"], a["fr"]["FR1"]["brecha"]), (0, 2))
        self.assertIn("SR 1.1", a["fr"]["FR1"]["sr_brecha"])
        self.assertNotEqual(_est(b, "SR 1.1"), lb.E_BRECHA)        # el activo esta en A, no en B
        self.assertEqual(b["fr"]["FR1"]["cota"], 4)

    def test_hallazgo_sin_zona_cuenta_en_todas_con_la_nota(self):
        h = _hallazgo("Hallazgo global", "SR 1.1 Identificacion")
        r = _lb(findings=[h])
        self.assertEqual({_est(z, "SR 1.1") for z in r["zonas"]}, {lb.E_BRECHA})
        fila = next(x for x in lb.filas_especifica(r) if x[0] == "B" and x[5] == "SR 1.1")
        self.assertIn("hallazgo sin zona", fila[9])

    def test_re_citada_explicitamente_no_propaga_a_las_demas(self):
        h = _hallazgo("Cita una RE", "SR 1.1 RE 1 Identificacion; SR 1.1 Identificacion", ["192.0.2.5"])
        a = _zona(_lb(findings=[h]), "A")
        self.assertEqual((_est(a, "SR 1.1"), _est(a, "SR 1.1 RE 1")), (lb.E_BRECHA, lb.E_BRECHA))
        h2 = _hallazgo("Cita solo la RE", "SR 1.1 RE 1 Identificacion", ["192.0.2.5"])
        a2 = _zona(_lb(findings=[h2]), "A")
        self.assertEqual(_est(a2, "SR 1.1"), lb.E_SIN)
        self.assertEqual(_est(a2, "SR 1.1 RE 1"), lb.E_BRECHA)

    def test_zona_sin_sl_t_ni_sl_objetivo_es_sl2_propuesto(self):
        b = _zona(_lb(), "B")
        self.assertEqual(b["sl_t"], 2)
        self.assertTrue(b["origen_sl_t"].startswith("propuesto por la herramienta"))
        self.assertIn("ISA-62443-3-2, ZCR 5", b["origen_sl_t"])
        self.assertEqual(_zona(_lb(), "A")["origen_sl_t"], lb.ORIGEN_PERFIL)

    def test_sl_objetivo_del_perfil_manda_sobre_el_defecto(self):
        zon = zo.asignar({"x": _activo("198.51.100.5")}, {"zonas": [{"nombre": "B", "redes": ["198.51.100.0/24"]}],
                                                          "sl_objetivo": {"B": "SL3"}}, None, None, None)
        r = lb.construir({"x": _activo("198.51.100.5", zona_asignada="B")}, zon, {}, {}, {}, [])
        self.assertEqual(_zona(r, "B")["sl_t"], 3)

    def test_no_evaluable_y_sin_evidencia(self):
        a = _zona(_lb(), "A")
        estados = {f["estado"] for f in a["filas"]}
        self.assertIn(lb.E_NOEVAL, estados)
        self.assertIn(lb.E_SIN, estados)
        self.assertNotIn(lb.E_BRECHA, estados)
        fila = next(f for f in a["filas"] if f["estado"] == lb.E_NOEVAL)
        self.assertEqual(fila["cobertura"], "no evidenciable")
        txt = [x for x in lb.filas_especifica(_lb()) if x[8] == lb.E_NOEVAL]
        self.assertTrue(txt)
        self.assertEqual(lb.E_NOEVAL, "no evaluable con datos de red (entrevista o documentos)")

    def test_sl1_sl3_sl4_traen_los_requisitos_del_catalogo(self):
        def ids(sl):
            z = [{"nombre": "A", "redes": ["192.0.2.0/24"], "sl_t": sl}]
            return {f["requisito"] for f in _zona(_lb(zonas=z), "A")["filas"]}
        s1, s3, s4 = ids("SL1"), ids("SL3"), ids("SL4")
        self.assertNotIn("SR 2.11", s1)                  # se exige desde SL2
        self.assertIn("SR 1.1", s1)
        self.assertNotIn("SR 1.1 RE 1", s1)
        self.assertIn("SR 1.1 RE 2", s3)
        self.assertNotIn("SR 1.1 RE 3", s3)              # esta RE es de SL4
        self.assertIn("SR 1.1 RE 3", s4)
        self.assertTrue(s1 < s3 < s4)

    def test_cota_es_un_techo_con_sin_evidencia_al_lado(self):
        z = _zona(_lb(), "A")["fr"]["FR2"]
        self.assertEqual((z["cota"], z["brecha"]), (4, 0))
        self.assertGreater(z["sin_evidencia"] + z["no_evaluable"], 0)


class ControlesTest(unittest.TestCase):
    REGLA = ("access-list CSM_FW_ACL_ line 1 extended permit tcp 192.0.2.0 255.255.255.0 any eq 80 rule-id 7\n")
    ZON: ClassVar[list] = [{"nombre": "Dentro", "redes": ["10.10.1.0/24"]},
                           {"nombre": "Fuera", "redes": ["10.10.9.0/24"]}]
    IP: ClassVar[dict] = {"a": ("10.10.1.5", ""), "b": ("10.10.9.5", "")}
    COND: ClassVar[list] = [_k("10.10.1.5", "10.10.9.5", 4840)]      # 80 marcaria servicios de riesgo

    def _con(self, reglas):
        d = _contraste(reglas, self.COND)
        r = _lb(zonas=self.ZON, ips=self.IP, cond=self.COND, firewall=d)
        return next(f for f in r["conductos"][0]["filas"] if f["requisito"] == "SR 5.1"), r

    def test_conducto_con_regla_especifica_es_control_observado(self):
        fila, r = self._con("access-list CSM_FW_ACL_ line 1 extended permit tcp 10.10.1.0 255.255.255.0 any "
                            "eq 4840 rule-id 7\n")
        self.assertEqual(fila["estado"], lb.E_CONTROL)
        sr52 = next(f for f in r["conductos"][0]["filas"] if f["requisito"] == "SR 5.2")
        self.assertEqual(sr52["estado"], lb.E_CONTROL)
        re1 = next(f for f in r["conductos"][0]["filas"] if f["requisito"] == "SR 5.1 RE 1")
        self.assertEqual(re1["estado"], lb.E_SIN)           # solo SR 5.1 y 5.2 tienen regla de control

    def test_regla_any_any_no_es_control(self):
        fila, _r = self._con("access-list CSM_FW_ACL_ line 1 extended permit ip any any rule-id 7\n"
                             "access-list CSM_FW_ACL_ line 2 extended deny ip any any rule-id 8\n")
        self.assertNotEqual(fila["estado"], lb.E_CONTROL)

    def test_confia_sin_inspeccion_no_es_control(self):
        fila, _r = self._con("access-list CSM_FW_ACL_ advanced trust tcp ifc inside any ifc dmz any eq 4840 "
                             "rule-id 7\naccess-list CSM_FW_ACL_ advanced deny ip any any rule-id 8\n")
        self.assertNotEqual(fila["estado"], lb.E_CONTROL)

    def test_sin_firewall_observado_es_brecha_en_sr_51_y_52(self):
        zonas = [{"nombre": "A", "redes": ["10.30.1.0/24"]}, {"nombre": "B", "redes": ["10.30.2.0/24"]},
                 {"nombre": "Corp", "redes": ["10.10.0.0/16"]}]
        ips = {"a": ("10.30.1.5", "Nivel 1"), "b": ("10.30.2.5", "Nivel 4"), "c": ("10.10.1.5", "Nivel 4")}
        cond = [_k("10.30.1.5", "10.30.2.5", 4840), _k("10.30.1.5", "10.10.1.5", 4840)]
        assets = {n: _activo(ip, purdue=p) for n, (ip, p) in ips.items()}
        _rutas, fw = fi.integrar_modelos(_cadena(), ["it.txt", "dmz.txt", "scada.txt"], assets, cond)
        zon = zo.asignar(assets, {"zonas": zonas}, None, fw)
        zcr = zc.construir(assets, cond, zon, fw)
        r = lb.construir(assets, zon, zcr, fw, {}, [], None)
        por = {(c["zona_a"], c["zona_b"]): c for c in r["conductos"]}
        ab = por[("A", "B")]
        est = {f["requisito"]: f for f in ab["filas"]}
        self.assertEqual((est["SR 5.1"]["estado"], est["SR 5.2"]["estado"]), (lb.E_BRECHA, lb.E_BRECHA))
        self.assertIn(zc.TIT_SIN_FW, [h[0] for h in est["SR 5.1"]["hallazgos"]])
        self.assertEqual(ab["sl_t"], 2)
        corp = {f["requisito"]: f for f in por[("A", "Corp")]["filas"]}["SR 5.1"]
        self.assertNotIn(zc.TIT_SIN_FW, [h[0] for h in corp["hallazgos"]])     # este si cruza firewalls
        fila = next(x for x in lb.filas_conductos(r) if x[0] == ab["conducto"] and x[5] == "SR 5.1")
        self.assertIn("sin firewall observado", fila[9])
        self.assertNotRegex(fila[9], r"\d+\.\d+\.\d+\.\d+")        # el resumen no lleva IP

    def test_conducto_toma_el_sl_t_mayor_de_sus_zonas(self):
        zonas = [{"nombre": "A", "redes": ["192.0.2.0/24"], "sl_t": "SL1"},
                 {"nombre": "B", "redes": ["198.51.100.0/24"], "sl_t": "SL3"}]
        r = _lb(zonas=zonas, cond=[_k("192.0.2.5", "198.51.100.5", 502)])
        self.assertEqual(r["conductos"][0]["sl_t"], 3)

    def test_switch_analizado_sin_hallazgo_de_hora_es_control_en_sr_211(self):
        extra = {"a1": {"switch_puerto": "SW1:Gi0/1", "vlan": "10"}}
        sw = {"switches": [object()]}
        r = _lb(switches=sw, asset_extra=extra)
        self.assertEqual(_est(_zona(r, "A"), "SR 2.11"), lb.E_CONTROL)
        self.assertNotEqual(_est(_zona(r, "B"), "SR 2.11"), lb.E_CONTROL)     # B no tiene switch analizado
        h = _hallazgo(TIT_HORA, "SR 2.11 Marcas de tiempo; SR 2.8 Eventos auditables")
        r2 = _lb(switches=sw, asset_extra=extra, findings=[h])
        self.assertEqual(_est(_zona(r2, "A"), "SR 2.11"), lb.E_BRECHA)


class GeneralTest(unittest.TestCase):
    def test_siete_fr_madurez_y_catorce_preguntas(self):
        r = _lb()
        filas = lb.filas_general(r)
        frs = [f for f in filas if f[0] == "FR"]
        self.assertEqual([f[1] for f in frs], [f"FR{i}" for i in range(1, 8)])
        self.assertEqual(sum(len(g["preguntas"]) for g in r["general"]["fr"]), 14)
        self.assertEqual(sum(len(f[14].split(" | ")) for f in frs), 14)
        ml = [f for f in filas if f[0] == "madurez"]
        self.assertEqual([f[1] for f in ml], ["ML 1", "ML 2", "ML 3", "ML 4"])
        obj = [f for f in ml if f[11]]
        self.assertEqual((obj[0][1], obj[0][11]), ("ML 2", "ML 2"))
        self.assertTrue(obj[0][12].startswith("propuesto"))
        self.assertTrue(all(f[13].startswith("por evaluar con entrevista") for f in ml))
        self.assertIn("62443-2-1:2024", obj[0][15])

    def test_ml_objetivo_del_perfil(self):
        r = _lb(perfil={"ml_objetivo": "ML3"})
        self.assertEqual(r["general"]["madurez"]["objetivo"], "ML 3")
        self.assertEqual(r["general"]["madurez"]["origen"], lb.ORIGEN_ML_PERFIL)

    def test_perfil_valida_ml_objetivo(self):
        from ot_assess import perfil as pf
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)

        def cargar(ml):
            p = tmp / "p.json"
            p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                     "ml_objetivo": ml}), encoding="utf-8")
            return pf.cargar(p)
        self.assertEqual(cargar("ML4")["ml_objetivo"], "ML4")
        with self.assertRaises(SystemExit):
            cargar("ML5")

    def test_resumen_por_fr(self):
        h = _hallazgo("Texto claro de ejemplo", "SR 1.1 Identificacion", ["192.0.2.5"])
        g = {x["fr"]: x for x in _lb(findings=[h])["general"]["fr"]}
        self.assertEqual((g["FR1"]["sl_t_max"], g["FR1"]["sl_t_min"], g["FR1"]["cota_min"]), (2, 2, 0))
        self.assertIn("SR 1.1", g["FR1"]["sr_brecha"])
        self.assertEqual(g["FR2"]["cota_min"], 4)

    def test_sin_zonas_no_se_genera(self):
        self.assertEqual(lb.construir({}, {}, {}, {}, {}, []), {})
        self.assertFalse(lb.hay({}))


class SalidasTest(unittest.TestCase):
    def tearDown(self):
        i18n.usar("es")

    def _todo(self):
        h = _hallazgo("Texto claro de ejemplo", "SR 1.1 Identificacion", ["192.0.2.5"])
        r = _lb(cond=[_k("192.0.2.5", "198.51.100.5", 502)], findings=[h])
        txt = [str(c) for _a, hoja, cab, filas in lb.tablas(r) for c in [hoja, *cab, *[x for f in filas for x in f]]]
        s = lb.seccion(r)
        txt += [s["titulo"], s["nota"], s["resumen"], s["nota_cota"]]
        txt += [str(c) for tabla in (s["pivote"], s["top"]) for fila in [tabla[0], *tabla[1]] for c in fila]
        return "\n".join(txt).lower()

    def test_nunca_cumple_ni_no_cumple(self):
        for idioma, prohibido in (("es", "cumple"), ("en", "compliant")):
            i18n.usar(idioma)
            self.assertNotIn(prohibido, self._todo(), idioma)

    def test_ingles_no_deja_claves_sin_traducir(self):
        i18n.FALTANTES.clear()
        i18n.usar("en")
        self._todo()
        self.assertEqual(i18n.FALTANTES - {"Texto claro de ejemplo"}, set())
        i18n.FALTANTES.clear()

    def test_seccion_tiene_pivote_top_10_y_fuentes(self):
        h = [_hallazgo(f"Hallazgo {i}", f"SR 1.{i} x", ["192.0.2.5"]) for i in range(1, 14)]
        r = _lb(findings=h)
        s = lb.seccion(r)
        self.assertEqual(len(s["pivote"][1]), 2)
        self.assertEqual(len(s["pivote"][0]), 2 + 7)
        self.assertEqual(len(s["top"][1]), 10)
        for ed in ("3-3:2013", "4-2:2018", "3-2:2020", "TR 2-2:2025"):
            self.assertIn(ed, s["nota"])

    def test_prioridad_brecha_antes_que_sin_evidencia(self):
        h = _hallazgo("Texto claro de ejemplo", "SR 7.7 Funcionalidad minima", ["192.0.2.5"])
        filas = lb.filas_especifica(_lb(findings=[h]))
        a = [f for f in filas if f[0] == "A"]
        self.assertEqual(a[0][8], lb.E_BRECHA)
        self.assertEqual([f[-1] for f in a], sorted(f[-1] for f in a))


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        com = gen_exports.xd_escribir_comunicaciones(cls.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI",
                                tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "N/A")])
        inv = _inventario_xdome(cls.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                      ("PLC-1", "10.10.2.20", "Campo"),
                                                      ("SRV-1", "10.10.3.30", "Campo")])
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.rc = main_diagrama(["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome",
                                    "-o", str(cls.out)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_archivos_json_y_secciones(self):
        self.assertEqual(self.rc, 0)
        for n, cab in (("linea_base_especifica.csv", lb.COL_ESP), ("linea_base_conductos.csv", lb.COL_CON),
                       ("linea_base_general.csv", lb.COL_GEN)):
            with open(self.out / n, encoding="utf-8-sig") as fh:
                filas = list(csv.reader(fh))
            self.assertEqual(filas[0], cab)
            self.assertGreater(len(filas), 1)
        for n in ("reporte_ot.html", "reporte_ot.md"):
            self.assertIn("Linea base ISA/IEC 62443 (as-is / to-be)", (self.out / n).read_text(encoding="utf-8"))
        self.assertTrue((self.out / "informe_ot.docx").exists())
        self.assertTrue((self.out / "reporte_ot.xlsx").exists())

    def test_resultado_json_trae_linea_base(self):
        d = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertIn("linea_base", d)
        self.assertTrue(d["linea_base"]["zonas"])


if __name__ == "__main__":
    unittest.main()
