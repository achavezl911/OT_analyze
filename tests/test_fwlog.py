"""FWLOG (D137): registro de eventos en firewalls y switches (reglas sin registro, switches sin syslog). Sintetico."""
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

import gen_exports
from test_aruba_cx import cmd, sesion
from test_rm1 import _error, _perfil
from test_zonas import _inventario_xdome

from ot_assess import i18n
from ot_assess import registro_red as rr
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.firewalls import cisco, fortigate
from ot_assess.firewalls import integracion as fi
from ot_assess.model import Capture
from ot_assess.switches import aruba_cx as ax
from ot_assess.switches import cisco_ios as ci

FTD = """FW1# show running-config
access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq https rule-id 1 event-log flow-end
access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq ssh rule-id 2
access-list CSM_FW_ACL_ advanced permit udp ifc inside any ifc outside any eq domain rule-id 3
access-list CSM_FW_ACL_ remark rule-id 4: L7 RULE: Limpieza
access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq www rule-id 4
access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq 8080 rule-id 5 inactive
access-list CSM_FW_ACL_ advanced permit ip any any rule-id 6
"""

FORTI = """config system global
    set hostname "FGT-1"
end
config firewall policy
    edit 1
        set name "p-sin"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic disable
    next
    edit 2
        set name "p-con"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
        set logtraffic all
    next
end
"""

IOS = """sw-a#show running-config
hostname sw-a
logging buffered 8192
logging host 10.9.9.9 transport udp port 514
logging 10.9.9.8
logging host syslog.planta.local
logging trap warnings
logging source-interface Vlan20
logging host 10.9.9.7 transport tcp port 6514 key 7 SECRETOPRUEBA1
end
"""
IOS_SIN = "sw-b#show running-config\nhostname sw-b\nlogging buffered 8192\nlogging console\nend\n"
AOS_CFG = """hostname sw-aoscx01
logging 10.5.5.5 vrf mgmt severity warning
logging 10.5.5.6 severity debug
logging facility local0
"""


def _fw(texto, forti=False):
    fw = fortigate.analizar_texto(texto)[0] if forti else cisco.analizar_texto(texto)
    return fi.contrastar(fw, [], "fw.txt", [])


def _sws(*textos):
    return {"switches": list(textos)}


def _ios(texto):
    return ci.leer(texto, "sw.txt")


def _perfil_rr(**cfg):
    return {"registro_red": {"colectores": [], "excluir_reglas": [], **cfg}}


class PerfilTest(unittest.TestCase):
    def test_validos(self):
        self.assertEqual(_perfil({"registro_red": {}})["registro_red"], {"colectores": [], "excluir_reglas": []})
        p = _perfil({"registro_red": {"colectores": ["10.0.0.5", "10.1.0.0/24", "10.0.0.5"],
                                      "excluir_reglas": [" limpieza ", "7"]}})["registro_red"]
        self.assertEqual(p, {"colectores": ["10.0.0.5", "10.1.0.0/24"], "excluir_reglas": ["limpieza", "7"]})

    def test_errores(self):
        casos = [
            ("lista", "debe ser un objeto"), ({"colectores": "10.0.0.5"}, "colectores"),
            ({"colectores": ["no-es-ip"]}, "no es una IP"), ({"colectores": ["10.0.0.0/33"]}, "no es una IP"),
            ({"colectores": [5]}, "colectores"), ({"colectores": [""]}, "colectores"),
            ({"colectores": [f"10.0.{i // 250}.{i % 250}" for i in range(51)]}, "0 a 50"),
            ({"excluir_reglas": "x"}, "excluir_reglas"), ({"excluir_reglas": [""]}, "1 a 100"),
            ({"excluir_reglas": ["  "]}, "1 a 100"), ({"excluir_reglas": ["x" * 101]}, "1 a 100"),
            ({"excluir_reglas": [3]}, "1 a 100"), ({"excluir_reglas": [str(i) for i in range(501)]}, "0 a 500"),
            ({"otra": 1}, "desconocida")]
        for v, frag in casos:
            self.assertIn(frag, _error({"registro_red": v}), v)


class SwitchesTest(unittest.TestCase):
    def test_ios_las_dos_formas_nivel_y_sin_secretos(self):
        sw = _ios(IOS)
        self.assertEqual(sw.syslog_destinos, ["10.9.9.9", "10.9.9.8", "syslog.planta.local", "10.9.9.7"])
        self.assertEqual(sw.syslog_nivel, "warnings")
        self.assertNotIn("SECRETOPRUEBA1", repr(sw.__dict__))

    def test_ios_sin_syslog(self):
        sw = _ios(IOS_SIN)
        self.assertEqual((sw.syslog_destinos, sw.syslog_nivel), ([], ""))

    def test_ios_quitar_destino(self):
        sw = _ios("sw-c#show running-config\nhostname sw-c\nlogging host 10.9.9.9\nno logging host 10.9.9.9\nend\n")
        self.assertEqual(sw.syslog_destinos, [])

    def test_aoscx_destinos_y_severidad(self):
        sw = ax.leer(sesion(cfg=False, extra=cmd("show running-config", AOS_CFG)), "s.txt")
        self.assertTrue(sw.config)
        self.assertEqual(sw.syslog_destinos, ["10.5.5.5", "10.5.5.6"])
        self.assertEqual(sw.syslog_nivel, "warning; debug")


class ConstruirTest(unittest.TestCase):
    def test_sin_la_clave_nada(self):
        self.assertEqual(rr.construir(_fw(FTD), _sws(_ios(IOS)), {}), {})
        self.assertEqual(rr.construir(_fw(FTD), _sws(_ios(IOS)), None), {})

    def test_sin_equipos_avisa(self):
        r = rr.construir({}, {}, _perfil_rr())
        self.assertFalse(rr.hay(r))
        self.assertIn("registro_red", rr.aviso(r))
        self.assertEqual(rr.aviso({}), "")
        self.assertEqual(rr.tablas(r), [])
        cap = Capture(Path("x"))
        rr.agregar_hallazgos(cap, r)
        self.assertEqual(cap.findings, [])

    def fila(self, r, equipo):
        return next(f for f in r["filas"] if f["equipo"] == equipo)

    def test_ftd_permite_con_y_sin_registro_defecto_inactiva(self):
        f = self.fila(rr.construir(_fw(FTD), {}, _perfil_rr()), "FW1")
        self.assertEqual(f["tipo"], "firewall")
        # 1 con registro, 2, 3 y 4 sin registro; 5 inactiva y 6 de defecto no cuentan
        self.assertEqual((f["permiten"], [r["id"] for r in f["sin"]]), (4, ["2", "3", "4"]))

    def test_excluida_por_id_y_por_nombre(self):
        f = self.fila(rr.construir(_fw(FTD), {}, _perfil_rr(excluir_reglas=["3", "Limpieza"])), "FW1")
        self.assertEqual((f["permiten"], [r["id"] for r in f["sin"]]), (2, ["2"]))

    def test_fortigate(self):
        r = rr.construir(_fw(FORTI, True), {}, _perfil_rr())
        f = r["filas"][0]
        self.assertEqual((f["equipo"], f["plataforma"], f["permiten"], [x["id"] for x in f["sin"]]),
                         ("FGT-1", "Fortinet FortiGate", 2, ["1"]))

    def test_varios_firewalls(self):
        a, b = _fw(FTD), _fw(FORTI, True)
        fw = {"firewalls": [{"id": "A", "fabricante": a["fabricante"], "datos": a},
                            {"id": "B", "fabricante": b["fabricante"], "datos": b}], "reglas": []}
        r = rr.construir(fw, {}, _perfil_rr(excluir_reglas=["A:2"]))
        self.assertEqual([(f["equipo"], len(f["sin"])) for f in r["filas"]], [("A", 2), ("B", 1)])

    def test_destino_declarado(self):
        sws = _sws(_ios(IOS), _ios(IOS_SIN))
        for cols, esperado in (([], ("sin colectores declarados",) * 2), (["10.9.9.0/24"], ("si", "no")),
                               (["192.0.2.1"], ("no", "no"))):
            r = rr.construir({}, sws, _perfil_rr(colectores=cols))
            self.assertEqual(tuple(f["declarado"] for f in r["filas"]), esperado, cols)

    def test_switch_sin_configuracion_queda_sin_dato(self):
        sw = ci.leer("sw-d#show mac address-table\n", "x.txt")
        self.assertFalse(sw.config)
        r = rr.construir({}, _sws(sw), _perfil_rr(colectores=["10.9.9.9"]))
        self.assertEqual(r["filas"][0]["declarado"], "sin dato")
        cap = Capture(Path("x"))
        rr.agregar_hallazgos(cap, r)
        self.assertEqual(cap.findings, [])

    def test_colector_observado(self):
        fl = {"colectores": [{"ip": "10.9.9.8"}]}
        r = rr.construir(_fw(FTD), _sws(_ios(IOS), _ios(IOS_SIN)), _perfil_rr())
        rr.completar(r, {})
        self.assertEqual({f["observado"] for f in r["filas"]}, {"sin dato"})
        rr.completar(r, fl)
        # FW1 y sw-b no tienen IP ni colectores declarados; sw-a tiene el destino 10.9.9.8
        self.assertEqual([f["observado"] for f in r["filas"]], ["sin dato", "si", "sin dato"])
        r = rr.construir(_fw(FTD), _sws(_ios(IOS), _ios(IOS_SIN)), _perfil_rr(colectores=["10.9.9.0/24"]))
        rr.completar(r, fl)
        self.assertEqual([f["observado"] for f in r["filas"]], ["si", "si", "si"])
        r = rr.construir({}, _sws(_ios(IOS)), _perfil_rr(colectores=["192.0.2.0/24"]))
        rr.completar(r, {"colectores": [{"ip": "10.8.8.8"}]})
        self.assertEqual(r["filas"][0]["observado"], "no")


class HallazgosTest(unittest.TestCase):
    def hall(self, r):
        cap = Capture(Path("x"))
        rr.agregar_hallazgos(cap, r)
        return {f["titulo"]: f for f in cap.findings}

    def test_firewall_media_con_evidencia(self):
        h = self.hall(rr.construir(_fw(FTD), {}, _perfil_rr()))
        self.assertEqual(list(h), [rr.TIT_FW])
        f = h[rr.TIT_FW]
        self.assertEqual(f["severidad"], "Media")
        self.assertIn("FW1", f["evidencia"])
        self.assertIn("Limpieza", f["evidencia"])
        self.assertIn("inside -> outside", f["evidencia"])
        self.assertEqual(f["categoria"], "Higiene")
        self.assertTrue(f["referencias"])

    def test_sin_reglas_sin_registro_no_hay_hallazgo(self):
        self.assertEqual(self.hall(rr.construir(_fw(FTD), {}, _perfil_rr(excluir_reglas=["2", "3", "4"]))), {})

    def test_switch_baja_sin_destino_o_sin_colector_declarado(self):
        sws = _sws(_ios(IOS), _ios(IOS_SIN))
        f = self.hall(rr.construir({}, sws, _perfil_rr()))[rr.TIT_SW]
        self.assertEqual(f["severidad"], "Baja")
        self.assertIn("sw-b: sin destino de syslog", f["evidencia"])
        self.assertNotIn("sw-a", f["evidencia"])
        f = self.hall(rr.construir({}, sws, _perfil_rr(colectores=["192.0.2.1"])))[rr.TIT_SW]
        self.assertIn("sw-a: destinos 10.9.9.9;10.9.9.8", f["evidencia"])
        self.assertIn("sw-b", f["evidencia"])
        self.assertEqual(self.hall(rr.construir({}, _sws(_ios(IOS)), _perfil_rr(colectores=["10.9.9.0/24"]))), {})

    def test_la_deteccion_depende_del_registro_de_la_regla(self):
        # si toda regla pasara por registrada, el hallazgo del firewall no aparece (guarda de la prueba)
        d = _fw(FTD)
        for r in d["reglas"]:
            r["registro"] = True
        self.assertEqual(self.hall(rr.construir(d, {}, _perfil_rr())), {})


class SalidasTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.n = 0
        com = gen_exports.xd_escribir_comunicaciones(cls.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC")])
        inv = _inventario_xdome(cls.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                      ("PLC-1", "10.10.2.20", "Campo")])
        (cls.tmp / "fw.txt").write_text(FTD, encoding="utf-8")
        (cls.tmp / "sw.txt").write_text(IOS, encoding="utf-8")
        cls.base = ["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome"]
        cls.zonas = [{"nombre": "Op", "redes": ["10.10.1.0/24"]}, {"nombre": "Campo", "redes": ["10.10.2.0/24"]}]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, equipos=True, **extra) -> Path:
        type(self).n += 1
        p = self.tmp / f"perfil{self.n}.json"
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                 "zonas": self.zonas, **extra}), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        eq = ["--firewall", str(self.tmp / "fw.txt"), "--switch", str(self.tmp / "sw.txt")] if equipos else []
        sal = io.StringIO()
        with contextlib.redirect_stdout(sal), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama([*self.base, *eq, "-o", str(out), "--perfil", str(p)]), 0)
        self.consola = sal.getvalue()
        return out

    def titulos(self, out):
        with open(out / "hallazgos_importados.csv", encoding="utf-8-sig", newline="") as fh:
            return [" ".join(f.values()) for f in csv.DictReader(fh)]

    def test_sin_la_clave_nada_cambia(self):
        o = self.correr()
        self.assertFalse((o / rr.ARCHIVO).exists())
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("registro_red", j)
        self.assertTrue(j["firewall"]["reglas"])
        for r in j["firewall"]["reglas"]:
            self.assertNotIn("registro", r)
            self.assertNotIn("defecto", r)
        self.assertFalse(any(x in t for t in self.titulos(o) for x in (rr.TIT_FW, rr.TIT_SW)))
        for p in o.iterdir():
            if p.suffix in (".html", ".md", ".csv", ".json"):
                self.assertNotIn(rr.TITULO, p.read_text(encoding="utf-8-sig"), p.name)

    def test_con_la_clave_csv_json_secciones_y_hallazgos(self):
        o = self.correr(registro_red={"colectores": ["10.9.9.0/24"]})
        with open(o / rr.ARCHIVO, encoding="utf-8-sig", newline="") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), rr.COLUMNAS)
        por = {f["equipo"]: f for f in filas}
        fw, sw = por["FW1"], por["sw-a"]
        self.assertEqual((fw["tipo"], fw["reglas_que_permiten"], fw["reglas_sin_registro"], fw["ids_sin_registro"]),
                         ("firewall", "4", "3", "2;3;4"))
        self.assertEqual((sw["tipo"], sw["destinos_syslog"], sw["nivel_syslog"], sw["destino_declarado"],
                          sw["reglas_que_permiten"]), ("switch", "10.9.9.9;10.9.9.8;syslog.planta.local;10.9.9.7",
                                                       "warnings", "si", ""))
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["registro_red"]
        self.assertEqual((j["conteos"]["reglas_sin_registro"], j["conteos"]["switches"]), (3, 1))
        self.assertEqual(j["filas"][1]["destinos_syslog"][0], "10.9.9.9")
        tit = self.titulos(o)
        self.assertTrue(any(rr.TIT_FW in x for x in tit))
        self.assertFalse(any(rr.TIT_SW in x for x in tit))       # el switch si envia a un colector declarado
        for nombre in ("reporte_ot.html", "reporte_ot.md"):
            ps = list(o.glob(nombre))
            if ps:
                self.assertIn(rr.TITULO, ps[0].read_text(encoding="utf-8"), nombre)
        self.assertTrue(list(o.glob("*.html")) or list(o.glob("*.md")))

    def test_hoja_y_docx(self):
        o = self.correr(registro_red={})
        for nombre, esperado in (("reporte_ot.xlsx", rr.HOJA), ("informe_ot.docx", rr.TITULO)):
            with zipfile.ZipFile(o / nombre) as z:
                texto = " ".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist() if n.endswith(".xml"))
            self.assertIn(esperado, texto, nombre)

    def test_sin_equipos_avisa(self):
        o = self.correr(equipos=False, registro_red={})
        self.assertIn("registro_red", self.consola)
        self.assertFalse((o / rr.ARCHIVO).exists())

    def test_ingles(self):
        o = self.correr(idioma="en", registro_red={})
        with open(o / rr.ARCHIVO, encoding="utf-8-sig", newline="") as fh:
            filas = list(csv.DictReader(fh))
        self.assertIn("rules_without_logging", filas[0])
        self.assertEqual(filas[1]["declared_destination"], "no collectors declared")
        self.assertTrue(any("Firewall rules that allow traffic without logging" in x for x in self.titulos(o)))


if __name__ == "__main__":
    unittest.main()
