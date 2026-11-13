"""RUTA1 (D134): inventario de rutas de acceso a OT (usada, configurada, declarada). Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import datetime
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
from test_rm1 import _error, _perfil
from test_zonas import _inventario_xdome

from ot_assess import i18n
from ot_assess import rutas_acceso as ra
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture

HOY = datetime.date(2026, 11, 12)
ZONAS: ClassVar[list] = [
    {"nombre": "Empresa", "redes": ["10.4.0.0/24"]}, {"nombre": "Control", "redes": ["10.1.0.0/24"]},
    {"nombre": "Supervision", "redes": ["10.2.0.0/24"]}]
IPS: ClassVar[dict] = {
    "it": ("10.4.0.5", "Nivel 4"), "it2": ("10.4.0.6", "Nivel 4"), "plc": ("10.1.0.5", "Nivel 1"),
    "hmi": ("10.2.0.5", "Nivel 2")}


def _ruta(conductos, cfg=None, fw=None, inds=(), hoy=HOY):
    assets, _zon, zcr = _armar(IPS, ZONAS, conductos, fw)
    perfil = {"zonas": ZONAS, "rutas_acceso": {"servicios": [], "declaradas": [], **(cfg or {})}}
    return ra.construir(assets, conductos, zcr, fw, perfil, inds, hoy)


def _fila(r, servicio, origen=None, destino="Control"):
    xs = [f for f in r["filas"] if f["servicio"] == servicio and (origen is None or f["zona_origen"] == origen)
          and f["zona_destino"] == destino]
    assert len(xs) == 1, xs
    return xs[0]


def _decl(**kw):
    return {"id": "A1", "origen": "Empresa", "destino": "Control", "servicio": "tcp/3389", "via": "", "proveedor": "",
            "autorizado_por": "", "vigencia": "", **kw}


class ValidacionTest(unittest.TestCase):
    def malo(self, v, fragmento):
        msg = _error({"rutas_acceso": v})
        self.assertIn(fragmento, msg, msg)

    def decl(self, **kw):
        return {"declaradas": [{"id": "A1", "origen": "Empresa", "destino": "Control", "servicio": "tcp/3389", **kw}]}

    def test_validos(self):
        cfg = _perfil({"rutas_acceso": {}})["rutas_acceso"]
        self.assertEqual((cfg["servicios"], cfg["declaradas"]), ([], []))
        cfg = _perfil({"rutas_acceso": {"servicios": ["tcp/22", "udp/500", "tcp/22"], "declaradas": [
            {"id": "A1", "origen": "10.4.0.0/24", "destino": "Control", "servicio": "*", "via": "VPN",
             "proveedor": "Acme", "autorizado_por": "Jefe", "vigencia": "2027-01-31"}]}})["rutas_acceso"]
        self.assertEqual(cfg["servicios"], ["tcp/22", "udp/500"])
        self.assertEqual(cfg["declaradas"][0]["vigencia"], "2027-01-31")

    def test_invalidos(self):
        self.malo([], "debe ser un objeto")
        self.malo({"otra": 1}, "clave desconocida")
        self.malo({"servicios": []}, "1 a 50")
        self.malo({"servicios": [f"tcp/{i + 1}" for i in range(51)]}, "1 a 50")
        self.malo({"servicios": ["ssh"]}, "no es proto/puerto")
        self.malo({"servicios": ["tcp/0"]}, "no es proto/puerto")
        self.malo({"servicios": ["tcp/70000"]}, "no es proto/puerto")
        self.malo({"servicios": ["icmp/1"]}, "no es proto/puerto")
        self.malo({"declaradas": "x"}, "lista de 0 a 200")
        self.malo({"declaradas": [self.decl()["declaradas"][0]] * 201}, "lista de 0 a 200")
        self.malo({"declaradas": [{"id": "A1", "origen": "x"}]}, "falta 'destino'")
        self.malo({"declaradas": [{"id": "", "origen": "x", "destino": "y", "servicio": "*"}]}, "1 a 30")
        self.malo({"declaradas": [{"id": "x" * 31, "origen": "x", "destino": "y", "servicio": "*"}]}, "1 a 30")
        rep = self.decl()["declaradas"][0]
        self.malo({"declaradas": [rep, dict(rep)]}, "esta repetido")
        self.malo(self.decl(servicio="rdp"), "no es proto/puerto")
        self.malo(self.decl(origen="10.0.0.0/33"), "no es una IP ni una red valida")
        self.malo(self.decl(destino="300.1.1.1"), "no es una IP ni una red valida")
        self.malo(self.decl(vigencia="31/01/2027"), "AAAA-MM-DD")
        self.malo(self.decl(vigencia="2027-02-30"), "fecha valida")
        self.malo(self.decl(via="x" * 201), "hasta 200")
        self.malo(self.decl(proveedor=3), "hasta 200")
        self.malo(self.decl(origen="x" * 201), "1 a 200")
        self.malo(self.decl(otra="x"), "clave desconocida")


class UsadasTest(unittest.TestCase):
    def test_agrupa_por_zonas_y_servicio_e_ignora_lo_que_no_es_acceso(self):
        r = _ruta([_k("10.4.0.5", "10.1.0.5", 3389), _k("10.4.0.6", "10.1.0.5", 3389),
                   _k("10.4.0.5", "10.1.0.5", 502), _k("10.4.0.5", "10.4.0.6", 22),
                   _k("10.4.0.5", "10.2.0.5", 3389, dias=3)])
        self.assertEqual(len(r["filas"]), 2)
        f = _fila(r, "tcp/3389", "Empresa")
        self.assertEqual((f["zona_destino"], f["conductos"]), ("Control", 2))
        self.assertEqual(f["activos_origen"], ["10.4.0.5", "10.4.0.6"])
        self.assertTrue(f["usada"])
        self.assertRegex(f["id"], r"^RA-[0-9a-f]{8}$")
        self.assertEqual({x["zona_destino"] for x in r["filas"]}, {"Control", "Supervision"})
        self.assertEqual(r["filas"][0]["id"], ra.id_ruta(*(r["filas"][0][k] for k in (
            "zona_origen", "zona_destino", "servicio"))))

    def test_lista_del_perfil_reemplaza_a_la_de_defecto(self):
        cond = [_k("10.4.0.5", "10.1.0.5", 502), _k("10.4.0.5", "10.1.0.5", 3389)]
        r = _ruta(cond, {"servicios": ["tcp/502"]})
        self.assertEqual([f["servicio"] for f in r["filas"]], ["tcp/502"])
        r = _ruta([_k("10.4.0.5", "10.1.0.5", 500, "udp")], {"servicios": ["udp/500"]})
        self.assertEqual([f["servicio"] for f in r["filas"]], ["udp/500"])

    def test_desde_internet(self):
        r = _ruta([_k("151.101.1.1", "10.1.0.5", 22)])
        f = r["filas"][0]
        self.assertEqual((f["zona_origen"], f["zona_destino"]), ("Internet", "Control"))

    def test_respuesta_probable_y_respuesta_no_generan_ruta(self):
        cond = [_k("10.1.0.5", "10.4.0.5", 40000, servicio="dns"), _k("10.4.0.5", "10.1.0.5", 3389)]
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido"}, {"resultado": "respuesta"}]}
        r = _ruta(cond, {"servicios": ["tcp/40000", "tcp/3389"]}, fw)
        self.assertEqual(r["filas"], [])
        self.assertEqual(r["respuestas_probables"], 1)

    def test_sentido_invertido_usa_el_sentido_real(self):
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido", "sentido": "invertido"}]}
        r = _ruta([_k("10.1.0.5", "10.4.0.5", 3389)], fw=fw)
        f = r["filas"][0]
        self.assertEqual((f["zona_origen"], f["zona_destino"], f["activos_origen"]), ("Empresa", "Control",
                                                                                      ["10.4.0.5"]))

    def test_herramienta_de_terceros_es_una_ruta(self):
        ind = {"ip": "10.4.0.5", "herramienta": "AnyDesk", "estado": "verificado", "metodo": "DNS",
               "indicador": "relay.anydesk.com", "destino": "Internet", "destino_ip": "5.6.7.8", "conductos": 2}
        r = _ruta([], inds=[ind, {**ind, "estado": "descartado", "herramienta": "Otra"}])
        self.assertEqual(len(r["filas"]), 1)
        f = r["filas"][0]
        self.assertEqual((f["zona_origen"], f["zona_destino"], f["herramienta"], f["conductos"]),
                         ("Empresa", "Internet", ["AnyDesk"], 2))
        self.assertEqual(f["configurada"], ra.CFG_SIN_FW)
        # una herramienta por puerto que ya es un conducto suma la herramienta, no otro conducto
        ind2 = {**ind, "metodo": "puerto", "indicador": "tcp/5938", "destino_ip": "10.1.0.5", "destino": "interno"}
        r = _ruta([_k("10.4.0.5", "10.1.0.5", 5938)], inds=[ind2])
        self.assertEqual((len(r["filas"]), r["filas"][0]["conductos"], r["filas"][0]["herramienta"]),
                         (1, 1, ["AnyDesk"]))


class ConfiguradaTest(unittest.TestCase):
    def test_si_no_y_sin_firewall(self):
        cond = [_k("10.4.0.5", "10.1.0.5", 3389), _k("10.4.0.5", "10.2.0.5", 22), _k("10.4.0.6", "10.2.0.5", 3389)]
        fw = {"hostname": "fw", "resultados": [
            {"resultado": "permitido", "regla": "R7", "regla_nombre": "rdp"}, {"resultado": "denegado_observado"},
            {"resultado": "no_cruza"}]}
        r = _ruta(cond, fw=fw)
        f = _fila(r, "tcp/3389", "Empresa")
        self.assertEqual(len(r["filas"]), 3)
        self.assertEqual([(x["servicio"], x["zona_destino"], x["configurada"], x["regla"]) for x in r["filas"]], [
            ("tcp/3389", "Control", ra.CFG_SI, "R7 rdp"), ("tcp/22", "Supervision", ra.CFG_NO, ""),
            ("tcp/3389", "Supervision", ra.CFG_SIN_FW, "")])
        self.assertEqual(f["regla"], "R7 rdp")

    def test_sin_firewall_o_largo_distinto(self):
        cond = [_k("10.4.0.5", "10.1.0.5", 3389)]
        self.assertEqual(_ruta(cond)["filas"][0]["configurada"], ra.CFG_SIN_FW)
        fw = {"hostname": "fw", "resultados": [{"resultado": "permitido"}, {"resultado": "permitido"}]}
        self.assertEqual(_ruta(cond, fw=fw)["filas"][0]["configurada"], ra.CFG_SIN_FW)


class DeclaradasTest(unittest.TestCase):
    COND: ClassVar[list] = [_k("10.4.0.5", "10.1.0.5", 3389)]

    def clase(self, declaradas, cond=None):
        r = _ruta(cond or self.COND, {"declaradas": declaradas})
        return r, {f["id"]: f for f in r["filas"]}

    def test_por_zona_por_cidr_y_por_ip(self):
        for d in (_decl(), _decl(origen="10.4.0.0/24", destino="10.1.0.5"), _decl(origen="10.4.0.5", destino="Control"),
                  _decl(servicio="*")):
            r, _ = self.clase([d])
            self.assertEqual([(f["clase"], f["usada"]) for f in r["filas"]], [(ra.C_DECL_USADA, True)], d)
            self.assertEqual(r["filas"][0]["declaradas"][0]["id"], "A1")

    def test_no_coincide(self):
        for d in (_decl(origen="Supervision"), _decl(destino="Supervision"), _decl(servicio="tcp/22"),
                  _decl(origen="10.5.0.0/24"), _decl(destino="10.1.0.9")):
            r, _ = self.clase([d])
            self.assertEqual(sorted(f["clase"] for f in r["filas"]), [ra.C_DECL_SIN_USO, ra.C_USADA_SIN], d)

    def test_declarada_sin_uso_es_fila_propia(self):
        f = self.clase([_decl(id="B2", servicio="tcp/22", via="VPN", proveedor="Acme")])[1]["B2"]
        self.assertEqual((f["clase"], f["usada"], f["conductos"], f["configurada"]), (ra.C_DECL_SIN_USO, False, 0, "-"))
        fila = dict(zip(ra.COLUMNAS, ra.fila_tabla(f)))
        self.assertEqual((fila["usada"], fila["declarada"], fila["via"], fila["proveedor"], fila["id_ruta"]),
                         ("no", "B2", "VPN", "Acme", "B2"))

    def test_usada_sin_declarar_y_orden(self):
        r, _ = self.clase([_decl(id="B2", servicio="tcp/22")])
        self.assertEqual([f["clase"] for f in r["filas"]], [ra.C_USADA_SIN, ra.C_DECL_SIN_USO])
        self.assertEqual(ra.cuenta(r)[ra.C_USADA_SIN], 1)

    def test_todos_los_activos_deben_caer_en_la_red_declarada(self):
        cond = [_k("10.4.0.5", "10.1.0.5", 3389), _k("10.4.0.6", "10.1.0.5", 3389)]
        r, _ = self.clase([_decl(origen="10.4.0.5")], cond)
        self.assertEqual(sorted(f["clase"] for f in r["filas"]), [ra.C_DECL_SIN_USO, ra.C_USADA_SIN])

    def test_vigencia_vencida(self):
        r, filas = self.clase([_decl(vigencia="2026-11-11"), _decl(id="B2", servicio="tcp/22", vigencia="2026-11-12"),
                               _decl(id="C3", servicio="tcp/23", vigencia="2026-01-01")])
        self.assertTrue(filas["C3"]["vencida"])
        self.assertFalse(filas["B2"]["vencida"])          # vence hoy: aun vigente
        usada = next(f for f in r["filas"] if f["usada"])
        self.assertTrue(usada["vencida"])
        self.assertEqual(dict(zip(ra.COLUMNAS, ra.fila_tabla(usada)))["clasificacion"],
                         "declarada y usada; vigencia vencida")
        self.assertEqual(ra.cuenta(r)[ra.VENCIDA], 2)

    def test_hallazgos(self):
        r, _ = self.clase([_decl(id="B2", servicio="tcp/22", vigencia="2026-01-01")],
                          self.COND + [_k("10.4.0.5", "10.2.0.5", 3389)])
        cap = Capture(Path("x"))
        ra.agregar_hallazgos(cap, r)
        por_t = {h["titulo"]: h for h in cap.findings}
        self.assertEqual(set(por_t), {ra.TIT_SIN_DECLARAR, ra.TIT_VENCIDA})
        self.assertEqual((por_t[ra.TIT_SIN_DECLARAR]["severidad"], por_t[ra.TIT_VENCIDA]["severidad"]),
                         ("Media", "Baja"))
        self.assertIn("Empresa -> Control tcp/3389", por_t[ra.TIT_SIN_DECLARAR]["evidencia"])
        self.assertIn("Empresa -> Supervision tcp/3389", por_t[ra.TIT_SIN_DECLARAR]["evidencia"])
        self.assertIn("B2", por_t[ra.TIT_VENCIDA]["evidencia"])
        self.assertTrue(por_t[ra.TIT_SIN_DECLARAR]["referencias"])
        # todo declarado y vigente: sin hallazgos
        r, _ = self.clase([_decl(servicio="*", destino="10.0.0.0/8")])
        cap = Capture(Path("y"))
        ra.agregar_hallazgos(cap, r)
        self.assertEqual(cap.findings, [])

    def test_sin_clave_no_construye(self):
        assets, _z, zcr = _armar(IPS, ZONAS, self.COND)
        self.assertEqual(ra.construir(assets, self.COND, zcr, None, {"zonas": ZONAS}), {})
        self.assertFalse(ra.hay({}))
        self.assertEqual(ra.tablas({}), [])


class SalidasTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.n = 0
        com = gen_exports.xd_escribir_comunicaciones(self.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 3389, "RDP", tipo_a="HMI"),
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", tipo_a="HMI", tipo_b="PLC"),
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 22, "SSH", tipo_a="HMI", tipo_b="PLC")])
        inv = _inventario_xdome(self.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                       ("PLC-1", "10.10.2.20", "Campo"),
                                                       ("SRV-1", "10.10.3.30", "Planta")])
        self.base = ["--activos", str(inv), "--enlaces", str(com), "--formato", "xdome"]
        self.zonas = [{"nombre": "Op", "redes": ["10.10.1.0/24"]}, {"nombre": "Campo", "redes": ["10.10.2.0/24"]},
                      {"nombre": "Planta", "redes": ["10.10.3.0/24"]}]

    def correr(self, **extra) -> Path:
        self.n += 1
        p = self.tmp / f"perfil{self.n}.json"
        p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}],
                                 "zonas": self.zonas, **extra}), encoding="utf-8")
        out = self.tmp / f"out{self.n}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama([*self.base, "-o", str(out), "--perfil", str(p)]), 0)
        return out

    def titulos(self, out):
        with open(out / "hallazgos_importados.csv", encoding="utf-8-sig", newline="") as fh:
            return [" ".join(f.values()) for f in csv.DictReader(fh)]

    def test_sin_la_clave_no_hay_nada(self):
        o = self.correr()
        self.assertFalse((o / ra.ARCHIVO).exists())
        self.assertNotIn("rutas_acceso", json.loads((o / "resultado.json").read_text(encoding="utf-8")))
        self.assertFalse(any(ra.TIT_SIN_DECLARAR in x for x in self.titulos(o)))
        for p in o.iterdir():
            if p.suffix in (".html", ".md", ".csv", ".json"):
                self.assertNotIn(ra.TITULO, p.read_text(encoding="utf-8-sig"), p.name)

    def test_con_la_clave_csv_json_secciones_y_hallazgos(self):
        o = self.correr(rutas_acceso={"declaradas": [
            {"id": "RDP-1", "origen": "Op", "destino": "Planta", "servicio": "tcp/3389", "via": "VPN",
             "proveedor": "Acme", "vigencia": "2026-01-01"}]})
        with open(o / ra.ARCHIVO, encoding="utf-8-sig", newline="") as fh:
            filas = list(csv.DictReader(fh))
        self.assertEqual(list(filas[0]), ra.COLUMNAS)
        por = {f["servicio"]: f for f in filas}
        self.assertEqual(por["22"]["clasificacion"], ra.C_USADA_SIN)
        self.assertEqual(por["3389"]["clasificacion"], "declarada y usada; vigencia vencida")
        self.assertEqual((por["3389"]["declarada"], por["3389"]["via"], por["3389"]["configurada"]),
                         ("RDP-1", "VPN", "sin firewall"))
        j = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["rutas_acceso"]
        self.assertEqual(j["conteos"][ra.C_USADA_SIN], 1)
        self.assertEqual(len(j["filas"]), 2)
        tit = self.titulos(o)
        self.assertTrue(any(ra.TIT_SIN_DECLARAR in x for x in tit))
        self.assertTrue(any(ra.TIT_VENCIDA in x for x in tit))
        for nombre in ("reporte_ot.html", "reporte_ot.md"):
            ps = list(o.glob(nombre))
            if ps:
                self.assertIn(ra.TITULO, ps[0].read_text(encoding="utf-8"), nombre)
        self.assertTrue(list(o.glob("*.html")) or list(o.glob("*.md")))

    def test_ingles(self):
        o = self.correr(idioma="en", rutas_acceso={})
        with open(o / ra.ARCHIVO, encoding="utf-8-sig", newline="") as fh:
            filas = list(csv.DictReader(fh))
        self.assertIn("route_id", filas[0])
        self.assertEqual({f["classification"] for f in filas}, {"used, not declared"})
        self.assertTrue(any("Access routes to OT in use and not declared" in x for x in self.titulos(o)))


if __name__ == "__main__":
    unittest.main()
