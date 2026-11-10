"""M1: varios firewalls en cadena (IT > DMZ > SCADA, sinteticos): enlaces, camino y coherencia."""
from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import RUTAS, _sesion

from ot_assess import i18n
from ot_assess.cli import main
from ot_assess.firewalls import integracion as fi
from ot_assess.firewalls import topologia as tp
from ot_assess.firewalls.modelo import Firewall, Interfaz, Regla, Ruta

N = ipaddress.IPv4Network
ANY = [N("0.0.0.0/0")]


def _i(nombre, ip, mascara):
    return Interfaz(nombre, nombre, ip, mascara)


def _c(red, ifc):
    return Ruta(N(red), ifc, "", "conectada")


def _s(red, ifc, salto, tipo="estatica"):
    return Ruta(N(red), ifc, salto, tipo)


def _regla(id_, accion="permitir", puertos=()):
    return Regla(id_, "r" + id_, accion=accion, protocolos=["tcp"] if puertos else [], origen=ANY, destino=ANY,
                 puertos=list(puertos))


def _cadena(reglas_dmz=None, reglas_scada=None, dmz_rota=False):
    """IT (corp, dmz, internet) - 172.16.0.0/30 - DMZ (it, scada, dmz) - 172.16.0.4/30 - SCADA (dmz, scada)."""
    it = Firewall("Cisco", "FW-IT", [_i("corp", "10.10.0.1", "255.255.0.0"), _i("dmz", "172.16.0.1", "255.255.255.252"),
                                     _i("internet", "192.0.2.2", "255.255.255.0")],
                  [_s("0.0.0.0/0", "internet", "192.0.2.1", "defecto"), _s("10.20.0.0/16", "dmz", "172.16.0.2"),
                   _s("10.30.0.0/16", "dmz", "172.16.0.2"), _c("172.16.0.0/30", "dmz"),
                   _c("192.0.2.0/24", "internet"), _c("10.10.0.0/16", "corp")],
                  reglas=[_regla("1")])
    dmz_rutas = [_s("0.0.0.0/0", "it", "172.16.0.1", "defecto"), _s("10.30.0.0/16", "scada", "172.16.0.6"),
                 _c("172.16.0.0/30", "it"), _c("172.16.0.4/30", "scada"), _c("10.20.0.0/16", "dmz")]
    if dmz_rota:      # el defecto sale por donde llega SCADA: el DMZ no cruzaria SCADA -> Internet
        dmz_rutas[0] = _s("0.0.0.0/0", "scada", "172.16.0.6", "defecto")
    dmz = Firewall("Cisco", "FW-DMZ", [_i("it", "172.16.0.2", "255.255.255.252"),
                                       _i("scada", "172.16.0.5", "255.255.255.252"),
                                       _i("dmz", "10.20.0.1", "255.255.0.0")],
                   dmz_rutas, reglas=reglas_dmz or [_regla("1")])
    scada = Firewall("Cisco", "FW-SCADA", [_i("dmz", "172.16.0.6", "255.255.255.252"),
                                           _i("scada", "10.30.0.1", "255.255.0.0")],
                     [_s("0.0.0.0/0", "dmz", "172.16.0.5", "defecto"), _c("172.16.0.4/30", "dmz"),
                      _c("10.30.0.0/16", "scada")], reglas=reglas_scada or [_regla("1")])
    return [it, dmz, scada]


def _k(src, dst, port=443):
    return {"src": src, "dst": dst, "l4": "tcp", "port": str(port), "servicio": "-", "bytes": 0}


def _integrar(fws, conductos):
    return fi.integrar_modelos(fws, [f.hostname + ".txt" for f in fws], {}, conductos)[1]


class EnlacesTest(unittest.TestCase):
    def test_enlaces_por_ruta_y_red_compartida(self):
        fws = _cadena()
        enl = tp.enlaces(["IT", "DMZ", "SCADA"], fws)
        self.assertEqual([(e["fw_a"], e["interfaz_a"], e["fw_b"], e["interfaz_b"], e["descubierto_por"])
                          for e in enl],
                         [("IT", "dmz", "DMZ", "it", "ruta; red compartida"),
                          ("DMZ", "scada", "SCADA", "dmz", "ruta; red compartida")])
        self.assertEqual((enl[0]["red"], enl[0]["ip_b"]), ("172.16.0.0/30", "172.16.0.2"))

    def test_solo_red_compartida_y_solo_ruta(self):
        it, dmz, _scada = _cadena()
        it.rutas = [r for r in it.rutas if not r.salto.startswith("172.")]       # sin rutas hacia el DMZ
        dmz.rutas = [r for r in dmz.rutas if r.salto != "172.16.0.1"]
        enl = tp.enlaces(["IT", "DMZ"], [it, dmz])
        self.assertEqual([e["descubierto_por"] for e in enl], ["red compartida"])
        # el DMZ sin la interfaz que comparte la red: queda solo el enlace por la ruta
        dmz2 = _cadena()[1]
        dmz2.interfaces = [i for i in dmz2.interfaces if i.nombre != "it"]
        enl = tp.enlaces(["IT", "DMZ"], [_cadena()[0], dmz2])
        self.assertEqual([e["descubierto_por"] for e in enl], ["ruta"])

    def test_identificadores(self):
        a, b = Firewall(hostname="X"), Firewall(hostname="X")
        self.assertEqual(tp.identificadores([a, b, Firewall(hostname="Z"), Firewall()],
                                            ["a.txt", "b.txt", "c.txt", "d.txt"]),
                         ["a.txt", "b.txt", "Z", "d.txt"])
        self.assertEqual(tp.identificadores([Firewall(), Firewall()], ["f.txt", "f.txt"]), ["f.txt#1", "f.txt#2"])


class CaminoTest(unittest.TestCase):
    def test_scada_a_internet_en_orden(self):
        r = _integrar(_cadena(), [_k("10.30.1.5", "8.8.8.8")])
        camino = r["cruces"]["detalle"][0]["camino"]
        self.assertEqual([(x["fw"], x["interfaz_entrada"], x["interfaz_salida"]) for x in camino],
                         [("FW-SCADA", "scada", "dmz"), ("FW-DMZ", "scada", "it"), ("FW-IT", "dmz", "internet")])
        from ot_assess.firewalls import cruces
        self.assertEqual(cruces.texto_camino(camino), "FW-SCADA (scada -> dmz) > FW-DMZ (scada -> it) > "
                                                      "FW-IT (dmz -> internet)")
        self.assertEqual(r["resultados"][0]["resultado"], "permitido")
        self.assertTrue(r["cruces"]["multiple"])
        self.assertEqual({a["firewall"] for a in r["cruces"]["agregado"]}, {"FW-SCADA", "FW-DMZ", "FW-IT"})

    def test_sentido_elegido_rige_todo_el_camino(self):
        """F1e: conducto bidireccional ordenado por IP (8.8.8.8 primero): se usa SCADA -> Internet en los 3."""
        sale = [Regla("1", "sale", accion="permitir", protocolos=["tcp"], origen=[N("10.30.0.0/16")],
                      destino=ANY, puertos=[(443, 443)]),
                Regla("2", "resto", accion="denegar", origen=ANY, destino=ANY)]
        r = _integrar(_cadena(sale, sale), [dict(_k("8.8.8.8", "10.30.1.5"), bidireccional=True)])
        x = r["resultados"][0]
        self.assertEqual((x["resultado"], x["sentido"]), ("permitido", "invertido"))
        self.assertEqual(r["resumen"]["invertidos"], 1)
        camino = r["cruces"]["detalle"][0]["camino"]
        self.assertEqual([(c["fw"], c["interfaz_entrada"], c["interfaz_salida"]) for c in camino],
                         [("FW-SCADA", "scada", "dmz"), ("FW-DMZ", "scada", "it"), ("FW-IT", "dmz", "internet")])
        fila = r["cruces"]["detalle"][0]
        self.assertEqual((fila["ip_origen"], fila["ip_destino"]), ("10.30.1.5", "8.8.8.8"))

    def test_orden_independiente_del_orden_de_los_argumentos(self):
        it, dmz, scada = _cadena()
        r = _integrar([dmz, scada, it], [_k("10.30.1.5", "8.8.8.8")])
        self.assertEqual([x["fw"] for x in r["cruces"]["detalle"][0]["camino"]], ["FW-SCADA", "FW-DMZ", "FW-IT"])

    def test_orden_no_verificado_sin_enlaces(self):
        it, dmz, scada = _cadena()
        for f in (it, dmz, scada):       # sin interfaces con IP ni saltos: no se puede saber como se unen
            f.interfaces = []
            f.rutas = [Ruta(r.red, r.interfaz, "", r.tipo) for r in f.rutas]
        r = _integrar([it, dmz, scada], [_k("10.30.1.5", "8.8.8.8")])
        d = r["cruces"]["detalle"][0]
        self.assertFalse(d["orden_verificado"])
        self.assertEqual([x["fw"] for x in d["camino"]], ["FW-IT", "FW-DMZ", "FW-SCADA"])

    def test_sin_firewall_en_el_camino(self):
        r = _integrar(_cadena(), [_k("10.30.1.5", "10.30.2.6", 502)])
        self.assertEqual(r["resultados"][0]["resultado"], "no_cruza")
        self.assertEqual(r["cruces"]["totales"]["conductos_cruzan"], 0)
        self.assertEqual(r["topologia"]["coherencia"]["filas"], [])  # solo se cuenta, no se lista
        self.assertEqual(r["topologia"]["coherencia"]["conteo"][tp.T_SIN_FW], 1)


class CoherenciaTest(unittest.TestCase):
    def test_permitido_en_dmz_y_denegado_en_scada(self):
        fws = _cadena(reglas_scada=[_regla("9", "bloquear", [(443, 443)]), _regla("10")],
                      reglas_dmz=[_regla("2", "permitir", [(443, 443)])])
        r = _integrar(fws, [_k("10.30.1.5", "8.8.8.8")])
        self.assertEqual(r["resultados"][0]["resultado"], "denegado_observado")
        fila = r["topologia"]["coherencia"]["filas"][0]
        self.assertEqual((fila["tipo"], fila["a"], fila["b"]), (tp.T_MIXTO, "FW-DMZ, FW-IT", "FW-SCADA"))
        self.assertEqual(tp.texto_marca(fila), "permitido en FW-DMZ, FW-IT, denegado en FW-SCADA")
        self.assertEqual(r["topologia"]["coherencia"]["conteo"][tp.T_MIXTO], 1)

    def test_sin_conflicto_no_marca(self):
        r = _integrar(_cadena(), [_k("10.30.1.5", "8.8.8.8")])
        self.assertEqual(r["topologia"]["coherencia"]["filas"], [])

    def test_salto_inconsistente(self):
        r = _integrar(_cadena(dmz_rota=True), [_k("10.30.1.5", "8.8.8.8")])
        fila = next(f for f in r["topologia"]["coherencia"]["filas"] if f["tipo"] == tp.T_SALTO)
        self.assertEqual((fila["a"], fila["b"]), ("FW-DMZ", "FW-SCADA"))
        self.assertEqual(tp.texto_marca(fila), "salto hacia FW-DMZ sin cruce en FW-DMZ (salto de FW-SCADA)")
        camino = r["cruces"]["detalle"][0]["camino"]
        self.assertEqual(sorted(x["fw"] for x in camino), ["FW-IT", "FW-SCADA"])     # el DMZ no cruza
        self.assertFalse(r["cruces"]["detalle"][0]["orden_verificado"])               # y el orden queda sin verificar

    def test_destino_en_la_red_del_enlace_no_marca(self):
        r = _integrar(_cadena(), [_k("10.30.1.5", "172.16.0.5", 22)])    # IP del propio DMZ
        self.assertEqual([f for f in r["topologia"]["coherencia"]["filas"] if f["tipo"] == tp.T_SALTO], [])


class IngresTest(unittest.TestCase):
    def test_salidas_en_ingles_sin_faltantes(self):
        from ot_assess.firewalls import cruces
        r = _integrar(_cadena(dmz_rota=True), [_k("10.30.1.5", "8.8.8.8"), _k("10.30.1.5", "10.30.2.6")])
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        for a, hoja, cab, filas in tp.tablas(r):
            i18n.t(hoja)
            if a.startswith("firewall_"):      # las tablas por firewall ya existian (columnas sin traducir: aparte)
                for c in cab:
                    i18n.t(c)
            self.assertIsInstance(filas, list)
        for c in cruces.columnas_agregado(r["cruces"]) + cruces.columnas_detalle(r["cruces"]):
            i18n.t(c)
        cruces.filas_detalle(r["cruces"])
        cruces.filas_agregado(r["cruces"])
        tp.tablas_reporte(r)
        i18n.t(tp.NOTA)
        i18n.t(tp.TITULO)
        txt = tp.resumen_texto(r)
        self.assertIn("links between them", txt)
        tp.texto_marca({"tipo": tp.T_MIXTO, "a": "A", "b": "B"})
        self.assertIn("order not verified", cruces.texto_camino([], False))
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


class UnFirewallTest(unittest.TestCase):
    def test_un_firewall_no_trae_estructura_multiple(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        f = tmp / "fw.txt"
        f.write_text(_sesion(RUTAS, "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"),
                     encoding="utf-8")
        _rutas, fw = fi.integrar([str(f)], {}, [_k("10.10.1.5", "8.8.8.8")])
        self.assertNotIn("firewalls", fw)
        self.assertNotIn("topologia", fw)
        self.assertNotIn("multiple", fw["cruces"])
        self.assertFalse(tp.es_multiple(fw))
        from ot_assess.firewalls import cruces
        self.assertEqual(cruces.columnas_agregado(fw["cruces"]), cruces.COL_AGREGADO)
        self.assertEqual(cruces.columnas_detalle(fw["cruces"]), cruces.COL_DETALLE)
        self.assertEqual(fw["archivo"], "fw.txt")


RUTAS_A = ("C        10.20.1.0 255.255.255.0 is directly connected, inside\n"
           "C        10.20.2.0 255.255.255.0 is directly connected, dmz\n"
           "C        192.0.2.0 255.255.255.0 is directly connected, outside\n")
ACL = ("access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"
       "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n")     # la ultima es la regla por defecto


class ArchivosPorFirewallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        sesiones = {"fw_a.txt": "FWA", "fw_b.txt": "FWB"}
        for nombre, host in sesiones.items():
            (cls.tmp / nombre).write_text(_sesion(RUTAS_A, ACL).replace("FW1#", host + "#"), encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                       "-o", str(cls.out), "--firewall", str(cls.tmp / "fw_a.txt"),
                       "--firewall", str(cls.tmp / "fw_b.txt")])
        assert rc == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        i18n.usar("es")

    def test_archivos_con_prefijo(self):
        nombres = {p.name for p in self.out.glob("*.csv")}
        for esperado in ("FWA_firewall_reglas.csv", "FWB_firewall_reglas.csv", "FWA_firewall_rutas.csv",
                         "FWB_firewall_interfaces.csv", "firewall_topologia.csv", "firewall_coherencia.csv",
                         "firewall_cruces.csv", "firewall_cruces_detalle.csv"):
            self.assertIn(esperado, nombres)
        self.assertNotIn("firewall_reglas.csv", nombres)
        self.assertNotIn("firewall_interfaces.csv", nombres)

    def test_columnas_nuevas_y_hallazgos_juntos(self):
        with open(self.out / "firewall_cruces.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), ["firewall"] + __import__("ot_assess.firewalls.cruces",
                                                                            fromlist=["x"]).COL_AGREGADO)
        with open(self.out / "firewall_cruces_detalle.csv", newline="", encoding="utf-8-sig") as fh:
            filas = list(csv.DictReader(fh))
        self.assertIn("camino", filas[0])
        self.assertIn("FWA (", filas[0]["camino"])
        self.assertIn("FWB (", filas[0]["camino"])
        with open(self.out / "hallazgos_importados.csv", newline="", encoding="utf-8-sig") as fh:
            hall = list(csv.DictReader(fh))
        anys = [h for h in hall if "cualquier origen" in " ".join(h.values())]
        self.assertEqual(len(anys), 1)      # un hallazgo por tipo, no uno por firewall
        texto = " ".join(anys[0].values())
        self.assertIn("FWA:1", texto)
        self.assertIn("FWB:1", texto)


if __name__ == "__main__":
    unittest.main()
