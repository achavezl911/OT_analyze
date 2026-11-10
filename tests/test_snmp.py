"""SN1 (D97): lector de recorridos SNMP (net-snmp) como fuente de switch. Recorridos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import shutil
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess.cli import main as main_capturas
from ot_assess.model import Capture
from ot_assess.switches import higiene as hg
from ot_assess.switches import integracion as si
from ot_assess.switches import snmp

COMUNIDAD = "secreto123"
MAC_ACTIVO = (0, 0, 0xBC, 0, 0, 0x20)      # 00:00:bc:00:00:20 (la de gen_pcaps)


def _fdb(vlan, mac, puerto):
    suf = f".{vlan}." + ".".join(str(b) for b in mac)
    return [("dot1qTpFdbPort", suf, f"INTEGER: {puerto}"), ("dot1qTpFdbStatus", suf, "INTEGER: learned(3)")]


def objetos(extra=()):
    """[(nombre, sufijo, valor)] de un switch de 4 puertos, 2 VLAN, 5 MAC y 1 vecino LLDP en el puerto 4."""
    o = [("sysName", ".0", 'STRING: "swsnmp-01"'), ("sysDescr", ".0", "STRING: Switch de prueba")]
    o += [("entPhysicalClass", ".1", "INTEGER: chassis(3)"), ("entPhysicalModelName", ".1", 'STRING: "MOD-4P"'),
          ("entPhysicalSoftwareRev", ".1", 'STRING: "1.2.3"')]
    for n in range(1, 5):
        i = 10100 + n
        o += [("ifName", f".{i}", f"STRING: 1/1/{n}"), ("ifDescr", f".{i}", f'STRING: "puerto fisico {n}"'),
              ("ifAlias", f".{i}", f'STRING: "enlace {n}"'), ("ifAdminStatus", f".{i}", "INTEGER: up(1)"),
              ("ifOperStatus", f".{i}", "INTEGER: up(1)" if n != 3 else "INTEGER: down(2)"),
              ("dot1dBasePortIfIndex", f".{n}", f"INTEGER: {i}"), ("dot1qPvid", f".{n}", f"Gauge32: {20 if n == 3 else 10}")]
    o += [("ifName", ".20000", "STRING: Vlan10")]                 # interfaz virtual: no es puerto
    o += [("dot1qVlanStaticName", ".10", "STRING: OT"), ("dot1qVlanStaticName", ".20", "STRING: GESTION"),
          ("dot1qVlanFdbId", ".0.10", "Gauge32: 10"), ("dot1qVlanFdbId", ".0.20", "Gauge32: 20")]
    # VLAN 10: puertos 1,2 sin etiqueta y 4 etiquetado; VLAN 20: puerto 3 sin etiqueta y 4 etiquetado
    o += [("dot1qVlanCurrentEgressPorts", ".0.10", 'Hex-STRING: D0'),
          ("dot1qVlanCurrentUntaggedPorts", ".0.10", "Hex-STRING: C0"),
          ("dot1qVlanCurrentEgressPorts", ".0.20", "Hex-STRING: 30"),
          ("dot1qVlanCurrentUntaggedPorts", ".0.20", "Hex-STRING: 20")]
    o += _fdb(10, (2, 0, 0, 0, 0, 1), 1) + _fdb(10, (2, 0, 0, 0, 0, 2), 2) + _fdb(10, (2, 0, 0, 0, 0, 3), 2)
    o += _fdb(20, MAC_ACTIVO, 3) + _fdb(20, (2, 0, 0, 0, 0, 5), 4)
    o += _fdb(20, MAC_ACTIVO, 4)                                  # la misma MAC vista en el troncal
    o += [("dot1qTpFdbPort", ".10.2.0.0.0.0.9", "INTEGER: 4"), ("dot1qTpFdbStatus", ".10.2.0.0.0.0.9",
                                                                 "INTEGER: self(4)")]     # no aprendida
    o += [("lldpRemSysName", ".0.4.1", 'STRING: "vecino-sw"'), ("lldpRemPortId", ".0.4.1", 'STRING: "2/1/7"'),
          ("lldpRemPortDesc", ".0.4.1", 'STRING: "uplink 7"'), ("lldpRemSysDesc", ".0.4.1", 'STRING: "X"'),
          ("lldpLocPortId", ".4", "STRING: 1/1/4")]
    return o + list(extra)


def recorrido(simbolico=False, extra=()):
    from ot_assess.switches.snmp import _NOMBRES
    mib = {"sysName": "SNMPv2-MIB", "sysDescr": "SNMPv2-MIB"}
    out = []
    for nombre, suf, val in objetos(extra):
        if simbolico:
            out.append(f"{mib.get(nombre, 'MIB')}::{nombre}{suf} = {val}")
        else:
            out.append(f".{_NOMBRES[nombre]}{suf} = {val}")
    return "\n".join(out) + "\n"


def sin_archivo(sw):
    d = asdict(sw)
    d["archivo"] = ""
    return d


class LectorTest(unittest.TestCase):
    def test_numerico_modelo_basico(self):
        sw = snmp.leer(recorrido(), "sw1.walk")
        self.assertEqual((sw.hostname, sw.origen, sw.modelo, sw.version, sw.config),
                         ("swsnmp-01", "snmp", "MOD-4P", "1.2.3", False))
        self.assertEqual([p.nombre for p in sw.puertos], ["1/1/1", "1/1/2", "1/1/3", "1/1/4"])
        p3 = sw.puerto("1/1/3")
        self.assertEqual((p3.descripcion, p3.estado), ("enlace 3", "down"))
        self.assertEqual(sw.vlans, {10: "OT", 20: "GESTION"})
        self.assertEqual(len(sw.mac), 5)
        self.assertIn((20, "00:00:bc:00:00:20", "1/1/3"), sw.mac)
        self.assertNotIn((10, "02:00:00:00:00:09", "1/1/4"), sw.mac)
        modos = {p.nombre: (p.modo, p.vlan_acceso, p.vlans_trunk) for p in sw.puertos}
        self.assertEqual(modos["1/1/4"][0:1] + (modos["1/1/4"][2],), ("trunk", [10, 20]))
        self.assertEqual(modos["1/1/1"], ("access", 10, []))
        self.assertEqual(modos["1/1/3"], ("access", 20, []))
        self.assertEqual(len(sw.cdp), 1)
        v = sw.cdp[0]
        self.assertEqual((v.id_equipo, v.interfaz, v.puerto_remoto), ("vecino-sw", "1/1/4", "uplink 7"))
        self.assertEqual(sw.avisos, [])

    def test_simbolico_da_el_mismo_switch(self):
        self.assertEqual(sin_archivo(snmp.leer(recorrido(), "a.walk")),
                         sin_archivo(snmp.leer(recorrido(simbolico=True), "a.walk")))

    def test_comunidad_nunca_se_guarda(self):
        cmd = f"$ snmpbulkwalk -v2c -c {COMUNIDAD} -On 192.0.2.1 1.3.6.1.2.1.17"
        lineas = recorrido().splitlines()
        texto = "\n".join([cmd] + lineas[:10] + [f"snmpwalk -v2c -c {COMUNIDAD} 192.0.2.1"] + lineas[10:]) + "\n"
        sw = snmp.leer(texto, "sw1.walk")
        self.assertNotIn(COMUNIDAD, repr(asdict(sw)))
        self.assertEqual(sw.avisos, ["2 lineas no son 'OID = valor' y se descartaron sin guardarlas"])
        base = snmp.leer(recorrido(), "sw1.walk")
        self.assertEqual(sin_archivo(sw)["puertos"], sin_archivo(base)["puertos"])

    def test_comillas_sin_cerrar_no_unen_lo_que_sigue(self):
        o = recorrido().replace('STRING: "enlace 1"', 'STRING: "enlace 1')
        o = o.replace(".1.3.6.1.2.1.2.2.1.7.10101 = ", "clave OtroSecreto9\n.1.3.6.1.2.1.2.2.1.7.10101 = ", 1)
        sw = snmp.leer(o, "sw1.walk")
        self.assertNotIn("OtroSecreto9", repr(asdict(sw)))
        self.assertEqual(sw.puerto("1/1/1").descripcion, "enlace 1")
        self.assertEqual(sw.avisos, ["1 lineas no son 'OID = valor' y se descartaron sin guardarlas"])

    def test_mac_del_puente_con_la_pista_de_la_mib(self):
        stp = [("dot1dStpPriority", ".0", "INTEGER: 32768"),
               ("dot1dStpDesignatedRoot", ".0", "Hex-STRING: 80 00 02 00 00 00 00 0A ")]
        for valor in ("STRING: 2:0:0:0:0:a", "Hex-STRING: 02 00 00 00 00 0A "):
            sw = snmp.leer(recorrido(extra=stp + [("dot1dBaseBridgeAddress", ".0", valor)]), "s.walk")
            self.assertEqual((sw.stp[0].puente, sw.stp[0].raiz), ("02:00:00:00:00:0a", "local"), valor)

    def test_hex_y_cadenas_de_varias_lineas(self):
        o = recorrido().replace('STRING: "swsnmp-01"', "Hex-STRING: 73 77 68 65 78 2D 30 31 00")
        o = o.replace('STRING: "enlace 1"', 'STRING: "primera linea\nsegunda linea con = signo\ncierre"')
        o += ".1.3.6.1.2.1.31.1.1.1.18.10102 = Hex-STRING: 41 42 43 44\n 45 46\n"
        sw = snmp.leer(o + f"snmpwalk -c {COMUNIDAD}\n", "x.walk")
        self.assertEqual(sw.hostname, "swhex-01")
        self.assertEqual(sw.puerto("1/1/1").descripcion, "primera linea segunda linea con = signo cierre")
        self.assertEqual(sw.puerto("1/1/2").descripcion, "enlace 2")        # el primer valor gana
        self.assertEqual(sw.vlans, {10: "OT", 20: "GESTION"})
        self.assertNotIn(COMUNIDAD, repr(asdict(sw)))
        solo = snmp.leer(".1.3.6.1.2.1.31.1.1.1.1.5 = STRING: p5\n.1.3.6.1.2.1.31.1.1.1.18.5 = Hex-STRING: 41 42 43\n"
                         " 44 45 46\n", "h.walk")
        self.assertEqual(solo.puertos[0].descripcion, "ABCDEF")

    def test_sin_objetos_reconocidos(self):
        sw = snmp.leer("snmpwalk -v2c -c secreto123 host\n.1.3.6.1.4.1.9.9.1.1.0 = INTEGER: 5\n", "vacio.walk")
        self.assertEqual((sw.hostname, sw.puertos, sw.mac, sw.origen), ("vacio", [], [], "snmp"))
        self.assertTrue(any("ningun objeto SNMP reconocido" in a for a in sw.avisos))
        self.assertNotIn(COMUNIDAD, " ".join(sw.avisos))

    def test_dos_sysname_y_corchetes(self):
        o = recorrido() + '.1.3.6.1.2.1.1.5.0 = STRING: "otro"\n'
        o += "Q-BRIDGE-MIB::dot1qTpFdbPort[1][STRING: 0:1:2:3:4:5] = INTEGER: 1\n"
        sw = snmp.leer(o, "x.walk")
        self.assertEqual(sw.hostname, "swsnmp-01")
        self.assertTrue(any("mas de un sysName" in a for a in sw.avisos))
        self.assertTrue(any("-On" in a for a in sw.avisos))

    def test_hostname_del_archivo_y_deteccion(self):
        sw = snmp.leer(".1.3.6.1.2.1.31.1.1.1.1.1 = STRING: p1\n", "mi-switch.walk")
        self.assertEqual(sw.hostname, "mi-switch")
        d = Path(tempfile.mkdtemp())
        try:
            (d / "a.walk").write_text("\n\nsnmpwalk -c x\n.1.3.6.1.2.1.1.5.0 = STRING: a\n", encoding="utf-8")
            (d / "b.walk").write_text("IF-MIB::ifName.1 = STRING: p\n", encoding="utf-8")
            (d / "c.txt").write_text("sw#show mac address-table\n", encoding="utf-8")
            self.assertEqual([snmp.es_snmp(d / n) for n in ("a.walk", "b.walk", "c.txt")], [True, True, False])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_sin_q_bridge_usa_bridge_mib_sin_vlan(self):
        o = ["1.3.6.1.2.1.31.1.1.1.1.7 = STRING: e7", "1.3.6.1.2.1.17.1.4.1.2.1 = INTEGER: 7",
             "1.3.6.1.2.1.17.4.3.1.2.2.0.0.0.0.1 = INTEGER: 1", "1.3.6.1.2.1.17.4.3.1.3.2.0.0.0.0.1 = INTEGER: 3"]
        sw = snmp.leer("\n".join(o), "d.walk")
        self.assertEqual(sw.mac, [(0, "02:00:00:00:00:01", "e7")])
        self.assertTrue(any("desconocida" in a for a in sw.avisos))
        activos = {"a": {"mac": "02:00:00:00:00:01"}}
        res = si.integrar([self._escribir("\n".join(o))], activos)
        self.assertNotIn("vlan", activos["a"])                                # VLAN 0 = desconocida, no se escribe
        self.assertEqual(res["ubicados"], 1)

    def _escribir(self, texto):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / "s.walk"
        p.write_text(texto, encoding="utf-8")
        return str(p)


class IntegracionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def archivo(self, texto, nombre="s.walk"):
        p = self.tmp / nombre
        p.write_text(texto, encoding="utf-8")
        return str(p)

    def hall(self, texto):
        res = si.integrar([self.archivo(texto)], {})
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, res)
        return res, {f["titulo"]: f for f in cap.findings}

    def test_ubicacion_en_puerto_de_acceso(self):
        assets = {"a": {"mac": "00:00:bc:00:00:20", "nombre": "PLC"}}
        res = si.integrar([self.archivo(recorrido())], assets)
        self.assertEqual((assets["a"]["switch_puerto"], assets["a"]["vlan"]), ("swsnmp-01:1/1/3", "20"))
        self.assertEqual(res["ubicados"], 1)

    def test_espejo_desconocido(self):
        res, h = self.hall(recorrido())
        self.assertEqual(res["sin_espejo"], [])
        self.assertEqual(si.espejo_por_vlan(res), {})
        from ot_assess import cobertura_captura as cc
        self.assertEqual(cc.vlans_del_span(res), set())   # no se esperan en la captura
        self.assertNotIn(hg.TIT_SIN_ESPEJO, h)
        filas = si.filas_vlans(res)
        self.assertEqual({f[1] for f in filas}, {10, 20})
        self.assertEqual({f[5] for f in filas}, {""})
        self.assertEqual({f[7] for f in filas}, {""})
        self.assertEqual(h, {})                       # sin running-config no se evalua la configuracion

    def test_sin_running_config_en_la_higiene(self):
        res, _h = self.hall(recorrido())
        self.assertFalse(res["switches"][0].config)
        self.assertIn("No evaluado, sin running-config: swsnmp-01", hg._alcance_config(res["switches"]))

    def test_contadores_con_errores(self):
        extra = [("ifInErrors", ".10101", "Counter32: 5000"), ("dot3StatsFCSErrors", ".10101", "Counter32: 5000"),
                 ("ifHCInUcastPkts", ".10101", "Counter64: 1000000"),
                 ("ifHCInBroadcastPkts", ".10101", "Counter64: 10"), ("ifHCOutUcastPkts", ".10101", "Counter64: 7"),
                 ("ifOutDiscards", ".10101", "Counter32: 3"), ("ifHighSpeed", ".10101", "Gauge32: 1000")]
        sw = snmp.leer(recorrido(extra=extra), "s.walk")
        c = sw.contadores[0]
        self.assertEqual((c.puerto, c.errores, c.crc, c.paquetes, c.broadcast, c.paquetes_salida, c.descartes,
                          c.bw_kbit), ("1/1/1", 5000, 5000, 1000010, 10, 7, 3, 1000000))
        self.assertIn("interfaces", sw.leyo)
        _res, h = self.hall(recorrido(extra=extra))
        self.assertIn("errores de entrada en 1/1/1: 5000 (5000 CRC)", h[hg.TIT_STP]["evidencia"])
        _res, h = self.hall(recorrido())
        self.assertNotIn(hg.TIT_STP, h)

    def test_stp_raiz_local_sin_prioridad(self):
        stp = [("dot1dBaseBridgeAddress", ".0", "Hex-STRING: 02 00 00 00 00 AA"),
               ("dot1dStpPriority", ".0", "INTEGER: 32768"), ("dot1dStpTopChanges", ".0", "Counter32: 2"),
               ("dot1dStpTimeSinceTopologyChange", ".0", "Timeticks: (12345) 0:02:03.45"),
               ("dot1dStpDesignatedRoot", ".0", "Hex-STRING: 80 00 02 00 00 00 00 AA")]
        sw = snmp.leer(recorrido(extra=stp), "s.walk")
        c = sw.stp[0]
        self.assertEqual((c.instancia, c.cambios, c.hace_s, c.prioridad, c.raiz, c.puente),
                         ("STP", 2, 123, 32768, "local", "02:00:00:00:00:aa"))
        self.assertIn("stp", sw.leyo)
        _res, h = self.hall(recorrido(extra=stp))
        self.assertIn(hg.TIT_RAIZ, h)
        otra = [x if x[0] != "dot1dStpDesignatedRoot" else (x[0], x[1], "Hex-STRING: 80 00 02 00 00 00 00 BB")
                for x in stp]
        self.assertEqual(snmp.leer(recorrido(extra=otra), "s.walk").stp[0].raiz, "02:00:00:00:00:bb")
        _res, h = self.hall(recorrido(extra=[(x[0], x[1], "INTEGER: 24576") if x[0] == "dot1dStpPriority" else x
                                             for x in stp]))
        self.assertNotIn(hg.TIT_RAIZ, h)

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_corrida_principal(self):
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("requiere scapy")
        import gen_pcaps
        sys.argv = ["gen", str(self.tmp / "pcaps")]
        gen_pcaps.main()
        walk = self.archivo(f"snmpwalk -v2c -c {COMUNIDAD} 192.0.2.1\n" + recorrido(), "recorrido.walk")
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_capturas([str(self.tmp / "pcaps"), "-o", str(out), "--switch", walk]), 0)
        with open(out / "inventario.csv", encoding="utf-8-sig", newline="") as f:
            inv = {r["mac"]: r for r in csv.DictReader(f)}
        r = inv["00:00:bc:00:00:20"]
        self.assertEqual((r["switch_puerto"], r["vlan"]), ("swsnmp-01:1/1/3", "20"))
        for p in out.rglob("*"):
            if p.is_file():
                self.assertNotIn(COMUNIDAD.encode(), p.read_bytes(), str(p))


class CiscoNoCambiaTest(unittest.TestCase):
    def test_origen_por_defecto(self):
        from ot_assess.switches import cisco_ios as ci
        self.assertEqual(ci.leer("hostname x\ninterface Gi1/0/1\n", "x.txt").origen, "cli")


if __name__ == "__main__":
    unittest.main()
