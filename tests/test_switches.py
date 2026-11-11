"""SW1a: lector de Cisco IOS/IOS-XE, ubicacion por MAC, cobertura SPAN y secretos. Texto sintetico."""
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
from dataclasses import asdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports as ge

from ot_assess import fuentes as fu
from ot_assess import i18n
from ot_assess.cli import main as main_capturas
from ot_assess.cli_diagrama import main
from ot_assess.switches import cisco_ios as ci
from ot_assess.switches import integracion as si

SECRETOS = ("0822455D0A16", "13061E010803", "Passw0rdPlano", "PublicTest", "PrivadaTest", "060506324F41",
            "070C285F4D06", "$9$FAKEHASH", "$9$XXXX", "3082032B", "FOC0000TEST", "usrprueba1", "usrprueba2",
            "usrprueba3")

CONFIG = """swtest-01#sh run
Building configuration...

Current configuration : 5321 bytes
!
version 17.15
service password-encryption
!
hostname swtest-01
!
enable secret 9 $9$FAKEHASH$abc
enable password 7 0822455D0A16
!
username usrprueba1 privilege 15 secret 9 $9$XXXX$yyy
username usrprueba2 privilege 1 password 7 13061E010803
username usrprueba3 password 0 Passw0rdPlano
!
snmp-server community PublicTest RO
snmp-server community PrivadaTest RW
tacacs-server host 192.0.2.50 key 7 060506324F41
!
banner motd ^C
interface GigabitEthernet9/9/9
 shutdown
^C
!
crypto pki certificate chain TP-self-signed-1
 certificate self-signed 01
  3082032B 30820213
  quit
!
vlan 4
 name Gestion
vlan 31-42
vlan 410
 name Planta_A
!
interface Port-channel1
 description Enlace a core
 switchport mode trunk
 switchport trunk allowed vlan 4,31-42,410
!
interface GigabitEthernet1/0/1
 description uplink
 switchport mode trunk
 switchport trunk native vlan 4
 switchport trunk allowed vlan 4,31-42
 switchport trunk allowed vlan add 410,411
 channel-group 1 mode active
!
interface GigabitEthernet1/0/5
 description PLC linea 1
 switchport access vlan 410
 switchport mode access
!
interface GigabitEthernet1/0/6
 description HMI
 switchport access vlan 31
 switchport mode access
!
interface GigabitEthernet1/0/7
 switchport access vlan 50
 switchport mode access
 shutdown
!
interface Loopback0
 ip address 203.0.113.9 255.255.255.255
!
interface Vlan4
 ip address 192.0.2.10 255.255.255.0
!
monitor session 1 source vlan 4 , 31 - 42
monitor session 1 destination interface Gi1/0/47 encapsulation replicate
monitor session 2 source interface Gi1/0/6 - 7 , Gi1/0/9 both
monitor session 2 destination interface Gi1/0/48
ip http server
ip http secure-server
!
line vty 0 4
 password 7 070C285F4D06
 transport input ssh
line vty 5 15
 transport input telnet ssh
!
end
"""
RESTO = """swtest-01#sh mac add
swtest-01#sh mac address-table
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
 All    ffff.ffff.ffff    STATIC      CPU
 410    aabb.cc00.0001    DYNAMIC     Gi1/0/1
 410    aabb.cc00.0001    DYNAMIC     Gi1/0/5
 410    aabb.cc00.0001    DYNAMIC     Po1
  31    aabb.cc00.0002    DYNAMIC     Gi1/0/6
 410    aabb.cc00.0009    DYNAMIC     Po1
  50    aabb.cc00.0004    DYNAMIC     Gi1/0/7
Total Mac Addresses for this criterion: 5
swtest-01#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Vlan4                  192.0.2.10      YES NVRAM  up                    up
GigabitEthernet1/0/5   unassigned      YES unset  up                    up
GigabitEthernet1/0/7   unassigned      YES unset  administratively down down
swtest-01#show interfaces description
Interface                      Status         Protocol Description
Gi1/0/1                        up             up       uplink
Gi1/0/5                        up             up       PLC linea 1
Gi1/0/7                        admin down     down
Po1                            up             up       Enlace a core
swtest-01#show cdp neighbors detail
-------------------------
Device ID: core-test.local
Entry address(es):
  IP address: 198.51.100.1
Platform: cisco C9300-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1
Holdtime : 150 sec
swtest-01#show inventory
NAME: "c9200L-48P-4X", DESCR: "Cisco Catalyst 9200L 48-port PoE+ 4x10G uplink Switch"
PID: C9200L-48P-4X, VID: V01  , SN: FOC0000TEST
swtest-01#show version
Cisco IOS XE Software, Version 17.15.01
swtest-01#show clock
*10:00:00.000 UTC Mon Nov 2 2026
swtest-01#
"""
SESION = CONFIG + RESTO


def _inv(nombre, ip, mac):
    return ["Ethernet", nombre, ip, mac, "Acme", "Net1", "OT", "Operator", "Acme", "HMI", "H100", "Windows", "10",
            "2026-11-02", "Low", 10, "N/A", "No", "N/A", "N/A", "N/A"]


class LectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sw = ci.leer(SESION, "sw.txt")

    def test_secciones_con_comandos_abreviados(self):
        secs, hosts, hubo = ci._secciones(ci._limpiar(SESION))
        self.assertTrue(hubo)
        self.assertEqual(set(hosts), {"swtest-01"})
        cmds = [c for c, _ in secs]
        self.assertEqual(cmds[:3], ["sh run", "sh mac add", "sh mac address-table"])
        self.assertEqual([ci._clase(c) for c in cmds],
                         ["config", "mac", "mac", "brief", "desc", "cdp", "inventario", "version", None])
        self.assertEqual(secs[1][1], [])                 # el eco abreviado no trae salida
        self.assertEqual(ci._clase("sho int desc"), "desc")
        self.assertEqual(ci._clase("show running-config | include vlan"), "config")
        self.assertIsNone(ci._clase("show ip route"))

    def test_rangos(self):
        self.assertEqual(ci.rango_vlans("4 , 31 - 42"), [4] + list(range(31, 43)))
        self.assertEqual(ci.rango_vlans("410,411,413,415"), [410, 411, 413, 415])
        self.assertEqual(ci.rango_vlans("70,72,100,110-111"), [70, 72, 100, 110, 111])
        self.assertEqual(ci._interfaces("Gi1/0/6 - 7 , Gi1/0/9 both"), ["Gi1/0/6", "Gi1/0/7", "Gi1/0/9"])
        self.assertEqual(si.comprimir([4] + list(range(31, 43))), "4;31-42")

    def test_modelo_basico(self):
        sw = self.sw
        self.assertEqual((sw.hostname, sw.modelo, sw.version), ("swtest-01", "C9200L-48P-4X", "17.15.01"))
        self.assertEqual(sw.vlans[4], "Gestion")
        self.assertEqual(sw.vlans[410], "Planta_A")
        self.assertIn(35, sw.vlans)
        self.assertEqual((sw.http, sw.vty_transport), ("http,https", ["ssh", "telnet"]))
        self.assertEqual([(s.vlan, s.ip, s.mascara) for s in sw.svis], [(4, "192.0.2.10", "255.255.255.0")])
        self.assertEqual([(v.id_equipo, v.ip, v.plataforma, v.interfaz, v.puerto_remoto) for v in sw.cdp],
                         [("core-test.local", "198.51.100.1", "cisco C9300-48P", "GigabitEthernet1/0/1",
                           "TenGigabitEthernet1/1/1")])
        self.assertNotIn("GigabitEthernet9/9/9", [p.nombre for p in sw.puertos])     # estaba dentro del banner

    def test_puertos(self):
        sw = self.sw
        p1 = sw.puerto("Gi1/0/1")
        self.assertEqual((p1.modo, p1.vlan_nativa, p1.canal, p1.trunk_todas), ("trunk", 4, 1, False))
        self.assertEqual(p1.vlans_trunk, [4] + list(range(31, 43)) + [410, 411])
        self.assertEqual(p1.estado, "up")
        p5 = sw.puerto("GigabitEthernet1/0/5")
        self.assertEqual((p5.modo, p5.vlan_acceso, p5.descripcion), ("access", 410, "PLC linea 1"))
        p7 = sw.puerto("Gi1/0/7")
        self.assertTrue(p7.apagado)
        self.assertEqual((p7.estado, p7.protocolo), ("admin down", "down"))
        self.assertEqual(sw.puerto("Po1").modo, "trunk")
        self.assertIsNone(sw.puerto("Loopback0"))

    def test_span_y_vlans_cubiertas(self):
        s1, s2 = self.sw.span
        self.assertEqual((s1.id, s1.destino), (1, "Gi1/0/47"))
        self.assertEqual(s1.vlans_origen, [4] + list(range(31, 43)))
        self.assertEqual((s2.interfaces_origen, s2.destino), (["Gi1/0/6", "Gi1/0/7", "Gi1/0/9"], "Gi1/0/48"))

    def test_tabla_mac_ignora_all_y_multicast(self):
        macs = self.sw.mac
        self.assertEqual(len(macs), 6)
        self.assertNotIn("All", [str(m[0]) for m in macs])
        self.assertIn((410, "aa:bb:cc:00:00:01", "Gi1/0/5"), macs)
        self.assertIn((410, "aa:bb:cc:00:00:01", "Po1"), macs)

    def test_conteo_de_credenciales(self):
        c = self.sw.credenciales
        self.assertEqual(c["tipo7"], 4)             # enable, usuario, llave tacacs, password de linea
        self.assertEqual((c["enable_password"], c["enable_secret"]), (1, 1))
        self.assertEqual((c["secret9"], c["tipo0"], c["usuario_local"]), (2, 1, 3))
        self.assertEqual((c["snmp_community"], c["snmp_rw"], c["aaa_key"]), (2, 1, 1))
        self.assertEqual((c["certificado_pki"], c["password_linea"]), (1, 1))

    def test_sin_secretos_en_el_modelo(self):
        for sw in (self.sw, ci.leer(CONFIG, "solo.txt")):
            volcado = json.dumps(asdict(sw), default=str)
            for s in SECRETOS:
                self.assertNotIn(s, volcado, s)

    def test_config_sin_prompts_y_basura(self):
        sw = ci.leer(CONFIG.split("\n", 1)[1], "solo.txt")
        self.assertEqual(sw.hostname, "swtest-01")
        self.assertEqual(sw.vlans[410], "Planta_A")
        malo = ci.leer("esto no es una sesion de switch", "x.txt")
        self.assertTrue(malo.avisos)
        self.assertEqual(malo.hostname, "x")


LIMPIO = """swh-01#show running-config
hostname swh-01
aaa new-model
tacacs server T1
 address ipv4 192.0.2.50
enable secret 9 $9$LIMPIOHASH$abc
username usrlimpio secret 9 $9$LIMPIOHASH$def
ip dhcp snooping
ip dhcp snooping vlan 20
ip arp inspection vlan 20
vlan 20
!
interface GigabitEthernet1/0/1
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 99
 switchport trunk allowed vlan 20
!
interface GigabitEthernet1/0/2
 switchport access vlan 20
 switchport mode access
 switchport port-security
 storm-control broadcast level 1.00
 spanning-tree bpduguard enable
!
interface Vlan20
 ip address 192.0.2.77 255.255.255.0
!
monitor session 1 source vlan 20
monitor session 1 destination interface Gi1/0/47
ip http secure-server
line vty 0 15
 transport input ssh
!
end
swh-01#show mac address-table
Vlan    Mac Address       Type        Ports
 20    aabb.cc00.0010    DYNAMIC     Gi1/0/2
swh-01#
"""


def _quitar(texto, *lineas):
    out = texto
    for ln in lineas:
        assert ln in out, ln
        out = out.replace(ln, "")
    return out


class HigieneTest(unittest.TestCase):
    """SW1b: cada hallazgo aparece con su caso y no aparece sin el."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hall(self, texto):
        from ot_assess.model import Capture
        from ot_assess.switches import higiene as hg
        a = self.tmp / "s.txt"
        a.write_text(texto, encoding="utf-8")
        res = si.integrar([str(a)], {})
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, res)
        return {f["titulo"]: f for f in cap.findings}

    def test_limpio_no_da_ningun_hallazgo(self):
        self.assertEqual(self.hall(LIMPIO), {})

    def test_todos_los_hallazgos_en_el_caso_completo(self):
        from ot_assess.switches import higiene as hg
        h = self.hall(SESION)
        self.assertEqual(set(h), {x for x in hg.TITULOS if x not in (   # sin puerto down ni estado
            hg.TIT_PUERTOS, hg.TIT_STP, hg.TIT_BUCLE, hg.TIT_DESCARTES, hg.TIT_HORA, hg.TIT_RAIZ)})
        self.assertEqual(h[hg.TIT_SIN_ESPEJO]["severidad"], "Baja")
        self.assertIn("swtest-01: VLAN 410 (Planta_A), 2 MAC", h[hg.TIT_SIN_ESPEJO]["evidencia"])
        self.assertEqual(h[hg.TIT_GESTION]["severidad"], "Media")
        self.assertIn("telnet", h[hg.TIT_GESTION]["evidencia"])
        self.assertIn("ip http server", h[hg.TIT_GESTION]["evidencia"])
        self.assertEqual(h[hg.TIT_CRED]["severidad"], "Media")
        self.assertEqual(h[hg.TIT_AAA]["activos"], ["192.0.2.10"])         # IP de gestion (SVI)
        for f in h.values():
            self.assertEqual(f["activos"], ["192.0.2.10"])
            self.assertIn(f["categoria"], ("Visibilidad", "Higiene", "Segmentacion"))

    def test_sin_espejo_desaparece_si_la_vlan_se_espeja(self):
        from ot_assess.switches import higiene as hg
        base = LIMPIO.replace("monitor session 1 source vlan 20\n", "")
        self.assertIn(hg.TIT_SIN_ESPEJO, self.hall(base))
        self.assertNotIn(hg.TIT_SIN_ESPEJO, self.hall(LIMPIO))

    def test_gestion_http_y_telnet(self):
        from ot_assess.switches import higiene as hg
        solo_seguro = _quitar(SESION, "ip http server\n").replace("transport input telnet ssh", "transport input ssh")
        self.assertNotIn(hg.TIT_GESTION, self.hall(solo_seguro))
        con_http = LIMPIO.replace("ip http secure-server", "ip http server")
        self.assertIn(hg.TIT_GESTION, self.hall(con_http))
        con_todo = LIMPIO.replace("transport input ssh", "transport input all")
        self.assertIn("transport input all", self.hall(con_todo)[hg.TIT_GESTION]["evidencia"])
        self.assertNotIn(hg.TIT_GESTION, self.hall(LIMPIO.replace("transport input ssh", "transport input ssh")))

    def test_credenciales_enable_secret_no_cuenta(self):
        from ot_assess.switches import higiene as hg
        self.assertNotIn(hg.TIT_CRED, self.hall(LIMPIO))
        pw7 = LIMPIO.replace("enable secret 9 $9$LIMPIOHASH$abc", "enable password 7 0822455D0A16")
        ev = self.hall(pw7)[hg.TIT_CRED]["evidencia"]
        self.assertIn("enable password", ev)
        self.assertIn("tipo 7", ev)
        txt = LIMPIO.replace("secret 9 $9$LIMPIOHASH$def", "password 0 Passw0rdPlano")
        self.assertIn("texto sin cifrar", self.hall(txt)[hg.TIT_CRED]["evidencia"])
        linea = LIMPIO.replace("transport input ssh", "password 7 070C285F4D06\n transport input ssh")
        self.assertIn(hg.TIT_CRED, self.hall(linea))

    def test_aaa_local(self):
        from ot_assess.switches import higiene as hg
        self.assertNotIn(hg.TIT_AAA, self.hall(LIMPIO))
        sin_modelo = LIMPIO.replace("aaa new-model\n", "no aaa new-model\n")
        ev = self.hall(sin_modelo)[hg.TIT_AAA]["evidencia"]
        self.assertIn("aaa new-model no", ev)
        self.assertNotIn("usrlimpio", ev)
        sin_srv = _quitar(LIMPIO, "tacacs server T1\n address ipv4 192.0.2.50\n")
        self.assertIn(hg.TIT_AAA, self.hall(sin_srv))
        sin_usuarios = _quitar(sin_srv, "username usrlimpio secret 9 $9$LIMPIOHASH$def\n")
        self.assertNotIn(hg.TIT_AAA, self.hall(sin_usuarios))

    def test_puertos_sin_uso(self):
        from ot_assess.switches import higiene as hg
        estado = ("swh-01#show interfaces description\nInterface Status Protocol Description\n"
                  "Gi1/0/2 up up\nGi1/0/3 down down\nGi1/0/4 down down\nGi1/0/5 down down\nGi1/0/47 down down\n"
                  "Gi1/0/1 down down\n")
        extra = ("interface GigabitEthernet1/0/3\n switchport access vlan 20\n switchport mode access\n"
                 "interface GigabitEthernet1/0/4\n switchport access vlan 20\n switchport mode access\n shutdown\n"
                 "interface GigabitEthernet1/0/5\n switchport mode trunk\n"
                 "interface GigabitEthernet1/0/47\n switchport access vlan 20\n switchport mode access\n")
        base = LIMPIO.replace("!\nend\n", extra + "!\nend\n") + estado
        ev = self.hall(base)[hg.TIT_PUERTOS]["evidencia"]
        self.assertIn("Puertos: 1.", ev)
        self.assertIn("Gi", ev.split("swh-01:")[1])
        self.assertIn("GigabitEthernet1/0/3", ev)
        for no in ("1/0/4", "1/0/5", "1/0/47", "1/0/1,"):       # shutdown, trunk, destino SPAN
            self.assertNotIn(no, ev)
        self.assertNotIn(hg.TIT_PUERTOS, self.hall(LIMPIO + estado))

    def test_vlan1(self):
        from ot_assess.switches import higiene as hg
        nativa = LIMPIO.replace(" switchport trunk native vlan 99\n", "")
        ev = self.hall(nativa)[hg.TIT_VLAN1]["evidencia"]
        self.assertIn("trunks con VLAN nativa 1: GigabitEthernet1/0/1", ev)
        acceso = LIMPIO.replace(" 20    aabb.cc00.0010", "  1    aabb.cc00.0010")
        self.assertIn("equipos en VLAN 1: GigabitEthernet1/0/2", self.hall(acceso)[hg.TIT_VLAN1]["evidencia"])
        self.assertNotIn(hg.TIT_VLAN1, self.hall(LIMPIO))

    def test_sin_running_config_no_inventa_hallazgos_de_configuracion(self):
        from ot_assess.switches import higiene as hg
        solo_mac = LIMPIO.split("swh-01#show mac address-table")[1]
        h = self.hall("swh-01#show mac address-table" + solo_mac)
        self.assertEqual(set(h) & {hg.TIT_GESTION, hg.TIT_CRED, hg.TIT_AAA, hg.TIT_PUERTOS, hg.TIT_VLAN1}, set())

    def test_ninguna_evidencia_trae_credenciales(self):
        h = self.hall(SESION)
        volcado = json.dumps(h, ensure_ascii=False)
        for s in SECRETOS:
            self.assertNotIn(s, volcado, s)

    def test_marcos_playbooks_y_plan(self):
        from ot_assess import playbooks
        from ot_assess import standards as st
        from ot_assess.switches import higiene as hg
        esperado = {hg.TIT_SIN_ESPEJO: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "tsa-sd-1580-82"},
                    hg.TIT_GESTION: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "mitre-ics", "tsa-sd-1580-82"},
                    hg.TIT_CRED: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "mitre-ics"},
                    hg.TIT_AAA: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "tsa-sd-1580-82"},
                    hg.TIT_PUERTOS: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "tsa-sd-1580-82"},
                    hg.TIT_VLAN1: {"iec62443", "nerc-cip", "nist-800-82", "nist-csf", "tsa-sd-1580-82"}}
        for tit, claves in esperado.items():
            self.assertEqual(set(st.referencias(tit)), claves, tit)
            self.assertTrue(playbooks.para_titulo(tit), tit)
            pb = playbooks.cargar()[playbooks.para_titulo(tit)]
            self.assertIn("Switch Cisco IOS/IOS-XE", pb["por_plataforma"])
        self.assertIn("Claroty xDome", playbooks.cargar()["pb-switch-sin-espejo"]["por_plataforma"])
        self.assertEqual(st.referencias(hg.TIT_GESTION)["mitre-ics"], "T0842 Network Sniffing; T0886 Remote Services")
        self.assertEqual(st.referencias(hg.TIT_CRED)["mitre-ics"], "T0859 Valid Accounts")


class IntegracionCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        ge.escribir_xlsx(cls.tmp / "inv.xlsx", [
            ge.XD_INVENTARIO,
            _inv("PLC-1", "10.10.2.20", "aa:bb:cc:00:00:01"),
            _inv("HMI-1", "10.10.1.10", "aa:bb:cc:00:00:02"),
            _inv("SRV-1", "10.10.3.30", "aa:bb:cc:00:00:03")])
        cls.inv = cls.tmp / "inv.xlsx"
        cls.enl = ge.xd_escribir_comunicaciones(cls.tmp / "enl.csv", [
            ge.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502, "Modbus", "2026-11-02", 100),
            ge.xd_fila("10.10.1.10", "10.10.3.30", "From A to B", 445, "SMB", "2026-11-02", 50)])
        cls.sw = cls.tmp / "swtest.txt"
        cls.sw.write_text(SESION, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        i18n.usar("es")

    def _cli(self, nombre, *extra):
        out = self.tmp / nombre
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--activos", str(self.inv), "--enlaces", str(self.enl), "-o", str(out), *extra])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    @staticmethod
    def _csv(p):
        with open(p, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def test_ubicacion_por_mac_gana_el_puerto_de_acceso(self):
        out, txt = self._cli("u", "--switch", str(self.sw))
        self.assertIn("2 de 3 activos con MAC ubicados", txt)
        inv = {f["nombre"]: f for f in self._csv(out / "inventario_importado.csv")}
        self.assertEqual((inv["PLC-1"]["switch_puerto"], inv["PLC-1"]["vlan"]),
                         ("swtest-01:GigabitEthernet1/0/5", "410"))     # tambien esta en Po1 (trunk)
        self.assertEqual(inv["HMI-1"]["vlan"], "31")
        self.assertEqual((inv["SRV-1"]["switch_puerto"], inv["SRV-1"]["vlan"]), ("", ""))

    def test_tablas_de_puertos_vlans_y_span(self):
        out, _ = self._cli("t", "--switch", str(self.sw))
        pto = {f["puerto"]: f for f in self._csv(out / "switch_puertos.csv")}
        self.assertEqual(pto["GigabitEthernet1/0/5"]["activos"], "PLC-1")
        self.assertEqual(pto["GigabitEthernet1/0/5"]["vlans"], "410")
        self.assertEqual(pto["Port-channel1"]["macs"], "aa:bb:cc:00:00:01;aa:bb:cc:00:00:09")
        self.assertEqual(pto["Port-channel1"]["activos"], "")          # PLC-1 esta en su puerto de acceso
        self.assertEqual(pto["GigabitEthernet1/0/5"]["fabricantes"], "Acme")
        self.assertEqual(pto["GigabitEthernet1/0/1"]["vlans"], "4;31-42;410-411 (nativa 4)")
        self.assertEqual(pto["GigabitEthernet1/0/7"]["estado"], "admin down")
        vl = {int(f["vlan"]): f for f in self._csv(out / "switch_vlans.csv")}
        self.assertEqual((vl[410]["espejada_span"], vl[410]["macs"], vl[410]["marcas"]), ("no", "2", "VLAN sin espejo"))
        self.assertEqual((vl[410]["nombre"], vl[410]["puertos_acceso"]), ("Planta_A", "GigabitEthernet1/0/5"))
        self.assertEqual((vl[31]["espejada_span"], vl[31]["sesion"], vl[31]["marcas"]), ("si", "1", ""))
        self.assertEqual((vl[50]["espejada_span"], vl[50]["sesion"]), ("parcial", "2"))
        self.assertEqual(vl[4]["espejada_span"], "si")
        self.assertEqual(vl[4]["marcas"], "")                          # sin MAC no hay marca
        span = self._csv(out / "switch_span.csv")
        self.assertEqual(span[0]["vlans_cubiertas"], "4;31-42")
        self.assertEqual((span[0]["destino"], span[0]["sesion"]), ("Gi1/0/47", "1"))
        self.assertEqual(span[1]["vlans_parciales"], "31;50")

    def test_hojas_y_secciones_de_reporte(self):
        out, _ = self._cli("r", "--switch", str(self.sw))
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            libro = z.read("xl/workbook.xml").decode("utf-8")
        for hoja in ("Switch puertos", "Switch VLAN", "Switch SPAN"):
            self.assertIn(hoja, libro)
        self.assertIn("<h2>Switches</h2>", (out / "reporte_ot.html").read_text(encoding="utf-8"))
        md = (out / "reporte_ot.md").read_text(encoding="utf-8")
        self.assertIn("## Switches", md)
        self.assertIn("VLAN sin espejo", md)
        with zipfile.ZipFile(out / "informe_ot.docx") as z:
            self.assertIn("Switches", z.read("word/document.xml").decode("utf-8"))
        js = json.loads((out / "resultado.json").read_text(encoding="utf-8"))["switches"]
        self.assertEqual(js["sin_espejo"], [{"switch": "swtest-01", "vlan": 410, "macs": 2}])
        self.assertEqual(js["switches"][0]["credenciales"]["tipo7"], 4)

    def test_sin_switch_no_hay_nada_nuevo(self):
        out, _ = self._cli("n")
        self.assertFalse((out / "switch_puertos.csv").exists())
        self.assertNotIn("switch_puerto", (out / "inventario_importado.csv").read_text(encoding="utf-8-sig"))
        self.assertNotIn("Switches", (out / "reporte_ot.md").read_text(encoding="utf-8"))

    def test_ningun_secreto_en_ninguna_salida(self):
        out, txt = self._cli("s", "--switch", str(self.sw))
        total = 0
        for f in out.rglob("*"):
            if not f.is_file():
                continue
            datos = f.read_bytes()
            if zipfile.is_zipfile(f):
                with zipfile.ZipFile(f) as z:
                    datos = b"".join(z.read(n) for n in z.namelist())
            for s in SECRETOS:
                self.assertNotIn(s.encode(), datos, f"{s} en {f.name}")
            total += 1
        self.assertGreater(total, 10)
        for s in SECRETOS:
            self.assertNotIn(s, txt)

    def test_archivo_inexistente_es_error(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            main(["--activos", str(self.inv), "--enlaces", str(self.enl), "-o", str(self.tmp / "e"),
                  "--switch", str(self.tmp / "no.txt")])

    def test_dos_switches_el_acceso_gana_al_trunk_de_otro(self):
        core = self.tmp / "core.txt"
        core.write_text("core-01#show mac address-table\n"
                        "Vlan    Mac Address       Type        Ports\n"
                        " 410    aabb.cc00.0001    DYNAMIC     Te1/1/1\n"
                        " 410    aabb.cc00.0003    DYNAMIC     Te1/1/1\n"
                        "core-01#show cdp neighbors detail\n"
                        "Device ID: swtest-01\n"
                        "Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): Port-channel1\n",
                        encoding="utf-8")
        out, _ = self._cli("d", "--switch", str(core), "--switch", str(self.sw))
        inv = {f["nombre"]: f for f in self._csv(out / "inventario_importado.csv")}
        self.assertEqual(inv["PLC-1"]["switch_puerto"], "swtest-01:GigabitEthernet1/0/5")
        # SRV-1 solo se ve en el core, en un puerto con vecino CDP: se ubica ahi igual
        self.assertEqual(inv["SRV-1"]["switch_puerto"], "core-01:Te1/1/1")

    def test_idioma_en_sin_palabras_espanolas(self):
        i18n.FALTANTES.clear()
        out, _ = self._cli("en", "--switch", str(self.sw), "--idioma", "en")
        self.assertEqual(i18n.FALTANTES, set())
        i18n.usar("es")
        self.assertIn("<h2>Switches</h2>", (out / "reporte_ot.html").read_text(encoding="utf-8"))
        vl = {int(f["vlan"]): f for f in self._csv(out / "switch_vlans.csv")}
        self.assertEqual(vl[410]["flags"], "VLAN not mirrored")        # cabeceras traducidas
        self.assertEqual(vl[50]["mirrored_by_span"], "partial")
        self.assertEqual(vl[31]["mirrored_by_span"], "yes")
        self.assertIn("(native 4)", (out / "switch_puertos.csv").read_text(encoding="utf-8-sig"))

    def test_cobertura_de_fuentes_por_espejo(self):
        d = self.tmp / "flujos"
        d.mkdir()
        a = ge.xd_escribir_comunicaciones(d / "a.csv", [ge.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 502,
                                                                   "Modbus", "2026-11-02", 100)])
        out, _ = self._cli("f", "--fuente-flujos", f"IT={a}", "--switch", str(self.sw))
        filas = self._csv(out / "fuentes_cobertura.csv")
        self.assertIn("espejo_switch", filas[0])
        self.assertEqual({f["espejo_switch"] for f in filas if f["segmento"] == "10.10.2.0/24"}, {"no"})
        self.assertEqual({f["espejo_switch"] for f in filas if f["segmento"] == "10.10.1.0/24"}, {"si"})
        out2, _ = self._cli("f2", "--fuente-flujos", f"IT={a}")
        self.assertEqual({f["espejo_switch"] for f in self._csv(out2 / "fuentes_cobertura.csv")}, {""})
        self.assertEqual(fu.COL_COBERTURA[-1], "espejo_switch")

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_cli_de_capturas(self):
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("requiere scapy")
        import gen_pcaps
        sys.argv = ["gen", str(self.tmp / "pcaps")]
        gen_pcaps.main()
        sw = self.tmp / "cap_sw.txt"
        sw.write_text("capsw#show mac address-table\n"
                      "Vlan    Mac Address       Type        Ports\n"
                      "  20    0000.bc00.0020    DYNAMIC     Gi1/0/3\n"
                      "capsw#show running-config\n"
                      "interface GigabitEthernet1/0/3\n switchport access vlan 20\n switchport mode access\n",
                      encoding="utf-8")
        out = self.tmp / "cap_out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_capturas([str(self.tmp / "pcaps"), "-o", str(out), "--switch", str(sw)]), 0)
        inv = {f["mac"]: f for f in self._csv(out / "inventario.csv")}
        self.assertEqual((inv["00:00:bc:00:00:20"]["switch_puerto"], inv["00:00:bc:00:00:20"]["vlan"]),
                         ("capsw:GigabitEthernet1/0/3", "20"))
        self.assertTrue((out / "switch_vlans.csv").exists())


if __name__ == "__main__":
    unittest.main()
