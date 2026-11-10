"""AR1 (D98): lector de la CLI de Aruba AOS-CX como fuente de switch. Sesiones sinteticas (nombres inventados,
MAC localmente administradas salvo la del activo de gen_pcaps)."""
from __future__ import annotations

import contextlib
import io
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

from ot_assess.cli import main as main_capturas
from ot_assess.model import Capture
from ot_assess.switches import aruba_cx as ax
from ot_assess.switches import cisco_ios as ci
from ot_assess.switches import higiene as hg
from ot_assess.switches import integracion as si

H = "sw-aoscx01"
ACTIVO = "00:00:bc:00:00:20"       # la de gen_pcaps
COMUNIDAD = "comunidad-secreta-77"
CLAVE = "AQBapXXsecretoXXcifrado=="

SYSTEM = """Hostname               : sw-aoscx01
System Description     : FL.10.13.1101
Vendor                 : Aruba
Product Name           : JL665A 6300F 48G CL4 PoE 4SFP56 Sw
Chassis Serial Nbr     : SYN0000001
Base MAC Address       : 020000-000001
ArubaOS-CX Version     : FL.10.13.1101
"""
VERSION = """-----------------------------------------------------------------------------
ArubaOS-CX
(c) Copyright 2017-2022 Hewlett Packard Enterprise Development LP
-----------------------------------------------------------------------------
Version      : FL.10.13.1101
Build Date   : 2022-05-25 10:22:06 UTC
"""
TABLA = """ Statistic                          RX                   TX                Total
 ---------------- -------------------- -------------------- --------------------
 Packets                      %(pk)s             39673355             64285454
   Unicast                    24608471             25244890             49853361
   Broadcast                         7                    0                    7
 Dropped                             0                   %(dr)s                    0
 Errors                      %(er)s                    0                    0
   CRC/FCS                    %(crc)s                  n/a                    0
"""
INTERFACES = """Interface 1/1/1 is up
 Admin state is up
 Link transitions: 9
 Description: PLC planta
 Speed 1000 Mb/s
 VLAN Mode: access
 Access VLAN: 20
 Rate collection interval: 300 seconds

 Rate                               RX                   TX        Total (RX+TX)
 ---------------- -------------------- -------------------- --------------------
 Broadcast                        9.00                 0.00                 0.00

""" + TABLA % {"pk": "24612099", "dr": "0", "er": "0", "crc": "0"} + """
Interface 1/1/2 is down (Administratively down)
 Admin state is down
 Description : 'Libre'
 VLAN Mode: access
 Access VLAN: 10

Interface 1/1/3 is up
 Admin state is up
 Description:
 Speed 10000 Mb/s
 VLAN Mode: native-untagged
 Native VLAN: 1
 Allowed VLAN List: 10,20-22

Interface 1/1/4 is up
 Admin state is up
 Description: Camara
 VLAN Mode: access
 Access VLAN: 10
""" + TABLA % {"pk": "%(pk)s", "dr": "0", "er": "%(er)s", "crc": "%(crc)s"} + """
Aggregate lag7 is up
 Admin state is up
 Description :
 MAC Address                 : 02:00:00:00:00:07
 Aggregated-interfaces       : 1/1/51 1/1/52
 Speed                       : 2000 Mb/s
 L3 Counters: Rx Disabled, Tx Disabled
 VLAN Mode: native-tagged
 Native VLAN: 1
 Allowed VLAN List: all

Interface vlan10 is up
 Admin state is up
 Description: Gestion
 IPv4 address 192.0.2.1/24
 L3 Counters: Rx Disabled, Tx Disabled

Interface 1/1/9 is up
 Admin state is up
 L3 Counters: Rx Enabled, Tx Enabled

Interface mgmt is up
 Admin state is up
 IPv4 address 198.51.100.5/24
"""
VLAN = """----------------------------------------------------------------------------------
VLAN  Name                 Status  Reason        Type      Interfaces
----------------------------------------------------------------------------------
1     DEFAULT_VLAN_1       up      ok            default   1/1/3,lag7
10    Gestion Planta       up      ok            static    1/1/2-1/1/4,
                                                           lag1-lag2
20    Procesos             up      ok            static    1/1/1,1/1/3
"""
MAC = """MAC age-time            : 300 seconds
Number of MAC addresses : 6

MAC Address          VLAN     Type                      Port
--------------------------------------------------------------
%(a)s    20       dynamic                   1/1/1
%(a)s    20       dynamic                   1/1/3
%(a)s    20       dynamic                   lag7
02:00:00:00:00:10    10       dynamic                   1/1/4
02:00:00:00:00:99    3        hsc                       vxlan1(10.1.1.1)
"""
LLDP = """LLDP Neighbor Information
=========================

Total Neighbor Entries          : 1

--------------------------------------------------------------------------------
Port                           : 1/1/3
Neighbor Entries               : 1
Neighbor %(n)s-Name          : sw-core-02
Neighbor %(n)s-Description   : Switch sintetico de nucleo
Neighbor Chassis-ID            : 02:00:00:00:00:c2
Neighbor Management-Address    : 192.0.2.2
Neighbor Port-ID               : 1/1/48
Neighbor Port-Desc             : enlace
TTL                            : 120
"""
MIRROR_RES = """ID  Admin Status  Operation Status
--- ------------- ----------------------------------------------------
1   enable        enabled
2   disable       disabled
"""
MIRROR1 = """ Mirror Session: 1
 Admin Status: enable
 Operation Status: enabled
 Comment: prueba
 Source: vlan 20 rx
 Source: interface 1/1/4 both
 Source: interface rx-filter none
 Destination: interface 1/1/48
"""
MIRROR2 = """ Mirror Session: 2
 Admin Status: disable
 Operation Status: disabled
 Source: vlan 10 both
 Destination: interface 1/1/47
"""
STP = """Spanning tree status      : Enabled Protocol: MSTP

MST0
  Root ID
    Priority      : %(pr)s, Root
    MAC-Address   : 02:00:00:00:00:AA
    Hello time(in seconds):2   Max Age(in seconds):20
    Forward Delay(in seconds):15

  Bridge ID
    Priority      : %(pr)s
    MAC-Address   : 02:00:00:00:00:AA
    Hello time(in seconds):2   Max Age(in seconds):20

PORT     ROLE        STATE      COST       PRIORITY  TYPE      BPDU-Tx    BPDU-Rx    TCN-Tx     TCN-Rx
-------- ----------- ---------- ---------- --------- --------- ---------- ---------- ---------- ----------
1/1/1    Designated  Forwarding 20000      128       P2P Edge  100        60         20         10

Number of topology changes    : 4
Last topology change occurred : 516 seconds ago
"""
RPVST = """Spanning tree status           : Enabled Protocol: RPVST

VLAN1
  Root ID    Priority   : 32768
             MAC-Address: 02:00:00:00:00:aa
             This bridge is the root
             Hello time(in seconds):2  Max Age(in seconds):20

  Bridge ID  Priority  : 32768
             MAC-Address: 02:00:00:00:00:aa

Number of topology changes    : 1
Last topology change occurred : 30 seconds ago

VLAN10
  Root ID    Priority   : 24576
             MAC-Address: 02:00:00:00:00:bb
             Hello time(in seconds):2  Max Age(in seconds):20

  Bridge ID  Priority  : 32768
             MAC-Address: 02:00:00:00:00:aa
"""
CONFIG = """Current configuration:
!
!Version ArubaOS-CX FL.10.13.1101
hostname sw-aoscx01
user usuario-secreto-x group administrators password ciphertext %(c)s
tacacs-server host 10.42.0.11 key ciphertext %(c)s
snmpv3 user lector-secreto-y auth sha auth-pass ciphertext %(c)s priv des priv-pass ciphertext %(c)s
snmp-server community %(s)s
    access-level rw
snmp-server host 10.7.32.31 trap version v2c community %(s)s
mirror session 1
    source interface lag45 rx
interface 1/1/1
    vlan access 498
"""


def cmd(c, cuerpo, host=H):
    return f"{host}# {c}\n{cuerpo}"


def sesion(mirror=True, stp=None, interfaces=None, lldp="System", extra="", cfg=False, mac=True):
    p = [f"Last login: 2026-04-15 06:55:16\n{H}# no page\n",
         cmd("show system", SYSTEM), cmd("show version", VERSION),
         cmd("show interface", interfaces or INTERFACES % {"pk": "24612099", "er": "0", "crc": "0"}),
         cmd("show vlan", VLAN)]
    if mac:
        p.append(cmd("show mac-address-table", MAC % {"a": ACTIVO}))
    p.append(cmd("show lldp neighbor-info detail", LLDP % {"n": lldp}))
    if mirror:
        p += [cmd("show mirror", MIRROR_RES), cmd("show mirror 1", MIRROR1), cmd("show mirror 2", MIRROR2)]
    p.append(cmd("show spanning-tree", STP % {"pr": "32768"} if stp is None else stp))
    if cfg:
        p.append(cmd("show running-config", CONFIG % {"c": CLAVE, "s": COMUNIDAD}))
    p.append(extra)
    return "".join(p) + f"{H}# "


def con_contadores(pk="1000000", er="5000", crc="5000"):
    return INTERFACES.replace("%(pk)s", pk).replace("%(er)s", er).replace("%(crc)s", crc)


class LectorTest(unittest.TestCase):
    def test_sesion_completa(self):
        sw = ax.leer(sesion(), "s.txt")
        self.assertEqual((sw.hostname, sw.origen, sw.config), (H, "aoscx", False))
        self.assertEqual(sw.modelo, "JL665A 6300F 48G CL4 PoE 4SFP56 Sw")
        self.assertEqual(sw.version, "FL.10.13.1101")
        p = {x.nombre: x for x in sw.puertos}
        self.assertEqual((p["1/1/1"].estado, p["1/1/1"].protocolo, p["1/1/1"].modo, p["1/1/1"].vlan_acceso,
                          p["1/1/1"].descripcion), ("up", "up", "access", 20, "PLC planta"))
        self.assertEqual((p["1/1/2"].estado, p["1/1/2"].apagado, p["1/1/2"].descripcion),
                         ("admin down", True, "Libre"))
        self.assertEqual((p["1/1/3"].modo, p["1/1/3"].vlan_nativa, p["1/1/3"].vlans_trunk, p["1/1/3"].trunk_todas),
                         ("trunk", 1, [10, 20, 21, 22], False))
        self.assertEqual((p["lag7"].modo, p["lag7"].trunk_todas), ("trunk", True))
        self.assertEqual((p["1/1/51"].canal, p["1/1/52"].canal, p["lag7"].canal, p["1/1/1"].canal), (7, 7, 7, None))
        self.assertEqual(p["1/1/9"].modo, "routed")
        self.assertNotIn("mgmt", p)
        self.assertNotIn("vlan10", p)
        self.assertEqual([(s.vlan, s.ip, s.mascara) for s in sw.svis], [(10, "192.0.2.1", "255.255.255.0")])
        self.assertEqual(sw.vlans, {1: "DEFAULT_VLAN_1", 10: "Gestion Planta", 20: "Procesos"})
        self.assertNotIn("02:00:00:00:00:99", [m for _v, m, _p in sw.mac])
        self.assertEqual(sorted((v, pt) for v, _m, pt in sw.mac), [(10, "1/1/4"), (20, "1/1/1"), (20, "1/1/3"),
                                                                    (20, "lag7")])
        self.assertEqual([(v.id_equipo, v.ip, v.interfaz, v.puerto_remoto, v.plataforma) for v in sw.cdp],
                         [("sw-core-02", "192.0.2.2", "1/1/3", "1/1/48", "Switch sintetico de nucleo")])
        self.assertEqual([(s.id, s.vlans_origen, s.interfaces_origen, s.destino) for s in sw.span],
                         [(1, [20], ["1/1/4"], "1/1/48")])
        self.assertTrue(any("sesion de espejo 2 sin efecto" in a for a in sw.avisos))
        c = sw.stp[0]
        self.assertEqual((c.instancia, c.raiz, c.prioridad, c.puente, c.cambios, c.hace_s),
                         ("MST0", "local", 32768, "02:00:00:00:00:aa", 4, 516))
        self.assertEqual(set(sw.leyo), {"interfaces", "espejo", "stp"})

    def test_clave_if_estable(self):
        self.assertEqual((ci.clave_if("1/1/1"), ci.clave_if("lag7"), ci.clave_if("Lag7")), ("1/1/1", "lag7", "lag7"))

    def test_abreviaturas(self):
        t = ("sw# sh int\nInterface 1/1/1 is up\n Admin state is up\n VLAN Mode: access\n Access VLAN: 5\n"
             "sw# sh mac-address-table\n00:00:bc:00:00:20  5  dynamic  1/1/1\n"
             "sw# sh lldp nei det\nPort : 1/1/1\nNeighbor Chassis-Name : x\n"
             "sw(config)# do show vlan\n5     V5  up  ok  static  1/1/1\nsw#sh mirror\nID  Admin Status  Operation Status\n")
        sw = ax.leer(t, "x.txt")
        self.assertEqual((sw.puertos[0].vlan_acceso, len(sw.mac), len(sw.cdp), sw.vlans, "espejo" in sw.leyo),
                         (5, 1, 1, {5: "V5"}, True))

    def test_lldp_system_y_chassis_dan_el_mismo_vecino(self):
        a = ax.leer(sesion(lldp="System"), "a.txt").cdp
        b = ax.leer(sesion(lldp="Chassis"), "a.txt").cdp
        self.assertEqual([asdict(x) for x in a], [asdict(x) for x in b])
        self.assertEqual(len(a), 1)

    def test_lldp_tabla_y_detalle_sin_duplicar(self):
        tabla = ("LOCAL-PORT  CHASSIS-ID         PORT-ID       PORT-DESC     TTL      SYS-NAME\n"
                 "------------------------------------------------------------------------------\n"
                 "1/1/3       02:00:00:00:00:c2  1/1/48        enlace        120      sw-core-02\n"
                 "1/1/7       02:00:00:00:00:c3  1/1/7                       120      \n")
        solo = ax.leer(cmd("show lldp neighbor-info", tabla), "x.txt").cdp
        self.assertEqual([(v.id_equipo, v.interfaz, v.puerto_remoto) for v in solo],
                         [("sw-core-02", "1/1/3", "1/1/48"), ("02:00:00:00:00:c3", "1/1/7", "1/1/7")])
        ambos = ax.leer(cmd("show lldp neighbor-info", tabla)
                        + cmd("show lldp neighbor-info detail", LLDP % {"n": "System"}), "x.txt").cdp
        self.assertEqual(sorted((v.id_equipo, v.ip) for v in ambos),
                         [("02:00:00:00:00:c3", ""), ("sw-core-02", "192.0.2.2")])

    def test_cdp(self):
        t = cmd("show cdp neighbor-info", "Port        Device ID                Platform                 Capability\n"
                "-------------------------------------------------------------------------------\n"
                "1/1/1       myswitch                 cisco WS-C2950-12        SI\n")
        v = ax.leer(t, "x.txt").cdp
        self.assertEqual([(x.id_equipo, x.plataforma, x.interfaz) for x in v], [("myswitch", "cisco WS-C2950-12", "1/1/1")])

    def test_paginador_y_crlf_no_cambian_nada(self):
        base = ax.leer(sesion(), "s.txt")
        txt = sesion().replace(f"{H}# show vlan", "-- MORE --, next page: Space, next line: Enter, quit: q\n"
                               f"{H}# show vlan")
        txt = txt.replace("10    Gestion", "-- MORE --, next page: Space, next line: Enter, quit: q\r\n10    Gestion")
        txt = txt.replace("\n", "\r\n").replace("   \r\n", "\r\n")
        otro = ax.leer(txt, "s.txt")
        self.assertEqual(asdict(base), asdict(otro))

    def test_contadores_y_formatos(self):
        sw = ax.leer(sesion(interfaces=con_contadores()), "s.txt")
        c = next(x for x in sw.contadores if x.puerto == "1/1/4")
        self.assertEqual((c.paquetes, c.errores, c.crc, c.broadcast, c.paquetes_salida, c.descartes),
                         (1000000, 5000, 5000, 7, 39673355, 0))
        c1 = next(x for x in sw.contadores if x.puerto == "1/1/1")
        self.assertEqual((c1.bw_kbit, c1.crc, c1.descartes), (1000000, 0, 0))     # n/a del CRC TX no estorba
        antiguo = cmd("show interface", "Interface 1/1/1 is up \n Admin state is up\n Speed 10000 Mb/s \n Rx\n"
                      "      2417650 total packets            457274611 total bytes\n"
                      "      586595   broadcast packets\n"
                      "            9 errors                           1 dropped\n"
                      "            4 CRC/FCS\n Tx\n    116722501 total packets           8432615310 total bytes\n"
                      "            0 errors                          14 dropped\n")
        c = ax.leer(antiguo, "x.txt").contadores[0]
        self.assertEqual((c.paquetes, c.broadcast, c.errores, c.crc, c.paquetes_salida, c.descartes, c.bw_kbit),
                         (2417650, 586595, 9, 4, 116722501, 14, 10000000))

    def test_human_readable(self):
        hr = cmd("show interface", "Interface 1/1/1 is up\n Admin state is up\n Statistic          RX     TX    Total\n"
                 " -------- ---- ---- ----\n Packets        577K      1M     2M\n Errors      < 1   0   0\n"
                 "Interface 1/1/2 is up\n Admin state is up\n Statistic          RX     TX    Total\n"
                 " -------- ---- ---- ----\n Packets        5      1     6\n Errors      0   0   0\n")
        sw = ax.leer(hr, "x.txt")
        self.assertEqual([c.puerto for c in sw.contadores], ["1/1/2"])
        self.assertTrue(any("human-readable" in a and "show interface sin human-readable" in a for a in sw.avisos))

    def test_brief_solo_completa_lo_que_falta(self):
        t = (cmd("show interface", "Interface 1/1/1 is up\n Admin state is up\n VLAN Mode: access\n Access VLAN: 5\n")
             + cmd("show interface brief",
                   "Port      Native  Mode    Type       Enabled Status  Reason                      Speed     Description\n"
                   "          VLAN                                                                   (Mb/s)\n"
                   "------------------------------------------------------------------------------------------------\n"
                   "1/1/1     1       trunk   SFP+SR     no      down    Administratively down       --        NYC...\n"
                   "1/1/2     1       trunk   SFP+SR     no      down    Administratively down       --        NYC...\n"
                   "1/1/3     1       access  1GbT       yes     up      --                          1000      x...\n"))
        p = {x.nombre: x for x in ax.leer(t, "x.txt").puertos}
        self.assertEqual((p["1/1/1"].modo, p["1/1/1"].estado, p["1/1/1"].descripcion), ("access", "up", ""))
        self.assertEqual((p["1/1/2"].modo, p["1/1/2"].estado, p["1/1/2"].apagado), ("trunk", "admin down", True))
        self.assertEqual((p["1/1/3"].modo, p["1/1/3"].estado, p["1/1/3"].descripcion), ("access", "up", ""))

    def test_mac_vacia_y_sin_tipo(self):
        sw = ax.leer(cmd("show mac-address-table", "No MAC entries found.\n"), "x.txt")
        self.assertEqual((sw.mac, [a for a in sw.avisos if "error" in a]), ([], []))
        est = cmd("show mac-address-table static", "Number of MAC addresses : 1\n\nMAC Address          VLAN     Port\n"
                  "--------------------------------------\n00:00:00:00:10:02    1        1/1/1\n")
        self.assertEqual(ax.leer(est, "x.txt").mac, [(1, "00:00:00:00:10:02", "1/1/1")])

    def test_espejo_variantes(self):
        det = cmd("show mirror 1", " Mirror Session: 1\n Admin Status: enable\n Operation Status: enabled\n"
                  " Source: vlan rx none\n Source: vlan tx none\n Source: interface lag45 rx\n"
                  " Destination: tunnel 2.2.2.2 source 1.1.1.1 dscp 0 vrf default\n")
        sw = ax.leer(cmd("show mirror", MIRROR_RES) + det, "x.txt")
        self.assertEqual([(s.vlans_origen, s.interfaces_origen, s.destino) for s in sw.span],
                         [([], ["lag45"], "tunnel 2.2.2.2")])
        self.assertIn("espejo", sw.leyo)
        # resumen con una sesion habilitada y sin su detalle: desconocido
        sw = ax.leer(cmd("show mirror", MIRROR_RES), "x.txt")
        self.assertNotIn("espejo", sw.leyo)
        self.assertTrue(any("falta show mirror 1" in a for a in sw.avisos))
        # resumen sin sesiones habilitadas: se leyo
        sw = ax.leer(cmd("show mirror", MIRROR_RES.replace("1   enable        enabled", "1   disable       disabled")), "x.txt")
        self.assertIn("espejo", sw.leyo)
        # sesion con destino interno aun sin efecto
        det = det.replace("Operation Status: enabled", "Operation Status: no_dest_configured")
        sw = ax.leer(det, "x.txt")
        self.assertEqual(sw.span, [])

    def test_stp_variantes(self):
        sw = ax.leer(cmd("show spanning-tree", RPVST), "x.txt")
        d = {c.instancia: c for c in sw.stp}
        self.assertEqual((d["VLAN1"].raiz, d["VLAN1"].prioridad, d["VLAN1"].cambios, d["VLAN1"].hace_s),
                         ("local", 32768, 1, 30))
        self.assertEqual((d["VLAN10"].raiz, d["VLAN10"].prioridad), ("02:00:00:00:00:bb", 32768))
        mst = cmd("show spanning-tree mst", "#### MST0\nVlans mapped   : 2,4-4094\nBridge Address : 48:0F:CF:AF:04:76\n"
                  "Priority       : 32768\nRoot\nRegional Root\nRoot           Address : 48:0F:CF:AF:04:76   Priority     : 32768\n"
                  "Number of topology changes    : 4\nLast topology change occurred : 516 seconds ago\n\n"
                  "#### MST1\nVlans mapped:  1\nBridge         Address : 48:0F:CF:AF:04:76          Priority: 24576\n"
                  "Root           Address : 48:0F:CF:AF:04:99          Priority: 4096\n")
        d = {c.instancia: c for c in ax.leer(mst, "x.txt").stp}
        self.assertEqual((d["MST0"].raiz, d["MST0"].prioridad, d["MST0"].puente, d["MST0"].cambios),
                         ("local", 32768, "48:0f:cf:af:04:76", 4))
        self.assertEqual((d["MST1"].raiz, d["MST1"].prioridad), ("48:0f:cf:af:04:99", 24576))

    def test_dos_hostnames(self):
        t = cmd("show system", SYSTEM) + cmd("show system", SYSTEM.replace("sw-aoscx01", "sw-aoscx02"), "sw-aoscx02")
        sw = ax.leer(t, "x.txt")
        self.assertEqual(sw.hostname, H)
        self.assertTrue(any("hostnames distintos" in a for a in sw.avisos))

    def test_hostname_del_prompt_y_del_archivo(self):
        self.assertEqual(ax.leer(cmd("show vlan", VLAN, "core.sw-1"), "x.txt").hostname, "core.sw-1")
        self.assertEqual(ax.leer("ArubaOS-CX\n", "mi-switch.txt").hostname, "mi-switch")

    def test_sin_salidas_reconocidas(self):
        sw = ax.leer(f"{H}# show clock\nMon Nov  9 2026\n{H}# show ntp status\nx\n", "x.txt")
        self.assertEqual((sw.puertos, sw.mac, sw.vlans, sw.stp, sw.span), ([], [], {}, [], []))
        self.assertTrue(any("no trae ninguna de las salidas" in a for a in sw.avisos))
        self.assertFalse(sw.config)

    def test_error_del_equipo(self):
        sw = ax.leer(cmd("show mirror", "% Unknown command.\n"), "x.txt")
        self.assertTrue(any("devolvio error" in a for a in sw.avisos))


class SecretosTest(unittest.TestCase):
    def test_running_config_sin_secretos(self):
        for cfg_sin_prompt in (False, True):
            txt = sesion(cfg=not cfg_sin_prompt)
            if cfg_sin_prompt:
                txt = txt.rstrip("# ").rstrip() + "\n" + CONFIG % {"c": CLAVE, "s": COMUNIDAD}
            sw = ax.leer(txt, "s.txt")
            volcado = repr(asdict(sw))
            for secreto in (CLAVE, COMUNIDAD, "tacacs", "password", "usuario-secreto-x", "lector-secreto-y"):
                self.assertNotIn(secreto, volcado)
            self.assertTrue(sw.config)
            self.assertEqual(sw.credenciales, {"usuario_local": 1, "snmpv3_usuario": 1, "snmp_community": 1,
                                               "snmp_rw": 1})
            self.assertEqual([s.interfaces_origen for s in sw.span], [["1/1/4"]])  # manda show mirror, no el lag45


class DeteccionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def archivo(self, texto, nombre="s.txt"):
        p = self.tmp / nombre
        p.write_text(texto, encoding="utf-8")
        return str(p)

    def test_marcas(self):
        for texto in ("!Version ArubaOS-CX FL.10.13\n", "x\nAOS-CX\n", "ArubaOS-CX Version : FL.10\n",
                      "MAC age-time            : 300 seconds\n"):
            self.assertTrue(ax.es_aoscx(self.archivo(texto)), texto)

    def test_cisco_sigue_yendo_a_cisco(self):
        cisco = "hostname sw-c\ninterface GigabitEthernet1/0/1\n switchport mode access\n"
        res = si.cargar([self.archivo(cisco)])
        self.assertEqual(res[0][0].origen, "cli")
        self.assertFalse(ax.es_aoscx(self.archivo("sw# show mac address-table\nVlan Mac Address Type Ports\n")))
        ios12 = ("sw-viejo# show mac-address-table\n          Mac Address Table\n"
                 "Vlan    Mac Address       Type        Ports\n"
                 "  10    0200.0000.0001    DYNAMIC     Fa0/1\n")
        self.assertFalse(ax.es_aoscx(self.archivo(ios12)))      # IOS 12.x usa el mismo comando con guion
        self.assertEqual(si.cargar([self.archivo(ios12)])[0][0].origen, "cli")

    def test_archivo_sin_salidas(self):
        sws, avisos = si.cargar([self.archivo("ArubaOS-CX\n")])
        self.assertEqual((sws[0].origen, sws[0].puertos), ("aoscx", []))
        self.assertTrue(any("no trae ninguna de las salidas" in a for a in avisos))


class IntegracionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def archivo(self, texto, nombre="s.txt"):
        p = self.tmp / nombre
        p.write_text(texto, encoding="utf-8")
        return str(p)

    def hall(self, texto, assets=None):
        res = si.integrar([self.archivo(texto)], {} if assets is None else assets)
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, res)
        return res, {f["titulo"]: f for f in cap.findings}

    def test_ubicacion_en_puerto_de_acceso(self):
        assets = {"a": {"mac": ACTIVO, "nombre": "PLC"}}
        res = si.integrar([self.archivo(sesion())], assets)
        self.assertEqual((assets["a"]["switch_puerto"], assets["a"]["vlan"]), (f"{H}:1/1/1", "20"))
        self.assertEqual(res["ubicados"], 1)

    def test_espejo_con_sesion_habilitada(self):
        res, h = self.hall(sesion(), {"a": {"mac": ACTIVO}})
        self.assertEqual(si.espejo_por_vlan(res), {"20": "si", "10": "parcial"})   # 1/1/4 espeja VLAN 10 solo en parte
        self.assertEqual(res["sin_espejo"], [])
        self.assertNotIn(hg.TIT_SIN_ESPEJO, h)
        filas = {f[1]: f for f in si.filas_vlans(res)}
        self.assertEqual((filas[20][5], filas[20][6]), ("si", "1"))
        self.assertTrue(any("sesion de espejo 2 sin efecto" in a for a in res["avisos"]))

    def test_vlan_con_mac_sin_espejo(self):
        solo20 = sesion().replace(" Source: interface 1/1/4 both\n", "")
        res, h = self.hall(solo20)
        self.assertEqual([(x[1], x[3]) for x in res["sin_espejo"]], [(10, 1)])
        self.assertIn(hg.TIT_SIN_ESPEJO, h)
        self.assertIn("10", h[hg.TIT_SIN_ESPEJO]["evidencia"])

    def test_sin_show_mirror_es_desconocido(self):
        res, h = self.hall(sesion(mirror=False))
        self.assertEqual(res["sin_espejo"], [])
        self.assertEqual(si.espejo_por_vlan(res), {})
        self.assertNotIn(hg.TIT_SIN_ESPEJO, h)
        self.assertEqual({f[5] for f in si.filas_vlans(res)}, {""})
        self.assertTrue(any("sin show mirror" in a for a in res["avisos"]))

    def test_resumen_habilitado_sin_detalle_es_desconocido(self):
        t = sesion(mirror=False, extra=cmd("show mirror", MIRROR_RES))
        res, _h = self.hall(t)
        self.assertEqual((res["sin_espejo"], si.espejo_por_vlan(res)), ([], {}))
        self.assertTrue(any("falta show mirror 1" in a for a in res["avisos"]))

    def test_stp_raiz_sin_prioridad(self):
        _res, h = self.hall(sesion())
        self.assertIn(hg.TIT_RAIZ, h)
        _res, h = self.hall(sesion(stp=STP % {"pr": "24576"}))
        self.assertNotIn(hg.TIT_RAIZ, h)
        _res, h = self.hall(sesion(stp=RPVST))
        self.assertIn(hg.TIT_RAIZ, h)
        self.assertIn("VLAN1", h[hg.TIT_RAIZ]["evidencia"])

    def test_contadores_con_errores(self):
        _res, h = self.hall(sesion(interfaces=con_contadores()))
        self.assertIn("errores de entrada en 1/1/4: 5000 (5000 CRC)", h[hg.TIT_STP]["evidencia"])
        _res, h = self.hall(sesion())
        self.assertNotIn("errores de entrada", h.get(hg.TIT_STP, {}).get("evidencia", ""))   # solo los cambios de STP

    def test_sin_running_config_en_la_higiene(self):
        res, _h = self.hall(sesion())
        self.assertFalse(res["switches"][0].config)
        self.assertIn(H, hg._alcance_config(res["switches"]))

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_corrida_principal_sin_secretos(self):
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("requiere scapy")
        import gen_pcaps
        sys.argv = ["gen", str(self.tmp / "pcaps")]
        gen_pcaps.main()
        sw = self.archivo(sesion(cfg=True), "sesion.txt")
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_capturas([str(self.tmp / "pcaps"), "-o", str(out), "--switch", sw]), 0)
        import csv
        with open(out / "inventario.csv", encoding="utf-8-sig", newline="") as f:
            inv = {r["mac"]: r for r in csv.DictReader(f)}
        r = inv[ACTIVO]
        self.assertEqual((r["switch_puerto"], r["vlan"]), (f"{H}:1/1/1", "20"))
        vistos = 0
        for p in out.rglob("*"):
            if not p.is_file():
                continue
            blobs = [p.read_bytes()]
            if zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as z:
                    blobs += [z.read(n) for n in z.namelist()]
                vistos += 1
            for b in blobs:
                for secreto in (COMUNIDAD, CLAVE, "usuario-secreto-x", "lector-secreto-y"):
                    self.assertNotIn(secreto.encode(), b, str(p))
        self.assertGreaterEqual(vistos, 2)          # docx y xlsx


def config_aoscx(aaa="aaa authentication login default local", stp="spanning-tree\nspanning-tree mode rpvst\n",
                 guard=False, mirror="", gestion="ssh server vrf mgmt\nhttps-server vrf mgmt\n"):
    g = "    spanning-tree bpdu-guard\n" if guard else ""
    return f"""Current configuration:
!
!Version ArubaOS-CX FL.10.13.1101
!export-password: default
hostname {H}
user ricardo-adm group administrators password ciphertext {CLAVE}
user operador-z group operators password ciphertext {CLAVE}
ntp server 192.0.2.10
{aaa}
tacacs-server host 192.0.2.20 key ciphertext {CLAVE}
snmpv3 user lector-w auth sha auth-pass ciphertext {CLAVE} priv des priv-pass ciphertext {CLAVE}
snmp-server community {COMUNIDAD}
snmp-server community {COMUNIDAD}-rw
    access-level rw
snmp-server host 192.0.2.30 trap version v2c community {COMUNIDAD}-trap
{gestion}!
vlan 1,42,48-49
vlan 10
    name Gestion Planta
vlan 20
    name Procesos Config
{stp}!
interface lag 7 multi-chassis static
    description Troncal core
    no shutdown
    no routing
    vlan trunk native 1
    vlan trunk allowed all
interface 1/1/1
    no shutdown
    description PLC planta
    vlan access 20
{g}    spanning-tree port-type admin-edge
interface 1/1/2
    shutdown
    vlan access 10
interface 1/1/3
    no shutdown
    vlan access 20
{g}interface 1/1/48
    no shutdown
    vlan trunk native 1
    vlan trunk allowed 10
    vlan trunk allowed 42,48-49
interface 1/1/49
    no shutdown
    lag 7
interface 1/1/50
    no shutdown
    routing
    ip address 10.9.9.1/30
interface 1/1/51
    no shutdown
    no routing
{g}interface vlan 10
    ip address 10.10.10.2/24
{mirror}"""


def sesion_config(cfg, extra=""):
    return (f"{H}# show interface\nInterface 1/1/3 is down\n Admin state is up\n"
            f"{extra}{H}# show running-config\n{cfg}{H}# ")


class ConfigAoscxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hall(self, texto, assets=None):
        p = self.tmp / "s.txt"
        p.write_text(texto, encoding="utf-8")
        res = si.integrar([str(p)], {} if assets is None else assets)
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, res)
        return res, {f["titulo"]: f for f in cap.findings}

    def test_puertos_vlan_y_svi(self):
        sw = ax.leer(sesion_config(config_aoscx()), "s.txt")
        self.assertTrue(sw.config)
        self.assertEqual((sw.hostname, sw.version), (H, "FL.10.13.1101"))
        p = {x.nombre: x for x in sw.puertos}
        a = p["1/1/1"]
        self.assertEqual((a.modo, a.vlan_acceso, a.descripcion, a.en_config, a.modo_explicito, a.dtp, a.portfast),
                         ("access", 20, "PLC planta", True, True, "", True))
        self.assertTrue(p["1/1/2"].apagado)
        self.assertEqual(p["1/1/2"].estado, "admin down")
        t = p["1/1/48"]
        self.assertEqual((t.modo, t.vlan_nativa, t.vlans_trunk, t.trunk_todas), ("trunk", 1, [10, 42, 48, 49], False))
        self.assertEqual((p["lag7"].modo, p["lag7"].trunk_todas, p["lag7"].canal), ("trunk", True, 7))
        self.assertEqual((p["1/1/49"].canal, p["1/1/49"].modo, p["1/1/49"].vlan_acceso), (7, "", None))
        self.assertEqual(p["1/1/50"].modo, "routed")
        self.assertEqual((p["1/1/51"].modo, p["1/1/51"].vlan_acceso), ("access", 1))
        self.assertNotIn("vlan10", p)
        self.assertEqual([(s.vlan, s.ip, s.mascara) for s in sw.svis], [(10, "10.10.10.2", "255.255.255.0")])
        self.assertEqual((sw.vlans[10], sw.vlans[20], sw.vlans[42]), ("Gestion Planta", "Procesos Config", ""))
        self.assertEqual((sw.http, sw.vty_transport, sw.ntp_servidores, sw.servidores_aaa, sw.aaa_modelo),
                         ("https", ["ssh"], 1, 1, False))

    def test_show_vlan_gana_y_show_interface_se_combina(self):
        extra = ("sw# show vlan\n-----\nVLAN  Name   Status  Reason  Type  Interfaces\n-----\n"
                 "10    Nombre Show   up   ok   static   1/1/2\n")
        sw = ax.leer(sesion_config(config_aoscx(), extra), "s.txt")
        self.assertEqual((sw.vlans[10], sw.vlans[20]), ("Nombre Show", "Procesos Config"))
        p = {x.nombre: x for x in sw.puertos}
        self.assertEqual((p["1/1/3"].estado, p["1/1/3"].modo, p["1/1/3"].vlan_acceso), ("down", "access", 20))

    def test_hostname_distinto_usa_show_system(self):
        txt = f"{H}# show system\nHostname : otro-nombre\n" + sesion_config(config_aoscx())
        sw = ax.leer(txt, "s.txt")
        self.assertEqual(sw.hostname, "otro-nombre")
        self.assertTrue(any("otro-nombre" in a and H in a for a in sw.avisos))

    def test_secretos_solo_conteos(self):
        txt = sesion_config(config_aoscx())
        sw = ax.leer(txt, "s.txt")
        self.assertEqual(sw.credenciales, {"usuario_local": 2, "snmpv3_usuario": 1, "snmp_community": 2,
                                           "snmp_rw": 1})
        volcado = repr(asdict(sw))
        for secreto in (CLAVE, COMUNIDAD, "ricardo-adm", "operador-z", "lector-w", "password", "ciphertext"):
            self.assertNotIn(secreto, volcado)

    def test_troncales_sin_dtp(self):
        _res, h = self.hall(sesion_config(config_aoscx()))
        self.assertNotIn(hg.TIT_DTP, h)

    def test_bpdu_guard_solo_esa_parte_y_la_nota(self):
        _res, h = self.hall(sesion_config(config_aoscx()))
        f = h[hg.TIT_L2]
        self.assertIn("sin BPDU guard: 3/3 (1/1/3, 1/1/1, 1/1/51)", f["evidencia"])
        self.assertIn("AOS-CX: storm-control, port-security, DHCP snooping e inspeccion ARP no evaluados",
                      f["evidencia"])
        self.assertNotIn("sin storm-control", f["evidencia"])
        self.assertNotIn("ip dhcp snooping", f["evidencia"])
        self.assertIn("modo STP rapid-pvst", f["evidencia"])
        self.assertIn("En AOS-CX: spanning-tree bpdu-guard en los puertos de acceso", f["recomendacion"])
        _res, h = self.hall(sesion_config(config_aoscx(guard=True)))
        self.assertNotIn(hg.TIT_L2, h)

    def test_aaa_de_login(self):
        _res, h = self.hall(sesion_config(config_aoscx()))
        f = h[hg.TIT_AAA]
        self.assertIn("AAA de login no, servidores AAA 1, usuarios locales 2", f["evidencia"])
        self.assertNotIn("aaa new-model", f["evidencia"])
        self.assertIn("En AOS-CX: aaa authentication login default group tacacs local", f["recomendacion"])
        _res, h = self.hall(sesion_config(config_aoscx(aaa="aaa authentication login default group tacacs local")))
        self.assertNotIn(hg.TIT_AAA, h)

    def test_gestion_cifrada_sin_hallazgo_y_frase_con_gestion_en_claro(self):
        _res, h = self.hall(sesion_config(config_aoscx()))
        self.assertNotIn(hg.TIT_GESTION, h)
        from ot_assess.switches.modelo import Switch
        sw = Switch(hostname="sw-x", origen="aoscx", config=True, http="http")
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, {"switches": [sw]})
        f = next(x for x in cap.findings if x["titulo"] == hg.TIT_GESTION)
        self.assertIn("En AOS-CX: ssh server vrf y https-server vrf solo en la VRF de gestion", f["recomendacion"])

    def test_puertos_sin_uso_y_vlan1(self):
        _res, h = self.hall(sesion_config(config_aoscx()))
        self.assertIn("1/1/3", h[hg.TIT_PUERTOS]["evidencia"])
        self.assertIn("trunks con VLAN nativa 1: 1/1/48", h[hg.TIT_VLAN1]["evidencia"])

    def test_stp_global(self):
        for stp, esperado in (("spanning-tree\nspanning-tree mode rpvst\n", "rapid-pvst"), ("spanning-tree\n", "mst"),
                              ("", "deshabilitado")):
            sw = ax.leer(sesion_config(config_aoscx(stp=stp)), "s.txt")
            self.assertEqual(sw.stp_modo, esperado)
        _res, h = self.hall(sesion_config(config_aoscx(stp="")))
        self.assertIn("modo STP deshabilitado", h[hg.TIT_L2]["evidencia"])
        self.assertNotIn("loopguard", h[hg.TIT_L2]["evidencia"])     # no se lee en AOS-CX: no se afirma
        self.assertNotIn("UDLD", h[hg.TIT_L2]["evidencia"])
        vivo = cmd("show spanning-tree", STP % {"pr": "32768"}).rstrip("\n") + "\n"
        sw = ax.leer(sesion_config(config_aoscx(stp=""), vivo), "s.txt")
        self.assertEqual(sw.stp_modo, "mst")      # sin la linea pero con STP activo en show: no deshabilitado

    def test_espejo_de_la_config(self):
        ses = ("mirror session 1\n    destination interface 1/1/48\n    source vlan 20 both\n"
               "    source interface 1/1/1 rx\n")
        res, _h = self.hall(sesion_config(config_aoscx(mirror=ses + "    enable\n")))
        sw = res["switches"][0]
        self.assertIn("espejo", sw.leyo)
        self.assertEqual([(s.id, s.vlans_origen, s.interfaces_origen, s.destino) for s in sw.span],
                         [(1, [20], ["1/1/1"], "1/1/48")])
        self.assertEqual(res["espejos"][0][20][0], si.SI)
        res, _h = self.hall(sesion_config(config_aoscx(mirror=ses)))
        sw = res["switches"][0]
        self.assertEqual((sw.span, "espejo" in sw.leyo), ([], False))
        self.assertTrue(any("sin enable" in a for a in sw.avisos))
        self.assertEqual(res["espejos"][0][20][0], si.DESCONOCIDO)

    def test_show_mirror_manda_sobre_la_config(self):
        ses = "mirror session 1\n    source vlan 99 both\n    destination interface 1/1/48\n    enable\n"
        extra = f"{H}# show mirror 1\n{MIRROR1}"
        sw = ax.leer(sesion_config(config_aoscx(mirror=ses), extra), "s.txt")
        self.assertEqual([(s.id, s.vlans_origen) for s in sw.span], [(1, [20])])

    def test_ingles_sin_faltantes(self):
        from ot_assess import i18n
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        i18n.FALTANTES.clear()
        _res, h = self.hall(sesion_config(config_aoscx()))
        for tit in (hg.TIT_L2, hg.TIT_AAA):
            self.assertIn("On AOS-CX", h[tit]["recomendacion"])
        self.assertFalse(i18n.FALTANTES, i18n.FALTANTES)


class SinSalidasCorridaTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_archivo_sin_salidas_termina(self):
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("requiere scapy")
        import gen_pcaps
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        (tmp / "vacio.txt").write_text(f"{H}# show clock\nMon Nov  9 2026\nArubaOS-CX\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_capturas([str(tmp / "pcaps"), "-o", str(tmp / "out"), "--switch",
                                            str(tmp / "vacio.txt")]), 0)


if __name__ == "__main__":
    unittest.main()
