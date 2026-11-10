"""SW2 (D73): controles de capa 2 y estado de STP/log/contadores de un switch Cisco. Sesiones sinteticas."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import i18n
from ot_assess import standards as st
from ot_assess.switches import cisco_ios as ci
from ot_assess.switches import higiene as hg
from ot_assess.switches import integracion as si

SECRETOS = ("usrl2secreto", "L2SecretoPlano", "usrprueba9", "192.0.2.99", "L2HASH")

CONFIG = """swl2-01#show running-config
hostname swl2-01
username usrl2secreto secret 9 $9$L2HASH$abc
enable password L2SecretoPlano
spanning-tree mode rapid-pvst
ip dhcp snooping vlan 20
ip dhcp snooping
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
 description PLC completo
 switchport access vlan 20
 switchport mode access
 switchport port-security
 storm-control broadcast level 1.00
 spanning-tree portfast edge
 spanning-tree bpduguard enable
 spanning-tree guard root
!
interface GigabitEthernet1/0/3
 description HMI sin controles
 switchport access vlan 20
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/4
 switchport access vlan 20
 switchport mode access
 shutdown
!
interface GigabitEthernet1/0/5
 switchport mode dynamic desirable
!
interface GigabitEthernet1/0/6
 switchport mode trunk
 switchport trunk allowed vlan 20
!
interface GigabitEthernet1/0/7
 description sin switchport mode
!
interface Vlan20
 ip address 192.0.2.77 255.255.255.0
!
end
"""
STP = """swl2-01#show spanning-tree detail
 VLAN0020 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32768, sysid 20, address 0011.2233.4455
  Current root has priority 4116, address aabb.cc00.0001
  Root port is 1 (GigabitEthernet1/0/1), cost of root path is 4
  Topology change flag not set, detected flag not set
  Number of topology changes 7 last change occurred 00:10:23 ago
          from GigabitEthernet1/0/5
  Times:  hold 1, topology change 35, notification 2
 VLAN0030 is executing the rstp compatible Spanning Tree protocol
  We are the root of the spanning tree
  Number of topology changes 45 last change occurred 12d04h ago
          from GigabitEthernet1/0/6
 VLAN0040 is executing the rstp compatible Spanning Tree protocol
  Number of topology changes 2 last change occurred 00:01:00 ago
          from GigabitEthernet1/0/2
"""
STP_ANTIGUO = STP.split(" VLAN0020")[0] + " VLAN0030" + STP.split(" VLAN0030")[1].split(" VLAN0040")[0]
LOG = """swl2-01#show logging
Syslog logging: enabled (0 messages dropped, 0 flushes)
*Nov  2 10:00:01.000: %SW_MATRIX-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 410 is flapping between port Gi1/0/1 and port Gi1/0/5
*Nov  2 10:00:02.000: %SW_MATRIX-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 410 is flapping between port Gi1/0/1 and port Gi1/0/5
*Nov  2 10:01:00.000: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state
*Nov  2 10:01:30.000: %STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on Gi1/0/6. The interface has been disabled.
*Nov  2 10:02:00.000: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: usrprueba9] [Source: 192.0.2.99] at 10:02:00
"""
LOG_ERRDIS = LOG.replace("MACFLAP_NOTIF", "OTRO_AVISO").replace("flapping between", "moviendose entre")
IFACES = """swl2-01#show interfaces
GigabitEthernet1/0/5 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 0011.2233.4466 (bia 0011.2233.4466)
     900000 packets input, 123456 bytes, 0 no buffer
     Received 400000 broadcasts (0 multicasts)
     5000 input errors, 4000 CRC, 0 frame, 0 overrun, 0 ignored
GigabitEthernet1/0/2 is up, line protocol is up (connected)
     900000 packets input, 123456 bytes, 0 no buffer
     Received 10 broadcasts (0 multicasts)
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
swl2-01#show interfaces counters errors
Port        Align-Err     FCS-Err    Xmit-Err     Rcv-Err  UnderSize  OutDiscards
Gi1/0/6             0        2500           0        2500          0            0
"""

# T10c (ajusta D73): sesiones sinteticas; MAC, nombres e IP inventados.
SECRETOS_T10C = ("192.0.2.50", "192.0.2.98", "usrajeno7", "ntpllave")
CFG_C = """swl2-01#show running-config
hostname swl2-01
ntp authentication-key 1 md5 ntpllave
ntp server 192.0.2.50
monitor session 1 source vlan 20
monitor session 1 destination interface GigabitEthernet1/0/24
!
interface GigabitEthernet1/0/3
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/24
 switchport mode access
!
end
"""
CFG_C_GUARD = CFG_C.replace(" spanning-tree portfast\n", " spanning-tree portfast\n spanning-tree bpduguard enable\n")
STP_C = """swl2-01#show spanning-tree detail
 VLAN0020 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32768, sysid 20, address 0011.2233.4455
  We are the root of the spanning tree
  Number of topology changes 3 last change occurred 00:05:00 ago
          from GigabitEthernet1/0/3
 Port 3 (GigabitEthernet1/0/3) of VLAN0020 is designated forwarding
   Designated root has priority 32788, address 0011.2233.4455
   Designated bridge has priority 32788, address 0011.2233.4455
   Designated port id is 128.3, designated path cost 0
   The port is in the portfast mode
   BPDU: sent 90000, received 0
 Port 5 (GigabitEthernet1/0/5) of VLAN0020 is backup blocking
   Designated root has priority 32788, address 0011.2233.4455
   Designated bridge has priority 32788, address 0011.2233.4455
   Designated port id is 128.3, designated path cost 0
   The port is in the portfast mode
   BPDU: sent 0, received 7654321
"""
STP_C_SANO = STP_C.replace("backup blocking", "alternate blocking").replace(
    "Designated bridge has priority 32788, address 0011.2233.4455\n   Designated port id is 128.3, designated path "
    "cost 0\n   The port is in the portfast mode\n   BPDU: sent 0",
    "Designated bridge has priority 4116, address aabb.cc00.0009\n   Designated port id is 128.9, designated path "
    "cost 4\n   The port is in the portfast mode\n   BPDU: sent 0")
CONT_C = """swl2-01#show interfaces counters errors
Port        Align-Err     FCS-Err    Xmit-Err     Rcv-Err  UnderSize  OutDiscards
Gi1/0/3             0           0           0           0          0            0
Gi1/0/24            0           0           0           0          0    121000000
"""
IFACE24_C = """swl2-01#show interfaces GigabitEthernet1/0/24
GigabitEthernet1/0/24 is up, line protocol is up (connected)
  Last clearing of "show interface" counters 3d02h
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 121000000
     379000000 packets output, 1 bytes, 0 underruns
"""
LOG_C = """swl2-01#show logging
Syslog logging: enabled (0 messages dropped)
*Nov  2 10:00:01.000: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: usrajeno7] [Source: 192.0.2.98] at 10:00:01
*Nov  2 10:00:02.000: %LINK-3-UPDOWN: Interface Gi1/0/9, changed state to up
 Nov  2 10:00:03.000: %LINK-3-UPDOWN: Interface Gi1/0/9, changed state to down
"""


class LectorL2Test(unittest.TestCase):
    def test_duracion(self):
        self.assertEqual(ci.duracion_s("00:10:23"), 623)
        self.assertEqual(ci.duracion_s("1d02h"), 93600)
        self.assertEqual(ci.duracion_s("2w3d"), 2 * 604800 + 3 * 86400)
        self.assertIsNone(ci.duracion_s("nunca"))

    def test_configuracion_por_puerto_y_globales(self):
        sw = ci.leer(CONFIG, "x.txt")
        self.assertEqual((sw.stp_modo, sw.dhcp_snooping, sw.dhcp_snooping_vlans, sw.dai_vlans),
                         ("rapid-pvst", True, [20], [20]))
        p2, p3 = sw.puerto("Gi1/0/2"), sw.puerto("Gi1/0/3")
        self.assertTrue(p2.portfast and p2.bpduguard and p2.storm_broadcast and p2.port_security and p2.root_guard)
        self.assertTrue(p3.portfast and not (p3.bpduguard or p3.storm_broadcast or p3.port_security))
        self.assertTrue(sw.puerto("Gi1/0/1").nonegotiate)
        self.assertEqual(sw.puerto("Gi1/0/5").dtp, "desirable")
        self.assertFalse(sw.puerto("Gi1/0/7").modo_explicito)

    def test_estado_stp_log_y_contadores(self):
        sw = ci.leer(CONFIG + STP + LOG + IFACES, "x.txt")
        v20 = next(c for c in sw.stp if c.instancia == "VLAN0020")
        self.assertEqual((v20.cambios, v20.hace_s, v20.puerto, v20.raiz), (7, 623, "GigabitEthernet1/0/5",
                                                                           "aa:bb:cc:00:00:01"))
        v30 = next(c for c in sw.stp if c.instancia == "VLAN0030")
        self.assertEqual((v30.cambios, v30.raiz, v30.puerto), (45, "local", "GigabitEthernet1/0/6"))
        self.assertEqual(sw.macflap, [("aa:bb:cc:00:00:01", 410, "Gi1/0/1 Gi1/0/5", 2)])
        self.assertEqual(sw.macflap_total, 2)
        self.assertEqual(sw.errdisable, [("Gi1/0/5", "bpduguard", 1), ("Gi1/0/6", "storm-control", 1)])
        c5 = next(c for c in sw.contadores if c.puerto == "GigabitEthernet1/0/5")
        self.assertEqual((c5.paquetes, c5.broadcast, c5.errores, c5.crc), (900000, 400000, 5000, 4000))
        c6 = next(c for c in sw.contadores if c.puerto == "Gi1/0/6")
        self.assertEqual((c6.errores, c6.crc), (2500, 2500))
        self.assertEqual(sorted(sw.leyo), ["interfaces", "logging", "stp"])

    def test_comandos_abreviados_y_otros_show_se_ignoran(self):
        self.assertEqual(ci._clase("sh span det"), "stp")
        self.assertEqual(ci._clase("show spanning-tree vlan 10 detail"), "stp")
        self.assertEqual(ci._clase("show spanning-tree summary"), None)
        self.assertEqual(ci._clase("sh log"), "logging")
        self.assertEqual(ci._clase("show interfaces"), "interfaces")
        self.assertEqual(ci._clase("show interfaces gi1/0/1"), "interfaces")
        self.assertEqual(ci._clase("show int counters errors"), "errores")
        self.assertEqual(ci._clase("show interfaces status"), None)
        self.assertEqual(ci._clase("show interfaces trunk"), None)
        self.assertEqual(ci._clase("show interfaces description"), "desc")


class HallazgosL2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hall(self, *textos):
        from ot_assess.model import Capture
        rutas = []
        for i, txt in enumerate(textos):
            a = self.tmp / f"s{i}.txt"
            a.write_text(txt, encoding="utf-8")
            rutas.append(str(a))
        cap = Capture(Path("x"))
        hg.agregar_hallazgos(cap, si.integrar(rutas, {}))
        return {f["titulo"]: f for f in cap.findings}

    def test_puertos_de_acceso_con_y_sin_controles(self):
        f = self.hall(CONFIG)[hg.TIT_L2]
        self.assertEqual(f["severidad"], "Media")
        ev = f["evidencia"]
        self.assertIn("sin BPDU guard: 1/2 (GigabitEthernet1/0/3)", ev)
        self.assertIn("sin storm-control de broadcast: 1/2 (GigabitEthernet1/0/3)", ev)
        self.assertIn("sin port-security: 1/2 (GigabitEthernet1/0/3)", ev)
        self.assertNotIn("GigabitEthernet1/0/2)", ev)           # el completo no aparece como faltante
        self.assertNotIn("GigabitEthernet1/0/4", ev)            # apagado: no es puerto de acceso activo
        self.assertIn("modo STP rapid-pvst", ev)
        self.assertIn("puertos con root guard (informativo): 1", ev)
        self.assertEqual(f["activos"], ["192.0.2.77"])

    def test_bpduguard_global_cubre_los_puertos_portfast(self):
        cfg = CONFIG.replace("ip dhcp snooping\n", "ip dhcp snooping\nspanning-tree portfast edge bpduguard default\n")
        self.assertNotIn("sin BPDU guard", self.hall(cfg)[hg.TIT_L2]["evidencia"])
        # un puerto de acceso sin portfast no queda cubierto por el global
        cfg2 = cfg.replace(" switchport mode access\n spanning-tree portfast\n", " switchport mode access\n")
        self.assertIn("sin BPDU guard: 1/2 (GigabitEthernet1/0/3)", self.hall(cfg2)[hg.TIT_L2]["evidencia"])

    def test_dhcp_snooping_y_dai_presentes_y_ausentes(self):
        completo = CONFIG.replace(" description HMI sin controles\n", " description HMI\n")
        completo = completo.replace(" switchport mode access\n spanning-tree portfast\n!",
                                    " switchport mode access\n switchport port-security\n"
                                    " storm-control broadcast level 1.00\n spanning-tree bpduguard enable\n!")
        self.assertNotIn(hg.TIT_L2, self.hall(completo))
        sin = completo.replace("ip dhcp snooping vlan 20\nip dhcp snooping\n", "").replace(
            "ip arp inspection vlan 20\n", "")
        ev = self.hall(sin)[hg.TIT_L2]["evidencia"]
        self.assertIn("DHCP snooping no habilitado", ev)
        self.assertIn("inspeccion ARP dinamica sin VLAN", ev)
        sin_vlan = completo.replace("ip dhcp snooping vlan 20\n", "")
        self.assertIn("DHCP snooping sin VLAN", self.hall(sin_vlan)[hg.TIT_L2]["evidencia"])

    def test_troncales_dtp(self):
        f = self.hall(CONFIG)[hg.TIT_DTP]
        ev = f["evidencia"]
        self.assertIn("troncales sin switchport nonegotiate: GigabitEthernet1/0/6", ev)
        self.assertNotIn("nonegotiate: GigabitEthernet1/0/1", ev)
        self.assertIn("puertos en modo dinamico: GigabitEthernet1/0/5 (desirable)", ev)
        self.assertIn("no se pudo determinar el modo de 1 puertos", ev)
        self.assertIn("GigabitEthernet1/0/7", ev)
        con_nonego = CONFIG.replace(" switchport mode trunk\n switchport trunk allowed vlan 20\n!\ninterface "
                                    "GigabitEthernet1/0/7", " switchport mode trunk\n switchport nonegotiate\n!\n"
                                    "interface GigabitEthernet1/0/7").replace(
            " switchport mode dynamic desirable\n", " switchport mode access\n")
        self.assertNotIn(hg.TIT_DTP, self.hall(con_nonego))

    def test_la_nativa_1_no_se_repite_aqui(self):
        cfg = CONFIG.replace(" switchport trunk native vlan 99\n", "")
        h = self.hall(cfg)
        self.assertIn(hg.TIT_VLAN1, h)
        self.assertNotIn("nativa", h[hg.TIT_DTP]["evidencia"])

    def test_stp_reciente_es_alta_con_vlan_cambios_ultimo_y_puerto(self):
        f = self.hall(CONFIG + STP)[hg.TIT_STP]
        self.assertEqual(f["severidad"], "Alta")
        ev = f["evidencia"]
        self.assertIn("VLAN0020: 7 cambios de topologia, el ultimo hace 10 min, desde GigabitEthernet1/0/5, "
                      "raiz aa:bb:cc:00:00:01", ev)
        self.assertIn("VLAN0030: 45 cambios de topologia, el ultimo hace 12 d, desde GigabitEthernet1/0/6, "
                      "raiz este switch", ev)
        self.assertNotIn("VLAN0040", ev)                        # 2 cambios: bajo el minimo
        self.assertIn("no incluido, no evaluado: show logging, show interfaces", ev)

    def test_stp_solo_antiguo_es_media(self):
        f = self.hall(CONFIG + STP_ANTIGUO)[hg.TIT_STP]
        self.assertEqual(f["severidad"], "Media")
        self.assertIn("VLAN0030: 45 cambios", f["evidencia"])

    def test_macflap_y_errdisable_del_log(self):
        f = self.hall(CONFIG + LOG)[hg.TIT_STP]
        self.assertEqual(f["severidad"], "Alta")
        ev = f["evidencia"]
        self.assertIn("2 mensajes de MAC flapping en el log", ev)
        self.assertIn("MAC aa:bb:cc:00:00:01 VLAN 410 entre Gi1/0/1 / Gi1/0/5 (2 mensajes)", ev)
        self.assertIn("err-disable por bpduguard en Gi1/0/5 (1 veces)", ev)
        self.assertIn("err-disable por storm-control en Gi1/0/6 (1 veces)", ev)
        solo = self.hall(CONFIG + LOG_ERRDIS)[hg.TIT_STP]          # sin MAC flapping ni STP: solo err-disable
        self.assertEqual(solo["severidad"], "Media")

    def test_contadores_de_interfaz(self):
        f = self.hall(CONFIG + IFACES)[hg.TIT_STP]
        self.assertEqual(f["severidad"], "Media")
        ev = f["evidencia"]
        self.assertIn("broadcast alto en GigabitEthernet1/0/5: 400000 de 900000", ev)
        self.assertIn("errores de entrada en GigabitEthernet1/0/5: 5000 (4000 CRC)", ev)
        self.assertIn("errores de entrada en Gi1/0/6: 2500 (2500 CRC)", ev)
        self.assertNotIn("GigabitEthernet1/0/2", ev)            # contadores normales: sin evidencia

    def test_estado_sano_no_da_hallazgo(self):
        sano = "swl2-01#show spanning-tree detail\n VLAN0020 is executing the rstp\n" \
               "  Number of topology changes 1 last change occurred 5d01h ago\n          from Gi1/0/5\n"
        self.assertNotIn(hg.TIT_STP, self.hall(CONFIG + sano))

    def test_sin_running_config_dice_que_no_se_evaluo(self):
        h = self.hall(STP + LOG)
        # nada inventado sobre controles; la hora (T10c) sale del propio LOG, que trae lineas con "*"
        self.assertEqual(set(h), {hg.TIT_STP, hg.TIT_HORA})
        self.assertIn("sin running-config: no se sabe si hay NTP", h[hg.TIT_HORA]["evidencia"])
        self.assertIn("no incluido, no evaluado: show interfaces", h[hg.TIT_STP]["evidencia"])
        otro = CONFIG.replace("swl2-01", "swl2-02")
        sin_cfg = "swl2-03#show mac address-table\nVlan Mac Address Type Ports\n 20 aabb.cc00.0010 DYNAMIC Gi1/0/2\n"
        h = self.hall(CONFIG, sin_cfg, otro)
        self.assertIn("No evaluado, sin running-config: swl2-03", h[hg.TIT_L2]["evidencia"])
        self.assertIn("No evaluado, sin running-config: swl2-03", h[hg.TIT_DTP]["evidencia"])
        solo_mac = self.hall(sin_cfg)
        self.assertEqual(set(solo_mac) & {hg.TIT_L2, hg.TIT_DTP, hg.TIT_STP}, set())

    def test_config_sin_interfaces_no_supone_ausencia_de_puertos(self):
        corta = "swl2-05#show running-config\nhostname swl2-05\nspanning-tree mode mst\nend\n"
        h = self.hall(corta)
        self.assertEqual(set(h), set())                          # no se vio ningun puerto: no se concluye nada

    def test_sin_secretos_en_la_evidencia(self):
        volcado = json.dumps(self.hall(CONFIG + STP + LOG + IFACES), ensure_ascii=False)
        for s in SECRETOS:
            self.assertNotIn(s, volcado, s)
        sw = ci.leer(CONFIG + STP + LOG + IFACES, "x.txt")
        from dataclasses import asdict
        modelo = json.dumps(asdict(sw), ensure_ascii=False)
        for s in SECRETOS:
            self.assertNotIn(s, modelo, s)

    def test_t10c_bucle_contenido_por_stp(self):
        f = self.hall(CFG_C + STP_C)[hg.TIT_BUCLE]
        self.assertEqual(f["severidad"], "Alta")                 # portfast sin BPDU guard en los dos puertos
        ev = f["evidencia"]
        for parte in ("VLAN0020", "puerto GigabitEthernet1/0/5 (backup blocking)", "par GigabitEthernet1/0/3",
                      "BPDU recibidas 7654321", "3 cambios de topologia", "desde GigabitEthernet1/0/3"):
            self.assertIn(parte, ev)
        self.assertEqual(self.hall(CFG_C_GUARD + STP_C)[hg.TIT_BUCLE]["severidad"], "Media")
        self.assertNotIn(hg.TIT_BUCLE, self.hall(CFG_C + STP_C.replace("backup blocking", "alternate blocking")
                                                 .replace("Designated bridge has priority 32788, address "
                                                          "0011.2233.4455\n   Designated port id is 128.3",
                                                          "Designated bridge has priority 4116, address "
                                                          "aabb.cc00.0009\n   Designated port id is 128.9")))
        self.assertNotIn(hg.TIT_BUCLE, self.hall(CFG_C + STP_C_SANO))
        # sin ningun puerto backup ni bloqueado: nada
        self.assertNotIn(hg.TIT_BUCLE, self.hall(CFG_C + STP_C.split(" Port 5")[0]))
        # bloqueado con el puente designado propio, aunque no se rotule backup
        otro = self.hall(CFG_C_GUARD + STP_C.replace("backup blocking", "alternate blocking"))
        self.assertIn(hg.TIT_BUCLE, otro)

    def test_t10c_perdida_en_el_destino_del_espejo(self):
        f = self.hall(CFG_C + CONT_C)[hg.TIT_DESCARTES]
        self.assertEqual((f["severidad"], f["categoria"]), ("Media", "Visibilidad"))
        self.assertIn("Gi1/0/24: 121000000 descartes de salida", f["evidencia"])
        self.assertNotIn("%", f["evidencia"])                    # sin paquetes de salida no hay porcentaje
        f = self.hall(CFG_C + CONT_C + IFACE24_C)[hg.TIT_DESCARTES]
        self.assertIn("24.2% de los 500000000 paquetes", f["evidencia"])
        self.assertIn("ultimo clear: 3d02h", f["evidencia"])
        self.assertNotIn(hg.TIT_DESCARTES, self.hall(CFG_C + CONT_C.replace("121000000", "0")))
        self.assertNotIn(hg.TIT_DESCARTES, self.hall(CFG_C))     # sin contadores
        # descartes en un puerto que no es destino de SPAN: no se reporta aqui
        self.assertNotIn(hg.TIT_DESCARTES, self.hall(CFG_C + CONT_C.replace("Gi1/0/24 ", "Gi1/0/3  ")))
        self.assertNotIn(hg.TIT_DESCARTES, self.hall(CONT_C))    # sin configuracion no se sabe cual es el destino

    def test_t10c_hora_sin_sincronizar(self):
        f = self.hall(CFG_C + LOG_C)[hg.TIT_HORA]
        self.assertEqual(f["severidad"], "Baja")
        self.assertIn("NTP configurado pero el reloj no esta sincronizado", f["evidencia"])
        self.assertIn("2 de 3 lineas", f["evidencia"])
        sin_ntp = self.hall(CFG_C.replace("ntp server 192.0.2.50\n", "") + LOG_C)[hg.TIT_HORA]
        self.assertIn("sin NTP configurado", sin_ntp["evidencia"])
        self.assertNotIn("NTP configurado pero", sin_ntp["evidencia"])
        self.assertNotIn(hg.TIT_HORA, self.hall(CFG_C + LOG_C.replace("*Nov", " Nov")))
        punto = self.hall(CFG_C + LOG_C.replace("*Nov", ".Nov"))[hg.TIT_HORA]
        self.assertIn("se perdio", punto["evidencia"])
        sw = ci.leer(CFG_C + LOG_C, "x.txt")
        self.assertEqual((sw.log_fechadas, sw.log_sin_sincronizar, sw.ntp_servidores), (3, 2, 1))

    def test_t10c_raiz_con_prioridad_de_fabrica(self):
        f = self.hall(CFG_C + STP_C)[hg.TIT_RAIZ]
        self.assertEqual(f["severidad"], "Baja")
        self.assertIn("VLAN0020", f["evidencia"])
        self.assertNotIn(hg.TIT_RAIZ, self.hall(CFG_C + STP_C.replace("priority 32768", "priority 24576")))
        no_raiz = STP_C.replace("  We are the root of the spanning tree\n", "")
        self.assertNotIn(hg.TIT_RAIZ, self.hall(CFG_C + no_raiz))
        muchas = "".join(STP_C.split(" Port 3")[0].replace("VLAN0020", f"VLAN{n:04d}") for n in range(20, 33))
        ev = self.hall(CFG_C + "swl2-01#show spanning-tree detail\n" + muchas.replace(
            "swl2-01#show spanning-tree detail\n", ""))[hg.TIT_RAIZ]["evidencia"]
        self.assertIn("raiz de 13 VLAN", ev)
        self.assertIn("y 3 mas", ev)

    def test_t10c_sin_usuarios_ni_ip_del_registro(self):
        completo = CFG_C + STP_C + CONT_C + IFACE24_C + LOG_C
        volcado = json.dumps(self.hall(completo), ensure_ascii=False)
        from dataclasses import asdict
        modelo = json.dumps(asdict(ci.leer(completo, "x.txt")), ensure_ascii=False)
        for s in SECRETOS_T10C:
            self.assertNotIn(s, volcado, s)
            self.assertNotIn(s, modelo, s)

    def test_t10c_marcos_playbooks_e_ingles(self):
        from ot_assess import playbooks
        nuevos = (hg.TIT_BUCLE, hg.TIT_DESCARTES, hg.TIT_HORA, hg.TIT_RAIZ)
        for tit in nuevos:
            self.assertTrue(st.referencias(tit), tit)
            pb = playbooks.cargar()[playbooks.para_titulo(tit)]
            self.assertIn("Switch Cisco IOS/IOS-XE", pb["por_plataforma"])
        # la raiz sin prioridad no cae en la fila "stp" ni en la del cambio de raiz de la captura
        self.assertIn("T0830", st.referencias(hg.TIT_RAIZ)["mitre-ics"])
        i18n.usar("en")
        i18n.FALTANTES.clear()
        try:
            h = self.hall(CFG_C + STP_C + CONT_C + IFACE24_C + LOG_C)
            for tit in nuevos:
                f = h[tit]
                for campo in ("titulo", "por_que_importa", "recomendacion"):
                    self.assertNotEqual(i18n.t(f[campo]), f[campo], campo)
            self.assertIn("topology changes", h[hg.TIT_BUCLE]["evidencia"])
            self.assertIn("NTP configured but", h[hg.TIT_HORA]["evidencia"])
            self.assertEqual(i18n.FALTANTES, set())
        finally:
            i18n.usar("es")

    def test_marcos_playbooks_e_ingles(self):
        from ot_assess import playbooks
        for tit in (hg.TIT_L2, hg.TIT_DTP, hg.TIT_STP):
            self.assertEqual(set(st.referencias(tit)), {"iec62443", "nist-800-82", "nist-csf", "mitre-ics"}, tit)
            pb = playbooks.cargar()[playbooks.para_titulo(tit)]
            self.assertIn("Switch Cisco IOS/IOS-XE", pb["por_plataforma"])
            self.assertIn("ventana", " ".join(pb["pasos"] + pb["precauciones"]).lower())
        self.assertEqual(st.referencias(hg.TIT_DTP)["mitre-ics"], "T0830 Adversary-in-the-Middle")
        # el STP del hallazgo nuevo no se confunde con la fila "stp" de la captura
        self.assertIn("T0826", st.referencias(hg.TIT_STP)["mitre-ics"])
        i18n.usar("en")
        i18n.FALTANTES.clear()
        try:
            h = self.hall(CONFIG + STP + LOG + IFACES)
            for tit in (hg.TIT_L2, hg.TIT_DTP, hg.TIT_STP):
                f = h[tit]
                for campo in ("titulo", "por_que_importa", "recomendacion"):
                    self.assertNotEqual(i18n.t(f[campo]), f[campo], campo)
            self.assertIn("no incluido", h[hg.TIT_STP]["evidencia"] + "no incluido")    # evidencia ya en ingles
            self.assertIn("topology changes", h[hg.TIT_STP]["evidencia"])
            self.assertEqual(i18n.FALTANTES, set())
        finally:
            i18n.usar("es")


if __name__ == "__main__":
    unittest.main()
