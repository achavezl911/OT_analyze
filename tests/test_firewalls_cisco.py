"""F1a: modelo comun de firewall y adaptador de la CLI de Cisco FTD/ASA (texto sintetico)."""
from __future__ import annotations

import ipaddress
import sys
import tempfile
import time
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess.firewalls import cisco

N = ipaddress.IPv4Network

SESION = (
    "> system support diagnostic-cli\r\n"
    "Attaching to Diagnostic CLI ...\r\n"
    "FW1# show version\r\n"
    "Cisco Adaptive Security Appliance Software Version 9.x\r\n"
    "FW1# show route\r\n"
    "Codes: L - local, C - connected, S - static, O - OSPF\r\n"
    "Gateway of last resort is 192.0.2.1 to network 0.0.0.0\r\n"
    "\r\n"
    "S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\r\n"
    "C        10.10.15.0 255.255.255.0 is directly connected, inside\r\n"
    "L        10.10.15.2 255.255.255.255 is directly connected, inside\r\n"
    "O E2     10.20.0.0 255.255.0.0 [110/20] via 10.10.15.1, 0:10:00, inside\r\n"
    "                               [110/20] via 10.10.15.9, 0:10:00, dmz\r\n"
    "C        192.0.2.0 255.255.255.0 is directly connected, outside\r\n"
    "FW1# show nameif\r\n"
    "Interface                Name                     Security\r\n"
    "GigabitEthernet0/0       outside                    0\r\n"
    "GigabitEthernet0/1       inside                   100\r\n"
    "FW1# show interface ip brief\r\n"
    "Interface                  IP-Address      OK? Method Status                Protocol\r\n"
    "GigabitEthernet0/0         192.0.2.2       YES CONFIG up                    up\r\n"
    "GigabitEthernet0/1         10.10.15.2      YES CONFIG up                    up\r\n"
    "GigabitEthernet0/2         unassigned      YES unset  administratively down down\r\n"
    "FW1# show zone\r\n"
    "ERROR: % Invalid input detected at '^' marker.\r\n"
    "FW1# show route --More--\r\n"
)

CONFIG_ZONA = """
FW1# show nameif
Interface                Name                     Security
GigabitEthernet0/0       outside                    0
GigabitEthernet0/1       inside                   100
FW1# show zone
Zone: OT_ZONE  Security-level: 0
Zone member(s): 1
  inside               GigabitEthernet0/1
"""

OBJETOS = """
object network H1
 host 10.0.0.1
 description ignorada
object network SUB
 subnet 10.1.0.0 255.255.0.0
object network RNG
 range 10.2.0.1 10.2.0.6
object network WEB
 fqdn www.example.test
object network NATOBJ
 host 10.9.9.9
 nat (inside,outside) static 203.0.113.5
object-group network A
 network-object host 10.3.0.1
 group-object B
object-group network B
 network-object 10.4.0.0 255.255.255.0
 network-object object H1
 group-object A
object-group service SVC tcp
 port-object eq www
 port-object range 8000 8010
 port-object eq raro
object-group service SVC2
 service-object tcp destination eq 502
 service-object udp destination eq domain
 group-object SVC
"""

FTD = """
access-list CSM_FW_ACL_ remark rule-id 268435457: ACCESS POLICY: Pol OT - Mandatory
access-list CSM_FW_ACL_ remark rule-id 268435457: L7 RULE: Permitir HMI
access-list CSM_FW_ACL_ advanced trust tcp ifc inside object-group A ifc outside object H1 object-group SVC rule-id 268435457 event-log flow-end
access-list CSM_FW_ACL_ advanced trust tcp ifc dmz 198.51.100.0 255.255.255.0 ifc outside object SUB object-group SVC rule-id 268435457 event-log flow-end
access-list CSM_FW_ACL_ remark rule-id 268435458: ACCESS POLICY: Pol OT - Default
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 268435458 log inactive
access-list CSM_FW_ACL_ advanced permit tcp any any object-group NOEXISTE rule-id 268435459
"""

HITS = """
FW1# show rule hits
RuleID        Hit Count   First Hit Time(UTC)        Last Hit Time(UTC)
268435457     12          10:01:02 Oct 5 2024        11:22:33 Nov 3 2024
"""

ASA = """
access-list OUTSIDE_IN extended permit tcp host 192.0.2.10 any eq www
"""
ASA_SHOW = """
FW1# show access-list OUTSIDE_IN
access-list OUTSIDE_IN; 1 elements; name hash: 0x1
access-list OUTSIDE_IN line 1 extended permit tcp host 192.0.2.10 any eq www (hitcnt=7) 0xabc
"""


def _analizar(*partes):
    """Config sin prompt va primero bajo un prompt de running-config; las partes con prompt, despues."""
    cfg = [p for p in partes if not p.lstrip().startswith("FW1#")]
    otras = [p for p in partes if p.lstrip().startswith("FW1#")]
    return cisco.analizar_texto("\n".join(["FW1# show running-config"] + cfg + otras))


class SesionTest(unittest.TestCase):
    def test_secciones_hostname_y_error(self):
        fw = cisco.analizar_texto(SESION)
        self.assertEqual(fw.hostname, "FW1")
        self.assertEqual(len(fw.interfaces), 3)
        self.assertTrue(any("show zone" in a and "error" in a for a in fw.avisos), fw.avisos)
        self.assertTrue(any("show route" in a and "vacia" in a for a in fw.avisos), fw.avisos)

    def test_rutas_tipo_interfaz_salto_y_ecmp(self):
        fw = cisco.analizar_texto(SESION)
        por = {(str(r.red), r.salto): r for r in fw.rutas}
        self.assertEqual(por[("0.0.0.0/0", "192.0.2.1")].tipo, "defecto")
        self.assertEqual(por[("10.10.15.0/24", "")].tipo, "conectada")
        self.assertEqual(por[("10.10.15.2/32", "")].tipo, "local")
        a, b = por[("10.20.0.0/16", "10.10.15.1")], por[("10.20.0.0/16", "10.10.15.9")]
        self.assertEqual((a.tipo, a.interfaz, a.distancia, a.metrica), ("dinamica", "inside", 110, 20))
        self.assertEqual(b.interfaz, "dmz")
        self.assertEqual(fw.interfaz_de("10.20.1.1"), "inside")
        self.assertEqual(fw.interfaz_de("10.10.15.2"), "inside")      # /32 local gana a /24
        self.assertEqual(fw.interfaz_de("8.8.8.8"), "outside")        # defecto
        self.assertEqual(fw.interfaz_de("192.0.2.77"), "outside")

    def test_show_arp_en_sesion_y_en_archivo_propio(self):
        txt = "FW1# show arp\n        inside 10.10.1.9 0011.2233.4455 12\n        dmz 10.10.9.1 0011.2233.4466 -\n"
        fw = cisco.analizar_texto(txt)
        self.assertEqual([(a.ip, a.edad) for a in fw.arp], [("10.10.1.9", 12), ("10.10.9.1", None)])
        self.assertNotIn("sin show arp: no se valida el salto", fw.avisos)
        fw = cisco.analizar_texto("        inside 10.10.1.9 0011.2233.4455 12\n", "show_arp.txt")
        self.assertEqual(len(fw.arp), 1)
        self.assertIn("sin show arp: no se valida el salto", cisco.analizar_texto(SESION).avisos)

    def test_interfaces_unidas_y_zonas(self):
        fw = cisco.analizar_texto(SESION)
        i = {x.fisica: x for x in fw.interfaces}
        g1 = i["GigabitEthernet0/1"]
        self.assertEqual((g1.nombre, g1.ip, g1.mascara, g1.seguridad), ("inside", "10.10.15.2", "255.255.255.0", 100))
        self.assertEqual(i["GigabitEthernet0/2"].ip, "")
        self.assertEqual(g1.zona, "inside")
        self.assertIn("zonas tomadas del nameif (sin show zone)", fw.avisos)
        fz = cisco.analizar_texto(CONFIG_ZONA)
        self.assertEqual(fz.zona_de("inside"), "OT_ZONE")
        self.assertEqual(fz.zona_de("outside"), "outside")
        self.assertNotIn("zonas tomadas del nameif (sin show zone)", fz.avisos)

    def test_carpeta_un_archivo_por_comando(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "show_route.txt").write_text(SESION.split("FW1# show route\r\n")[1].split("FW1# show nameif")[0])
            (Path(d) / "show_access-list.txt").write_text(ASA_SHOW.split("\n", 2)[2])
            fw = cisco.cargar(d)
        self.assertEqual(len(fw.rutas), 6)
        self.assertEqual(fw.reglas[0].aciertos, 7)


class ObjetosTest(unittest.TestCase):
    def setUp(self):
        self.fw = _analizar(OBJETOS)
        self.o = {(x.tipo, x.nombre): x for x in self.fw.objetos}

    def test_host_subnet_range(self):
        self.assertEqual(self.o[("red", "H1")].valores, [N("10.0.0.1/32")])
        self.assertEqual(self.o[("red", "SUB")].valores, [N("10.1.0.0/16")])
        self.assertEqual(self.o[("red", "RNG")].valores,
                         [N("10.2.0.1/32"), N("10.2.0.2/31"), N("10.2.0.4/31"), N("10.2.0.6/32")])

    def test_grupos_anidados_con_ciclo(self):
        a, b = self.o[("red", "A")].valores, self.o[("red", "B")].valores
        self.assertEqual(set(a), {N("10.3.0.1/32"), N("10.4.0.0/24"), N("10.0.0.1/32")})
        self.assertEqual(set(b), set(a))
        self.assertTrue(any("ciclo" in x for x in self.fw.avisos))

    def test_fqdn_y_puerto_desconocido_avisan(self):
        self.assertEqual(self.o[("red", "WEB")].valores, [])
        self.assertTrue(any("fqdn" in x and "WEB" in x for x in self.fw.avisos))
        self.assertTrue(any("raro" in x for x in self.fw.avisos))
        self.assertEqual(self.o[("servicio", "SVC")].valores,
                         [("tcp", 80, 80), ("tcp", 8000, 8010)])
        self.assertEqual(self.o[("servicio", "SVC2")].valores,
                         [("tcp", 502, 502), ("udp", 53, 53), ("tcp", 80, 80), ("tcp", 8000, 8010)])

    def test_nat_de_objeto(self):
        n = self.fw.nat[0]
        self.assertEqual((n.interfaces, n.tipo, n.objetos), (["inside", "outside"], "static", ["NATOBJ"]))

    def test_objeto_no_definido_avisa(self):
        fw = _analizar(OBJETOS, FTD)
        self.assertTrue(any("no definido: NOEXISTE" in x for x in fw.avisos), fw.avisos)
        r = next(x for x in fw.reglas if x.id == "268435459")
        self.assertTrue(any("NOEXISTE" in x for x in r.no_resuelto))


class ReglasTest(unittest.TestCase):
    def test_misma_regla_en_dos_lineas_ftd(self):
        fw = _analizar(OBJETOS, FTD, HITS)
        self.assertEqual([r.id for r in fw.reglas], ["268435457", "268435458", "268435459"])
        r = fw.reglas[0]
        self.assertEqual((r.politica, r.seccion, r.nombre, r.accion), ("Pol OT", "Mandatory", "Permitir HMI", "confiar"))
        self.assertEqual(r.zonas_origen, ["inside", "dmz"])
        self.assertEqual(r.zonas_destino, ["outside"])
        self.assertEqual(set(r.origen), {N("10.3.0.1/32"), N("10.4.0.0/24"), N("10.0.0.1/32"), N("198.51.100.0/24")})
        self.assertEqual(set(r.destino), {N("10.0.0.1/32"), N("10.1.0.0/16")})
        self.assertEqual(r.protocolos, ["tcp"])
        self.assertEqual(r.puertos, [(80, 80), (8000, 8010)])
        self.assertTrue(r.registro and r.activa)
        self.assertEqual(len(r.lineas), 2)
        d = fw.reglas[1]
        self.assertEqual((d.accion, d.protocolos, d.puertos, d.activa, d.registro, d.seccion),
                         ("bloquear", [], [], False, True, "Default"))

    def test_aciertos_y_regla_sin_aciertos(self):
        fw = _analizar(OBJETOS, FTD, HITS)
        r = fw.reglas[0]
        self.assertEqual((r.aciertos, r.primer_acierto, r.ultimo_acierto),
                         (12, "2024-10-05 10:01:02", "2024-11-03 11:22:33"))
        self.assertEqual((fw.reglas[1].aciertos, fw.reglas[1].primer_acierto), (0, ""))

    def test_asa_sin_rule_id_con_hitcnt(self):
        fw = _analizar(ASA, ASA_SHOW)
        self.assertEqual(len(fw.reglas), 1)
        r = fw.reglas[0]
        self.assertEqual((r.id, r.accion, r.protocolos, r.puertos, r.aciertos, r.seccion),
                         ("OUTSIDE_IN:1", "permitir", ["tcp"], [(80, 80)], 7, "OUTSIDE_IN"))
        self.assertEqual((r.origen, r.destino), ([N("192.0.2.10/32")], [N("0.0.0.0/0")]))

    def test_puerto_desconocido_marca_la_regla(self):
        fw = _analizar("access-list X extended permit tcp any any eq chinchin")
        self.assertTrue(any("chinchin" in x for x in fw.reglas[0].no_resuelto))
        self.assertTrue(any("chinchin" in x for x in fw.avisos))


class SeguridadYRendimientoTest(unittest.TestCase):
    def test_secretos_no_llegan_al_modelo(self):
        texto = (
            "FW1# show running-config\n"
            "hostname FW1\n"
            "username admin password SECRETOX encrypted\n"
            "snmp-server community SECRETOY\n"
            "crypto ikev1 policy 1\n authentication pre-share\n"
            "tunnel-group 1.1.1.1 ipsec-attributes\n ikev1 pre-shared-key SECRETOZ\n"
            "object network H1\n host 10.0.0.1\n"
            "access-list A extended permit ip any any\n"
            "nat (inside,outside) source static H1 H1\n")
        fw = cisco.analizar_texto(texto)
        self.assertEqual((len(fw.objetos), len(fw.reglas), len(fw.nat)), (1, 1, 1))
        self.assertEqual(fw.hostname, "FW1")
        volcado = repr(fw)
        for s in ("SECRETOX", "SECRETOY", "SECRETOZ", "pre-share", "crypto"):
            self.assertNotIn(s, volcado)

    def test_rendimiento(self):
        lin = []
        for i in range(450):
            lin.append(f"object network O{i}\n host 10.{i // 250}.{i % 250}.1")
        for i in range(1200):
            lin.append(f"access-list CSM_FW_ACL_ advanced permit tcp ifc inside object O{i % 450} ifc outside any "
                       f"eq {1 + i % 60000} rule-id {1000 + i // 2}")
        t0 = time.time()
        fw = cisco.analizar_texto("\n".join(lin))
        self.assertLess(time.time() - t0, 2.0)
        self.assertEqual(len(fw.reglas), 600)


if __name__ == "__main__":
    unittest.main()


class RemarkPrefiltroTest(unittest.TestCase):
    def test_nombre_de_regla_de_prefiltro(self):
        txt = ("FW1# show running-config access-list\n"
               "access-list CSM_FW_ACL_ remark rule-id 268441705: PREFILTER POLICY: Prefiltro-1\n"
               "access-list CSM_FW_ACL_ remark rule-id 268441705: RULE: Confiar-HMI\n"
               "access-list CSM_FW_ACL_ advanced trust tcp any any eq 443 rule-id 268441705 event-log both\n")
        fw = cisco.analizar_texto(txt)
        r = next(x for x in fw.reglas if x.id == "268441705")
        self.assertEqual(r.nombre, "Confiar-HMI")
        self.assertEqual(r.politica, "Prefiltro-1")
