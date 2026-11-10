"""F2: adaptador FortiGate (FortiOS) al modelo comun de firewall. Texto sintetico, sin muestra real."""
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

from ot_assess.cli import main
from ot_assess.firewalls import cisco, fortigate
from ot_assess.firewalls import integracion as fi

N = ipaddress.IPv4Network

SECRETOS = (
    'config system admin\n    edit "admin"\n        set password ENC SECRETOX\n    next\nend\n'
    'config vpn certificate local\n    edit "c1"\n        set private-key "SECRETOY"\n    next\nend\n'
    'config vpn ipsec phase1-interface\n    edit "t1"\n        set psksecret ENC SECRETOZ\n    next\nend\n'
    'config system snmp community\n    edit 1\n        set name "SECRETOW"\n    next\nend\n')

BASE = SECRETOS + '''config system global
    set hostname "FGT-1"
    set admin-password SECRETOV
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 192.0.2.2 255.255.255.0
        set alias "WAN"
        set role wan
        set passwd SECRETOU
    next
    edit "port2"
        set vdom "root"
        set ip 10.20.1.1 255.255.255.0
    next
    edit "port3"
        set vdom "root"
        set ip 10.20.2.1 255.255.255.0
    next
    edit "vlan10"
        set vdom "root"
        set ip 10.20.3.1 255.255.255.0
        set type vlan
        set interface "port3"
        set vlanid 10
    next
end
config system zone
    edit "OT"
        set interface "port2" "vlan10"
    next
end
config router static
    edit 1
        set gateway 192.0.2.1
        set device "port1"
    next
    edit 2
        set dst 172.16.0.0 255.240.0.0
        set gateway 10.20.1.254
    next
    edit 3
        set dst 203.0.113.0 255.255.255.0
        set blackhole enable
    next
    edit 4
        set dst 198.51.100.0 255.255.255.0
        set gateway 192.0.2.1
        set device "port1"
        set status disable
    next
end
config firewall address
    edit "scada"
        set subnet 10.20.2.0 255.255.255.0
    next
    edit "rango"
        set type iprange
        set start-ip 10.20.1.10
        set end-ip 10.20.1.13
    next
    edit "web"
        set type fqdn
        set fqdn "ejemplo.invalid"
    next
    edit "pais"
        set type geography
        set country "XX"
    next
end
config firewall addrgrp
    edit "g1"
        set member "scada" "g2"
    next
    edit "g2"
        set member "rango" "g1" "web"
    next
end
config firewall service custom
    edit "OT-SVC"
        set tcp-portrange 502 8080-8090 1024-65535:53
        set udp-portrange 2222
    next
    edit "GRE-X"
        set protocol IP
        set protocol-number 47
    next
    edit "PING-X"
        set protocol ICMP
    next
end
config firewall service group
    edit "GRP-SVC"
        set member "OT-SVC" "HTTPS"
    next
end
config firewall vip
    edit "vip1"
        set extip 192.0.2.50
    next
end
config firewall policy
    edit 20
        set name "ot-a-wan"
        set srcintf "OT"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 5
        set name "bloquear-telnet"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "scada"
        set dstaddr "all"
        set action deny
        set service "TELNET"
    next
    edit 7
        set name "todo"
        set srcintf "port3"
        set dstintf "port2"
        set srcaddr "g1"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set status disable
    next
    edit 8
        set name "ot-svc"
        set srcintf "port3"
        set dstintf "OT"
        set srcaddr "scada"
        set dstaddr "rango"
        set action accept
        set service "GRP-SVC" "GRE-X" "PING-X"
    next
    edit 9
        set name "servicio-raro"
        set srcintf "port3"
        set dstintf "port2"
        set srcaddr "scada"
        set dstaddr "all"
        set action accept
        set service "NO-EXISTE"
    next
end
'''

TABLA = ("FGT-1 # get router info routing-table all\n"
         "Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP\n"
         "Routing table for VRF=0\n"
         "S*      0.0.0.0/0 [10/0] via 192.0.2.1, port1\n"
         "C       10.20.1.0/24 is directly connected, port2\n"
         "O       10.99.0.0/16 [110/20] via 10.20.1.254, port2, 00:10:00\n"
         "                     [110/20] via 10.20.2.254, port3, 00:10:00\n")


def _fw(texto=BASE):
    fws = fortigate.analizar_texto(texto)
    assert len(fws) == 1
    return fws[0]


def _c(src, dst, port=443, l4="tcp"):
    return {"src": src, "dst": dst, "l4": l4, "port": str(port)}


class InterfacesRutasTest(unittest.TestCase):
    def test_interfaces_zonas_y_hostname(self):
        fw = _fw()
        self.assertEqual((fw.fabricante, fw.hostname), (fortigate.FABRICANTE, "FGT-1"))
        z = {i.fisica: (i.ip, i.mascara, i.zona) for i in fw.interfaces}
        self.assertEqual(z["port1"], ("192.0.2.2", "255.255.255.0", "port1"))
        self.assertEqual(z["port2"][2], "OT")
        self.assertEqual(z["vlan10"], ("10.20.3.1", "255.255.255.0", "OT"))
        self.assertEqual(fw.zona_de("port3"), "port3")

    def test_rutas_estaticas_con_y_sin_dst_device_y_blackhole(self):
        fw = _fw()
        r = {(str(x.red), x.interfaz): x for x in fw.rutas}
        d = r[("0.0.0.0/0", "port1")]
        self.assertEqual((d.salto, d.tipo), ("192.0.2.1", "defecto"))
        e = r[("172.16.0.0/12", "port2")]            # sin device: sale de la red conectada del gateway
        self.assertEqual((e.salto, e.tipo), ("10.20.1.254", "estatica"))
        b = r[("203.0.113.0/24", fortigate.BLACKHOLE)]
        self.assertEqual(b.salto, "")
        self.assertNotIn("198.51.100.0/24", {k[0] for k in r})      # status disable
        self.assertEqual(r[("10.20.2.0/24", "port3")].tipo, "conectada")
        self.assertEqual(fw.interfaz_de("203.0.113.9"), fortigate.BLACKHOLE)
        self.assertTrue(any("blackhole" in a for a in fw.avisos))

    def test_tabla_de_rutas(self):
        fw = _fw(BASE + TABLA)
        r = {(str(x.red), x.interfaz): x for x in fw.rutas}
        self.assertEqual((r[("10.99.0.0/16", "port2")].tipo, r[("10.99.0.0/16", "port2")].salto,
                          r[("10.99.0.0/16", "port2")].distancia), ("dinamica", "10.20.1.254", 110))
        self.assertIn(("10.99.0.0/16", "port3"), r)          # continuacion ECMP
        self.assertEqual(r[("10.20.1.0/24", "port2")].codigo, "C")
        self.assertEqual(sum(1 for x in fw.rutas if str(x.red) == "0.0.0.0/0"), 1)    # sin duplicar la estatica
        self.assertFalse(any("sin get router info" in a for a in fw.avisos))
        self.assertTrue(any("sin get router info" in a for a in _fw().avisos))

    def test_tabla_sola_se_detecta_y_se_lee(self):
        self.assertIsNotNone(fortigate_detectar(TABLA))
        fw = fortigate.analizar_texto(TABLA)[0]
        self.assertEqual(fw.interfaz_de("10.99.1.1"), "port2")


def fortigate_detectar(texto):
    d = Path(tempfile.mkdtemp())
    try:
        (d / "x.txt").write_text(texto, encoding="utf-8")
        return fortigate.detectar(d / "x.txt")
    finally:
        shutil.rmtree(d, ignore_errors=True)


class ObjetosPoliticasTest(unittest.TestCase):
    def setUp(self):
        self.fw = _fw()
        self.r = {x.id: x for x in self.fw.reglas}

    def test_direcciones_grupo_con_ciclo_y_no_resolubles(self):
        r = self.r["7"]                      # g1 -> scada, g2 -> rango, g1 (ciclo), web (fqdn)
        self.assertEqual(set(r.origen), {N("10.20.2.0/24"), N("10.20.1.10/31"), N("10.20.1.12/31")})
        self.assertIn("fqdn: web", r.no_resuelto)
        self.assertTrue(any("circular" in a for a in self.fw.avisos))
        self.assertEqual(self.r["8"].destino, [N("10.20.1.10/31"), N("10.20.1.12/31")])

    def test_servicios_custom_grupo_y_protocolos(self):
        r = self.r["8"]
        por = {tuple(s.protocolos): s for s in r.subreglas}
        tcp = next(s for s in r.subreglas if s.protocolos == ["tcp"] and not s.puertos_origen)
        self.assertEqual(tcp.puertos_destino, [(443, 443), (502, 502), (8080, 8090)])
        con_origen = [s for s in r.subreglas if s.puertos_origen]
        self.assertEqual(con_origen[0].puertos_origen, [(53, 53)])
        self.assertEqual(con_origen[0].puertos_destino, [(1024, 65535)])
        self.assertEqual(por[("udp",)].puertos_destino, [(2222, 2222)])
        self.assertIn(("gre",), por)
        self.assertIn(("icmp",), por)

    def test_politicas_en_orden_de_aparicion_y_atributos(self):
        self.assertEqual([x.id for x in self.fw.reglas], ["20", "5", "7", "8", "9", "implicit-deny"])
        a, b, c = self.r["20"], self.r["5"], self.r["7"]
        self.assertEqual((a.accion, a.protocolos, a.puertos, a.registro), ("permitir", ["tcp"], [(443, 443)], True))
        self.assertEqual(a.zonas_origen, ["port2", "vlan10"])        # srcintf = zona OT, expandida
        self.assertEqual(a.origen, [N("0.0.0.0/0")])
        self.assertEqual((b.accion, b.puertos, b.nombre), ("bloquear", [(23, 23)], "bloquear-telnet"))
        self.assertFalse(c.activa)
        self.assertEqual((c.protocolos, c.puertos), ([], []))         # ALL

    def test_servicio_desconocido_es_aviso_y_no_casa(self):
        self.assertIn("puerto no resuelto: servicio NO-EXISTE", self.r["9"].no_resuelto)
        self.assertTrue(any("NO-EXISTE" in a for a in self.fw.avisos))
        self.assertEqual(self.r["9"].subreglas[0].protocolos, ["no_resuelto"])

    def test_denegacion_implicita_al_final(self):
        ult = self.fw.reglas[-1]
        self.assertEqual((ult.nombre, ult.accion, ult.origen, ult.destino),
                         ("Implicit deny", "bloquear", [N("0.0.0.0/0")], [N("0.0.0.0/0")]))

    def test_vip_es_aviso(self):
        self.assertTrue(any("vip" in a and "NAT" in a for a in self.fw.avisos))


class ContrasteTest(unittest.TestCase):
    def setUp(self):
        self.fw = _fw()

    def _res(self, conductos):
        return fi.contrastar(self.fw, conductos, "fg.txt", [])

    def test_conducto_casa_con_la_politica_de_su_zona(self):
        # 10.20.1.5 esta en port2, miembro de la zona OT; la politica 20 dice srcintf OT -> port1
        r = self._res([_c("10.20.1.5", "8.8.8.8", 443), _c("10.20.3.5", "8.8.8.8", 443),
                       _c("10.20.2.5", "8.8.8.8", 443)])
        self.assertEqual([(x["resultado"], x["regla"]) for x in r["resultados"]],
                         [("permitido", "20"), ("permitido", "20"), ("denegado_observado", "implicit-deny")])
        self.assertEqual(r["resultados"][0]["if_origen"], "port2")

    def test_deny_explicita_e_implicita(self):
        r = self._res([_c("10.20.2.5", "8.8.8.8", 23), _c("10.20.2.5", "8.8.8.8", 80)])
        self.assertEqual([(x["resultado"], x["regla"]) for x in r["resultados"]],
                         [("denegado_observado", "5"), ("denegado_observado", "implicit-deny")])
        self.assertEqual(r["resultados"][0]["regla_nombre"], "bloquear-telnet")

    def test_politica_desactivada_no_casa_y_tabla(self):
        r = self._res([_c("10.20.2.5", "10.20.1.5", 80)])      # la 7 (ALL) esta desactivada
        self.assertEqual(r["resultados"][0]["regla"], "implicit-deny")
        tab = {x["id"]: x for x in r["reglas"]}
        self.assertEqual(tab["7"]["activa"], False)
        self.assertEqual(tab["20"]["interfaces_origen"], "port2;vlan10")

    def test_sin_contadores_no_se_evalua_sin_aciertos(self):
        r = self._res([])
        self.assertFalse(r["resumen"]["con_contadores"])

    def test_contadores_por_id_y_por_nombre(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        csv_ = d / "hits.csv"
        csv_.write_text('ID,Name,Hit Count,Bytes\n20,ot-a-wan,"1,234",5 MB\n,bloquear-telnet,7,1 KB\n'
                        "8,,0,0\n", encoding="utf-8")
        fortigate.aplicar_contadores([self.fw], csv_)
        a = {r.id: r.aciertos for r in self.fw.reglas}
        self.assertEqual((a["20"], a["5"], a["8"], a["7"]), (1234, 7, 0, 0))
        self.assertFalse(any(x.startswith("sin contadores") for x in self.fw.avisos))
        r = self._res([_c("10.20.1.5", "8.8.8.8", 443)])
        self.assertTrue(r["resumen"]["con_contadores"])
        self.assertEqual({x["id"]: x["aciertos"] for x in r["reglas"]}["20"], 1234)


class VdomTest(unittest.TestCase):
    VDOMS = '''config vdom
edit root
next
edit ot
next
end
config global
config system global
    set hostname "FGT-V"
end
config system interface
    edit "wan"
        set vdom "root"
        set ip 192.0.2.2 255.255.255.0
    next
    edit "lan"
        set vdom "root"
        set ip 10.1.0.1 255.255.0.0
    next
    edit "ot1"
        set vdom "ot"
        set ip 10.2.0.1 255.255.0.0
    next
    edit "ot2"
        set vdom "ot"
        set ip 10.3.0.1 255.255.0.0
    next
end
end
config vdom
edit root
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
next
edit ot
config firewall policy
    edit 1
        set srcintf "ot1"
        set dstintf "ot2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
next
end
'''

    def test_cada_vdom_es_un_firewall(self):
        fws = fortigate.analizar_texto(self.VDOMS)
        self.assertEqual([f.hostname for f in fws], ["FGT-V:root", "FGT-V:ot"])
        self.assertEqual([i.fisica for i in fws[0].interfaces], ["wan", "lan"])
        self.assertEqual([i.fisica for i in fws[1].interfaces], ["ot1", "ot2"])
        self.assertEqual(fws[1].reglas[0].puertos, [(443, 443)])
        self.assertEqual(fws[0].reglas[0].protocolos, [])


class SeguridadTest(unittest.TestCase):
    def test_secretos_no_llegan_al_modelo(self):
        fw = _fw(BASE + TABLA)
        txt = repr(fw)
        for s in ("SECRETOX", "SECRETOY", "SECRETOZ", "SECRETOW", "SECRETOV", "SECRETOU", "ENC"):
            self.assertNotIn(s, txt)

    def test_secretos_no_llegan_a_las_salidas(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        est = gen_exports.escribir(tmp / "ex")["b"]
        fg = tmp / "fg.txt"
        fg.write_text(BASE, encoding="utf-8")
        out = tmp / "out"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                       "-o", str(out), "--firewall", str(fg)])
        self.assertEqual(rc, 0)
        with open(out / "firewall_reglas.csv", newline="", encoding="utf-8-sig") as fh:
            ids = [f["id"] for f in csv.DictReader(fh)]
        self.assertIn("implicit-deny", ids)
        self.assertNotIn("SECRETO", buf.getvalue())
        for f in out.rglob("*"):
            if f.is_file():
                self.assertNotIn(b"SECRETO", f.read_bytes(), f.name)

    def test_contadores_sin_firewall_es_error(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            main(["no_importa", "--firewall-contadores", "x.csv"])
        self.assertEqual(cm.exception.code, 2)


class DespachoTest(unittest.TestCase):
    def test_detecta_el_fabricante_por_el_contenido(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        fg = tmp / "fg.txt"
        fg.write_text(BASE, encoding="utf-8")
        ci = tmp / "ci.txt"
        ci.write_text(_sesion(RUTAS, "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"),
                      encoding="utf-8")
        fws, nombres = fi.cargar_todos([str(ci), str(fg)])
        self.assertEqual([f.fabricante for f in fws], [cisco.FABRICANTE, fortigate.FABRICANTE])
        self.assertEqual(nombres, ["ci.txt", "fg.txt"])

    def test_cadena_cisco_y_fortigate_descubre_el_enlace(self):
        """Cisco (outside 192.0.2.0/24 ... inside) y FortiGate en cadena: comparten la red 192.0.2.0/24."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        cisco_txt = tmp / "cisco.txt"
        cisco_txt.write_text(_sesion(
            "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
            "C   192.0.2.0 255.255.255.0 is directly connected, outside\n"
            "C   10.10.1.0 255.255.255.0 is directly connected, inside\n",
            "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n",
            "FW1# show interface ip brief\nInterface IP-Address OK? Method Status Protocol\n"
            "GigabitEthernet0/0 192.0.2.1 YES CONFIG up up\n"
            "GigabitEthernet0/1 10.10.1.2 YES CONFIG up up\n"), encoding="utf-8")
        fg = tmp / "fg.txt"
        fg.write_text(BASE, encoding="utf-8")
        _, res = fi.integrar([str(cisco_txt), str(fg)], {}, [_c("10.20.1.5", "10.10.1.7", 443)])
        enlaces = res["topologia"]["enlaces"]
        self.assertEqual(len(enlaces), 1, res["topologia"])
        txt = repr(enlaces)
        self.assertIn("FGT-1", txt)
        self.assertIn("192.0.2", txt)


if __name__ == "__main__":
    unittest.main()
