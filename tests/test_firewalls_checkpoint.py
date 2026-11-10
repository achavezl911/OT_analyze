"""F4: adaptador Check Point (mgmt_cli JSON + Gaia clish) al modelo comun de firewall. Sintetico, sin muestra real."""
from __future__ import annotations

import ipaddress
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_firewalls_integracion import _sesion

from ot_assess.firewalls import checkpoint, cisco, fortigate, paloalto
from ot_assess.firewalls import integracion as fi

N = ipaddress.IPv4Network

OBJETOS = [
    {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    {"uid": "acc", "name": "Accept", "type": "RulebaseAction"},
    {"uid": "drp", "name": "Drop", "type": "RulebaseAction"},
    {"uid": "rej", "name": "Reject", "type": "RulebaseAction"},
    {"uid": "lay", "name": "Apply Layer", "type": "RulebaseAction"},
    {"uid": "tlog", "name": "Log", "type": "Track"},
    {"uid": "tnone", "name": "None", "type": "Track"},
    {"uid": "h1", "name": "srv", "type": "host", "ipv4-address": "10.20.1.10",
     "password": "SECRETOA", "shared-secret": "SECRETOB"},
    {"uid": "h6", "name": "srv6", "type": "host", "ipv6-address": "2001:db8::1"},
    {"uid": "n1", "name": "it-net", "type": "network", "subnet4": "10.20.2.0", "mask-length4": 24,
     "pre-shared-key": "SECRETOC"},
    {"uid": "r1", "name": "rng", "type": "address-range", "ipv4-address-first": "10.20.3.10",
     "ipv4-address-last": "10.20.3.20"},
    {"uid": "g1", "name": "g1", "type": "group", "members": ["h1", "g2"]},
    {"uid": "g2", "name": "g2", "type": "group", "members": ["r1", "g1"]},
    {"uid": "dom", "name": "fq", "type": "dns-domain"},
    {"uid": "s502", "name": "modbus", "type": "service-tcp", "port": "502"},
    {"uid": "sweb", "name": "web", "type": "service-tcp", "port": "443", "certificate": "SECRETOD"},
    {"uid": "srng", "name": "rango", "type": "service-tcp", "port": "8080-8090"},
    {"uid": "shi", "name": "altos", "type": "service-udp", "port": ">1023"},
    {"uid": "slo", "name": "bajos", "type": "service-tcp", "port": "<1024"},
    {"uid": "sg", "name": "sg", "type": "service-group", "members": ["s502", "sweb", "sg2"]},
    {"uid": "sg2", "name": "sg2", "type": "service-group", "members": ["srng", "sg"]},
    {"uid": "ping", "name": "echo-request", "type": "service-icmp"},
    {"uid": "oth", "name": "gre", "type": "service-other"},
    {"uid": "zdmz", "name": "DMZ", "type": "security-zone"},
    {"uid": "lyr", "name": "SubCapa", "type": "access-layer"},
]


def _r(n, src, dst, svc, acc="acc", **kw):
    d = {"uid": f"u{n}", "type": "access-rule", "rule-number": n, "name": f"R{n}", "source": src,
         "destination": dst, "service": svc, "action": acc, "enabled": True, "track": {"type": "tlog"},
         "install-on": ["any"], "comments": "SECRETOE"}
    d.update(kw)
    return d


def _pagina(reglas, nombre="Network", objetos=OBJETOS, **kw):
    d = {"uid": "L1", "name": nombre, "rulebase": reglas, "objects-dictionary": objetos, "total": 9}
    d.update(kw)
    return d


def _reglas_base():
    return [
        {"uid": "sec1", "type": "access-section", "name": "OT", "rulebase": [
            _r(1, ["n1"], ["g1"], ["sg"], hits={"value": 7, "first-date": {"posix": 1700000000000},
                                                "last-date": {"iso-8601": "2024-01-02T10:30+0100"}}),
            _r(2, ["any"], ["h1"], ["ping"], acc="rej")]},
        {"uid": "sec2", "type": "access-section", "name": "Resto", "rulebase": [
            _r(3, ["any"], ["any"], ["any"], acc="drp", enabled=False),
            _r(4, ["n1"], ["h1"], ["slo", "shi"])]},
    ]


def _fw(reglas=None, texto="", **kw):
    return checkpoint.analizar([_pagina(reglas if reglas is not None else _reglas_base(), **kw)], texto)


def _regla(fw, rid):
    return next(r for r in fw.reglas if r.id == rid)


def _c(src, dst, port=80, l4="tcp"):
    return {"src": src, "dst": dst, "l4": l4, "port": str(port)}


CLISH = '''gw1> show interfaces all
Interface eth1
    state on
    mac-addr 00:1c:7f:00:00:01
    ipv4-address 10.20.1.1/24
Interface eth2
    state on
    ipv4-address 10.20.2.1/24
Interface eth3
    state off
    ipv4-address 10.20.3.1/24
Interface lo
    state on
    ipv4-address 127.0.0.1/8
gw1> show route
Codes: C - Connected, S - Static, R - RIP, B - BGP (D - Default), O - OSPF IntraArea (IA - InterArea)

S      0.0.0.0/0          via 10.20.1.254, eth1, cost 0, age 1234
C      10.20.1.0/24       is directly connected, eth1
C      10.20.2.0/24       is directly connected, eth2
O      10.30.0.0/16       via 10.20.1.253, eth1, cost 20, age 99
'''

NETSTAT = '''Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         10.20.1.254     0.0.0.0         UG        0 0          0 eth1
10.20.1.0       0.0.0.0         255.255.255.0   U         0 0          0 eth1
'''


class PaginacionYSeccionesTest(unittest.TestCase):
    def test_dos_archivos_en_orden_con_secciones(self):
        base = _reglas_base()
        p2 = _pagina([{"uid": "sec2", "type": "access-section", "name": "Resto", "rulebase": base[1]["rulebase"]}],
                     **{"from": 3})
        p1 = _pagina([base[0]])
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        # el orden de los nombres de archivo es el inverso del de las paginas
        (tmp / "a_pagina2.json").write_text(json.dumps(p2), encoding="utf-8")
        (tmp / "b_pagina1.json").write_text(json.dumps(p1), encoding="utf-8")
        (tmp / "gw.txt").write_text(CLISH, encoding="utf-8")
        fw = checkpoint.cargar(tmp)
        self.assertEqual([r.id for r in fw.reglas], ["1", "2", "3", "4", "cleanup-implicita"])
        self.assertEqual([r.seccion for r in fw.reglas][:4], ["OT", "OT", "Resto", "Resto"])
        self.assertEqual(fw.reglas[0].politica, "Network")
        self.assertEqual(fw.hostname, "gw1")

    def test_regla_repetida_entre_paginas_no_se_duplica(self):
        p = _pagina(_reglas_base())
        fw = checkpoint.analizar([p, p])
        self.assertEqual(len(fw.reglas), 5)

    def test_regla_sin_numero_o_pagina_desordenada(self):
        b = _reglas_base()
        fw = _fw([b[1], b[0]])
        self.assertEqual([r.id for r in fw.reglas][:4], ["1", "2", "3", "4"])


class ObjetosTest(unittest.TestCase):
    def test_host_network_rango_grupos_con_ciclo_y_any(self):
        fw = _fw()
        r1, r2, r4 = _regla(fw, "1"), _regla(fw, "2"), _regla(fw, "4")
        self.assertEqual(r1.origen, [N("10.20.2.0/24")])
        self.assertIn(N("10.20.1.10/32"), r1.destino)
        rango = list(ipaddress.summarize_address_range(ipaddress.IPv4Address("10.20.3.10"),
                                                       ipaddress.IPv4Address("10.20.3.20")))
        self.assertTrue(set(rango) <= set(r1.destino))
        self.assertTrue(any("referencia circular" in a for a in fw.avisos))
        self.assertEqual(r2.origen, [N("0.0.0.0/0")])
        self.assertEqual(r4.destino, [N("10.20.1.10/32")])

    def test_servicios_puertos_rangos_y_grupos(self):
        fw = _fw()
        r1, r4, r2 = _regla(fw, "1"), _regla(fw, "4"), _regla(fw, "2")
        self.assertEqual(r1.protocolos, ["tcp"])
        self.assertEqual(r1.puertos, [(443, 443), (502, 502), (8080, 8090)])
        self.assertEqual(r4.protocolos, ["tcp", "udp"])
        por_proto = {s.protocolos[0]: s.puertos_destino for s in r4.subreglas}
        self.assertEqual(por_proto, {"tcp": [(1, 1023)], "udp": [(1024, 65535)]})
        self.assertEqual(r2.protocolos, ["icmp"])

    def test_any_servicio_y_no_resueltos_avisan(self):
        fw = _fw([_r(1, ["h6"], ["dom"], ["oth"]), _r(2, ["any"], ["any"], ["any"])])
        r = _regla(fw, "1")
        txt = " ".join(r.no_resuelto)
        self.assertIn("IPv6", txt)
        self.assertIn("dns-domain", txt)
        self.assertIn("service-other", txt)
        self.assertEqual(r.origen, [])
        self.assertEqual(r.subreglas[0].protocolos, ["no_resuelto"])
        self.assertEqual(_regla(fw, "2").protocolos, [])


class AccionesTest(unittest.TestCase):
    def test_accept_drop_reject_enabled_hits(self):
        fw = _fw()
        self.assertEqual([_regla(fw, i).accion for i in "1234"], ["permitir", "bloquear", "bloquear", "permitir"])
        self.assertFalse(_regla(fw, "3").activa)
        self.assertTrue(_regla(fw, "1").activa)
        r1 = _regla(fw, "1")
        self.assertEqual(r1.aciertos, 7)
        self.assertEqual(r1.primer_acierto, "2023-11-14 22:13:20")
        self.assertEqual(r1.ultimo_acierto, "2024-01-02 09:30:00")      # +0100 pasado a UTC
        self.assertTrue(r1.registro)
        self.assertFalse(any("sin contadores" in a for a in fw.avisos))

    def test_sin_hits_avisa_y_track_none(self):
        fw = _fw([_r(1, ["any"], ["h1"], ["any"], track={"type": "tnone"})])
        self.assertTrue(any("sin contadores" in a for a in fw.avisos))
        self.assertFalse(_regla(fw, "1").registro)

    def test_negate_inline_layer_e_install_on_son_aviso(self):
        fw = _fw([_r(1, ["n1"], ["h1"], ["sg"], **{"source-negate": True}),
                  _r(2, ["any"], ["h1"], ["any"], acc="lay", **{"inline-layer": "lyr"}),
                  _r(3, ["any"], ["h1"], ["any"], **{"install-on": ["h1"]})])
        r1, r2, r3 = _regla(fw, "1"), _regla(fw, "2"), _regla(fw, "3")
        self.assertEqual(r1.origen, [])
        self.assertIn("source-negate no modelado", r1.no_resuelto)
        self.assertTrue(any("inline-layer SubCapa no se expande" in x for x in r2.no_resuelto))
        self.assertEqual(r2.accion, "bloquear")
        self.assertTrue(any("install-on srv" in x for x in r3.no_resuelto))

    def test_zona_de_seguridad_es_la_interfaz_de_la_regla_con_aviso(self):
        fw = _fw([_r(1, ["zdmz"], ["h1"], ["sg"])])
        r = _regla(fw, "1")
        self.assertEqual(r.zonas_origen, ["DMZ"])
        self.assertEqual(r.origen, [N("0.0.0.0/0")])
        self.assertTrue(any("--zonas-fw" in a for a in fw.avisos))


class CleanupTest(unittest.TestCase):
    def test_cleanup_implicita_al_final(self):
        fw = _fw()
        ult = fw.reglas[-1]
        self.assertEqual((ult.id, ult.accion, ult.origen, ult.destino), ("cleanup-implicita", "bloquear",
                                                                       [N("0.0.0.0/0")], [N("0.0.0.0/0")]))

    def test_cleanup_explicita_no_se_duplica(self):
        fw = _fw([_r(1, ["n1"], ["h1"], ["sg"]), _r(2, ["any"], ["any"], ["any"], acc="drp")])
        self.assertEqual([r.id for r in fw.reglas], ["1", "2"])

    def test_cleanup_explicita_deshabilitada_o_con_zona_no_cuenta(self):
        fw = _fw([_r(1, ["any"], ["any"], ["any"], acc="drp", enabled=False)])
        self.assertEqual(fw.reglas[-1].id, "cleanup-implicita")
        fw = _fw([_r(1, ["zdmz"], ["any"], ["any"], acc="drp")])
        self.assertEqual(fw.reglas[-1].id, "cleanup-implicita")


class GatewayTest(unittest.TestCase):
    def test_interfaces_y_rutas_de_clish(self):
        fw = _fw(texto=CLISH)
        self.assertEqual([(i.nombre, i.ip, i.mascara) for i in fw.interfaces],
                         [("eth1", "10.20.1.1", "255.255.255.0"), ("eth2", "10.20.2.1", "255.255.255.0"),
                          ("lo", "127.0.0.1", "255.0.0.0")])
        self.assertTrue(any("eth3" in a and "state off" in a for a in fw.avisos))
        por_red = {str(r.red): r for r in fw.rutas}
        self.assertEqual((por_red["0.0.0.0/0"].tipo, por_red["0.0.0.0/0"].salto, por_red["0.0.0.0/0"].interfaz),
                         ("defecto", "10.20.1.254", "eth1"))
        self.assertEqual(por_red["10.20.2.0/24"].tipo, "conectada")
        self.assertEqual((por_red["10.30.0.0/16"].tipo, por_red["10.30.0.0/16"].metrica), ("dinamica", 20))
        self.assertEqual(fw.interfaz_de("10.30.4.4"), "eth1")

    def test_netstat_expert(self):
        fw = _fw(texto=NETSTAT)
        por_red = {str(r.red): r for r in fw.rutas}
        self.assertEqual((por_red["0.0.0.0/0"].tipo, por_red["0.0.0.0/0"].salto), ("defecto", "10.20.1.254"))
        self.assertEqual((por_red["10.20.1.0/24"].tipo, por_red["10.20.1.0/24"].interfaz), ("conectada", "eth1"))

    def test_set_interface_de_la_configuracion(self):
        fw = _fw(texto="set interface eth5 ipv4-address 10.50.0.1 mask-length 24\nset interface eth5 state on\n")
        self.assertEqual([(i.nombre, i.mascara) for i in fw.interfaces], [("eth5", "255.255.255.0")])

    def test_contraste_con_interfaces_casa_reglas_sin_zona(self):
        fw = _fw(texto=CLISH)
        d = fi.contrastar(fw, [_c("10.20.2.15", "10.20.1.10", 502),      # eth2 -> eth1: regla 1
                               _c("10.20.2.15", "10.20.1.10", 3000),     # puerto no permitido: regla 4 (tcp <1024) no
                               _c("10.20.1.5", "10.20.1.10", 502)],      # misma interfaz
                          "cp", [])
        r = [(x["resultado"], x["regla"]) for x in d["resultados"]]
        self.assertEqual(r[0], ("permitido", "1"))
        self.assertEqual(r[1][0], "denegado_observado")      # cae en la cleanup implicita
        self.assertEqual(r[1][1], "cleanup-implicita")
        self.assertEqual(r[2][0], "no_cruza")
        self.assertEqual(d["resumen"]["reglas"], 5)

    def test_sin_interfaces_avisa_y_no_hay_cruce(self):
        fw = _fw()
        self.assertEqual(fw.interfaces, [])
        self.assertTrue(any("sin show interfaces all" in a for a in fw.avisos))
        self.assertTrue(all(not r.zonas_origen and not r.zonas_destino for r in fw.reglas))   # cualquier interfaz
        d = fi.contrastar(fw, [_c("10.20.2.15", "10.20.1.10", 502)], "cp", [])
        self.assertEqual(d["resultados"][0]["resultado"], "no_cruza")

    def test_regla_con_zona_no_casa_con_interfaz_real(self):
        fw = _fw([_r(1, ["zdmz"], ["h1"], ["sg"])], texto=CLISH)
        d = fi.contrastar(fw, [_c("10.20.2.15", "10.20.1.10", 502)], "cp", [])
        self.assertEqual(d["resultados"][0]["regla"], "cleanup-implicita")


class SeguridadTest(unittest.TestCase):
    def test_secretos_fuera_del_modelo_y_de_la_salida(self):
        texto = CLISH + "set user admin password-hash SECRETOF\nset interface eth1 comments SECRETOG\n"
        fw = _fw(texto=texto)
        d = fi.contrastar(fw, [_c("10.20.2.15", "10.20.1.10", 502)], "cp", [])
        for obj in (repr(fw), repr(d)):
            for s in "ABCDEFG":
                self.assertNotIn("SECRETO" + s, obj)


class DespachoTest(unittest.TestCase):
    def test_detecta_por_contenido_y_los_demas_siguen_igual(self):
        from test_firewalls_paloalto import SET as PA_SET
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "cp.json").write_text(json.dumps(_pagina(_reglas_base())), encoding="utf-8")
        (tmp / "otro.json").write_text(json.dumps({"rulebase": [], "x": 1}), encoding="utf-8")
        (tmp / "pa.txt").write_text(PA_SET, encoding="utf-8")
        (tmp / "ci.txt").write_text(_sesion(
            "C        10.10.1.0 255.255.255.0 is directly connected, inside\n",
            "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"), encoding="utf-8")
        (tmp / "fg.txt").write_text("config system interface\n    edit \"port1\"\n        set vdom \"root\"\n"
                                    "    next\nend\n", encoding="utf-8")
        fws, nombres = fi.cargar_todos([str(tmp / n) for n in ("ci.txt", "fg.txt", "pa.txt", "cp.json")])
        self.assertEqual([f.fabricante for f in fws],
                         [cisco.FABRICANTE, fortigate.FABRICANTE, paloalto.FABRICANTE, checkpoint.FABRICANTE])
        self.assertEqual(nombres, ["ci.txt", "fg.txt", "pa.txt", "cp.json"])
        self.assertIsNone(checkpoint.detectar(tmp / "otro.json"))
        self.assertIsNone(checkpoint.detectar(tmp / "pa.txt"))

    def test_carpeta_con_json_y_clish_integra(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "rulebase.json").write_text(json.dumps(_pagina(_reglas_base())), encoding="utf-8")
        (tmp / "gaia.txt").write_text(CLISH, encoding="utf-8")
        _, res = fi.integrar([str(tmp)], {}, [_c("10.20.2.15", "10.20.1.10", 502)])
        self.assertEqual(res["fabricante"], "Check Point")
        self.assertEqual(res["resultados"][0]["regla"], "1")


if __name__ == "__main__":
    unittest.main()
