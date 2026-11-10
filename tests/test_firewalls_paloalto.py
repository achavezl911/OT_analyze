"""F3: adaptador Palo Alto (PAN-OS) al modelo comun de firewall. Texto sintetico, sin muestra real."""
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
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_integracion import _sesion

from ot_assess.cli import main
from ot_assess.firewalls import cisco, fortigate, paloalto
from ot_assess.firewalls import integracion as fi

N = ipaddress.IPv4Network

SET = '''set deviceconfig system hostname PA-1
set mgt-config users admin phash $1$SECRETOX
set shared certificate cert1 private-key SECRETOY
set network interface ethernet ethernet1/1 layer3 ip [ 192.0.2.2/24 ]
set network interface ethernet ethernet1/2 layer3 ip 10.20.1.1/24
set network interface ethernet ethernet1/2 layer3 pre-shared-key SECRETOW
set network interface ethernet ethernet1/3 layer3 units ethernet1/3.10 ip 10.20.3.1/24
set network interface ethernet ethernet1/3 layer3 units ethernet1/3.10 tag 10
set network interface ethernet ethernet1/4 layer3 ip 10.20.2.1/24
set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]
set network virtual-router default routing-table ip static-route def destination 0.0.0.0/0 nexthop ip-address 192.0.2.1 interface ethernet1/1
set network virtual-router default routing-table ip static-route ot destination 10.30.0.0/16 nexthop ip-address 10.20.1.254
set vsys vsys1 zone untrust network layer3 [ ethernet1/1 ]
set vsys vsys1 zone OT network layer3 [ ethernet1/2 ethernet1/3.10 ]
set vsys vsys1 zone OT authentication-profile SECRETOV
set vsys vsys1 zone IT network layer3 ethernet1/4
set vsys vsys1 address srv ip-netmask 10.20.1.10/32
set vsys vsys1 address rng ip-range 10.20.2.10-10.20.2.20
set vsys vsys1 address fq fqdn plc.example.com
set vsys vsys1 address wc ip-wildcard 10.0.0.0/0.0.255.255
set vsys vsys1 address-group g1 static [ srv g2 ]
set vsys vsys1 address-group g2 static [ rng g1 ]
set vsys vsys1 address-group dyn dynamic filter "'x'"
set vsys vsys1 service modbus protocol tcp port 502
set vsys vsys1 service web protocol tcp port 443,8080-8090
set vsys vsys1 service dns protocol udp port 53
set vsys vsys1 service dns protocol udp source-port 1024-65535
set vsys vsys1 service-group sg members [ modbus web ]
set vsys vsys1 rulebase security rules r-ot-it from IT
set vsys vsys1 rulebase security rules r-ot-it to OT
set vsys vsys1 rulebase security rules r-ot-it source rng
set vsys vsys1 rulebase security rules r-ot-it destination srv
set vsys vsys1 rulebase security rules r-ot-it service sg
set vsys vsys1 rulebase security rules r-ot-it application any
set vsys vsys1 rulebase security rules r-ot-it action allow
set vsys vsys1 rulebase security rules r-app from OT
set vsys vsys1 rulebase security rules r-app to IT
set vsys vsys1 rulebase security rules r-app source any
set vsys vsys1 rulebase security rules r-app destination any
set vsys vsys1 rulebase security rules r-app service application-default
set vsys vsys1 rulebase security rules r-app application [ modbus ssl ]
set vsys vsys1 rulebase security rules r-app action allow
set vsys vsys1 rulebase security rules r-drop from untrust
set vsys vsys1 rulebase security rules r-drop to [ OT IT ]
set vsys vsys1 rulebase security rules r-drop source any
set vsys vsys1 rulebase security rules r-drop destination g1
set vsys vsys1 rulebase security rules r-drop service any
set vsys vsys1 rulebase security rules r-drop action drop
set vsys vsys1 rulebase security rules r-off from [ IT ] to [ OT ] source any destination any service service-https action allow disabled yes
set vsys vsys1 rulebase security rules r-neg from IT
set vsys vsys1 rulebase security rules r-neg to untrust
set vsys vsys1 rulebase security rules r-neg source srv
set vsys vsys1 rulebase security rules r-neg negate-source yes
set vsys vsys1 rulebase security rules r-neg destination any
set vsys vsys1 rulebase security rules r-neg service service-http
set vsys vsys1 rulebase security rules r-neg source-user alice
set vsys vsys1 rulebase security rules r-neg action reset-both
'''

XML = '''<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
<mgt-config><users><entry name="admin"><phash>$1$SECRETOX</phash></entry></users></mgt-config>
<shared><certificate><entry name="cert1"><private-key>SECRETOY</private-key></entry></certificate></shared>
<devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>PA-1</hostname></system></deviceconfig>
<network>
<interface><ethernet>
<entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.2/24"/></ip></layer3></entry>
<entry name="ethernet1/2"><layer3><ip><entry name="10.20.1.1/24"/></ip><pre-shared-key>SECRETOW</pre-shared-key></layer3></entry>
<entry name="ethernet1/3"><layer3><units><entry name="ethernet1/3.10"><ip><entry name="10.20.3.1/24"/></ip><tag>10</tag></entry></units></layer3></entry>
<entry name="ethernet1/4"><layer3><ip><entry name="10.20.2.1/24"/></ip></layer3></entry>
</ethernet></interface>
<virtual-router><entry name="default">
<interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
<routing-table><ip><static-route>
<entry name="def"><destination>0.0.0.0/0</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop><interface>ethernet1/1</interface></entry>
<entry name="ot"><destination>10.30.0.0/16</destination><nexthop><ip-address>10.20.1.254</ip-address></nexthop></entry>
</static-route></ip></routing-table>
</entry></virtual-router>
</network>
<vsys><entry name="vsys1">
<zone>
<entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
<entry name="OT"><network><layer3><member>ethernet1/2</member><member>ethernet1/3.10</member></layer3></network><authentication-profile>SECRETOV</authentication-profile></entry>
<entry name="IT"><network><layer3><member>ethernet1/4</member></layer3></network></entry>
</zone>
<address>
<entry name="srv"><ip-netmask>10.20.1.10/32</ip-netmask></entry>
<entry name="rng"><ip-range>10.20.2.10-10.20.2.20</ip-range></entry>
<entry name="fq"><fqdn>plc.example.com</fqdn></entry>
<entry name="wc"><ip-wildcard>10.0.0.0/0.0.255.255</ip-wildcard></entry>
</address>
<address-group>
<entry name="g1"><static><member>srv</member><member>g2</member></static></entry>
<entry name="g2"><static><member>rng</member><member>g1</member></static></entry>
<entry name="dyn"><dynamic><filter>'x'</filter></dynamic></entry>
</address-group>
<service>
<entry name="modbus"><protocol><tcp><port>502</port></tcp></protocol></entry>
<entry name="web"><protocol><tcp><port>443,8080-8090</port></tcp></protocol></entry>
<entry name="dns"><protocol><udp><port>53</port><source-port>1024-65535</source-port></udp></protocol></entry>
</service>
<service-group><entry name="sg"><members><member>modbus</member><member>web</member></members></entry></service-group>
<rulebase><security><rules>
<entry name="r-ot-it"><from><member>IT</member></from><to><member>OT</member></to><source><member>rng</member></source><destination><member>srv</member></destination><service><member>sg</member></service><application><member>any</member></application><action>allow</action></entry>
<entry name="r-app"><from><member>OT</member></from><to><member>IT</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>application-default</member></service><application><member>modbus</member><member>ssl</member></application><action>allow</action></entry>
<entry name="r-drop"><from><member>untrust</member></from><to><member>OT</member><member>IT</member></to><source><member>any</member></source><destination><member>g1</member></destination><service><member>any</member></service><action>drop</action></entry>
<entry name="r-off"><from><member>IT</member></from><to><member>OT</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>service-https</member></service><action>allow</action><disabled>yes</disabled></entry>
<entry name="r-neg"><from><member>IT</member></from><to><member>untrust</member></to><source><member>srv</member></source><negate-source>yes</negate-source><destination><member>any</member></destination><service><member>service-http</member></service><source-user><member>alice</member></source-user><action>reset-both</action></entry>
</rules></security></rulebase>
</entry></vsys>
</entry></devices>
</config>
'''

TABLA = '''admin@PA-1> show routing route
flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp, E:ecmp

VIRTUAL ROUTER: default (id 1)
  ==========
destination                    nexthop                  metric flags      age   interface          next-AS
0.0.0.0/0                      192.0.2.1                10     A S                ethernet1/1
10.20.1.0/24                   10.20.1.1                0      A C                ethernet1/2
10.20.1.1/32                   0.0.0.0                  0      A H
10.99.0.0/16                   10.20.1.254              110    A O2     3d 4h     ethernet1/2
10.98.0.0/16                   10.20.1.254              10     S                  ethernet1/2
'''

HITS = '''admin@PA-1> show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
Total Rules: 7
Rule        Hit Count   Last Hit Timestamp    First Hit Timestamp
r-ot-it     1,234       2024/05/01 10:11:12   2023/01/02 03:04:05
r-app       0           -                     -
r-drop      7           2024/06/01 00:00:01   2024/05/30 00:00:02
intrazone-default  55   2024/06/02 01:02:03   2024/01/01 01:01:01
'''


def _fw(texto: str = SET, i: int = 0):
    return paloalto.analizar_texto(texto)[i]


def _c(src, dst, port=80, l4="tcp"):
    return {"src": src, "dst": dst, "l4": l4, "port": str(port)}


def _regla(fw, rid):
    return next(r for r in fw.reglas if r.id == rid)


class FormatosTest(unittest.TestCase):
    def test_set_y_xml_equivalentes_dan_el_mismo_modelo(self):
        a, b = _fw(SET), _fw(XML)
        self.assertEqual(repr(a), repr(b))
        self.assertEqual((a.fabricante, a.hostname), (paloalto.FABRICANTE, "PA-1"))

    def test_xml_dentro_de_otro_texto_y_con_tabla_de_rutas(self):
        fw = _fw("admin@PA-1> show config running\n" + XML + "\n" + TABLA)
        self.assertTrue(any(r.red == N("10.99.0.0/16") for r in fw.rutas))

    def test_xml_con_doctype_o_entity_se_rechaza(self):
        for peligro in ('<!DOCTYPE config [<!ENTITY x "y">]>\n', '<!ENTITY x "y">\n'):
            with self.assertRaises(SystemExit) as cm:
                _fw(peligro + XML)
            self.assertIn("DOCTYPE o ENTITY", str(cm.exception))

    def test_xml_demasiado_grande_se_rechaza(self):
        with mock.patch.object(paloalto, "MAX_XML", 100), self.assertRaises(SystemExit):
            _fw(XML)

    def test_xml_mal_formado_se_rechaza(self):
        with self.assertRaises(SystemExit):
            _fw("<config><devices><rulebase>")


class InterfacesRutasTest(unittest.TestCase):
    def test_interfaces_subinterfaces_y_zonas(self):
        fw = _fw()
        z = {i.nombre: (i.ip, i.mascara, i.zona) for i in fw.interfaces}
        self.assertEqual(z["ethernet1/1"], ("192.0.2.2", "255.255.255.0", "untrust"))
        self.assertEqual(z["ethernet1/3.10"], ("10.20.3.1", "255.255.255.0", "OT"))
        self.assertEqual(z["ethernet1/3"][0], "")
        self.assertEqual(fw.zona_de("ethernet1/4"), "IT")

    def test_rutas_estaticas_y_conectadas(self):
        fw = _fw()
        r = {str(x.red): x for x in fw.rutas}
        self.assertEqual((r["0.0.0.0/0"].interfaz, r["0.0.0.0/0"].salto, r["0.0.0.0/0"].tipo),
                         ("ethernet1/1", "192.0.2.1", "defecto"))
        # sin interfaz en la ruta: la de la red conectada al salto
        self.assertEqual(r["10.30.0.0/16"].interfaz, "ethernet1/2")
        self.assertEqual(r["10.20.3.0/24"].tipo, "conectada")
        self.assertEqual(fw.interfaz_de("10.20.3.9"), "ethernet1/3.10")

    def test_tabla_de_rutas_solo_activas(self):
        fw = _fw(SET + TABLA)
        r = {str(x.red): x for x in fw.rutas}
        self.assertEqual(r["10.99.0.0/16"].tipo, "dinamica")
        self.assertEqual(r["10.99.0.0/16"].interfaz, "ethernet1/2")
        self.assertEqual(r["10.99.0.0/16"].codigo, "O2")
        self.assertNotIn("10.98.0.0/16", r)      # sin bandera A
        self.assertFalse([a for a in fw.avisos if a.startswith("sin show routing route")])
        self.assertTrue([a for a in _fw().avisos if a.startswith("sin show routing route")])


class ObjetosReglasTest(unittest.TestCase):
    def test_direcciones_grupos_con_ciclo_y_no_resolubles(self):
        fw = _fw()
        r = _regla(fw, "r-drop")
        self.assertEqual(sorted(map(str, r.destino)),
                         sorted(["10.20.1.10/32"] + [str(x) for x in ipaddress.summarize_address_range(
                             ipaddress.IPv4Address("10.20.2.10"), ipaddress.IPv4Address("10.20.2.20"))]))
        self.assertIn("referencia circular", " ".join(fw.avisos))
        ctx = paloalto._Ctx([{}], [])
        self.assertEqual(ctx.direccion("nada")[1], ["direccion no definida: nada"])

    def test_fqdn_wildcard_y_dinamico_son_avisos(self):
        ctx = paloalto._Ctx([{"address": {"fq": {"fqdn": {"x.example": {}}}, "wc": {"ip-wildcard": {"1.0.0.0/0.0.0.255": {}}}},
                              "address-group": {"d": {"dynamic": {"filter": {}}}}}], [])
        self.assertEqual(ctx.direccion("fq"), ([], ["fqdn: fq"]))
        self.assertIn("ip-wildcard", ctx.direccion("wc")[1][0])
        self.assertIn("dinamico", ctx.direccion("d")[1][0])

    def test_servicios_rangos_grupos_y_predefinidos(self):
        fw = _fw()
        r = _regla(fw, "r-ot-it")
        self.assertEqual((r.protocolos, r.puertos), (["tcp"], [(443, 443), (502, 502), (8080, 8090)]))
        self.assertEqual(_regla(fw, "r-neg").puertos, [(80, 80), (8080, 8080)])
        self.assertEqual(_regla(fw, "r-off").puertos, [(443, 443)])
        ctx = paloalto._Ctx([{"service": {"dns": {"protocol": {"udp": {"port": {"53": {}},
                                                                       "source-port": {"1024-65535": {}}}}}}}], [])
        ents, malos, _ = ctx.servicio("dns")
        self.assertEqual((ents, malos), ([("udp", ((53, 53),), ((1024, 65535),))], []))

    def test_reglas_en_orden_con_zonas_y_acciones(self):
        fw = _fw()
        self.assertEqual([r.id for r in fw.reglas], ["r-ot-it", "r-app", "r-drop", "r-off", "r-neg",
                                                     "intrazone-default", "interzone-default"])
        self.assertEqual([r.accion for r in fw.reglas],
                         ["permitir", "permitir", "bloquear", "permitir", "bloquear", "permitir", "bloquear"])
        self.assertEqual(_regla(fw, "r-ot-it").zonas_origen, ["ethernet1/4"])
        self.assertEqual(_regla(fw, "r-ot-it").zonas_destino, ["ethernet1/2", "ethernet1/3.10"])
        self.assertEqual(_regla(fw, "r-drop").zonas_destino, ["ethernet1/2", "ethernet1/3.10", "ethernet1/4"])
        self.assertEqual(_regla(fw, "r-app").zonas_origen, ["ethernet1/2", "ethernet1/3.10"])
        self.assertFalse(_regla(fw, "r-off").activa)
        self.assertTrue(_regla(fw, "r-ot-it").activa)

    def test_application_default_se_marca_y_avisa(self):
        fw = _fw()
        r = _regla(fw, "r-app")
        self.assertEqual((r.protocolos, r.puertos), ([], []))     # cualquier puerto
        self.assertTrue([m for m in r.no_resuelto if m.startswith("app-id:")])
        self.assertIn("aplicaciones: modbus, ssl", r.lineas)
        self.assertTrue([a for a in fw.avisos if a.startswith("app-id:")])
        self.assertFalse([m for m in _regla(fw, "r-ot-it").no_resuelto if m.startswith("app-id:")])

    def test_negate_y_source_user_son_avisos(self):
        r = _regla(_fw(), "r-neg")
        self.assertEqual(r.origen, [])
        txt = " ".join(r.no_resuelto)
        self.assertIn("negate-source no modelado", txt)
        self.assertIn("source-user", txt)

    def test_reglas_por_defecto_intrazone_e_interzone(self):
        fw = _fw()
        intra, inter = _regla(fw, "intrazone-default"), _regla(fw, "interzone-default")
        self.assertEqual(len(intra.subreglas), 3)
        self.assertEqual(intra.subreglas[1].zonas_origen, ["ethernet1/2", "ethernet1/3.10"])
        self.assertEqual(intra.subreglas[1].zonas_origen, intra.subreglas[1].zonas_destino)
        self.assertEqual((inter.accion, inter.zonas_origen), ("bloquear", []))
        self.assertEqual(fw.reglas[-1].id, "interzone-default")


class ContrasteTest(unittest.TestCase):
    def _res(self, conductos, texto=SET):
        d = fi.contrastar(_fw(texto), conductos, "pa.txt", [])
        return d, [(x["resultado"], x["regla"]) for x in d["resultados"]]

    def test_conducto_entre_zonas_casa_con_su_regla(self):
        _, r = self._res([_c("10.20.2.15", "10.20.1.10", 502),       # IT -> OT, rango -> srv, modbus
                          _c("192.0.2.50", "10.20.1.10", 22),        # untrust -> OT: drop
                          _c("10.20.1.5", "192.0.2.9", 80),          # OT -> untrust: ninguna explicita
                          _c("10.20.2.15", "10.20.1.10", 3000)])     # IT -> OT puerto no permitido
        self.assertEqual(r, [("permitido", "r-ot-it"), ("denegado_observado", "r-drop"),
                             ("denegado_observado", "interzone-default"),
                             ("denegado_observado", "interzone-default")])

    def test_dentro_de_la_misma_zona_es_intrazone_default(self):
        _, r = self._res([_c("10.20.1.5", "10.20.3.5", 4840)])       # ethernet1/2 -> ethernet1/3.10 (zona OT)
        self.assertEqual(r, [("permitido", "intrazone-default")])

    def test_regla_desactivada_no_casa_y_tabla(self):
        d, r = self._res([_c("10.20.2.15", "10.20.1.5", 443)])
        self.assertEqual(r, [("denegado_observado", "interzone-default")])
        filas = {x["id"]: x for x in d["reglas"]}
        self.assertFalse(filas["r-off"]["activa"])
        self.assertIn("app-id", filas["r-app"]["avisos"])
        self.assertEqual(filas["r-ot-it"]["interfaces_origen"], "ethernet1/4")


class ContadoresTest(unittest.TestCase):
    def test_en_el_mismo_archivo(self):
        fw = _fw(SET + HITS)
        r = _regla(fw, "r-ot-it")
        self.assertEqual((r.aciertos, r.ultimo_acierto, r.primer_acierto),
                         (1234, "2024-05-01 10:11:12", "2023-01-02 03:04:05"))
        self.assertEqual(_regla(fw, "r-app").aciertos, 0)
        self.assertEqual(_regla(fw, "intrazone-default").aciertos, 55)
        self.assertFalse([a for a in fw.avisos if a.startswith("sin contadores")])
        d = fi.contrastar(fw, [_c("10.20.2.15", "10.20.1.10", 502)], "pa.txt", [])
        self.assertTrue(d["resumen"]["con_contadores"])

    def test_orden_de_columnas_primero_y_ultimo(self):
        txt = ("Rule Hit Count First Hit Timestamp Last Hit Timestamp\n"
               "r-ot-it 3 2020/01/01 00:00:00 2021/02/02 00:00:00\n")
        fw = _fw()
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "h.txt").write_text(txt, encoding="utf-8")
        paloalto.aplicar_contadores([fw], str(tmp / "h.txt"))
        r = _regla(fw, "r-ot-it")
        self.assertEqual((r.aciertos, r.primer_acierto, r.ultimo_acierto),
                         (3, "2020-01-01 00:00:00", "2021-02-02 00:00:00"))

    def test_sin_contadores_no_se_evalua(self):
        d = fi.contrastar(_fw(), [_c("10.20.2.15", "10.20.1.10", 502)], "pa.txt", [])
        self.assertFalse(d["resumen"]["con_contadores"])

    def test_archivo_sin_tabla_avisa(self):
        fw = _fw()
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "h.txt").write_text("nada util\n", encoding="utf-8")
        paloalto.aplicar_contadores([fw], str(tmp / "h.txt"))
        self.assertTrue([a for a in fw.avisos if "sin tabla de Hit Count" in a])


class VsysTest(unittest.TestCase):
    TEXTO = '''set deviceconfig system hostname PA-V
set network interface ethernet ethernet1/1 layer3 ip 10.1.0.1/24
set network interface ethernet ethernet1/2 layer3 ip 10.2.0.1/24
set vsys vsys1 zone a network layer3 ethernet1/1
set vsys vsys2 zone b network layer3 ethernet1/2
set vsys vsys1 rulebase security rules x from a
set vsys vsys1 rulebase security rules x to a
set vsys vsys1 rulebase security rules x source any
set vsys vsys1 rulebase security rules x destination any
set vsys vsys1 rulebase security rules x service any
set vsys vsys1 rulebase security rules x action allow
'''

    def test_cada_vsys_es_un_firewall(self):
        a, b = paloalto.analizar_texto(self.TEXTO)
        self.assertEqual((a.hostname, b.hostname), ("PA-V:vsys1", "PA-V:vsys2"))
        self.assertEqual([i.nombre for i in a.interfaces], ["ethernet1/1"])
        self.assertEqual([i.nombre for i in b.interfaces], ["ethernet1/2"])
        self.assertIn("x", [r.id for r in a.reglas])
        self.assertNotIn("x", [r.id for r in b.reglas])

    def test_un_solo_vsys_no_lleva_sufijo(self):
        self.assertEqual(_fw().hostname, "PA-1")


class SeguridadTest(unittest.TestCase):
    def test_secretos_no_llegan_al_modelo(self):
        for texto in (SET, XML):
            txt = repr(_fw(texto))
            for s in ("SECRETOX", "SECRETOY", "SECRETOW", "SECRETOV", "phash", "pre-shared"):
                self.assertNotIn(s, txt)

    def test_secretos_no_llegan_a_las_salidas(self):
        for nombre, texto in (("set", SET + HITS), ("xml", XML + HITS)):
            with self.subTest(nombre):
                tmp = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
                est = gen_exports.escribir(tmp / "ex")["b"]
                pa = tmp / "pa.txt"
                pa.write_text(texto, encoding="utf-8")
                out = tmp / "out"
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                               "-o", str(out), "--firewall", str(pa)])
                self.assertEqual(rc, 0)
                with open(out / "firewall_reglas.csv", newline="", encoding="utf-8-sig") as fh:
                    ids = [f["id"] for f in csv.DictReader(fh)]
                self.assertIn("interzone-default", ids)
                self.assertNotIn("SECRETO", buf.getvalue())
                for f in out.rglob("*"):
                    if f.is_file():
                        self.assertNotIn(b"SECRETO", f.read_bytes(), f.name)


class DespachoTest(unittest.TestCase):
    def test_detecta_el_fabricante_por_el_contenido(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "pa.txt").write_text(SET, encoding="utf-8")
        (tmp / "pax.xml").write_text(XML, encoding="utf-8")
        (tmp / "ci.txt").write_text(_sesion(
            "C        10.10.1.0 255.255.255.0 is directly connected, inside\n",
            "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n"), encoding="utf-8")
        (tmp / "fg.txt").write_text("config system interface\n    edit \"port1\"\n        set vdom \"root\"\n"
                                    "    next\nend\n", encoding="utf-8")
        fws, nombres = fi.cargar_todos([str(tmp / n) for n in ("ci.txt", "fg.txt", "pa.txt", "pax.xml")])
        self.assertEqual([f.fabricante for f in fws],
                         [cisco.FABRICANTE, fortigate.FABRICANTE, paloalto.FABRICANTE, paloalto.FABRICANTE])
        self.assertEqual(nombres, ["ci.txt", "fg.txt", "pa.txt", "pax.xml"])

    def test_contadores_de_la_cli_se_aplican(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "pa.txt").write_text(SET, encoding="utf-8")
        (tmp / "h.txt").write_text(HITS, encoding="utf-8")
        fws, _ = fi.cargar_todos([str(tmp / "pa.txt")], str(tmp / "h.txt"))
        self.assertEqual(_regla(fws[0], "r-drop").aciertos, 7)

    def test_cadena_cisco_y_paloalto_descubre_el_enlace(self):
        """Cisco (outside 192.0.2.0/24) y PAN-OS (ethernet1/1 192.0.2.2/24) comparten la red 192.0.2.0/24."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        ci = tmp / "cisco.txt"
        ci.write_text(_sesion(
            "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
            "C   192.0.2.0 255.255.255.0 is directly connected, outside\n"
            "C   10.10.1.0 255.255.255.0 is directly connected, inside\n",
            "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 1\n",
            "FW1# show interface ip brief\nInterface IP-Address OK? Method Status Protocol\n"
            "GigabitEthernet0/0 192.0.2.1 YES CONFIG up up\n"
            "GigabitEthernet0/1 10.10.1.2 YES CONFIG up up\n"), encoding="utf-8")
        pa = tmp / "pa.txt"
        pa.write_text(SET, encoding="utf-8")
        _, res = fi.integrar([str(ci), str(pa)], {}, [_c("10.20.1.5", "10.10.1.7", 443)])
        enlaces = res["topologia"]["enlaces"]
        self.assertEqual(len(enlaces), 1, res["topologia"])
        txt = repr(enlaces)
        self.assertIn("PA-1", txt)
        self.assertIn("192.0.2", txt)


if __name__ == "__main__":
    unittest.main()
