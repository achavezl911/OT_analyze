"""D70: NAT estatico de Cisco FTD/ASA en el contraste, la propuesta y la validacion. Configuraciones sinteticas."""
from __future__ import annotations

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_validar_politica import Base, cruce

from ot_assess.firewalls import cisco, cruces
from ot_assess.firewalls import integracion as fi
from ot_assess.firewalls import nat as nt
from ot_assess.firewalls import politica as po
from ot_assess.firewalls import validar_politica as vp

SECRETOS = "username admin password SECRETOX encrypted\n"
OBJ = ("object network RS\n host 10.10.1.5\n"
       "object network MS\n host 10.10.9.50\n"
       "object network RD\n host 192.0.2.77\n"
       "object network MD\n host 198.51.100.77\n")
TWICE = "nat (inside,outside) source static RS MS destination static MD RD description servidor de prueba\n"
PERMITE = ("access-list CSM_FW_ACL_ advanced permit tcp ifc inside host 10.10.1.5 ifc outside host 192.0.2.77 "
           "eq 80 rule-id 11\n"
           "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 99\n")
RUTAS = ("S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
         "C        192.0.2.0 255.255.255.0 is directly connected, outside\n"
         "C        10.10.1.0 255.255.255.0 is directly connected, inside\n"
         "C        10.10.9.0 255.255.255.0 is directly connected, dmz\n")


def _sesion(config: str) -> str:
    return ("FW1# show running-config\n" + SECRETOS + config
            + "FW1# show route\nCodes: L - local, C - connected, S - static\n" + RUTAS
            + "FW1# show nameif\nInterface Name Security\n"
              "GigabitEthernet0/0 outside 0\nGigabitEthernet0/1 inside 100\nGigabitEthernet0/2 dmz 50\n"
            + "FW1# show interface ip brief\n"
              "Interface                  IP-Address      OK? Method Status                Protocol\n"
              "GigabitEthernet0/0         192.0.2.2       YES CONFIG up                    up\n"
              "GigabitEthernet0/1         10.10.1.2       YES CONFIG up                    up\n"
              "GigabitEthernet0/2         10.10.9.2       YES CONFIG up                    up\n")


def _c(src, dst, port=80, l4="tcp", **kw):
    return dict({"src": src, "dst": dst, "l4": l4, "port": str(port)}, **kw)


def _fw(config: str):
    return cisco.analizar_texto(_sesion(config))


def _contraste(config: str, conductos: list, assets=None) -> dict:
    return fi.contrastar(_fw(config), conductos, "fw.txt", [], assets)


def _res(d: dict, i: int = 0):
    r = d["resultados"][i]
    return r["resultado"], r["regla"]


class TwiceNatHostsTest(unittest.TestCase):
    def test_visto_del_lado_mapeado_se_evalua_con_las_ip_reales(self):
        con = [_c("10.10.9.50", "192.0.2.77")]
        d = _contraste(OBJ + TWICE + PERMITE, con)
        self.assertEqual(_res(d), ("permitido", "11"))
        r = d["resultados"][0]
        self.assertEqual((r["nat"]["s"], r["nat"]["d"], r["nat"]["lado"]), ("10.10.1.5", "192.0.2.77", "lado mapeado"))
        self.assertEqual((r["if_origen"], r["if_destino"]), ("inside", "outside"))
        # sin las lineas nat el mismo conducto es otra cosa (las IP traducidas no casan con la regla)
        sin = _contraste(OBJ + PERMITE, con)
        self.assertEqual(_res(sin), ("denegado_observado", "99"))
        self.assertNotIn("nat", sin["resultados"][0])
        self.assertNotIn("nat", sin)

    def test_columnas_del_detalle(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.9.50", "192.0.2.77")])
        cr = d["cruces"]
        self.assertTrue(cr["con_nat"])
        cab = cruces.columnas_detalle(cr)
        self.assertEqual(cab[-4:], ["ip_origen_real", "ip_destino_real", "nat_regla", "nat_sentido"])
        self.assertEqual(cab[:-4], cruces.COL_DETALLE)
        f = dict(zip(cab, cruces.filas_detalle(cr)[0]))
        self.assertEqual((f["ip_origen"], f["ip_destino"]), ("10.10.9.50", "192.0.2.77"))
        self.assertEqual((f["ip_origen_real"], f["ip_destino_real"]), ("10.10.1.5", "192.0.2.77"))
        self.assertEqual((f["nat_regla"], f["nat_sentido"]), ("linea 1: servidor de prueba", "lado mapeado"))
        self.assertEqual(f["regla_actual"], "11")

    def test_sin_nat_no_hay_columnas_nuevas(self):
        d = _contraste(OBJ + PERMITE, [_c("10.10.1.5", "192.0.2.77")])
        self.assertFalse(d["cruces"]["con_nat"])
        self.assertEqual(cruces.columnas_detalle(d["cruces"]), cruces.COL_DETALLE)

    def test_visto_del_lado_real(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.1.5", "198.51.100.77")])
        self.assertEqual(_res(d), ("permitido", "11"))
        n = d["resultados"][0]["nat"]
        self.assertEqual((n["s"], n["d"], n["lado"]), ("10.10.1.5", "192.0.2.77", "lado real"))
        self.assertEqual(_res(_contraste(OBJ + PERMITE, [_c("10.10.1.5", "198.51.100.77")])), ("denegado_observado", "99"))

    def test_sentido_inverso_y_unidirectional(self):
        con = [_c("192.0.2.77", "10.10.9.50")]
        d = _contraste(OBJ + TWICE + PERMITE, con)
        n = d["resultados"][0]["nat"]
        self.assertEqual((n["s"], n["d"], n["lado"]), ("192.0.2.77", "10.10.1.5", "lado mapeado (inverso)"))
        uni = _contraste(OBJ + TWICE.replace(" description", " unidirectional description") + PERMITE, con)
        self.assertNotIn("nat", uni["resultados"][0])

    def test_conducto_bidireccional_prueba_el_otro_extremo(self):
        con = [_c("192.0.2.77", "10.10.9.50", bidireccional=True)]
        uni = _contraste(OBJ + TWICE.replace(" description", " unidirectional description") + PERMITE, con)
        self.assertEqual(uni["resultados"][0]["nat"]["d"], "10.10.1.5")      # en el orden del conducto
        self.assertEqual((uni["resultados"][0]["sentido"], uni["resultados"][0]["resultado"]),
                         ("invertido", "permitido"))

    def test_conducto_ajeno_que_comparte_una_ip_no_se_traduce(self):
        config = OBJ + TWICE + PERMITE
        for src, dst in (("10.10.9.50", "192.0.2.99"),         # solo comparte el MAPEADO de origen
                         ("10.10.1.77", "198.51.100.77"),      # solo comparte el MAPEADO de destino
                         ("10.10.1.5", "192.0.2.99")):         # solo comparte el REAL de origen
            d = _contraste(config, [_c(src, dst)])
            self.assertNotIn("nat", d["resultados"][0], (src, dst))
        self.assertEqual(d["nat"]["filas"][0]["estado"], "sin uso en la ventana")

    def test_nombres_de_activo_con_la_ip_real(self):
        assets = {"a": {"ips": {"10.10.1.5"}, "nombre": "PLC real"},
                  "b": {"ips": {"10.10.9.50"}, "nombre": "IP traducida"}}
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.9.50", "192.0.2.77", src_nombre="IP traducida")], assets)
        f = d["cruces"]["detalle"][0]
        self.assertEqual(f["nombre_origen"], "PLC real")
        self.assertIn("10.10.1.5", assets["b"]["nat_nota"])
        self.assertEqual(assets["b"]["nat_nota"], "IP traducida por el NAT del firewall (real: 10.10.1.5)")
        self.assertNotIn("nat_nota", assets["a"])
        self.assertEqual(len(assets), 2)       # no se fusionan


class SubredesObjetoEInterfazTest(unittest.TestCase):
    ACL = ("access-list CSM_FW_ACL_ advanced permit tcp ifc inside host 10.10.1.9 ifc outside any eq 80 rule-id 21\n"
           "access-list CSM_FW_ACL_ advanced permit tcp ifc inside host 10.10.1.15 ifc outside any eq 80 rule-id 22\n"
           "access-list CSM_FW_ACL_ advanced permit tcp ifc inside host 10.10.1.30 ifc outside any eq 80 rule-id 23\n"
           "access-list CSM_FW_ACL_ advanced permit tcp ifc inside host 10.10.1.31 ifc outside any eq 80 rule-id 24\n"
           "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 99\n")

    def test_subred_por_desplazamiento(self):
        cfg = ("object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
               "object network PUB\n subnet 172.20.0.0 255.255.255.0\n"
               "nat (inside,outside) source static LAN PUB\n") + self.ACL
        d = _contraste(cfg, [_c("172.20.0.9", "8.8.8.8"), _c("172.20.1.9", "8.8.8.8")])
        self.assertEqual(_res(d, 0), ("permitido", "21"))
        self.assertEqual(d["resultados"][0]["nat"]["s"], "10.10.1.9")
        self.assertNotIn("nat", d["resultados"][1])         # fuera de la subred mapeada
        self.assertEqual(d["nat"]["filas"][0]["estado"], "usada")

    def test_range_por_desplazamiento(self):
        cfg = ("object network RR\n range 10.10.1.10 10.10.1.20\n"
               "object network MR\n range 172.21.0.100 172.21.0.110\n"
               "nat (inside,outside) source static RR MR\n") + self.ACL
        d = _contraste(cfg, [_c("172.21.0.105", "8.8.8.8")])
        self.assertEqual(_res(d), ("permitido", "22"))
        self.assertEqual(d["resultados"][0]["nat"]["s"], "10.10.1.15")

    def test_tamanos_distintos_no_es_modelable_y_avisa(self):
        cfg = ("object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
               "object network PUB\n subnet 172.20.0.0 255.255.255.128\n"
               "nat (inside,outside) source static LAN PUB\n") + self.ACL
        fw = _fw(cfg)
        self.assertFalse(fw.nat[0].modelable)
        self.assertTrue(any("NAT linea 1 no modelable" in a and "tamanos" in a for a in fw.avisos), fw.avisos)
        d = fi.contrastar(fw, [_c("172.20.0.9", "8.8.8.8")], "fw.txt", [])
        self.assertNotIn("nat", d["resultados"][0])
        self.assertTrue(d["nat"]["filas"][0]["estado"].startswith("no modelable: origen: tamanos distintos"))

    def test_object_nat_estatico(self):
        cfg = ("object network SRV\n host 10.10.1.30\n nat (inside,outside) static 172.22.0.30\n") + self.ACL
        fw = _fw(cfg)
        self.assertEqual((fw.nat[0].clase, fw.nat[0].seccion, fw.nat[0].origen_real), ("objeto", 2, "SRV"))
        d = fi.contrastar(fw, [_c("172.22.0.30", "8.8.8.8")], "fw.txt", [])
        self.assertEqual(_res(d), ("permitido", "23"))
        self.assertEqual(d["resultados"][0]["nat"]["s"], "10.10.1.30")

    def test_interface_como_mapeado(self):
        cfg = ("object network SRV2\n host 10.10.1.31\n"
               "nat (inside,outside) source static SRV2 interface\n") + self.ACL
        d = _contraste(cfg, [_c("192.0.2.2", "8.8.8.8")])
        self.assertEqual(_res(d), ("permitido", "24"))
        self.assertEqual(d["resultados"][0]["nat"]["s"], "10.10.1.31")
        self.assertEqual(d["nat"]["filas"][0]["origen_mapeado"], "interface")


class DinamicoInactivoYOrdenTest(unittest.TestCase):
    def test_pat_marca_y_no_cambia_la_ip(self):
        cfg = ("object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
               "nat (inside,outside) source dynamic LAN interface\n"
               "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 5\n")
        d = _contraste(cfg, [_c("192.0.2.2", "10.10.9.5")])
        r = d["resultados"][0]
        self.assertEqual((r["nat"]["s"], r["nat"]["d"], r["nat"]["lado"]), ("192.0.2.2", "10.10.9.5", nt.PAT))
        self.assertEqual(r["resultado"], "permitido")
        f = d["nat"]["filas"][0]
        self.assertEqual((f["tipo"], f["estado"], f["conductos_traducidos"]), ("pat", "usada", 1))
        det = d["cruces"]["detalle"][0]
        self.assertEqual((det["ip_origen_real"], det["nat_sentido"]), ("192.0.2.2", nt.PAT))

    def test_inactive_no_se_aplica(self):
        d = _contraste(OBJ + TWICE.replace(" description", " inactive description") + PERMITE,
                       [_c("10.10.9.50", "192.0.2.77")])
        self.assertNotIn("nat", d["resultados"][0])
        self.assertEqual(d["resultados"][0]["resultado"], "denegado_observado")
        self.assertEqual(d["nat"]["filas"][0]["estado"], "inactiva")

    def test_gana_la_primera_regla_que_casa(self):
        # identidad (exencion) antes que la traduccion: el mapeado de la segunda no se invierte
        cfg = (OBJ + "nat (inside,outside) source static MS MS\n" + TWICE + PERMITE)
        d = _contraste(cfg, [_c("10.10.9.50", "192.0.2.77")])
        self.assertNotIn("nat", d["resultados"][0])
        self.assertEqual([f["conductos_traducidos"] for f in d["nat"]["filas"]], [1, 0])

    def test_service_se_avisa_y_se_aplica_a_las_ip(self):
        cfg = OBJ + TWICE.replace(" description", " service tcp 80 8080 description") + PERMITE
        fw = _fw(cfg)
        self.assertTrue(fw.nat[0].con_servicio)
        self.assertTrue(any("service" in a for a in fw.avisos))


class ArchivoNatTest(unittest.TestCase):
    def test_estados_en_la_tabla(self):
        cfg = (OBJ + TWICE
               + "object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
               + "object network PUB\n subnet 172.20.0.0 255.255.255.128\n"
               + "nat (inside,outside) source static LAN PUB\n"
               + "nat (inside,outside) source static RS NOEXISTE\n"
               + PERMITE)
        d = _contraste(cfg, [_c("10.10.9.50", "192.0.2.77")])
        nat = d["nat"]
        estados = [f["estado"].split(":")[0] for f in nat["filas"]]
        self.assertEqual(estados, ["usada", "no modelable", "no modelable"])
        self.assertIn("objeto no definido: NOEXISTE", nat["filas"][2]["estado"])
        self.assertEqual(nt.columnas(nat), nt.COL_NAT)
        fila = dict(zip(nt.COL_NAT, nt.filas_tabla(nat)[0]))
        self.assertEqual((fila["linea"], fila["interfaces"], fila["tipo"], fila["origen_real"],
                          fila["origen_mapeado"], fila["destino_mapeado"], fila["destino_real"],
                          fila["conductos_traducidos"]), (1, "inside,outside", "static", "RS", "MS", "MD", "RD", 1))
        self.assertTrue(nt.hay(d))
        self.assertFalse(nt.hay(_contraste(OBJ + PERMITE, [])))

    def test_sin_uso_en_la_ventana(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.1.99", "8.8.8.8")])
        self.assertEqual(d["nat"]["filas"][0]["estado"], "sin uso en la ventana")

    def test_object_nat_va_despues_del_twice_y_before_auto(self):
        cfg = ("object network A\n host 10.10.1.40\n nat (inside,outside) static 172.23.0.40\n"
               + OBJ + TWICE + "nat (inside,outside) after-auto source static RS MS\n")
        fw = _fw(cfg)
        self.assertEqual([(n.seccion, n.clase) for n in fw.nat], [(1, "twice"), (2, "objeto"), (3, "twice")])

    def test_sin_secretos(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.9.50", "192.0.2.77")])
        self.assertNotIn("SECRETOX", repr(d["nat"]))


DET_TWICE = ("Manual NAT Policies (Section 1)\n"
             "1 (inside) to (outside) source static RS MS destination static MD RD   description servidor de prueba\n"
             "    translate_hits = 5, untranslate_hits = 7\n"
             "    Source - Origin: 10.10.1.5/32, Translated: 10.10.9.50/32\n"
             "    Destination - Origin: 198.51.100.77/32, Translated: 192.0.2.77/32\n")
OBJ_A = "object network A\n host 10.10.1.40\n nat (inside,outside) static 172.23.0.40\n"
DET_AUTO = ("\nAuto NAT Policies (Section 2)\n"
            "1 (inside) to (outside) source static A 172.23.0.40\n"
            "    translate_hits = 0, untranslate_hits = 3\n"
            "    Source - Origin: 10.10.1.40/32, Translated: 172.23.0.40/32\n")


def _fw_nd(config: str, detalle: str):
    return cisco.analizar_texto(_sesion(config) + "FW1# show nat detail\n" + SECRETOS + detalle)


def _contraste_nd(config: str, detalle: str, conductos: list) -> dict:
    return fi.contrastar(_fw_nd(config, detalle), conductos, "fw.txt", [], None)


def _fila(d: dict, i: int = 0) -> dict:
    return dict(zip(nt.columnas(d["nat"]), nt.filas_tabla(d["nat"])[i]))


class ShowNatDetailTest(unittest.TestCase):
    def test_manual_y_auto_nat_contadores_y_redes(self):
        d = _contraste_nd(OBJ_A + OBJ + TWICE + PERMITE, DET_TWICE + DET_AUTO, [_c("10.10.9.50", "192.0.2.77")])
        self.assertIn("translate_hits", nt.columnas(d["nat"]))
        self.assertEqual(nt.columnas(d["nat"])[-2:], ["translate_hits", "untranslate_hits"])
        tw, auto = _fila(d, 0), _fila(d, 1)
        self.assertEqual((tw["translate_hits"], tw["untranslate_hits"]), (5, 7))
        self.assertEqual((auto["translate_hits"], auto["untranslate_hits"]), (0, 3))
        self.assertEqual((tw["origen_real_red"], tw["origen_mapeado_red"], tw["destino_mapeado_red"],
                          tw["destino_real_red"]), ("10.10.1.5/32", "10.10.9.50/32", "198.51.100.77/32",
                                                    "192.0.2.77/32"))
        self.assertEqual((auto["origen_real_red"], auto["origen_mapeado_red"], auto["destino_real_red"]),
                         ("10.10.1.40/32", "172.23.0.40/32", ""))
        self.assertEqual(tw["estado"], "usada")
        self.assertEqual(auto["estado"], nt.ESTADO_CON_ACIERTOS)       # solo untranslate_hits > 0
        self.assertIn("0 sin emparejar", d["nat"]["nota"])
        self.assertNotIn("SECRETOX", repr(d["nat"]))

    def test_estados_con_y_sin_aciertos_en_el_contador(self):
        cfg = (OBJ + "object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
               "object network PUB\n subnet 172.20.0.0 255.255.255.0\n"
               "nat (inside,outside) source static LAN PUB\n"
               "nat (inside,outside) source static RS MS\n" + PERMITE)
        det = ("Manual NAT Policies (Section 1)\n"
               "1 (inside) to (outside) source static LAN PUB\n"
               "    translate_hits = 4, untranslate_hits = 0\n"
               "    Source - Origin: 10.10.1.0/24, Translated: 172.20.0.0/24\n"
               "2 (inside) to (outside) source static RS MS\n"
               "    translate_hits = 0, untranslate_hits = 0\n"
               "    Source - Origin: 10.10.1.5/32, Translated: 10.10.9.50/32\n")
        d = _contraste_nd(cfg, det, [_c("10.10.1.99", "8.8.8.8")])
        self.assertEqual([f["estado"] for f in d["nat"]["filas"]], [nt.ESTADO_CON_ACIERTOS, nt.ESTADO_SIN_ACIERTOS])

    def test_objeto_ausente_se_modela_con_show_nat_detail(self):
        cfg = OBJ + "nat (inside,outside) source static RS NOEXISTE\n" + PERMITE
        det = ("Manual NAT Policies (Section 1)\n"
               "1 (inside) to (outside) source static RS NOEXISTE\n"
               "    translate_hits = 1, untranslate_hits = 1\n"
               "    Source - Origin: 10.10.1.5/32, Translated: 203.0.113.9-203.0.113.9\n")
        con = [_c("203.0.113.9", "192.0.2.77")]
        sin = _contraste(cfg, con)
        self.assertTrue(sin["nat"]["filas"][0]["estado"].startswith("no modelable"))
        d = _contraste_nd(cfg, det, con)
        self.assertEqual(_res(d), ("permitido", "11"))
        self.assertEqual(d["nat"]["filas"][0]["estado"], "usada")
        self.assertEqual(_fila(d)["origen_mapeado_red"], "203.0.113.9/32")
        self.assertIn("1 modeladas con las redes de show nat detail", d["nat"]["nota"])
        self.assertTrue(any("redes tomadas de show nat detail" in a for a in _fw_nd(cfg, det).avisos))

    def test_regla_que_no_empareja_se_cuenta_sin_inventar(self):
        det = DET_TWICE + ("2 (dmz) to (outside) source static ZZ YY\n"
                           "    translate_hits = 9, untranslate_hits = 9\n"
                           "    Source - Origin: 10.99.0.1/32, Translated: 10.99.0.2/32\n")
        d = _contraste_nd(OBJ + TWICE + PERMITE, det, [])
        self.assertEqual(len(d["nat"]["filas"]), 1)
        self.assertEqual(_fila(d)["translate_hits"], 5)
        self.assertIn("1 sin emparejar", d["nat"]["nota"])
        self.assertTrue(any("1 de 2 reglas sin emparejar" in a for a in _fw_nd(OBJ + TWICE + PERMITE, det).avisos))
        # una regla de la configuracion sin pareja queda sin contadores y no se le inventan
        d2 = _contraste_nd(OBJ + TWICE + "nat (inside,outside) source static RS MS\n" + PERMITE, DET_TWICE, [])
        self.assertEqual(_fila(d2, 1)["translate_hits"], "")
        self.assertEqual(d2["nat"]["filas"][1]["estado"], "sin uso en la ventana")
        self.assertIn("1 reglas de la configuracion sin contadores", d2["nat"]["nota"])

    def test_sin_show_nat_detail_todo_igual(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.9.50", "192.0.2.77")])
        self.assertEqual(nt.columnas(d["nat"]), nt.COL_NAT)
        self.assertEqual(d["nat"]["nota"], "")
        self.assertFalse(d["nat"]["con_contadores"])
        self.assertEqual(_fila(d)["origen_real_red"], "10.10.1.5/32")
        self.assertFalse(any("show nat detail" in a for a in _fw(OBJ + TWICE + PERMITE).avisos))


CFG_C = (OBJ + "object network LAN\n subnet 10.10.1.0 255.255.255.0\n"
         "object network PUB\n subnet 172.20.0.0 255.255.255.0\n"
         "nat (inside,outside) source static LAN PUB\n"
         "nat (inside,outside) source static RS MS\n" + PERMITE)


def _det_c(h1: tuple, h2: tuple) -> str:
    return ("Manual NAT Policies (Section 1)\n"
            "1 (inside) to (outside) source static LAN PUB\n"
            f"    translate_hits = {h1[0]}, untranslate_hits = {h1[1]}\n"
            "    Source - Origin: 10.10.1.0/24, Translated: 172.20.0.0/24\n"
            "2 (inside) to (outside) source static RS MS\n"
            f"    translate_hits = {h2[0]}, untranslate_hits = {h2[1]}\n"
            "    Source - Origin: 10.10.1.5/32, Translated: 10.10.9.50/32\n")


def _fw_tomas(config: str, *detalles: str):
    return cisco.analizar_texto(_sesion(config) + "".join("FW1# show nat detail\n" + d for d in detalles))


def _contraste_tomas(config: str, *detalles: str) -> dict:
    return fi.contrastar(_fw_tomas(config, *detalles), [], "fw.txt", [], None)


class VariasTomasTest(unittest.TestCase):
    """F6c: varias tomas de show nat detail; maximo por regla y reinicio de contadores."""

    def test_reinicio_entre_tomas_usa_el_maximo(self):
        d = _contraste_tomas(CFG_C, _det_c((30, 0), (198, 12)), _det_c((0, 0), (0, 0)))
        f0, f1 = _fila(d, 0), _fila(d, 1)
        self.assertEqual((f0["translate_hits"], f0["untranslate_hits"]), (30, 0))
        self.assertEqual((f1["translate_hits"], f1["untranslate_hits"]), (198, 12))
        self.assertEqual([f["estado"] for f in d["nat"]["filas"]], [nt.ESTADO_CON_ACIERTOS] * 2)
        self.assertEqual((f0["tomas_nat"], f0["translate_hits_por_toma"], f0["untranslate_hits_por_toma"],
                          f0["reinicio_contadores"]), (2, "30; 0", "0; 0", "si"))
        self.assertEqual((f1["translate_hits_por_toma"], f1["untranslate_hits_por_toma"]), ("198; 0", "12; 0"))
        self.assertEqual(nt.columnas(d["nat"])[-4:], nt.COL_TOMAS)
        self.assertIn("2 tomas de show nat detail; se usa el maximo por regla", d["nat"]["nota"])
        self.assertIn("contadores reiniciados entre la toma 1 y la 2", d["nat"]["nota"])
        self.assertFalse(any("sin emparejar" in a for a in _fw_tomas(CFG_C, _det_c((30, 0), (198, 12)),
                                                                      _det_c((0, 0), (0, 0))).avisos))
        self.assertEqual(d["nat"]["nota"].count("0 sin emparejar"), 1)

    def test_contadores_que_suben_no_son_reinicio(self):
        d = _contraste_tomas(CFG_C, _det_c((10, 1), (0, 0)), _det_c((25, 3), (0, 0)))
        f0, f1 = _fila(d, 0), _fila(d, 1)
        self.assertEqual((f0["translate_hits"], f0["reinicio_contadores"]), (25, ""))
        self.assertEqual(f0["translate_hits_por_toma"], "10; 25")
        self.assertEqual(f1["estado"], nt.ESTADO_SIN_ACIERTOS)
        self.assertNotIn("reiniciados", d["nat"]["nota"])
        self.assertIn("2 tomas", d["nat"]["nota"])

    def test_sin_aciertos_en_todas_las_tomas_tras_reinicio_no_cambia_el_estado(self):
        d = _contraste_tomas(CFG_C, _det_c((5, 0), (0, 0)), _det_c((0, 0), (0, 0)))
        self.assertEqual(_fila(d, 1)["estado"], nt.ESTADO_SIN_ACIERTOS)
        self.assertEqual(_fila(d, 1)["reinicio_contadores"], "")
        self.assertIn("los aciertos entre esas tomas no se ven", d["nat"]["nota"])

    def test_carpeta_con_dos_archivos_nombra_las_tomas(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "00_sesion.txt").write_text(_sesion(CFG_C), encoding="utf-8")
            Path(tmp, "show_nat_detail_20261110.txt").write_text(_det_c((0, 0), (0, 0)), encoding="utf-8")
            Path(tmp, "show_nat_detail_20261106.txt").write_text(_det_c((30, 0), (198, 12)), encoding="utf-8")
            fw = cisco.cargar(tmp)
        d = fi.contrastar(fw, [], "fw.txt", [], None)
        self.assertEqual((_fila(d, 0)["translate_hits_por_toma"], _fila(d, 0)["reinicio_contadores"]), ("30; 0", "si"))
        self.assertEqual(_fila(d, 1)["untranslate_hits"], 12)
        self.assertIn("1=show_nat_detail_20261106.txt, 2=show_nat_detail_20261110.txt", d["nat"]["nota"])
        self.assertFalse(any("sin emparejar" in a for a in fw.avisos))

    def test_carpeta_de_sesiones_con_prompt_nombra_las_tomas(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "00_sesion.txt").write_text(_sesion(CFG_C), encoding="utf-8")
            Path(tmp, "fw_20261106.txt").write_text("FW1# show nat detail\n" + _det_c((30, 0), (0, 0)), encoding="utf-8")
            Path(tmp, "fw_20261110.txt").write_text("FW1# show nat detail\n" + _det_c((0, 0), (0, 0)), encoding="utf-8")
            fw = cisco.cargar(tmp)
        d = fi.contrastar(fw, [], "fw.txt", [], None)
        self.assertIn("1=fw_20261106.txt, 2=fw_20261110.txt", d["nat"]["nota"])
        self.assertEqual(_fila(d, 0)["reinicio_contadores"], "si")

    def test_sesion_pegada_con_dos_tomas_no_nombra_archivos(self):
        texto = (_sesion(CFG_C) + "FW1# show nat detail\n" + _det_c((30, 0), (0, 0))
                 + "FW1# show nat detail\n" + _det_c((0, 0), (0, 0)))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "sesion.txt").write_text(texto, encoding="utf-8")
            fw = cisco.cargar(str(Path(tmp, "sesion.txt")))
        d = fi.contrastar(fw, [], "fw.txt", [], None)
        self.assertIn("2 tomas", d["nat"]["nota"])
        self.assertNotIn("tomas: 1=", d["nat"]["nota"])

    def test_una_toma_queda_como_en_f6b(self):
        d = _contraste_tomas(CFG_C, _det_c((4, 0), (0, 0)))
        self.assertEqual(nt.columnas(d["nat"]), nt.COL_NAT + nt.COL_CONTADORES)
        self.assertNotIn("tomas_nat", d["nat"]["filas"][0])
        self.assertEqual(d["nat"]["nota"], "show nat detail: 2 reglas leidas, 0 sin emparejar con la "
                                           "configuracion, 0 reglas de la configuracion sin contadores")
        self.assertEqual(d["nat"]["filas"][0]["translate_hits"], 4)
        det = _det_c((4, 0), (0, 0)) + ("3 (dmz) to (outside) source static ZZ YY\n"
                                        "    translate_hits = 9, untranslate_hits = 9\n")
        self.assertEqual([a for a in _fw_tomas(CFG_C, det).avisos if "show nat detail" in a],
                         ["show nat detail: 1 de 3 reglas sin emparejar con la configuracion y 0 de 2 reglas de la "
                          + "configuracion sin contadores"])

    def test_aviso_sin_emparejar_dice_la_toma(self):
        extra = ("3 (dmz) to (outside) source static ZZ YY\n"
                 "    translate_hits = 9, untranslate_hits = 9\n")
        fw = _fw_tomas(CFG_C, _det_c((4, 0), (0, 0)), _det_c((6, 0), (0, 0)) + extra)
        av = [a for a in fw.avisos if "show nat detail" in a]
        self.assertEqual(len(av), 2)
        self.assertTrue(av[1].startswith("show nat detail, toma 2: 1 de 3 reglas sin emparejar"))
        self.assertTrue(av[0].startswith("show nat detail, toma 1: 0 de 2 reglas sin emparejar"))

    def test_ingles(self):
        from ot_assess import i18n
        try:
            i18n.usar("en")
            d = _contraste_tomas(CFG_C, _det_c((30, 0), (198, 12)), _det_c((0, 0), (0, 0)))
            nota = d["nat"]["nota"]
        finally:
            i18n.usar("es")
        self.assertIn("2 show nat detail captures; the maximum per rule is used", nota)
        self.assertIn("counters reset between capture 1 and 2", nota)


class PropuestaYValidacionTest(Base):
    def _pol(self, config, conductos):
        fw = _fw(config)
        d = fi.contrastar(fw, conductos, "fw.txt", [], {})
        p = po.construir_todo(["FW1"], ["fw.txt"], [fw], [d], conductos, {}, lambda x: x, {})["firewalls"][0]
        return d, p

    def test_la_propuesta_usa_la_ip_real_y_cita_la_observada(self):
        cfg = OBJ + TWICE + "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 5\n"
        d, p = self._pol(cfg, [_c("10.10.9.50", "192.0.2.77", 443)])
        self.assertEqual(len(p["reglas"]), 1)
        texto = repr(po.filas_propuesta(p)) + repr(po.filas_objetos(p))
        self.assertIn("10.10.1.5", texto)
        self.assertNotIn("10.10.9.50", repr(po.filas_objetos(p)))
        self.assertIn("observado como 10.10.9.50 -> 192.0.2.77 (NAT linea 1: servidor de prueba)", texto)
        self.assertEqual((p["reglas"][0]["ifo"], p["reglas"][0]["ifd"]), ("inside", "outside"))

    def test_validar_usa_la_ip_real_de_la_columna(self):
        reglas = [{"orden": 1, "nombre": "r1", "decision": "permitir", "razones": "", "zona_entrada": "SZ_inside",
                   "zona_salida": "SZ_outside", "interfaces": "inside -> outside", "origen": "H_RS",
                   "destino": "H_RD", "servicios": "S_443", "justificacion": "x"}]
        objetos = [("H_RS", "host", "10.10.1.5", ""), ("H_RD", "host", "192.0.2.77", ""),
                   ("S_443", "servicio", "tcp/443", "")]
        con = cruce("inside", "outside", "10.10.9.50", "192.0.2.77", "tcp", 443)
        con_real = dict(con, ip_origen_real="10.10.1.5", ip_destino_real="192.0.2.77", nat_regla="linea 1",
                        nat_sentido="lado mapeado")
        self.preparar(reglas=reglas, objetos=objetos, cruces=[con])
        self.correr()
        self.assertEqual(self.filas()[("10.10.9.50", "192.0.2.77", "443", "inside")]["categoria"], vp.SE_ROMPERIA)
        columnas = vp.COL_ENTRADA + ["l4_inferido", "etiquetas", "fuentes", "ip_origen_real", "ip_destino_real",
                                     "nat_regla", "nat_sentido"]
        from test_validar_politica import escribir_csv
        d = self.dir / "v2"
        d.mkdir()
        escribir_csv(d / vp.ARCHIVO_CRUCES, columnas, [con_real])
        self.correr(carpetas=("v2",), out="out2")
        fila = self.filas("out2")[("10.10.1.5", "192.0.2.77", "443", "inside")]
        self.assertNotEqual(fila["categoria"], vp.SE_ROMPERIA)


class CsvSalidaTest(unittest.TestCase):
    def test_la_tabla_nat_viaja_con_la_salida(self):
        d = _contraste(OBJ + TWICE + PERMITE, [_c("10.10.9.50", "192.0.2.77")])
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(nt.columnas(d["nat"]))
        w.writerows(nt.filas_tabla(d["nat"]))
        self.assertIn("conductos_traducidos", buf.getvalue().splitlines()[0])


if __name__ == "__main__":
    unittest.main()
