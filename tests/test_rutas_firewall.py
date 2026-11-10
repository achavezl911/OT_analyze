"""XD-b: rutas de firewall -> interfaz por IP y conductos que cruzan el firewall."""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import rutas_firewall as rf
from ot_assess.report.common import escritor_csv

EJEMPLO = RAIZ / "docs" / "ejemplos" / "rutas_firewall.csv"

COMANDOS = """route DMZ-CORP 0.0.0.0 0.0.0.0 192.0.2.1 1
route OT-NET 10.0.0.0 255.0.0.0 10.10.15.1
route PROCESO 10.130.0.0 255.255.0.0 10.130.0.254 1
route SERVIDORES 172.16.5.0 255.255.255.0 172.16.5.254
route PROCESO 10.130.7.9 255.255.255.255 10.130.0.253
route OT-NET 10.0.0.0 255.0.0.0 10.10.15.1
"""

SHOW = """Codes: L - local, C - connected, S - static, O - OSPF
Gateway of last resort is 192.0.2.1 to network 0.0.0.0

S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, DMZ-CORP
S        10.0.0.0 255.0.0.0 [1/0] via 10.10.15.1, OT-NET
S        10.130.0.0 255.255.0.0 [1/0] via 10.130.0.254, PROCESO
C        10.10.15.0 255.255.255.0 is directly connected, OT-NET
L        10.10.15.2 255.255.255.255 is directly connected, OT-NET
S        172.16.5.0 255.255.255.0 [1/0] via 172.16.5.254, SERVIDORES
S        10.130.7.9 255.255.255.255 [1/0] via 10.130.0.253, PROCESO
"""

IOS = """S* 0.0.0.0/0 [1/0] via 192.0.2.1, DMZ-CORP
S  10.0.0.0/8 [1/0] via 10.10.15.1, OT-NET
S  10.130.0.0/16 [1/0] via 10.130.0.254, PROCESO
C  10.10.15.0/24 is directly connected, OT-NET
L  10.10.15.2/32 is directly connected, OT-NET
S  172.16.5.0/24 [1/0] via 172.16.5.254, SERVIDORES
S  10.130.7.9/32 [1/0] via 10.130.0.253, PROCESO
"""


def _cargar(texto, nombre="r.txt"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / nombre
        p.write_text(texto, encoding="utf-8")
        return rf.cargar(p)


def _pares(rutas):
    return sorted((str(r["red"]), r["interfaz"]) for r in rutas)


def _error(texto, nombre="r.txt"):
    with unittest.TestCase().assertRaises(SystemExit) as cm:
        _cargar(texto, nombre)
    return str(cm.exception)


class TestFormatos(unittest.TestCase):
    def test_tabla_de_ejemplo_con_titulo_y_resumen(self):
        rutas, avisos = rf.cargar(EJEMPLO)
        self.assertEqual(len(rutas), 6)  # el resumen no cuenta
        self.assertEqual(rutas[1]["interfaz"], "OT-NET")
        self.assertEqual(rutas[0]["zona"], "Corporativa")
        self.assertEqual(rutas[2]["siguiente_salto"], "10.130.0.254")
        self.assertEqual(avisos, [])

    def test_tres_formatos_dan_las_mismas_rutas(self):
        tabla, _ = rf.cargar(EJEMPLO)
        cmd, _ = _cargar(COMANDOS)
        show, _ = _cargar(SHOW)
        ios, _ = _cargar(IOS)
        base = _pares(tabla)
        # los comandos route no traen la ruta conectada C del ejemplo
        self.assertEqual(_pares(cmd), [x for x in base if x != ("10.10.15.0/24", "OT-NET")])
        # show route trae ademas la ruta local L (/32 del propio firewall)
        solo = [x for x in _pares(show) if x != ("10.10.15.2/32", "OT-NET")]  # sin la L
        self.assertEqual(solo, base)
        self.assertEqual(_pares(ios), _pares(show))

    def test_repetidas_se_cuentan_una_vez(self):
        rutas, _ = _cargar(COMANDOS)
        self.assertEqual(len(rutas), 5)

    def test_tipos_show_route(self):
        rutas, _ = _cargar(SHOW + "O        10.20.0.0 255.255.0.0 [110/20] via 10.10.15.9, 0:01:02, OT-NET\n")
        t = {str(r["red"]): r["tipo"] for r in rutas}
        self.assertEqual((t["0.0.0.0/0"], t["10.0.0.0/8"], t["10.10.15.0/24"], t["10.10.15.2/32"]),
                         ("S*", "S", "C", "L"))
        self.assertEqual(t["10.20.0.0/16"], "O")
        self.assertEqual([r["interfaz"] for r in rutas if str(r["red"]) == "10.20.0.0/16"], ["OT-NET"])

    def test_ecmp_otro_camino_de_la_misma_red(self):
        rutas, _ = _cargar("S   10.50.0.0 255.255.0.0 [1/0] via 10.1.1.1, DMZ-A\n"
                           "                          [1/0] via 10.2.2.2, DMZ-B\n")
        self.assertEqual([(str(r["red"]), r["interfaz"], r["siguiente_salto"], r["tipo"]) for r in rutas],
                         [("10.50.0.0/16", "DMZ-A", "10.1.1.1", "S"), ("10.50.0.0/16", "DMZ-B", "10.2.2.2", "S")])
        avisos = []
        self.assertEqual(rf.interfaz_de("10.50.1.1", rutas, avisos), "DMZ-A")
        self.assertEqual(len(avisos), 1)
        self.assertIn("DMZ-A", avisos[0])

    def test_tabla_red_mas_mascara_y_red_mas_prefijo(self):
        a, _ = _cargar("Interfaz,Red,Mascara\nA,10.0.0.0,255.0.0.0\n", "t.csv")
        b, _ = _cargar("nameif;network;prefix\nA;10.0.0.0;8\n", "t.csv")
        c, _ = _cargar("iface,cidr\nA,10.0.0.5/8\n", "t.csv")
        self.assertEqual(_pares(a), _pares(b))
        self.assertEqual(_pares(a), _pares(c))
        self.assertEqual(_pares(a), [("10.0.0.0/8", "A")])


class TestErrores(unittest.TestCase):
    def test_red_invalida_dice_la_fila(self):
        msg = _error("Interfaz,CIDR\nA,10.0.0.0/8\nB,10.0.0.0/33\n", "t.csv")
        self.assertIn("fila 3", msg)
        self.assertIn("10.0.0.0/33", msg)

    def test_interfaz_vacia_dice_la_fila(self):
        self.assertIn("fila 2", _error("Interfaz,CIDR\n,10.0.0.0/8\n", "t.csv"))

    def test_mascara_no_contigua_en_comando_dice_la_linea(self):
        msg = _error("route A 10.0.0.0 255.0.255.0 10.1.1.1\n")
        self.assertIn("linea 1", msg)

    def test_linea_show_route_rota_dice_la_linea(self):
        self.assertIn("linea 2", _error("Codes: C\nS 10.0.0.0 255.0.0.0 [1/0] via 10.1.1.1\n"))

    def test_sin_encabezado(self):
        self.assertIn("encabezado", _error("a,b\n1,2\n", "t.csv"))


class TestAsignacion(unittest.TestCase):
    def setUp(self):
        self.rutas, _ = _cargar(SHOW)

    def test_prefijo_mas_largo(self):
        d = lambda ip: rf.interfaz_de(ip, self.rutas)
        self.assertEqual(d("10.5.5.5"), "OT-NET")          # /8
        self.assertEqual(d("10.130.1.1"), "PROCESO")       # /16 sobre /8
        self.assertEqual(d("10.130.7.9"), "PROCESO")       # /32
        self.assertEqual(d("10.10.15.7"), "OT-NET")        # C /24
        self.assertEqual(d("172.16.5.9"), "SERVIDORES")

    def test_gana_el_mas_especifico_aunque_vaya_despues(self):
        rutas, _ = _cargar("route A 10.0.0.0 255.0.0.0 1.1.1.1\nroute B 10.130.0.0 255.255.0.0 1.1.1.2\n"
                           "route C 10.130.7.9 255.255.255.255 1.1.1.3\n")
        self.assertEqual([rf.interfaz_de(i, rutas) for i in ("10.1.1.1", "10.130.1.1", "10.130.7.9")],
                         ["A", "B", "C"])

    def test_ruta_por_defecto_y_sin_ruta(self):
        self.assertEqual(rf.interfaz_de("8.8.8.8", self.rutas), "DMZ-CORP (ruta por defecto)")
        sin_default, _ = _cargar("route A 10.0.0.0 255.0.0.0 1.1.1.1\n")
        self.assertEqual(rf.interfaz_de("8.8.8.8", sin_default), "sin ruta")
        self.assertEqual(rf.interfaz_de("no-es-ip", sin_default), "sin ruta")

    def test_ip_local_del_firewall(self):
        self.assertEqual(rf.interfaz_de("10.10.15.2", self.rutas), "el firewall (OT-NET)")

    def test_empate_entre_interfaces_avisa(self):
        rutas, _ = _cargar("route A 10.0.0.0 255.0.0.0 1.1.1.1\nroute B 10.0.0.0 255.0.0.0 1.1.1.2\n")
        avisos = []
        self.assertEqual(rf.interfaz_de("10.1.1.1", rutas, avisos), "A")
        self.assertEqual(len(avisos), 1)

    def test_aviso_sin_rutas_conectadas(self):
        _, avisos = _cargar(COMANDOS)
        self.assertEqual(avisos, [rf.AVISO_SIN_C])
        _, avisos = _cargar(SHOW)
        self.assertEqual(avisos, [])


def _k(src, dst, port=502, l4="tcp", servicio="Modbus", bytes_=100):
    return {"src": src, "dst": dst, "port": port, "l4": l4, "servicio": servicio, "bytes": bytes_}


class TestAplicar(unittest.TestCase):
    def _aplicar(self):
        activos = {"a": {"ips": {"10.5.5.5"}}, "b": {"ips": {"10.130.1.1"}},
                   "c": {"ips": {"8.8.8.8"}}, "fw": {"ips": {"10.10.15.2"}},
                   "d": {"ips": {"10.5.5.6"}}}
        conductos = [_k("10.5.5.5", "10.130.1.1"), _k("10.5.5.6", "10.130.1.1", 443, "tcp", "TLS", 50),
                     _k("10.5.5.5", "10.5.5.6"),                      # misma interfaz
                     _k("10.5.5.5", "10.10.15.2"),                    # contra el firewall mismo
                     _k("10.130.1.1", "10.5.5.5", 2222, "tcp", "EtherNet/IP"),
                     _k("10.5.5.5", "9.9.9.9")]                       # 9.9.9.9 -> DMZ-CORP
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.txt"
            p.write_text(SHOW, encoding="utf-8")
            return rf.aplicar(p, activos, conductos), activos, conductos

    def test_conductos_y_activos(self):
        r, activos, k = self._aplicar()
        self.assertEqual([(x["if_origen"], x["if_destino"], x["cruza_firewall"]) for x in k], [
            ("OT-NET", "PROCESO", True), ("OT-NET", "PROCESO", True), ("OT-NET", "OT-NET", False),
            ("OT-NET", "el firewall (OT-NET)", False), ("PROCESO", "OT-NET", True),
            ("OT-NET", "DMZ-CORP (ruta por defecto)", True)])
        self.assertEqual({a: v["interfaz_firewall"] for a, v in activos.items()},
                         {"a": "OT-NET", "b": "PROCESO", "c": "DMZ-CORP (ruta por defecto)", "fw": "el firewall (OT-NET)",
                          "d": "OT-NET"})
        self.assertEqual(r["asignacion"]["10.10.15.2"], "el firewall (OT-NET)")

    def test_matriz_servicios_y_orden(self):
        r, _a, _k_ = self._aplicar()
        m = r["matriz"]
        self.assertEqual([(x["interfaz_origen"], x["interfaz_destino"], x["conductos"]) for x in m],
                         [("OT-NET", "PROCESO", 2), ("OT-NET", "DMZ-CORP (ruta por defecto)", 1), ("PROCESO", "OT-NET", 1)])
        self.assertEqual(m[0]["servicios"], "443/tcp TLS 1; 502/tcp Modbus 1")
        self.assertEqual((m[0]["bytes"], m[0]["origenes"], m[0]["destinos"]), (150, 2, 1))

    def test_interfaces(self):
        r, _a, _k_ = self._aplicar()
        por = {i["interfaz"]: i for i in r["interfaces"]}
        self.assertEqual([i["interfaz"] for i in r["interfaces"]], ["DMZ-CORP (ruta por defecto)", "OT-NET", "PROCESO", "SERVIDORES"])
        self.assertEqual(por["DMZ-CORP (ruta por defecto)"]["redes"], "0.0.0.0/0")
        self.assertEqual(por["DMZ-CORP (ruta por defecto)"]["zona"], "")
        self.assertEqual(por["OT-NET"]["redes"], "10.0.0.0/8;10.10.15.0/24;10.10.15.2/32")
        self.assertEqual(por["OT-NET"]["rutas"], 3)
        self.assertEqual((por["OT-NET"]["activos"], por["PROCESO"]["activos"], por["DMZ-CORP (ruta por defecto)"]["activos"]), (2, 1, 1))
        self.assertEqual(por["PROCESO"]["siguientes_saltos"], "10.130.0.254;10.130.0.253")

    def test_el_orden_de_zonas_se_une_con_punto_y_coma(self):
        rutas, _ = rf.cargar(EJEMPLO)
        self.assertEqual(rutas[0]["zona"], "Corporativa")


class TestServiciosYDefecto(unittest.TestCase):
    def test_formato_de_servicios(self):
        s = rf._servicio
        self.assertEqual(s(_k("a", "b", 443, "tcp", "TLS")), "443/tcp TLS")
        self.assertEqual(s(_k("a", "b", 443, "", "TLS")), "443 TLS")
        self.assertEqual(s(_k("a", "b", 8080, "", "-")), "8080")
        self.assertEqual(s(_k("a", "b", 8080, "tcp", "-")), "8080/tcp")
        self.assertEqual(s(_k("a", "b", "", "", "-")), "sin puerto")
        self.assertEqual(s(_k("a", "b", "", "tcp", "x")), "sin puerto")

    def test_internet_y_red_interna_de_la_misma_interfaz_no_cruzan(self):
        self.assertFalse(rf._cruza("DMZ (ruta por defecto)", "DMZ"))
        self.assertTrue(rf._cruza("DMZ (ruta por defecto)", "OT"))

    def test_ip_publica_va_a_la_fila_de_ruta_por_defecto(self):
        rutas, _ = _cargar("route DMZ 0.0.0.0 0.0.0.0 1.1.1.1\nroute DMZ 192.168.0.0 255.255.0.0 1.1.1.2\n")
        self.assertEqual(rf.interfaz_de("8.8.8.8", rutas), "DMZ (ruta por defecto)")
        self.assertEqual(rf.interfaz_de("192.168.1.1", rutas), "DMZ")


class TestSeccion(unittest.TestCase):
    def _rutas(self, n=25):
        m = [{"interfaz_origen": f"A{i}", "interfaz_destino": "B", "conductos": 100 - i,
              "servicios": "502/tcp Modbus 1; " * 10, "bytes": 2048, "origenes": 1, "destinos": 1}
             for i in range(n)]
        return {"archivo": "r.txt", "rutas": 3, "avisos": ["aviso <x>"], "matriz": m,
                "interfaces": [{"interfaz": "A0", "zona": "Z", "redes": "10.0.0.0/8;" * 20, "rutas": 1,
                                "activos": 4, "siguientes_saltos": ""}]}

    def test_recorta_y_remite_al_csv(self):
        s = rf.seccion(self._rutas(), [{"cruza_firewall": True}, {"cruza_firewall": False}])
        self.assertIn("1 interfaces y 3 rutas", s["resumen"])
        self.assertIn("1 de 2 conductos", s["resumen"])
        self.assertEqual(len(s["matriz"]), 20)
        self.assertEqual(len(s["matriz"][0][3]), 80)
        self.assertTrue(s["matriz"][0][3].endswith("..."))
        self.assertEqual(s["matriz"][0][4], "2.0 KB")
        self.assertEqual(len(s["interfaces"][0][2]), 80)
        self.assertIn("firewall_matriz.csv", s["mas"])
        self.assertEqual(rf.seccion(self._rutas(3), [])["mas"], "")


class TestDiagramaPorInterfaz(unittest.TestCase):
    def _activos(self):
        base = {"vendor": "", "modelo": "", "firmware": "", "tipo_texto": "", "role": "", "pkts": 1,
                "purdue": "Nivel 2", "zona": "ZonaPlat"}
        return {"a": dict(base, mac="a", ips={"10.5.5.5"}, nombre="a", interfaz_firewall="OT-NET",
                          grupo_firewall="OT-NET (Planta)"),
                "b": dict(base, mac="b", ips={"10.130.1.1"}, nombre="b", interfaz_firewall="PROCESO",
                          grupo_firewall="PROCESO")}

    def test_banda_por_interfaz_con_zona_entre_parentesis(self):
        from ot_assess.diagram.graph import construir_activos
        k = [{"src": "10.5.5.5", "dst": "10.130.1.1", "l4": "tcp", "port": 502, "servicio": "Modbus",
              "categoria": "control", "multicast": False, "criticidad": "", "pkts": 1, "bytes": 1, "escrituras": 0, "cruza_zona": False,
              "bidireccional": False}]
        g = construir_activos(self._activos(), k, agrupar="interfaz")
        self.assertEqual(sorted(g.bandas), ["OT-NET (Planta)", "PROCESO"])
        g = construir_activos(self._activos(), k, agrupar="nivel")
        self.assertEqual(g.bandas, ["Nivel 2"])

    def test_aplicar_deja_el_grupo_con_la_zona(self):
        activos = {"a": {"ips": {"10.5.5.5"}}, "c": {"ips": {"8.8.8.8"}}}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.csv"
            p.write_text("Interfaz,Zona,CIDR\nDMZ,Corp,0.0.0.0/0\nOT,,10.0.0.0/8\n", encoding="utf-8")
            rf.aplicar(p, activos, [])
        self.assertEqual(activos["a"]["grupo_firewall"], "OT")
        self.assertEqual(activos["c"]["grupo_firewall"], "DMZ (ruta por defecto) (Corp)")


class TestCsv(unittest.TestCase):
    def test_columnas_nuevas_vacias_sin_la_opcion(self):
        from ot_assess.model import Assessment
        from ot_assess.report.csvout import tablas
        a = {"nombre": "x", "ips": {"10.0.0.1"}, "mac": "", "vendor": "", "role": "", "purdue": "",
             "vlans": set(), "role_why": "", "ports_served": {}, "protos": __import__("collections").Counter(),
             "pkts": 1, "bytes": 1, "capturas": set()}
        k = dict(_k("10.0.0.1", "10.0.0.2"), src_nombre="", src_rol="", src_zona="", dst_nombre="", dst_rol="",
                 dst_zona="", categoria="", bidireccional=False, cruza_zona=False, escrituras=0,
                 criticidad="", pkts=1, capturas=set())
        res = Assessment([], {"x": a}, [k], None)
        t = {x[0]: x for x in tablas(res)}
        self.assertEqual(t["inventario.csv"][2][-3:], ["interfaz_firewall", "zona_asignada", "origen_asignacion"])
        self.assertEqual(t["inventario.csv"][3][0][-3:], ["", "", ""])
        self.assertEqual(t["comunicaciones.csv"][2][-3:], ["if_origen", "if_destino", "cruza_firewall"])
        self.assertEqual(t["comunicaciones.csv"][3][0][-3:], ["", "", ""])
        self.assertNotIn("firewall_matriz.csv", t)

    def test_csv_con_la_opcion(self):
        from ot_assess.model import Assessment
        from ot_assess.report.csvout import tablas
        res = Assessment([], {}, [], None)
        res.rutas = {"interfaces": [{"interfaz": "A", "zona": "", "redes": "10.0.0.0/8", "rutas": 1,
                                     "activos": 0, "siguientes_saltos": ""}],
                     "matriz": [{"interfaz_origen": "A", "interfaz_destino": "B", "conductos": 1,
                                 "servicios": "502/tcp Modbus 1", "bytes": 5, "origenes": 1, "destinos": 1}]}
        t = {x[0]: x for x in tablas(res)}
        self.assertEqual((t["firewall_interfaces.csv"][1], t["firewall_matriz.csv"][1]),
                         ("FW interfaces", "FW matriz"))
        self.assertEqual(t["firewall_interfaces.csv"][2], rf.COL_INTERFACES)
        self.assertEqual(t["firewall_matriz.csv"][3], [["A", "B", 1, "502/tcp Modbus 1", 5, 1, 1]])
        buf = io.StringIO()
        escritor_csv(buf).writerows(t["firewall_matriz.csv"][3])
        self.assertIn("A,B,1", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
