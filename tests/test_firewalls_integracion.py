"""F1b: --firewall (salida de la CLI de un FTD/ASA) integrado al analisis. Texto sintetico."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports

from ot_assess.cli import main
from ot_assess.firewalls import cisco
from ot_assess.firewalls import integracion as fi

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

SECRETOS = "username admin password SECRETOX encrypted\nsnmp-server community SECRETOY\n"


def _sesion(rutas: str, reglas: str, hits: str = "") -> str:
    return ("FW1# show running-config\n" + SECRETOS + reglas
            + "FW1# show route\nCodes: L - local, C - connected, S - static\n" + rutas
            + "FW1# show nameif\nInterface Name Security\n"
              "GigabitEthernet0/0 outside 0\nGigabitEthernet0/1 inside 100\n"
              "GigabitEthernet0/2 dmz 50\n" + hits)


RUTAS = ("S*       0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
         "C        192.0.2.0 255.255.255.0 is directly connected, outside\n"
         "C        10.10.1.0 255.255.255.0 is directly connected, inside\n"
         "L        10.10.1.2 255.255.255.255 is directly connected, inside\n"
         "C        10.10.9.0 255.255.255.0 is directly connected, dmz\n")


def _c(src, dst, port=80, l4="tcp"):
    return {"src": src, "dst": dst, "l4": l4, "port": str(port)}


def _contraste(reglas: str, conductos: list, hits: str = "") -> dict:
    fw = cisco.analizar_texto(_sesion(RUTAS, reglas, hits))
    return fi.contrastar(fw, conductos, "fw.txt", [])


class ContrasteTest(unittest.TestCase):
    def test_interfaces_de_la_regla_deciden(self):
        """Dos reglas iguales salvo ifc: casa la de su interfaz, no la primera."""
        reglas = (
            "access-list CSM_FW_ACL_ advanced deny tcp ifc dmz any ifc outside any eq 80 rule-id 10\n"
            "access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq 80 rule-id 11\n")
        r = _contraste(reglas, [_c("10.10.1.5", "8.8.8.8"), _c("10.10.9.5", "8.8.8.8"),
                                _c("10.10.1.5", "10.10.9.5")])
        self.assertEqual([(x["resultado"], x["regla"]) for x in r["resultados"]],
                         [("permitido", "11"), ("denegado_observado", "10"), ("sin_regla", "")])

    def test_confiar_deny_antes_y_regla_por_defecto(self):
        reglas = (
            "access-list CSM_FW_ACL_ remark rule-id 1: L7 RULE: Bloquear telnet\n"
            "access-list CSM_FW_ACL_ advanced deny tcp any any eq 23 rule-id 1\n"
            "access-list CSM_FW_ACL_ remark rule-id 2: L7 RULE: Confiar HTTP\n"
            "access-list CSM_FW_ACL_ advanced trust tcp ifc inside any ifc outside any eq 80 rule-id 2\n"
            "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 3\n"
            "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 4\n")
        r = _contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 23), _c("10.10.1.5", "8.8.8.8", 80),
                                _c("10.10.9.5", "10.10.1.5", 502)])
        self.assertEqual([(x["resultado"], x["regla"]) for x in r["resultados"]],
                         [("denegado_observado", "1"), ("permitido", "2"), ("permitido", "3")])
        self.assertEqual(r["resultados"][1]["regla_nombre"], "Confiar HTTP")
        d = _contraste(reglas.replace("permit ip any any rule-id 3", "deny ip any any rule-id 3"),
                       [_c("10.10.9.5", "10.10.1.5", 502)])
        self.assertEqual(d["resultados"][0]["resultado"], "denegado_observado")

    def test_tabla_de_reglas_y_contadores(self):
        reglas = (
            "access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq 80 rule-id 1\n"
            "access-list CSM_FW_ACL_ advanced permit tcp any any eq 22 rule-id 2\n"
            "access-list CSM_FW_ACL_ advanced permit tcp any any eq 443 rule-id 3\n"
            "access-list CSM_FW_ACL_ advanced permit tcp any any object-group NOEXISTE rule-id 4\n")
        hits = ("FW1# show rule hits\nRuleID Hit Count First Hit Time(UTC) Last Hit Time(UTC)\n"
                "2   5   10:01:02 Oct 5 2024   11:22:33 Nov 3 2024\n")
        r = _contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 80)], hits)
        tab = {x["id"]: x for x in r["reglas"]}
        self.assertEqual((tab["1"]["conductos_observados"], tab["1"]["aciertos"]), (1, 0))
        self.assertEqual((tab["2"]["conductos_observados"], tab["2"]["aciertos"],
                          tab["2"]["primer_acierto"]), (0, 5, "2024-10-05 10:01:02"))
        self.assertEqual(tab["1"]["interfaces_origen"], "inside")
        self.assertIn("NOEXISTE", tab["4"]["avisos"])
        res = r["resumen"]
        self.assertTrue(res["con_contadores"])
        self.assertEqual((res["permitir_con_aciertos_sin_conductos"],
                          res["permitir_con_conductos_sin_aciertos"]), (1, 1))

    def test_redes_recortadas_a_diez(self):
        import ipaddress
        redes = [ipaddress.ip_network(f"10.50.0.{i}/32") for i in range(1, 13)]
        txt = fi._redes(redes)
        self.assertEqual(txt.count(";"), 10)
        self.assertTrue(txt.endswith("y 2 mas"))
        self.assertEqual(fi._redes([ipaddress.ip_network("0.0.0.0/0")]), "any")


class CliDiagramaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.fw = cls.tmp / "fw.txt"
        cls.fw.write_text(_sesion(
            "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
            "C   10.20.1.0 255.255.255.0 is directly connected, campo\n"
            "C   10.20.2.0 255.255.255.0 is directly connected, superv\n",
            "access-list CSM_FW_ACL_ advanced permit ip ifc superv any ifc campo any rule-id 1\n"
            "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n"), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _correr(self, destino, *extra):
        out = self.tmp / destino
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["diagrama", "--activos", str(self.est["activos"]), "--enlaces", str(self.est["enlaces"]),
                       "-o", str(out), *extra])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    def test_rutas_conectadas_interfaz_y_reglas(self):
        out, txt = self._correr("a", "--firewall", str(self.fw))
        self.assertNotIn("sin rutas conectadas", txt)
        with open(out / "inventario_importado.csv", newline="", encoding="utf-8-sig") as fh:
            ifs = {f["nombre"]: f["interfaz_firewall"] for f in csv.DictReader(fh)}
        self.assertEqual((ifs["PLC-BOMBAS"], ifs["HMI-SALA-1"]), ("campo", "superv"))
        with open(out / "firewall_reglas.csv", newline="", encoding="utf-8-sig") as fh:
            reglas = {f["id"]: f for f in csv.DictReader(fh)}
        self.assertEqual(reglas["1"]["interfaces_origen"], "superv")
        self.assertGreater(int(reglas["1"]["conductos_observados"]), 0)
        self.assertGreater(int(reglas["2"]["conductos_observados"]), 0)  # lo demas cae en la de por defecto
        self.assertTrue((out / "firewall_matriz.csv").exists())

    def test_sin_firewall_no_hay_tabla_de_reglas(self):
        out, _ = self._correr("b")
        self.assertFalse((out / "firewall_reglas.csv").exists())

    def test_manda_firewall_sobre_rutas_firewall(self):
        rutas = self.tmp / "rutas.csv"
        rutas.write_text("Interfaz,CIDR\nOTRA,10.20.0.0/16\n", encoding="utf-8")
        out, txt = self._correr("c", "--firewall", str(self.fw), "--rutas-firewall", str(rutas))
        self.assertIn("manda --firewall", txt)
        self.assertNotIn("OTRA", (out / "inventario_importado.csv").read_text(encoding="utf-8"))

    def test_firewall_repetido_avisa(self):
        """M1: ya no se descarta el segundo; el mismo archivo dos veces se distingue con #1 y #2."""
        _, txt = self._correr("d", "--firewall", str(self.fw), "--firewall", str(self.fw))
        self.assertNotIn("usa solo el primero", txt)
        self.assertIn("fw.txt#2", txt)

    def test_secretos_no_llegan_a_ninguna_salida(self):
        out, txt = self._correr("e", "--firewall", str(self.fw))
        for f in out.rglob("*"):
            if f.is_file():
                datos = f.read_bytes()
                self.assertNotIn(b"SECRETOX", datos, f.name)
                self.assertNotIn(b"SECRETOY", datos, f.name)
        self.assertNotIn("SECRETO", txt)


class CliCapturasTest(unittest.TestCase):
    def test_firewall_con_reglas_firewall_es_error(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            main(["no_importa", "--firewall", "x.txt", "--reglas-firewall", "y.csv"])
        self.assertEqual(cm.exception.code, 2)

    @unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
    def test_capturas_con_firewall(self):
        import gen_pcaps
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        fw = tmp / "fw.txt"
        fw.write_text(_sesion(
            "S*  0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
            "C   10.10.1.0 255.255.255.0 is directly connected, inside\n"
            "C   10.10.2.0 255.255.255.0 is directly connected, dmz\n",
            "access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc outside any eq 80 rule-id 1\n"
            "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 2\n"), encoding="utf-8")
        out = tmp / "out"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([str(tmp / "pcaps"), "-o", str(out), "--firewall", str(fw)])
        self.assertNotIn("sin rutas conectadas", buf.getvalue())
        with open(out / "inventario.csv", newline="", encoding="utf-8-sig") as fh:
            ifs = {f["ips"]: f["interfaz_firewall"] for f in csv.DictReader(fh)}
        self.assertEqual(ifs.get("10.10.1.10"), "inside")
        self.assertEqual(ifs.get("10.10.2.5"), "dmz")
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))["firewall"]
        self.assertEqual(res["archivo"], "fw.txt")
        self.assertIn("1", {x["regla"] for x in res["resultados"]})  # HTTP inside -> outside
        self.assertIn("2", {x["regla"] for x in res["resultados"]})  # lo demas, la de por defecto
        self.assertTrue((out / "firewall_reglas.csv").exists())
        for f in out.rglob("*"):
            if f.is_file():
                self.assertNotIn(b"SECRETOX", f.read_bytes(), f.name)


PERMITE_DMZ_A_INSIDE = (
    "access-list CSM_FW_ACL_ remark rule-id 7: RULE: DMZ_a_inside\n"
    "access-list CSM_FW_ACL_ advanced permit tcp ifc dmz any ifc inside any eq 443 rule-id 7\n"
    "access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9\n")


def _bi(src, dst, port=443):
    return dict(_c(src, dst, port), bidireccional=True)


class DireccionRealTest(unittest.TestCase):
    """F1e (D43): sentido real de los conductos bidireccionales y respuestas de sesion."""

    def test_bidireccional_con_servidor_de_ip_menor_se_invierte(self):
        # la clave del importador ordena por IP: el servidor 10.10.1.5 queda como origen
        r = _contraste(PERMITE_DMZ_A_INSIDE, [_bi("10.10.1.5", "10.10.9.5")])
        x = r["resultados"][0]
        self.assertEqual((x["resultado"], x["sentido"], x["regla"]), ("permitido", "invertido", "7"))
        self.assertEqual((x["if_origen"], x["if_destino"]), ("dmz", "inside"))
        self.assertEqual(r["resumen"]["invertidos"], 1)
        self.assertEqual(r["reglas"][0]["conductos_observados"], 1)
        fila = r["cruces"]["detalle"][0]          # F5a usa el sentido real
        self.assertEqual((fila["ip_origen"], fila["ip_destino"], fila["interfaz_origen"]),
                         ("10.10.9.5", "10.10.1.5", "dmz"))

    def test_bidireccional_negado_en_los_dos_sentidos_queda_original(self):
        r = _contraste(PERMITE_DMZ_A_INSIDE, [_bi("10.10.1.5", "10.10.9.5", 502)])
        x = r["resultados"][0]
        self.assertEqual((x["resultado"], x["sentido"]), ("denegado_observado", "original"))
        self.assertEqual((x["if_origen"], x["if_destino"]), ("inside", "dmz"))
        self.assertEqual(r["resumen"]["invertidos"], 0)

    def test_puerto_alto_con_inverso_permitido_es_respuesta(self):
        ida = _c("10.10.9.5", "10.10.1.5", 443)       # dmz -> inside:443 permitido
        vuelta = _c("10.10.1.5", "10.10.9.5", 33440)  # inside -> dmz:33440, denegado por defecto
        r = _contraste(PERMITE_DMZ_A_INSIDE, [ida, vuelta])
        self.assertEqual([x["resultado"] for x in r["resultados"]], ["permitido", "respuesta"])
        self.assertEqual(r["resultados"][1]["regla"], "7")
        self.assertEqual(r["resumen"]["respuesta"], 1)
        self.assertEqual(r["resumen"]["denegado_observado"], 0)
        self.assertEqual(r["reglas"][0]["conductos_observados"], 2)

    def test_puerto_alto_sin_inverso_permitido_sigue_denegado(self):
        r = _contraste(PERMITE_DMZ_A_INSIDE, [_c("10.10.1.5", "10.10.9.5", 33440)])
        self.assertEqual(r["resultados"][0]["resultado"], "denegado_observado")
        # el inverso existe pero por otro puerto alto: tampoco es respuesta
        r = _contraste(PERMITE_DMZ_A_INSIDE, [_c("10.10.9.5", "10.10.1.5", 40000),
                                              _c("10.10.1.5", "10.10.9.5", 33440)])
        self.assertEqual(r["resumen"]["respuesta"], 0)


class SinL4Test(unittest.TestCase):
    """Exportaciones sin transporte (solo protocolo de aplicacion): una regla tcp casa por puerto y se marca."""

    def test_regla_tcp_casa_por_puerto_sin_l4(self):
        reglas = "access-list CSM_FW_ACL_ advanced permit tcp 10.0.0.0 255.0.0.0 any eq 443 rule-id 1\n"
        r = _contraste(reglas, [_c("10.10.1.5", "203.0.113.5", 443, ""), _c("10.10.1.5", "203.0.113.5", 443, "udp")])
        self.assertEqual([(x["resultado"], x.get("l4_inferido")) for x in r["resultados"]],
                         [("permitido", True), ("sin_regla", None)])
        self.assertEqual(r["resumen"]["l4_inferido"], 1)


TUNEL = (
    "access-list CSM_FW_ACL_ remark rule-id 5: PREFILTER POLICY: pf\n"
    "access-list CSM_FW_ACL_ remark rule-id 5: RULE: DEFAULT TUNNEL ACTION RULE\n"
    "access-list CSM_FW_ACL_ advanced permit ipinip any any rule-id 5\n"
    "access-list CSM_FW_ACL_ advanced permit 41 any any rule-id 5\n"
    "access-list CSM_FW_ACL_ advanced permit gre any any rule-id 5\n"
    "access-list CSM_FW_ACL_ advanced permit udp any eq 3544 any range 1025 65535 rule-id 5\n"
    "access-list CSM_FW_ACL_ advanced permit udp any range 1025 65535 any eq 3544 rule-id 5\n")


class SubreglasTest(unittest.TestCase):
    def test_reglas_de_tunel_no_casan_trafico_normal(self):
        reglas = TUNEL + "access-list CSM_FW_ACL_ advanced permit tcp any any eq 443 rule-id 6\n"
        r = _contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 443), _c("10.10.1.5", "8.8.8.8", 8080, ""),
                                _c("10.10.1.5", "8.8.8.8", 3544, "udp"), _c("10.10.1.5", "8.8.8.8", 0, "gre"),
                                _c("10.10.1.5", "8.8.8.8", 3544, "")])
        self.assertEqual([(x["resultado"], x["regla"]) for x in r["resultados"]],
                         [("permitido", "6"), ("sin_regla", ""), ("sin_regla", ""),
                          ("permitido", "5"), ("sin_regla", "")])
        self.assertEqual(r["resumen"]["subreglas_con_puerto_origen"], 2)

    def test_puertos_de_origen_y_destino_se_separan(self):
        fw = cisco.analizar_texto(_sesion(RUTAS, TUNEL))
        subs = next(x for x in fw.reglas if x.id == "5").subreglas
        self.assertEqual(len(subs), 5)
        self.assertEqual((subs[3].puertos_origen, subs[3].puertos_destino), ([(3544, 3544)], [(1025, 65535)]))
        self.assertEqual((subs[4].puertos_origen, subs[4].puertos_destino), ([(1025, 65535)], [(3544, 3544)]))
        self.assertEqual(subs[2].protocolos, ["gre"])
        self.assertEqual(next(x for x in fw.reglas if x.id == "5").puertos, [(1025, 65535)])   # union solo de destino

    def test_cada_linea_del_mismo_rule_id_casa_por_separado(self):
        reglas = ("access-list CSM_FW_ACL_ advanced permit tcp host 10.10.1.5 any eq 443 rule-id 7\n"
                  "access-list CSM_FW_ACL_ advanced permit udp host 10.10.1.6 any eq 53 rule-id 7\n")
        r = _contraste(reglas, [_c("10.10.1.5", "8.8.8.8", 53), _c("10.10.1.5", "8.8.8.8", 443, "tcp"),
                                _c("10.10.1.6", "8.8.8.8", 53, "udp")])
        self.assertEqual([x["resultado"] for x in r["resultados"]], ["sin_regla", "permitido", "permitido"])

    def test_object_group_de_servicio_en_origen_es_puerto_de_origen(self):
        reglas = ("object-group service SVC tcp\n port-object eq 1234\n"
                  "access-list CSM_FW_ACL_ advanced permit tcp any object-group SVC any eq 80 rule-id 8\n"
                  "access-list CSM_FW_ACL_ advanced permit tcp any any object-group SVC rule-id 9\n")
        fw = cisco.analizar_texto(_sesion(RUTAS, reglas))
        por_id = {x.id: x.subreglas[0] for x in fw.reglas}
        self.assertEqual((por_id["8"].puertos_origen, por_id["8"].puertos_destino), ([(1234, 1234)], [(80, 80)]))
        self.assertEqual((por_id["9"].puertos_origen, por_id["9"].puertos_destino), ([], [(1234, 1234)]))


if __name__ == "__main__":
    unittest.main()


class RespuestaSentidoRealTest(unittest.TestCase):
    """La respuesta va del servidor al cliente del sentido REAL de la sesion, no del orden de la clave."""

    def test_puertos_altos_en_el_mismo_sentido_que_la_sesion_no_son_respuesta(self):
        import ipaddress

        from ot_assess.firewalls.modelo import Firewall, Interfaz, Regla, Ruta, Subregla
        N = ipaddress.ip_network
        fw = Firewall(fabricante="Cisco FTD/ASA", hostname="FW",
                      interfaces=[Interfaz(fisica="e1", nombre="corp", ip="10.100.37.1", mascara="255.255.255.248", zona="corp"),
                                  Interfaz(fisica="e2", nombre="scada", ip="10.10.15.2", mascara="255.255.255.0", zona="scada")],
                      rutas=[Ruta(red=N("192.168.100.2/32"), interfaz="corp", salto="10.100.37.6", tipo="estatica", codigo="S"),
                             Ruta(red=N("10.130.0.0/16"), interfaz="scada", salto="10.10.15.11", tipo="estatica", codigo="S")])
        sub = Subregla(protocolos=["tcp"], origen=[N("0.0.0.0/0")], destino=[N("10.130.14.101/32")],
                       puertos_origen=[], puertos_destino=[(443, 443)], zonas_origen=["corp"], zonas_destino=["scada"], linea="")
        fw.reglas = [Regla(id="1", nombre="CGA", accion="permitir", protocolos=["tcp"], origen=sub.origen,
                           destino=sub.destino, puertos=[(443, 443)], zonas_origen=["corp"], zonas_destino=["scada"],
                           subreglas=[sub], acl="CSM_FW_ACL_")]
        # bidireccional ordenado por IP (servidor primero) + puerto alto cliente -> servidor (mismo sentido que la sesion)
        cs = [{"src": "10.130.14.101", "dst": "192.168.100.2", "port": "443", "l4": "", "bidireccional": True},
              {"src": "192.168.100.2", "dst": "10.130.14.101", "port": "33500", "l4": "", "bidireccional": False},
              {"src": "10.130.14.101", "dst": "192.168.100.2", "port": "19618", "l4": "", "bidireccional": False}]
        res = fi.contrastar(fw, cs, "x", [], {})["resultados"]
        self.assertEqual((res[0]["resultado"], res[0]["sentido"]), ("permitido", "invertido"))
        self.assertNotEqual(res[1]["resultado"], "respuesta")      # nueva conexion a un puerto alto
        self.assertEqual(res[2]["resultado"], "respuesta")               # vuelta servidor -> cliente
