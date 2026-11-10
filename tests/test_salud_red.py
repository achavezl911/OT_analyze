"""L1 (D81): salud de la red y linea base de trafico.

Unitarias (sin tshark): Acumulador de C1 con filas sinteticas, reglas, parser de `show interfaces`, linea base y
exportaciones. Extremo a extremo (tshark y scapy): una captura sintetica con sondeo Modbus y una rafaga de ARP.
Todo sintetico: IP de documentacion (RFC 5737), MAC y nombres inventados.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import cobertura_captura as cc  # noqa: E402
from ot_assess import i18n  # noqa: E402
from ot_assess import playbooks  # noqa: E402
from ot_assess import salud_red as sr  # noqa: E402
from ot_assess.cli import main as main_completo  # noqa: E402
from ot_assess.fields import COBERTURA_FIELDS  # noqa: E402
from ot_assess.model import Capture  # noqa: E402
from ot_assess.rules import salud_red as rsr  # noqa: E402
from ot_assess.switches import integracion as si  # noqa: E402

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

LEE_CAPTURAS = unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
IDX = {f: i for i, f in enumerate(COBERTURA_FIELDS)}
T0 = 1_699_999_980          # alineado al minuto: la ventana de 10 minutos cuenta 10 y no 11
BCAST = "ff:ff:ff:ff:ff:ff"


def fila(t, ln=100, src="192.0.2.10", dst="192.0.2.20", dport="", sport="40000", eth_dst="02:00:00:00:00:02",
         col="TCP", eth_src="02:00:00:00:00:01", retrans=False, tcp_len="0", udp=False):
    r = [""] * len(COBERTURA_FIELDS)
    r[IDX["frame.time_epoch"]], r[IDX["frame.len"]], r[IDX["frame.cap_len"]] = f"{t:.6f}", str(ln), str(ln)
    r[IDX["eth.src"]], r[IDX["eth.dst"]] = eth_src, eth_dst
    r[IDX["ip.src"]], r[IDX["ip.dst"]] = src, dst
    if dport:
        if udp:
            r[IDX["udp.srcport"]], r[IDX["udp.dstport"]] = sport, dport
        else:
            r[IDX["tcp.srcport"]], r[IDX["tcp.dstport"]], r[IDX["tcp.len"]] = sport, dport, tcp_len
    r[IDX["_ws.col.protocol"]] = col
    if retrans:
        r[IDX["tcp.analysis.retransmission"]] = "1"
    return r


def acumular(filas):
    a = cc.Acumulador(IDX)
    for f in filas:
        a.fila(f)
    return a.cerrar()


def cobertura_de(raw, nombre="punto1/a.pcap"):
    return cc.construir([{"path": nombre, "dato": dict(raw, duplicados=None, muestreada=False), "error": ""}])


def cap_con(raw):
    c = Capture(Path("x.pcap"))
    c.cobertura = raw
    return c


class TopYMezclaTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def sintetico(self):
        filas = []
        t = T0
        for i in range(300):         # A (60 % de los bytes) habla con B y con C
            filas.append(fila(t + i * 0.1, 1000, "192.0.2.1", "192.0.2.2", "502", tcp_len="900"))
            filas.append(fila(t + i * 0.1 + 0.01, 1000, "192.0.2.1", "192.0.2.3", "8080", tcp_len="900"))
        for i in range(400):         # D -> E, UDP 4000
            filas.append(fila(t + i * 0.1, 1000, "192.0.2.4", "192.0.2.5", "4000", udp=True, col="UDP"))
        filas.append(fila(t + 61, 60, "", "", eth_dst=BCAST, col="ARP"))
        return filas

    def test_equipo_con_60_por_ciento_es_el_primero(self):
        raw = acumular([f for f in self.sintetico() if f[IDX["_ws.col.protocol"]] != "ARP"])
        por_b, _ = sr.top_equipos(raw, {"192.0.2.1": "plc-a"})
        self.assertEqual(por_b[0][1], "192.0.2.1")
        self.assertEqual(por_b[0][0], "plc-a")
        self.assertAlmostEqual(por_b[0][3], 60.0, places=1)
        self.assertEqual(por_b[1][1], "192.0.2.4")      # D genera el 40 % restante

    def test_la_mezcla_suma_100(self):
        raw = acumular(self.sintetico())
        m = sr.mezcla(raw)
        self.assertAlmostEqual(sum(x[3] for x in m), 100.0, places=6)
        self.assertAlmostEqual(sum(x[5] for x in m), 100.0, places=6)
        self.assertEqual(m[0][0], "industrial")          # los industriales van primero
        self.assertIn("Modbus/TCP", [x[1] for x in m])
        self.assertIn("ARP", [x[1] for x in m])
        self.assertEqual({x[0] for x in m}, {"industrial", "otro"})

    def test_tablas_y_resultado_por_punto(self):
        raw = acumular(self.sintetico())
        cob = cobertura_de(raw)
        rep = sr.construir(cob, [Capture(Path("punto1/a.pcap"))], {}, [], {})
        self.assertEqual([b["punto"] for b in rep["puntos"]], ["a.pcap"])
        tablas = {a: f for a, _h, _c, f in sr.tablas(rep)}
        self.assertEqual(set(tablas) & {"salud_red.csv", "top_equipos.csv", "top_conductos.csv",
                                        "mezcla_protocolos.csv"}, {"salud_red.csv", "top_equipos.csv",
                                                                   "top_conductos.csv", "mezcla_protocolos.csv"})
        self.assertNotIn("interfaces_switch.csv", tablas)
        self.assertEqual(tablas["top_equipos.csv"][0][4], "192.0.2.1")
        s = sr.seccion(rep)
        self.assertEqual(s["titulo"], "Salud de la red y linea base de trafico")
        self.assertTrue(s["tablas"])

    def test_memoria_acotada(self):
        a = cc.Acumulador(IDX)
        n = 50
        for i in range(n):
            a.fila(fila(T0 + i, 100, "192.0.2.1", "192.0.2.2", "", col=f"PROTO{i}"))
        self.assertEqual(len(a.mezcla), n)
        cc.MAX_CLAVES, antes = 5, cc.MAX_CLAVES
        try:
            b = cc.Acumulador(IDX)
            for i in range(n):
                b.fila(fila(T0 + i, 100, "192.0.2.1", "192.0.2.2", "", col=f"PROTO{i}"))
            self.assertLessEqual(len(b.mezcla), 6)
            self.assertEqual(sum(v[1] for v in b.mezcla.values()), n)
        finally:
            cc.MAX_CLAVES = antes


class DifusionTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def fondo(self):
        return [fila(T0 + i * 5, 100, "192.0.2.1", "192.0.2.2", "502", tcp_len="10") for i in range(40)]

    def rafaga(self, n=6000, t=T0 + 90):
        return [fila(t + i / (n + 1), 60, "", "", eth_dst=BCAST, col="ARP", eth_src="02:00:00:00:00:09")
                for i in range(n)]

    def test_rafaga_de_6000_pps_es_tormenta(self):
        raw = acumular(self.fondo() + self.rafaga())
        d = sr.stats_difusion(raw)
        self.assertEqual(d["pico_s"], 6000)
        self.assertEqual(d["arp_total"], 6000)
        c = cap_con(raw)
        rsr.tormenta_difusion(c)
        self.assertEqual([f["titulo"] for f in c.findings], [rsr.TIT_TORMENTA])
        self.assertEqual(c.findings[0]["severidad"], "Media")

    def test_zona_ot_sube_la_severidad(self):
        c = cap_con(acumular(self.fondo() + self.rafaga()))
        h = c.host("02:00:00:00:00:01", "")
        h["purdue"] = "Nivel 1 (control basico)"
        rsr.tormenta_difusion(c)
        self.assertEqual(c.findings[0]["severidad"], "Alta")

    def test_sin_rafaga_no_hay_hallazgo(self):
        c = cap_con(acumular(self.fondo() + self.rafaga(100)))
        rsr.tormenta_difusion(c)
        self.assertEqual(c.findings, [])

    def test_emisores_de_arp_en_el_punto(self):
        raw = acumular(self.fondo() + self.rafaga(50))
        rep = sr.construir(cobertura_de(raw), [Capture(Path("punto1/a.pcap"))], {}, [], {})
        self.assertEqual(rep["total"]["arp_emisores"], [("02:00:00:00:00:09", 50)])


class RetransmisionesTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def conducto(self, segmentos, retrans, puerto="502", base=0):
        out = []
        for i in range(segmentos):
            cliente_a_servidor = i % 2 == 0
            r = fila(T0 + base + i, 100, "192.0.2.10" if cliente_a_servidor else "192.0.2.20",
                     "192.0.2.20" if cliente_a_servidor else "192.0.2.10", puerto if cliente_a_servidor else "40001",
                     sport="40001" if cliente_a_servidor else puerto, tcp_len="10", retrans=cliente_a_servidor and i // 2 < retrans)
            out.append(r)
        return out

    def test_modbus_con_8_por_ciento_y_300_segmentos(self):
        raw = acumular(self.conducto(300, 24))     # 24 de 300 segmentos = 8 %
        malos = sr.tcp_sobre_umbral(raw)
        self.assertEqual(len(malos), 1)
        self.assertEqual(malos[0][2], 502)
        self.assertAlmostEqual(malos[0][4], 8.0, places=1)
        c = cap_con(raw)
        rsr.retransmisiones_ot(c)
        self.assertEqual([f["titulo"] for f in c.findings], [rsr.TIT_RETRANS])
        self.assertEqual(c.findings[0]["severidad"], "Media")
        self.assertIn("502", c.findings[0]["evidencia"])

    def test_150_segmentos_no_alcanzan(self):
        c = cap_con(acumular(self.conducto(150, 12)))
        rsr.retransmisiones_ot(c)
        self.assertEqual(c.findings, [])

    def test_puerto_no_industrial_no_dispara(self):
        raw = acumular(self.conducto(300, 24, puerto="8080"))
        self.assertEqual(sr.tcp_sobre_umbral(raw), [])
        self.assertEqual(len(sr.tcp_conductos(raw)), 1)      # se mide, pero no es hallazgo OT

    def test_bajo_el_umbral(self):
        c = cap_con(acumular(self.conducto(300, 10)))         # 3.3 %
        rsr.retransmisiones_ot(c)
        self.assertEqual(c.findings, [])


IFACES_SW = """sw-l1#show running-config
hostname sw-l1
monitor session 1 source vlan 20
monitor session 1 destination interface GigabitEthernet1/0/24
!
interface GigabitEthernet1/0/1
 switchport mode trunk
!
interface GigabitEthernet1/0/2
 switchport mode access
!
interface GigabitEthernet1/0/3
 switchport mode access
!
interface GigabitEthernet1/0/24
 switchport mode access
!
end
sw-l1#show interfaces
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,
  5 minute input rate 80000000 bits/sec, 9000 packets/sec
  5 minute output rate 1000000 bits/sec, 100 packets/sec
     900000 packets input, 123456 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     800000 packets output, 1 bytes, 0 underruns
GigabitEthernet1/0/2 is up, line protocol is up (connected)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 10000000 bits/sec, 1000 packets/sec
  5 minute output rate 5000000 bits/sec, 500 packets/sec
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 1000
     900000 packets input, 123456 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     99000 packets output, 1 bytes, 0 underruns
GigabitEthernet1/0/3 is up, line protocol is up (connected)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 10000000 bits/sec, 1000 packets/sec
  5 minute output rate 5000000 bits/sec, 500 packets/sec
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
     900000 packets input, 123456 bytes, 0 no buffer
     9000 input errors, 1500 CRC, 0 frame, 0 overrun, 0 ignored
     99000 packets output, 1 bytes, 0 underruns
GigabitEthernet1/0/24 is up, line protocol is up (connected)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 950000000 bits/sec, 90000 packets/sec
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 121000000
     10 packets input, 123456 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     379000000 packets output, 1 bytes, 0 underruns
"""
SECRETO_SW = ("usrajeno7", "192.0.2.98")


class SwitchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def leer(self, texto):
        a = self.tmp / "sw.txt"
        a.write_text(texto, encoding="utf-8")
        return si.integrar([str(a)], {})

    def test_parser_de_bw_y_tasas(self):
        sw = self.leer(IFACES_SW)["switches"][0]
        c = {x.puerto: x for x in sw.contadores}["GigabitEthernet1/0/1"]
        self.assertEqual((c.bw_kbit, c.tasa_entrada_bps, c.tasa_salida_bps), (100000, 80000000, 1000000))

    def test_cuellos_de_botella_y_span(self):
        rep = sr.interfaces_switch(self.leer(IFACES_SW))
        por = {f["interfaz"]: f for f in rep["filas"]}
        self.assertAlmostEqual(por["GigabitEthernet1/0/1"]["util"], 80.0)
        self.assertTrue(por["GigabitEthernet1/0/1"]["troncal"])
        cuellos = [f["interfaz"] for f in rep["cuellos"]]
        self.assertEqual(cuellos[0], "GigabitEthernet1/0/1")        # el troncal primero
        self.assertIn("GigabitEthernet1/0/2", cuellos)              # descartes: 1000 de 100000 = 1 %
        self.assertIn("GigabitEthernet1/0/3", cuellos)              # CRC > 1000
        # el destino del SPAN (95 % de utilizacion y millones de descartes) no se repite aqui (T10c)
        self.assertNotIn("GigabitEthernet1/0/24", cuellos)
        self.assertTrue(por["GigabitEthernet1/0/24"]["span"])

    def test_hallazgo_y_sin_cuellos(self):
        rep = sr.interfaces_switch(self.leer(IFACES_SW))
        cap = Capture(Path("x"))
        sr.agregar_hallazgos(cap, {"switch": rep})
        self.assertEqual([f["titulo"] for f in cap.findings], [sr.TIT_INTERFAZ])
        f = cap.findings[0]
        self.assertEqual(f["severidad"], "Media")
        self.assertIn("GigabitEthernet1/0/1", f["evidencia"])
        self.assertNotIn("GigabitEthernet1/0/24", f["evidencia"])
        sano = IFACES_SW.replace("80000000", "50000000").replace("Total output drops: 1000", "Total output drops: 0") \
                        .replace("1500 CRC", "10 CRC")
        rep = sr.interfaces_switch(self.leer(sano))
        self.assertEqual(rep["cuellos"], [])
        cap = Capture(Path("x"))
        sr.agregar_hallazgos(cap, {"switch": rep})
        self.assertEqual(cap.findings, [])

    def test_tabla_del_switch_y_sin_switch(self):
        rep = {"switch": sr.interfaces_switch(self.leer(IFACES_SW))}
        t = {a: (c, f) for a, _h, c, f in sr.tablas(rep)}
        self.assertEqual(list(t), ["interfaces_switch.csv"])
        self.assertEqual(t["interfaces_switch.csv"][0], sr.C_SWITCH)
        self.assertEqual(sr.interfaces_switch({}), {})
        self.assertFalse(sr.hay({}))


def _flujo(src, dst, dport, minutos, l4="tcp"):
    """Flujo con la serie por minuto de flows.py: minutos = {minuto: (bytes, paquetes)}."""
    return {"src": src, "dst": dst, "dport": dport, "l4": l4, "pkts": sum(p for _b, p in minutos.values()),
            "bytes": sum(b for b, _p in minutos.values()), "proto": "", "first": T0 + 5, "last": T0 + 590,
            "sports": set(), "min": {T0 // 60 + m: (b << 32) | p for m, (b, p) in minutos.items()}}


def _conducto(src, dst, port, bytes_, pkts):
    return {"src": src, "dst": dst, "l4": "tcp", "port": port, "servicio": "Modbus/TCP", "bytes": bytes_,
            "pkts": pkts, "src_nombre": "plc-1", "dst_nombre": "hmi-1", "bidireccional": True}


class LineaBaseTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def cap(self):
        c = Capture(Path("sitio/a.pcap"))
        c.ventana = [T0, T0 + 599]            # 10 minutos
        act = {0: (100, 1), 1: (100, 1), 2: (100, 1), 3: (100, 1), 4: (100, 1), 5: (100, 1), 6: (200, 2), 7: (5000, 50)}
        f1 = _flujo("192.0.2.1", "192.0.2.2", "502", act)
        f2 = _flujo("192.0.2.3", "192.0.2.2", "40000", {0: (10, 1)})
        f2["min"] = None                      # cupo agotado: sin serie
        c.flows = {("192.0.2.1", "192.0.2.2", "502", "tcp"): f1, ("192.0.2.3", "192.0.2.2", "40000", "tcp"): f2}
        return c

    def test_p50_p95_y_metadatos(self):
        conds = [_conducto("192.0.2.1", "192.0.2.2", "502", 5800, 59),
                 _conducto("192.0.2.3", "192.0.2.2", "40000", 10, 1)]
        lb = sr.linea_base([self.cap()], conds, "9.9.9", "cliente-demo")
        a, b = lb["conductos"]
        self.assertEqual((a["origen_ip"], a["puerto"]), ("192.0.2.1", "502"))
        self.assertEqual((a["bytes_min_p50"], a["bytes_min_p95"]), (100, 5000))
        self.assertEqual((a["paquetes_min_p50"], a["paquetes_min_p95"]), (1, 50))
        self.assertEqual((a["minutos_ventana"], a["minutos_activos"], a["serie_por_minuto"]), (10, 8, True))
        self.assertIsNone(b["bytes_min_p50"])
        self.assertFalse(b["serie_por_minuto"])
        m = lb["meta"]
        self.assertEqual((m["version"], m["cliente"], m["ventana"]["minutos"]), ("9.9.9", "cliente-demo", 10))
        self.assertEqual(m["capturas"], ["a.pcap"])
        self.assertEqual(m["puntos_de_captura"], ["sitio"])
        self.assertTrue(m["ventana"]["inicio"].endswith("Z"))
        json.dumps(lb)                          # serializable y determinista
        self.assertEqual(json.dumps(lb, sort_keys=True),
                         json.dumps(sr.linea_base([self.cap()], conds, "9.9.9", "cliente-demo"), sort_keys=True))

    def test_tablas_y_json(self):
        conds = [_conducto("192.0.2.1", "192.0.2.2", "502", 5800, 59)]
        rep = {"origen": "captura", "linea_base": sr.linea_base([self.cap()], conds, "1", "")}
        t = {a: (c, f) for a, _h, c, f in sr.tablas(rep)}
        cab, filas = t["linea_base_trafico.csv"]
        self.assertEqual(cab, sr.C_BASE)
        self.assertEqual(filas[0][cab.index("bytes_min_p95")], 5000)
        self.assertEqual(sr.linea_base_json(rep)["conductos"][0]["destino_ip"], "192.0.2.2")
        self.assertEqual(sr.linea_base_json({}), {})


class ExportacionTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")

    def test_sin_series_lo_aclara(self):
        conds = [dict(_conducto("192.0.2.1", "192.0.2.2", "502", 5800, 59), categoria="ot"),
                 dict(_conducto("192.0.2.3", "192.0.2.2", "80", 200, 4), categoria="otro", servicio="HTTP")]
        rep = sr.de_exportacion({}, conds)
        self.assertTrue(rep["exportacion"])
        self.assertEqual(rep["total"]["equipos_bytes"][0][1], "192.0.2.2")     # recibe de los dos
        s = sr.seccion(rep)
        self.assertIn("no hay series por minuto", s["nota"])
        self.assertIn("no hay series por minuto", s["resumen"])
        t = {a: f for a, _h, _c, f in sr.tablas(rep)}
        self.assertEqual(t["linea_base_trafico.csv"][0][10], "")              # sin p50
        self.assertNotIn("salud_red.csv", t)
        self.assertEqual(sr.mezcla({"mezcla": {"ot:Modbus/TCP": [5800, 59], "p:HTTP": [200, 4]}})[0][0], "industrial")

    def test_exportacion_sin_bytes_no_genera_nada(self):
        self.assertEqual(sr.de_exportacion({}, [_conducto("192.0.2.1", "192.0.2.2", "502", 0, 0)]), {})


class DiagramaTest(unittest.TestCase):
    def test_diagrama_sin_series_lo_aclara(self):
        sys.path.insert(0, str(RAIZ / "tests"))
        import gen_exports
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(i18n.usar, "es")
        est = gen_exports.escribir(tmp / "ex")["b"]
        with redirect_stdout(io.StringIO()):
            rc = main_completo(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                                "-o", str(tmp / "o")])
        self.assertEqual(rc, 0)
        res = json.loads((tmp / "o" / "resultado.json").read_text("utf-8"))
        if res["salud_red"]:          # la exportacion de prueba trae bytes
            self.assertEqual(res["salud_red"]["origen"], "exportacion")
            md = (tmp / "o" / "reporte_ot.md").read_text("utf-8")
            self.assertIn("no hay series por minuto", md)
            self.assertFalse((tmp / "o" / "salud_red.csv").exists())


class PlaybooksYMapeosTest(unittest.TestCase):
    TITULOS = (rsr.TIT_TORMENTA, rsr.TIT_RETRANS, sr.TIT_INTERFAZ)

    def test_playbook_y_referencias(self):
        from ot_assess.standards import referencias
        for tit in self.TITULOS:
            self.assertTrue(playbooks.para_titulo(tit), tit)
            self.assertTrue(referencias(tit), tit)

    def test_en_ingles(self):
        i18n.usar("en")
        try:
            for tit in self.TITULOS:
                self.assertNotEqual(i18n.t(tit), tit)
            self.assertIn("Network health", i18n.t(sr.TITULO))
        finally:
            i18n.usar("es")


def _pcap(ruta: Path) -> None:
    from scapy.all import ARP, IP, TCP, Ether, Raw, wrpcap
    pk = []
    mc, ms = "02:00:00:11:00:01", "02:00:00:11:00:02"
    seq_c = seq_s = 1000
    for i in range(90):          # 3 minutos de sondeo Modbus cada 2 s
        t = T0 + i * 2
        p = Ether(src=mc, dst=ms) / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
            sport=40000, dport=502, flags="PA", seq=seq_c, ack=seq_s) / Raw(b"\x00" * 12)
        p.time = t
        q = Ether(src=ms, dst=mc) / IP(src="192.0.2.20", dst="192.0.2.10") / TCP(
            sport=502, dport=40000, flags="PA", seq=seq_s, ack=seq_c + 12) / Raw(b"\x00" * 15)
        q.time = t + 0.01
        seq_c, seq_s = seq_c + 12, seq_s + 15
        pk += [p, q]
    for i in range(6000):        # rafaga de ARP en un segundo
        a = Ether(src="02:00:00:11:00:09", dst=BCAST) / ARP(op=1, psrc="192.0.2.99", pdst="192.0.2.98")
        a.time = T0 + 91 + i / 6001
        pk.append(a)
    pk.sort(key=lambda x: float(x.time))
    wrpcap(str(ruta), pk)


@LEE_CAPTURAS
class ExtremoAExtremoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        entrada = cls.tmp / "punto1"
        entrada.mkdir()
        _pcap(entrada / "a.pcap")
        cls.salida = cls.tmp / "salida"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            main_completo([str(entrada), "-o", str(cls.salida)])

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_archivos_y_linea_base(self):
        for n in ("salud_red.csv", "top_equipos.csv", "top_conductos.csv", "mezcla_protocolos.csv",
                  "linea_base_trafico.csv", "linea_base_trafico.json"):
            self.assertTrue((self.salida / n).exists(), n)
        self.assertFalse((self.salida / "interfaces_switch.csv").exists())      # sin --switch
        lb = json.loads((self.salida / "linea_base_trafico.json").read_text("utf-8"))
        modbus = [c for c in lb["conductos"] if c["puerto"] == "502" and c["origen_ip"] == "192.0.2.10"][0]
        self.assertTrue(modbus["serie_por_minuto"])
        self.assertGreater(modbus["bytes_min_p50"], 0)
        self.assertGreaterEqual(modbus["bytes_min_p95"], modbus["bytes_min_p50"])
        self.assertEqual(lb["meta"]["capturas"], ["a.pcap"])
        self.assertTrue(lb["meta"]["version"])
        res = json.loads((self.salida / "resultado.json").read_text("utf-8"))
        self.assertGreater(res["salud_red"]["total"]["difusion_pico_pps"], 5000)

    def test_tormenta_en_el_reporte(self):
        csv_h = (self.salida / "hallazgos.csv").read_text("utf-8-sig")
        self.assertIn("Tormenta de difusion o multidifusion", csv_h)
        html = (self.salida / "reporte_ot.html").read_text("utf-8") if (self.salida / "reporte_ot.html").exists() \
            else "".join(p.read_text("utf-8") for p in self.salida.glob("*.html"))
        self.assertIn("Salud de la red y linea base de trafico", html)


if __name__ == "__main__":
    unittest.main()
