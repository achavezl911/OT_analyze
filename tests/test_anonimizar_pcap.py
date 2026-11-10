"""E5b: anonimizador de capturas (cabeceras, sumas, recorte de carga, pcapng)."""
from __future__ import annotations

import collections
import contextlib
import csv
import io
import json
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess.anonimizar_pcap import suma  # noqa: E402
from ot_assess.cli import main  # noqa: E402

CLAVE = "ab" * 32
RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def correr(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(["anonimizar", *map(str, argv)])
    return rc, out.getvalue() + err.getvalue()


def escribir_pcap(path, registros, enlace=1, fin="<", nano=False):
    """registros: [(bytes, origlen|None)]; escribe un pcap clasico con el orden y la precision dados."""
    magic = {("<", False): 0xA1B2C3D4, ("<", True): 0xA1B23C4D,
             (">", False): 0xA1B2C3D4, (">", True): 0xA1B23C4D}[(fin, nano)]
    with open(path, "wb") as fh:
        fh.write(struct.pack(fin + "IHHiIII", magic, 2, 4, 0, 0, 65535, enlace))
        for i, (datos, orig) in enumerate(registros):
            fh.write(struct.pack(fin + "IIII", 1_700_000_000 + i, 123456 + i, len(datos),
                                 orig if orig is not None else len(datos)))
            fh.write(datos)


def leer_pcap(path):
    """-> (cabecera global, [(ts, tf, caplen, origlen, datos)]) de un pcap little endian."""
    raw = Path(path).read_bytes()
    pos, regs = 24, []
    while pos < len(raw):
        ts, tf, cl, ol = struct.unpack("<IIII", raw[pos:pos + 16])
        regs.append((ts, tf, cl, ol, raw[pos + 16:pos + 16 + cl]))
        pos += 16 + cl
    return raw[:24], regs


@unittest.skipUnless(HAY_SCAPY, "requiere scapy")
class CapturaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scapy.all import (ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment)
        cls.E = (ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment)

    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.d = Path(self.t.name)
        self.ent = self.d / "ent"
        self.ent.mkdir()
        (self.d / "mapa.json").write_text(json.dumps({"clave": CLAVE}), encoding="utf-8")
        self.mapa = self.d / "mapa.json"

    def paquetes(self):
        ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment = self.E
        a, b = "00:1b:1b:00:00:10", "00:00:bc:00:00:20"
        ia, ib = "10.10.1.10", "10.10.1.20"
        eth = Ether(src=a, dst=b)
        tcp = eth / IP(src=ia, dst=ib) / TCP(sport=40000, dport=502, seq=1) / Raw(b"\x01" * 13)
        udp = eth / IP(src=ia, dst=ib) / UDP(sport=5000, dport=53) / Raw(b"abc")   # longitud impar
        vlan = Ether(src=a, dst=b) / Dot1Q(vlan=10) / IP(src=ia, dst=ib) / UDP(sport=1, dport=2) / Raw(b"xy")
        qinq = Ether(src=a, dst=b, type=0x88A8) / Dot1Q(vlan=20, type=0x8100) / Dot1Q(vlan=30) \
            / IP(src=ia, dst=ib) / TCP(sport=1, dport=2) / Raw(b"q")
        arp = Ether(src=a, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=a, psrc=ia, hwdst="00:00:00:00:00:00", pdst=ib)
        interno = IP(src=ib, dst="192.168.5.9") / UDP(sport=53, dport=5000) / Raw(b"zz")
        icmp_err = Ether(src=b, dst=a) / IP(src="10.10.1.30", dst=ia) / ICMP(type=3, code=3) / interno
        eco = eth / IP(src=ia, dst=ib) / ICMP() / Raw(b"ping")
        frag = fragment(eth / IP(src=ia, dst=ib, id=77) / UDP(sport=9, dport=9) / Raw(b"f" * 60), fragsize=40)
        bcast = Ether(src=a, dst="ff:ff:ff:ff:ff:ff") / IP(src=ia, dst="255.255.255.255") \
            / UDP(sport=68, dport=67) / Raw(b"d")
        return [tcp, udp, vlan, qinq, arp, icmp_err, eco, bcast, *frag]

    def tcp_http(self, datos):
        ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment = self.E
        return bytes(Ether(src="00:1b:1b:00:00:10", dst="00:00:bc:00:00:20")
                     / IP(src="10.10.1.10", dst="10.10.1.20") / TCP(sport=40000, dport=80, seq=1) / Raw(datos))

    def pcap_base(self, nombre="c.pcap", **kw):
        pk = [bytes(p) for p in self.paquetes()]
        if kw.pop("sin_fragmentos", False):
            pk = pk[:8]       # la suma L4 de un fragmento no se recalcula (limitacion documentada)
        escribir_pcap(self.ent / nombre, [(x, None) for x in pk], **kw)
        return pk

    def anon(self, salida="out", *extra, mapa=None):
        rc, txt = correr(self.ent, "-o", self.d / salida, "--mapa", mapa or self.mapa, *extra)
        self.assertEqual(rc, 0, txt)
        return self.d / salida, txt

    # ---- (1) direcciones y (2) sumas ---------------------------------------------------------
    def test_direcciones_y_sumas(self):
        self.pcap_base()
        out, txt = self.anon()
        _, orig = leer_pcap(self.ent / "c.pcap")
        _, nuevo = leer_pcap(out / "c.pcap")
        self.assertEqual(len(orig), len(nuevo))
        macs_o = {m for r in orig for m in (r[4][0:6], r[4][6:12])}
        macs_n = {m for r in nuevo for m in (r[4][0:6], r[4][6:12])}
        ips_o = {"10.10.1.10", "10.10.1.20", "10.10.1.30", "192.168.5.9"}
        crudo = b"".join(r[4] for r in nuevo)
        for m in macs_o - {b"\xff" * 6}:
            self.assertNotIn(m, macs_n)
        for ip in ips_o:
            self.assertNotIn(socket.inet_aton(ip), crudo, ip)      # ni en IP, ni en ARP, ni en ICMP
        self.assertIn(b"\xff" * 6, macs_n)                          # broadcast intacto
        self.assertIn(socket.inet_aton("255.255.255.255"), crudo)
        for (_, _, _, _, o), (_, _, _, _, n) in zip(orig, nuevo):
            self.assertEqual(o[0:3], n[0:3])                        # OUI
        self.verificar_sumas(nuevo)

    def verificar_sumas(self, regs):
        vistos = collections.Counter()
        for r in regs:
            d = r[4]
            o = 14
            tipo = struct.unpack(">H", d[12:14])[0]
            while tipo in (0x8100, 0x88A8):
                o += 4
                tipo = struct.unpack(">H", d[o - 2:o])[0]
            if tipo != 0x0800:
                continue
            ihl = (d[o] & 15) * 4
            self.assertEqual(suma(d[o:o + ihl]), 0, "suma IP")
            vistos["ip"] += 1
            total = struct.unpack(">H", d[o + 2:o + 4])[0]
            frag = struct.unpack(">H", d[o + 6:o + 8])[0] & 0x3FFF
            seg = d[o + ihl:o + total]
            if frag:
                continue
            ps = d[o + 12:o + 20]
            proto = d[o + 9]
            if proto in (6, 17) and (proto == 6 or seg[6:8] != b"\x00\x00"):
                pseudo = suma(ps + bytes([0, proto]) + len(seg).to_bytes(2, "big"))
                self.assertEqual(suma(seg, (~pseudo) & 0xFFFF), 0, f"suma L4 {proto}")
                vistos[proto] += 1
            if proto == 1:
                self.assertEqual(suma(seg), 0, "suma ICMP")
                vistos[1] += 1
                if seg[0] == 3:
                    self.assertEqual(suma(seg[8:28]), 0, "suma IP interna")
                    vistos["interna"] += 1
        for k in ("ip", 6, 17, 1, "interna"):
            self.assertGreater(vistos[k], 0, k)

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_tshark_no_ve_sumas_malas(self):
        self.pcap_base(sin_fragmentos=True)
        out, _ = self.anon()
        r = subprocess.run(
            ["tshark", "-r", str(out / "c.pcap"), "-o", "ip.check_checksum:TRUE",
             "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
             "-T", "fields", "-e", "ip.checksum.status",
             "-e", "tcp.checksum.status", "-e", "udp.checksum.status", "-e", "icmp.checksum.status"],
            capture_output=True, text=True)
        estados = [x for ln in r.stdout.splitlines() for c in ln.split("\t") for x in c.split(",") if x]
        self.assertIn("1", estados, r.stderr[-300:])
        self.assertNotIn("0", estados, r.stdout)        # 0 = Bad

    # ---- (4) estabilidad ----------------------------------------------------------------------
    def test_misma_salida_con_el_mismo_mapa(self):
        self.pcap_base()
        a, _ = self.anon("a")
        b, _ = self.anon("b")
        self.assertEqual((a / "c.pcap").read_bytes(), (b / "c.pcap").read_bytes())
        otra = self.d / "otro.json"
        otra.write_text(json.dumps({"clave": "cd" * 32}), encoding="utf-8")
        c, _ = self.anon("c", mapa=otra)
        self.assertNotEqual((a / "c.pcap").read_bytes(), (c / "c.pcap").read_bytes())

    def test_ip_igual_a_la_de_las_tablas(self):
        self.pcap_base()
        (self.ent / "t.csv").write_text("Name,IP\nhmi,10.10.1.10\n", encoding="utf-8")
        out, _ = self.anon()
        _, regs = leer_pcap(out / "c.pcap")
        ip_pcap = socket.inet_ntoa(regs[0][4][26:30])
        self.assertIn(ip_pcap, (out / "t.csv").read_text())

    # ---- formatos de pcap ---------------------------------------------------------------------
    def test_ordenes_de_bytes_y_nanosegundos_conservan_cabecera_y_tiempos(self):
        pk = [bytes(p) for p in self.paquetes()][:3]
        for fin in ("<", ">"):
            for nano in (False, True):
                nombre = f"c{fin == '<'}{nano}.pcap"
                escribir_pcap(self.ent / nombre, [(x, None) for x in pk], fin=fin, nano=nano)
        out, _ = self.anon()
        for p in self.ent.glob("*.pcap"):
            o, s = p.read_bytes(), (out / p.name).read_bytes()
            self.assertEqual(o[:24], s[:24])
            fin = "<" if o[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            pos_o = pos_s = 24
            for _ in pk:
                ho = struct.unpack(fin + "IIII", o[pos_o:pos_o + 16])
                hs = struct.unpack(fin + "IIII", s[pos_s:pos_s + 16])
                self.assertEqual(ho, hs)                             # ts, tf, caplen y origlen
                self.assertNotEqual(o[pos_o + 16 + 26:pos_o + 16 + 30],
                                    s[pos_s + 16 + 26:pos_s + 16 + 30])
                pos_o += 16 + ho[2]
                pos_s += 16 + hs[2]

    def test_ipv4_crudo(self):
        ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment = self.E
        pk = bytes(IP(src="10.10.1.10", dst="10.10.1.20") / TCP(sport=1, dport=2) / Raw(b"hi"))
        for enlace in (101, 228):
            escribir_pcap(self.ent / f"r{enlace}.pcap", [(pk, None)], enlace=enlace)
        out, txt = self.anon()
        for enlace in (101, 228):
            _, regs = leer_pcap(out / f"r{enlace}.pcap")
            d = regs[0][4]
            self.assertNotEqual(d[12:16], socket.inet_aton("10.10.1.10"))
            self.assertEqual(suma(d[:20]), 0)
            pseudo = suma(d[12:20] + bytes([0, 6]) + (len(d) - 20).to_bytes(2, "big"))
            self.assertEqual(suma(d[20:], (~pseudo) & 0xFFFF), 0)

    # ---- (5) casos especiales -------------------------------------------------------------------
    def test_snaplen_fragmento_y_udp_sin_suma(self):
        ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment = self.E
        eth = Ether(src="00:1b:1b:00:00:10", dst="00:00:bc:00:00:20")
        completo = bytes(eth / IP(src="10.10.1.10", dst="10.10.1.20") / TCP(sport=1, dport=2) / Raw(b"x" * 100))
        cortado = completo[:60]                                       # snaplen: faltan datos
        sin_suma = bytearray(bytes(eth / IP(src="10.10.1.10", dst="10.10.1.20") / UDP(sport=1, dport=2)
                                   / Raw(b"u")))
        sin_suma[14 + 20 + 6:14 + 20 + 8] = b"\x00\x00"
        frags = [bytes(f) for f in fragment(eth / IP(src="10.10.1.10", dst="10.10.1.20", id=5)
                                            / UDP(sport=1, dport=2) / Raw(b"f" * 80), fragsize=48)]
        escribir_pcap(self.ent / "c.pcap", [(cortado, len(completo)), (bytes(sin_suma), None),
                                            *[(f, None) for f in frags]])
        out, _ = self.anon()
        res = list(csv.DictReader(open(out / "anonimizacion.csv")))
        fila = [r for r in res if r["archivo"] == "c.pcap"][0]
        self.assertEqual(fila["sumas_sin_recalcular"], str(1 + len(frags)))
        _, regs = leer_pcap(out / "c.pcap")
        self.assertEqual(regs[0][3], len(completo))                   # origlen intacto
        self.assertEqual(regs[0][2], 60)
        self.assertEqual(regs[0][4][14 + 20 + 16:14 + 20 + 18], cortado[14 + 20 + 16:14 + 20 + 18])
        self.assertEqual(suma(regs[0][4][14:34]), 0)                  # la suma IP si se arregla
        self.assertEqual(regs[1][4][14 + 20 + 6:14 + 20 + 8], b"\x00\x00")
        for r in regs[2:]:
            self.assertEqual(suma(r[4][14:34]), 0)

    # ---- (3) mismos conteos del analisis ---------------------------------------------------------
    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_el_analisis_da_los_mismos_conteos(self):
        import gen_pcaps
        orig = self.d / "orig"
        sys.argv = ["gen", str(orig)]
        gen_pcaps.main()
        rc, txt = correr(orig, "-o", self.d / "anon", "--mapa", self.mapa)
        self.assertEqual(rc, 0, txt)
        res = {}
        for nombre, carpeta in (("o", orig), ("a", self.d / "anon")):
            sal = self.d / ("res_" + nombre)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(carpeta), "-o", str(sal)]), 0)
            filas = lambda n: list(csv.DictReader(open(sal / n, newline="", encoding="utf-8-sig")))
            res[nombre] = {
                "activos": len(filas("inventario.csv")),
                "conductos": len(filas("comunicaciones.csv")),
                "hallazgos": sorted((r["severidad"], RE_IP.sub("IP", r["titulo"]), r["categoria"])
                                    for r in filas("hallazgos.csv")),
            }
        self.assertGreater(res["o"]["activos"], 0)
        self.assertGreater(len(res["o"]["hallazgos"]), 0)
        self.assertEqual(res["o"], res["a"])

    # ---- (6) recortar -------------------------------------------------------------------------------
    def test_recortar_deja_solo_cabeceras(self):
        self.pcap_base()
        out, txt = self.anon("rec", "--carga", "recortar")
        _, orig = leer_pcap(self.ent / "c.pcap")
        _, rec = leer_pcap(out / "c.pcap")
        tcp0, udp0, ping = rec[0], rec[1], rec[6]
        self.assertEqual(tcp0[2], 14 + 20 + 20)
        self.assertEqual(udp0[2], 14 + 20 + 8)
        self.assertEqual(ping[2], 14 + 20 + 8)
        self.assertEqual(rec[2][2], 14 + 4 + 20 + 8)                  # VLAN
        self.assertEqual(rec[3][2], 14 + 8 + 20 + 20)                 # QinQ
        self.assertEqual(rec[4][2], 14 + 28)                          # ARP
        for o, r in zip(orig, rec):
            self.assertEqual(o[3], r[3])                              # origlen igual
            self.assertEqual(r[2], len(r[4]))
        self.assertIn("pierde la deteccion", txt)
        fila = [r for r in csv.DictReader(open(out / "anonimizacion.csv")) if r["archivo"] == "c.pcap"][0]
        self.assertEqual(fila["carga_recortada"], "si")
        self.assertEqual(fila["paquetes"], str(len(orig)))

    def test_mantener_avisa_de_la_carga(self):
        self.pcap_base()
        _, txt = self.anon()
        self.assertIn("conserva el texto libre", txt)

    # ---- (7) pcapng y enlaces no soportados -----------------------------------------------------------
    @unittest.skipUnless(shutil.which("editcap"), "requiere editcap")
    def test_pcapng_sale_como_pcap(self):
        self.pcap_base("base.pcap")
        subprocess.run(["editcap", "-F", "pcapng", str(self.ent / "base.pcap"),
                        str(self.ent / "c.pcapng")], check=True)
        (self.ent / "base.pcap").unlink()
        out, txt = self.anon()
        self.assertTrue((out / "c.pcap").exists())
        self.assertFalse((out / "c.pcapng").exists())
        self.assertEqual([p.name for p in out.iterdir() if p.name.startswith(".")], [])
        _, regs = leer_pcap(out / "c.pcap")
        self.assertEqual(len(regs), len(self.paquetes()))
        self.assertIn("c.pcap", [r["archivo"] for r in csv.DictReader(open(out / "anonimizacion.csv"))])
        self.assertIn("antes c.pcapng", txt)

    def test_enlace_no_soportado_se_omite(self):
        escribir_pcap(self.ent / "w.pcap", [(b"\x00" * 30, None)], enlace=105)
        self.pcap_base()
        out, txt = self.anon()
        self.assertFalse((out / "w.pcap").exists())
        self.assertFalse(list(out.glob("*.parcial")))
        self.assertIn("enlace 105 no soportado", txt)
        self.assertTrue((out / "c.pcap").exists())
        self.assertIn("w.pcap,omitido", (out / "anonimizacion.csv").read_text())

    def test_captura_truncada_se_omite_sin_dejar_salida(self):
        self.pcap_base()
        p = self.ent / "c.pcap"
        p.write_bytes(p.read_bytes()[:-5])
        out, txt = self.anon()
        self.assertFalse((out / "c.pcap").exists())
        self.assertFalse(list(out.glob("*.parcial")))
        self.assertIn("truncada", txt)

    # ---- rendimiento ----------------------------------------------------------------------------------
    def test_rendimiento_captura_grande(self):
        pk = [bytes(p) for p in self.paquetes()]
        texto = b"GET /v1.2/datos.html HTTP/1.1\r\nHost: 10.10.1.20 planta.local\r\nX-V: 4.1.2.0\r\n" * 4
        pk.append(self.tcp_http(texto))
        regs = [(x, None) for x in pk] * 36000                        # ~ 33 MB
        escribir_pcap(self.ent / "g.pcap", regs)
        # unas 3000 IP conocidas (de las tablas) y 20 terminos: el costo de la busqueda en la carga
        ips = {f"10.{20 + i // 250}.{i % 250}.7": f"10.{120 + i // 250}.{i % 250}.7" for i in range(3000)}
        self.mapa.write_text(json.dumps({"clave": CLAVE, "ips": ips}), encoding="utf-8")
        terminos = self.d / "t.txt"
        terminos.write_text("\n".join(f"cliente{i}.planta.local" for i in range(20)), encoding="utf-8")
        t0 = time.time()
        self.anon("out", "--terminos", terminos)
        dt = time.time() - t0
        mb = (self.ent / "g.pcap").stat().st_size / 1e6
        print(f"\n[rendimiento] {mb:.1f} MB, 3000 IP conocidas, en {dt:.1f} s", file=sys.stderr)
        self.assertLess(dt, 90)


A_MAC, B_MAC = "00:1b:1b:00:00:10", "00:00:bc:00:00:20"
A_IP, B_IP, C_IP = "10.10.1.10", "10.10.1.20", "10.10.1.30"


def sumas_ok(test, regs):
    """Sumas IP, TCP y UDP de todos los paquetes completos."""
    for r in regs:
        d = r[4]
        if struct.unpack(">H", d[12:14])[0] != 0x0800:
            continue
        ihl = (d[14] & 15) * 4
        test.assertEqual(suma(d[14:14 + ihl]), 0)
        total = struct.unpack(">H", d[16:18])[0]
        seg = d[14 + ihl:14 + total]
        if d[23] in (6, 17):
            pseudo = suma(d[26:34] + bytes([0, d[23]]) + len(seg).to_bytes(2, "big"))
            test.assertEqual(suma(seg, (~pseudo) & 0xFFFF), 0, "suma L4")


@unittest.skipUnless(HAY_SCAPY, "requiere scapy")
class CargaTest(unittest.TestCase):
    """E5c: IP, MAC, terminos y nombres dentro de la carga, sin cambiar ninguna longitud."""
    setUpClass = classmethod(CapturaTest.setUpClass.__func__)
    setUp = CapturaTest.setUp
    anon = CapturaTest.anon

    def eth(self, ip_s=A_IP, ip_d=B_IP):
        ARP, Dot1Q, Ether, ICMP, IP, TCP, UDP, Raw, fragment = self.E
        return Ether(src=A_MAC, dst=B_MAC) / IP(src=ip_s, dst=ip_d)

    def udp(self, datos, dport=9999, ip_s=A_IP, ip_d=B_IP):
        UDP = self.E[6]
        return bytes(self.eth(ip_s, ip_d) / UDP(sport=5000, dport=dport) / datos)

    def tcp(self, datos, dport=80):
        TCP = self.E[5]
        return bytes(self.eth() / TCP(sport=40000, dport=dport, seq=1) / datos)

    def escribir(self, pk, nombre="c.pcap"):
        escribir_pcap(self.ent / nombre, [(x, None) for x in pk])

    def mapa_json(self):
        return json.loads(self.mapa.read_text(encoding="utf-8"))

    def fila(self, out, archivo="c.pcap"):
        return [r for r in csv.DictReader(open(out / "anonimizacion.csv")) if r["archivo"] == archivo][0]

    def test_dns_a_con_ip_de_la_captura(self):
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        resp = DNS(id=7, qr=1, rd=1, ra=1, qd=DNSQR(qname="scada.planta.local"), ancount=1,
                   an=DNSRR(rrname="scada.planta.local", type="A", ttl=60, rdata=C_IP))
        pk = [self.udp(DNS(id=7, rd=1, qd=DNSQR(qname="scada.planta.local")), 53),
              bytes(self.eth(B_IP, A_IP) / self.E[6](sport=53, dport=5000) / resp),
              self.udp(b"hola", ip_s=C_IP)]                   # C_IP tambien aparece en una cabecera
        self.escribir(pk)
        out, _ = self.anon()
        nueva = self.mapa_json()["ips"][C_IP]
        _, regs = leer_pcap(out / "c.pcap")
        self.assertNotEqual(nueva, C_IP)
        self.assertIn(socket.inet_aton(nueva), regs[1][4][14 + 20 + 8:])
        self.assertNotIn(socket.inet_aton(C_IP), regs[1][4])
        self.assertEqual([r[2] for r in regs], [len(x) for x in pk])
        sumas_ok(self, regs)
        self.assertEqual(self.fila(out)["ip_binarias"], "1")
        if shutil.which("tshark"):
            sal = self.d / "res"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(out), "-o", str(sal)]), 0)
            filas = list(csv.DictReader(open(sal / "dns_resoluciones.csv", encoding="utf-8-sig")))
            self.assertIn((nueva, "scada.planta.local"), [(f["ip"], f["nombre"]) for f in filas])

    def test_mac_en_la_carga(self):
        pk = [self.udp(b"\xaa\xaa" + bytes.fromhex(A_MAC.replace(":", "")) + b"\x00zz"),
              self.udp(b"x", ip_s=B_IP)]
        self.escribir(pk)
        out, _ = self.anon()
        nueva = bytes.fromhex(self.mapa_json()["macs"][A_MAC].replace(":", ""))
        _, regs = leer_pcap(out / "c.pcap")
        carga = regs[0][4][14 + 20 + 8:]
        self.assertEqual(carga, b"\xaa\xaa" + nueva + b"\x00zz")
        self.assertEqual(self.fila(out)["mac_binarias"], "1")
        sumas_ok(self, regs)

    def terminos(self, *t):
        f = self.d / "terminos.txt"
        f.write_text("\n".join(t) + "\n", encoding="utf-8")
        return f

    def test_terminos_ascii_y_utf16(self):
        http = (b"GET /datos HTTP/1.1\r\nHost: Planta-Norte.cliente.com\r\nX: PLANTA-NORTE 2\r\n\r\n")
        u16 = "Cliente: DUCTO7".encode("utf-16-le")
        pk = [self.tcp(http), self.udp(u16)]
        self.escribir(pk)
        out, _ = self.anon("out", "--terminos", self.terminos("planta-norte", "ducto7"))
        _, regs = leer_pcap(out / "c.pcap")
        h = regs[0][4][14 + 20 + 20:]
        self.assertEqual(len(h), len(http))
        self.assertNotIn(b"lanta-", h.lower())
        self.assertIn(b".cliente.com\r\n", h)                       # lo que no es termino se queda
        i = http.index(b"Planta-Norte")
        j = http.index(b"PLANTA-NORTE")
        self.assertEqual(h[i + 6:i + 7], b"-")
        for k in list(range(i, i + 12)) + list(range(j, j + 12)):
            self.assertEqual(chr(h[k]).isupper(), chr(http[k]).isupper(), k)
            self.assertEqual(chr(h[k]).isalpha(), chr(http[k]).isalpha(), k)
            self.assertEqual(h[k:k + 1] == b"-", http[k:k + 1] == b"-")
        self.assertEqual(h[i:i + 12].lower(), h[j:j + 12].lower())    # mismo seudonimo
        self.assertNotEqual(h[i:i + 12].lower(), http[i:i + 12].lower())
        u = regs[1][4][14 + 20 + 8:]
        self.assertEqual(len(u), len(u16))
        self.assertTrue(u.startswith("Cliente: ".encode("utf-16-le")))
        ps = u[len("Cliente: ".encode("utf-16-le")):].decode("utf-16-le")
        self.assertEqual(len(ps), 6)
        self.assertTrue(ps[:5].isupper() and ps[5].isdigit() and ps != "DUCTO7")
        self.assertEqual(self.fila(out)["terminos_carga"], "3")
        carga = self.mapa_json()["carga"]
        self.assertEqual(set(carga), {"planta-norte", "ducto7"})
        self.assertEqual(len(carga["planta-norte"]), 12)
        sumas_ok(self, regs)

    def test_nombre_del_mapa_en_la_carga(self):
        (self.ent / "t.csv").write_text("Name,IP\nhmi-norte,10.10.1.10\nab,10.10.1.20\n", encoding="utf-8")
        self.escribir([self.udp(b"id=HMI-Norte;ab;"), self.udp(b"z", ip_s=B_IP)])
        out, _ = self.anon()
        _, regs = leer_pcap(out / "c.pcap")
        carga = regs[0][4][14 + 20 + 8:]
        self.assertEqual(len(carga), len(b"id=HMI-Norte;ab;"))
        self.assertNotIn(b"orte", carga.lower())
        self.assertTrue(carga.endswith(b";ab;"))                      # menos de 4 caracteres: no se busca

    def test_ip_en_texto_igual_y_distinta_longitud(self):
        from ot_assess.anonimizar import Mapa
        m = Mapa(self.mapa)
        igual = dist = None
        for a in range(1, 60):
            ip = f"10.{a}.{a}.9"
            if m.ip(ip) != ip:
                if len(m.ip(ip)) == len(ip) and igual is None:
                    igual = ip
                if len(m.ip(ip)) != len(ip) and dist is None:
                    dist = ip
        self.assertTrue(igual and dist)
        texto = f"ir a {igual} o {dist} fin".encode()
        self.escribir([self.udp(texto)])
        out, _ = self.anon()
        _, regs = leer_pcap(out / "c.pcap")
        carga = regs[0][4][14 + 20 + 8:]
        mapa_ips = Mapa(self.mapa)
        enmascarada = re.sub(r"\d", "x", dist)
        self.assertEqual(carga.decode(), f"ir a {mapa_ips.ip(igual)} o {enmascarada} fin")
        self.assertEqual(len(carga), len(texto))
        f = self.fila(out)
        self.assertEqual((f["ip_texto"], f["ip_texto_enmascaradas"]), ("1", "1"))
        self.assertIn("enmascar", self.anon("out2")[1])
        sumas_ok(self, regs)

    def test_modbus_sin_coincidencias_y_con_ip_conocida(self):
        limpio = bytes.fromhex("000100000009010306") + b"\x00\x01\x00\x02\x00\x03"
        con_ip = bytes.fromhex("000200000009010306") + socket.inet_aton(B_IP) + b"\x00\x03"
        pk = [self.tcp(limpio, 502), self.tcp(con_ip, 502), self.tcp(con_ip, 8080)]
        self.escribir(pk)
        out, txt = self.anon()
        _, regs = leer_pcap(out / "c.pcap")
        ini = 14 + 20 + 20
        self.assertEqual(regs[0][4][ini:], limpio)                    # byte a byte
        nueva = socket.inet_aton(self.mapa_json()["ips"][B_IP])
        self.assertEqual(regs[1][4][ini:], bytes.fromhex("000200000009010306") + nueva + b"\x00\x03")
        self.assertEqual(self.fila(out)["carga_ot_modificada"], "1")  # el de 8080 no es OT
        self.assertEqual(self.fila(out)["ip_binarias"], "2")
        self.assertIn("protocolos OT", txt)
        sumas_ok(self, regs)

    def test_recortar_no_busca_en_la_carga(self):
        self.escribir([self.udp(socket.inet_aton(B_IP) + b"planta"), self.udp(b"x", ip_s=B_IP)])
        out, _ = self.anon("out", "--carga", "recortar", "--terminos", self.terminos("planta"))
        f = self.fila(out)
        for k in ("ip_binarias", "mac_binarias", "ip_texto", "ip_texto_enmascaradas",
                  "terminos_carga", "carga_ot_modificada"):
            self.assertEqual(f[k], "0", k)
        self.assertEqual(self.mapa_json()["carga"], {})

    def test_misma_salida_con_el_mismo_mapa(self):
        self.escribir([self.udp(socket.inet_aton(B_IP) + b" Planta 10.77.8.9"),
                       self.udp(b"x", ip_s=B_IP), self.tcp(b"Planta")])
        t = self.terminos("planta")
        a, _ = self.anon("a", "--terminos", t)
        b, _ = self.anon("b", "--terminos", t)
        self.assertEqual((a / "c.pcap").read_bytes(), (b / "c.pcap").read_bytes())

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_el_analisis_da_lo_mismo_con_la_carga_seudonimizada(self):
        import gen_pcaps
        orig = self.d / "orig"
        sys.argv = ["gen", str(orig)]
        gen_pcaps.main()
        rc, txt = correr(orig, "-o", self.d / "anon", "--mapa", self.mapa)
        self.assertEqual(rc, 0, txt)
        res = {}
        for nombre, carpeta in (("o", orig), ("a", self.d / "anon")):
            sal = self.d / ("res_" + nombre)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(carpeta), "-o", str(sal)]), 0)
            filas = lambda n: list(csv.DictReader(open(sal / n, newline="", encoding="utf-8-sig")))
            res[nombre] = {
                "activos": len(filas("inventario.csv")),
                "conductos": len(filas("comunicaciones.csv")),
                "dns": len(filas("dns_registros.csv")),
                "resoluciones": len(filas("dns_resoluciones.csv")),
                "hallazgos": sorted((r["severidad"], RE_IP.sub("IP", r["titulo"])) for r in filas("hallazgos.csv")),
            }
        self.assertGreater(res["o"]["dns"], 0)
        self.assertGreater(len(res["o"]["hallazgos"]), 0)
        self.assertEqual(res["o"], res["a"])

    @unittest.skipUnless(shutil.which("tshark"), "requiere tshark")
    def test_tshark_acepta_las_sumas_con_carga_cambiada(self):
        self.escribir([self.udp(socket.inet_aton(B_IP) + b" 10.77.8.9 Planta"),
                       self.tcp(socket.inet_aton(A_IP) + b"Planta"), self.udp(b"x", ip_s=B_IP)])
        out, _ = self.anon("out", "--terminos", self.terminos("planta"))
        r = subprocess.run(
            ["tshark", "-r", str(out / "c.pcap"), "-o", "ip.check_checksum:TRUE",
             "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
             "-T", "fields", "-e", "tcp.checksum.status", "-e", "udp.checksum.status"],
            capture_output=True, text=True)
        estados = [x for ln in r.stdout.splitlines() for x in ln.split("\t") if x]
        self.assertIn("1", estados)
        self.assertNotIn("0", estados, r.stdout)


if __name__ == "__main__":
    unittest.main()
