"""E5a: anonimizador (mapa estable, tablas, JSON y configuraciones en texto)."""
from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports  # noqa: E402
from ot_assess.anonimizar import Anonimizador, Mapa  # noqa: E402
from ot_assess.cli import main  # noqa: E402
from ot_assess.importers import importar  # noqa: E402
from ot_assess.report.xlsx import escribir_xlsx  # noqa: E402

CLAVE = "ab" * 32
CLAVE2 = "cd" * 32

CONFIG = """hostname fw-planta-acme
ip domain-name acme.local
enable secret 5 $1$abcd$xyz
snmp-server community publica RO
username admin password Sup3rS3cret
crypto pki certificate chain TP
 certificate ca 01
  30820123308201AA
  quit
interface Gi0/1
 description Enlace a planta Norte Acme
 ip address 10.1.1.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 10.1.1.1
object-group network SRV
 network-object 10.2.3.0 255.255.255.0
access-list X permit ip 10.0.0.0 0.0.0.255 any
access-list X permit tcp host 203.0.113.5 host 8.8.4.4 eq 443
access-list X remark Regla de Acme para 10.1.1.1
arp 10.1.1.9 00:1b:1b:aa:bb:cc arpa
ipv6 route ::/0 2001:db8::1
contact admin@acme.local planta-sur
"""

INVENTARIO = ("Device Name,IP,MAC,Vendor,Description,Serial Number,Site\n"
              "PLC-BOMBAS,10.20.5.7,00:1b:1b:10:00:11,Siemens,Bombas de Acme Norte,SN123456,Planta Norte\n"
              "HMI-SALA,10.20.5.9,00-1B-1B-10-00-12,Siemens,Sala de control,SN123457,Planta Norte\n"
              "PC-OFICINA,10.20.9.1,001b.1b10.0013,Dell,,SN123458,Planta Sur\n"
              "WEB-PUB,8.8.4.4,ff:ff:ff:ff:ff:ff,Google,Salida a Internet,SN123459,Planta Sur\n")
RUTAS = "Interface,Network\nOT-NET,10.20.0.0/16\nPUB,0.0.0.0/0\n"
TERMINOS = "# cliente\nAcme\nacme.local\nPlanta Norte\n"


def correr(*argv) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(["anonimizar", *map(str, argv)])


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.d = Path(self.t.name)
        self.ent = self.d / "entrada"
        (self.ent / "sub").mkdir(parents=True)
        (self.ent / "inventario.csv").write_text(INVENTARIO, encoding="utf-8")
        (self.ent / "sub" / "rutas.csv").write_text(RUTAS, encoding="utf-8")
        (self.ent / "fw.cfg").write_text(CONFIG, encoding="utf-8")
        (self.ent / "datos.json").write_text(json.dumps(
            {"devices": [{"name": "PLC-BOMBAS", "ip": "10.20.5.7", "notes": "revisar Acme",
                          "email": "jefe@acme.local", "serial": 4455}]}), encoding="utf-8")
        escribir_xlsx(self.ent / "libro.xlsx", [
            ("Planta Norte", ["Titulo de reporte", "", ""], [["Name", "IP", "Comments"],
                                                           ["PLC-BOMBAS", "10.20.5.7", "nota Acme"]]),
            ("Rutas", ["Interface", "Network"], [["OT-NET", "10.20.0.0/16"]])])
        self.terminos = self.d / "terminos.txt"
        self.terminos.write_text(TERMINOS, encoding="utf-8")

    def mapa(self, nombre="mapa.json", clave=CLAVE):
        p = self.d / nombre
        p.write_text(json.dumps({"clave": clave}), encoding="utf-8")
        return p

    def anonimizar(self, salida, mapa, entradas=None):
        rc = correr(*(entradas or [self.ent]), "-o", self.d / salida, "--mapa", mapa,
                    "--terminos", self.terminos)
        self.assertEqual(rc, 0)
        return self.d / salida

    @staticmethod
    def leer(carpeta):
        return {str(p.relative_to(carpeta)): p.read_bytes() for p in sorted(carpeta.rglob("*"))
                if p.is_file()}


class EstabilidadTest(Base):
    def test_mismo_mapa_misma_salida_y_otro_mapa_distinta(self):
        m = self.mapa()
        a = self.leer(self.anonimizar("a", m))
        b = self.leer(self.anonimizar("b", m))             # el mapa ya tiene contenido
        self.assertEqual(a, b)
        c = self.leer(self.anonimizar("c", self.mapa("otro.json", CLAVE2)))
        self.assertNotEqual(a["inventario.csv"], c["inventario.csv"])
        self.assertNotEqual(a["fw.cfg"], c["fw.cfg"])
        self.assertEqual(sorted(a), sorted(c))

    def test_mapa_nuevo_es_0600_y_reversible(self):
        m = self.d / "nuevo.json"
        self.anonimizar("a", m)
        self.assertEqual(stat.S_IMODE(os.stat(m).st_mode), 0o600)
        datos = json.loads(m.read_text())
        self.assertEqual(len(datos["clave"]), 64)
        self.assertIn("10.20.5.7", datos["ips"])
        self.assertIn("PLC-BOMBAS", datos["nombres"])
        self.assertIn("Acme", datos["terminos"])
        self.assertIn("00:1b:1b:10:00:11", datos["macs"])
        otra = self.leer(self.anonimizar("b", m))
        self.assertEqual(otra, self.leer(self.d / "a"))     # reutilizado: misma salida


class SinFugasTest(Base):
    def test_nada_del_original_en_la_salida(self):
        out = self.anonimizar("a", self.mapa())
        texto = "\n".join(v.decode("utf-8", "replace") for k, v in self.leer(out).items()
                          if not k.endswith(".xlsx"))
        # El xlsx se comprueba abriendolo, no como bytes comprimidos.
        from ot_assess.importers.lector import leer_xlsx_hojas
        texto += "\n" + "\n".join(str(f) for _, filas in leer_xlsx_hojas((out / "libro.xlsx").read_bytes())
                                  for f in filas)
        for dato in ["10.20.5.7", "10.20.5.9", "10.20.9.1", "10.1.1.1", "10.2.3.0", "10.0.0.0",
                     "203.0.113.5", "8.8.4.4", "PLC-BOMBAS", "HMI-SALA", "PC-OFICINA", "WEB-PUB",
                     "fw-planta-acme", "SN123456", "4455", "acme", "Acme", "Planta Norte", "Planta Sur",
                     "10:00:11", "10:00:12", "10:00:13", "aa:bb:cc", "Sup3rS3cret", "publica",
                     "30820123", "Bombas", "jefe@", "admin@"]:
            self.assertNotIn(dato.lower(), texto.lower(), dato)
        self.assertIn("Siemens", texto)                      # el fabricante se conserva
        self.assertIn("host-0001", texto)

    def test_oui_se_conserva_y_formato_de_mac(self):
        a = Anonimizador(Mapa(self.mapa()))
        self.assertTrue(a.texto("00:1b:1b:10:00:11").startswith("00:1b:1b:"))
        self.assertRegex(a.texto("00-1B-1B-10-00-12"), r"^00-1B-1B-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$")
        self.assertRegex(a.texto("001b.1b10.0013"), r"^001b\.1b[0-9a-f]{2}\.[0-9a-f]{4}$")
        self.assertNotEqual(a.texto("00:1b:1b:10:00:11"), "00:1b:1b:10:00:11")
        self.assertEqual(a.texto("ff:ff:ff:ff:ff:ff"), "ff:ff:ff:ff:ff:ff")
        self.assertEqual(a.texto("01:00:5e:00:00:fb"), "01:00:5e:00:00:fb")


class PrefijosTest(Base):
    def setUp(self):
        super().setUp()
        self.a = Anonimizador(Mapa(self.mapa()))

    def ip(self, s):
        return ipaddress.ip_address(self.a.texto(s))

    def test_mismas_subredes(self):
        h1, h2, h3 = self.ip("10.20.5.7"), self.ip("10.20.5.9"), self.ip("10.20.9.1")
        self.assertEqual(int(h1) >> 8, int(h2) >> 8)                 # misma /24
        self.assertEqual(int(h1) >> 16, int(h3) >> 16)               # misma /16
        self.assertNotEqual(int(h1) >> 8, int(h3) >> 8)
        self.assertEqual((int(h1) & 255, int(h2) & 255), (7, 9))     # ultimo octeto intacto
        self.assertNotEqual(str(h1), "10.20.5.7")

    def test_cidr_de_otra_tabla_contiene_los_hosts(self):
        out = self.anonimizar("a", self.mapa("m2.json"))
        lineas = (out / "sub" / "rutas.csv").read_text().splitlines()
        rutas = lineas[1]
        red = ipaddress.ip_network(rutas.split(",")[1])              # estricto: bits de host en cero
        self.assertEqual(red.prefixlen, 16)
        filas = (out / "inventario.csv").read_text().splitlines()
        for f in filas[1:3]:
            self.assertIn(ipaddress.ip_address(f.split(",")[1]), red)
        self.assertEqual(ipaddress.ip_network(rutas.split(",")[1]).prefixlen, 16)
        self.assertEqual(lineas[2], "PUB,0.0.0.0/0")

    def test_privadas_publicas_y_especiales(self):
        bloques = [("10.1.2.3", "10.0.0.0/8"), ("172.20.3.4", "172.16.0.0/12"),
                   ("192.168.7.8", "192.168.0.0/16"), ("100.70.1.1", "100.64.0.0/10"),
                   ("169.254.9.9", "169.254.0.0/16")]
        for ip, bloque in bloques:
            r = self.ip(ip)
            self.assertIn(r, ipaddress.ip_network(bloque), ip)
            self.assertNotEqual(str(r), ip)
        for ip in ["8.8.4.4", "1.1.1.1", "195.12.5.9", "192.0.5.5", "172.32.1.1"]:
            r = self.ip(ip)
            self.assertTrue(r.is_global, ip)
            self.assertEqual(str(r).split(".")[0], ip.split(".")[0])
        for ip in ["0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.251", "239.1.1.1", "240.0.0.1"]:
            self.assertEqual(self.a.texto(ip), ip)

    def test_mascaras_y_wildcards_intactas(self):
        lineas = ["route outside 0.0.0.0 0.0.0.0 10.1.1.1",
                  "network-object 10.2.3.0 255.255.255.0",
                  "access-list X permit ip 10.0.0.0 0.0.0.255 any",
                  "netmask 128.0.0.0 gateway 10.9.9.9", "ip 172.16.0.0 192.0.0.0"]
        self.assertTrue(self.a.texto(lineas[0]).startswith("route outside 0.0.0.0 0.0.0.0 10."))
        self.assertNotIn("10.1.1.1", self.a.texto(lineas[0]))
        self.assertIn(" 255.255.255.0", self.a.texto(lineas[1]))
        self.assertNotIn("10.2.3.0", self.a.texto(lineas[1]))
        self.assertTrue(self.a.texto(lineas[2]).endswith(" 0.0.0.255 any"))
        self.assertNotIn("10.0.0.0", self.a.texto(lineas[2]))
        self.assertIn("netmask 128.0.0.0 gateway", self.a.texto(lineas[3]))
        self.assertIn(" 192.0.0.0", self.a.texto(lineas[4]))

    def test_ipv6_se_cuenta_y_no_cambia(self):
        self.a.reiniciar()
        self.assertEqual(self.a.texto("ruta ::/0 via 2001:db8::1 mac 00:1b:1b:10:00:11"),
                         self.a.texto("ruta ::/0 via 2001:db8::1 mac 00:1b:1b:10:00:11"))
        self.assertEqual(self.a.c["ipv6"], 4)
        self.assertIn("2001:db8::1", self.a.texto("x 2001:db8::1"))


class ConfigTest(Base):
    def test_secretos_certificado_y_hostname(self):
        out = self.anonimizar("a", self.mapa())
        cfg = (out / "fw.cfg").read_text().splitlines()
        self.assertRegex(cfg[0], r"^hostname host-\d{4}$")
        self.assertEqual(cfg[1], "ip domain-name dominio-01.invalid")
        self.assertEqual(cfg[2:5], ["! [linea omitida: secreto]"] * 3)
        self.assertEqual(cfg[5], "crypto pki certificate chain TP")
        self.assertEqual(cfg[6], "! [bloque omitido: certificado]")
        self.assertEqual(cfg[7], "interface Gi0/1")                  # sin restos del bloque
        self.assertEqual(cfg[8], " description [texto omitido]")
        self.assertIn(" ip address ", cfg[9])
        self.assertTrue(cfg[9].endswith(" 255.255.255.0"))
        resumen = (out / "anonimizacion.csv").read_text().splitlines()
        self.assertEqual(resumen[0], "archivo,tipo,ips,macs,nombres,terminos,lineas_omitidas,ipv6_sin_cambio,"
                         "paquetes,sumas_sin_recalcular,carga_recortada,ip_binarias,mac_binarias,"
                         "ip_texto,ip_texto_enmascaradas,terminos_carga,carga_ot_modificada")
        fila = [f for f in resumen if f.startswith("fw.cfg")][0].split(",")
        self.assertEqual(fila[1], "texto")
        self.assertEqual(fila[6], "6")           # 3 secretos + 3 lineas del bloque
        self.assertEqual(fila[7], "2")           # ::/0 y 2001:db8::1

    def test_tablas_json_y_xlsx(self):
        out = self.anonimizar("a", self.mapa())
        filas = (out / "inventario.csv").read_text().splitlines()
        self.assertEqual(filas[0], "Device Name,IP,MAC,Vendor,Description,Serial Number,Site")
        self.assertEqual(len(filas), 5)
        self.assertTrue(filas[1].startswith("host-0001,"))
        self.assertIn("[texto omitido]", filas[1])
        self.assertIn("serie-0002", filas[1])        # datos.json se procesa antes y toma serie-0001
        self.assertIn("sitio-001", filas[1])
        j = json.loads((out / "datos.json").read_text())["devices"][0]
        self.assertEqual((j["name"], j["notes"], j["serial"]), ("host-0001", "[texto omitido]", "serie-0001"))
        self.assertEqual(j["email"], "correo-001@ejemplo.invalid")
        from ot_assess.importers.lector import leer_xlsx_hojas
        hojas = leer_xlsx_hojas((out / "libro.xlsx").read_bytes())
        self.assertEqual([h[0] for h in hojas], ["termino-02", "Rutas"])
        self.assertEqual(hojas[0][1][0], ["Titulo de reporte", "", ""])
        self.assertEqual(hojas[0][1][1], ["Name", "IP", "Comments"])
        self.assertEqual(hojas[0][1][2][0], "host-0001")
        self.assertEqual(hojas[0][1][2][2], "[texto omitido]")
        self.assertEqual(len(hojas[1][1]), 2)

    def test_pcap_y_binarios_se_saltan(self):
        (self.ent / "captura.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        (self.ent / "raro.bin").write_bytes(b"\x00\x01\x02" * 10)
        out = self.anonimizar("a", self.mapa())
        self.assertFalse((out / "captura.pcap").exists())
        self.assertFalse((out / "raro.bin").exists())
        res = (out / "anonimizacion.csv").read_text()
        self.assertIn("captura.pcap,omitido", res)


class ImportadorTest(Base):
    def test_mismos_conteos_y_fabricantes(self):
        exp = self.d / "exp"
        r = gen_exports.xdome(exp)
        antes = importar([r["inventario"]], r["comunicaciones"])
        self.assertEqual(correr(exp, "-o", self.d / "anon", "--mapa", self.mapa()), 0)
        despues = importar([self.d / "anon" / "xdome_all_devices.xlsx"],
                           [self.d / "anon" / "xdome_comunicaciones_1.csv",
                            self.d / "anon" / "xdome_comunicaciones_2.csv"])
        self.assertEqual(antes.resumen, despues.resumen)
        self.assertEqual(sorted(a["vendor"] for a in antes.assets.values()),
                         sorted(a["vendor"] for a in despues.assets.values()))
        self.assertEqual(sorted(a["tipo"] for a in antes.assets.values()),
                         sorted(a["tipo"] for a in despues.assets.values()))
        self.assertEqual(len(antes.conduits), len(despues.conduits))
        ips = {ip for a in despues.assets.values() for ip in a["ips"]}
        self.assertFalse(ips & {"10.10.1.10", "10.10.2.20", "10.10.3.30"})

    def test_los_cuatro_estilos_resuelven_igual_tras_anonimizar(self):
        # El estilo b une enlaces por nombre y MAC con guiones; el c anida "type": {"name": ...}.
        exp = self.d / "exp"
        e = gen_exports.escribir(exp)
        self.assertEqual(correr(exp, "-o", self.d / "anon", "--mapa", self.mapa()), 0)

        def rel(p):
            return self.d / "anon" / Path(p).relative_to(exp)
        for estilo, x in e.items():
            antes = importar([x["activos"]], [x["enlaces"]])
            despues = importar([rel(x["activos"])], [rel(x["enlaces"])])
            self.assertEqual(antes.resumen, despues.resumen, estilo)
            self.assertEqual(sorted(a["tipo"] for a in antes.assets.values()),
                             sorted(a["tipo"] for a in despues.assets.values()), estilo)
            self.assertEqual(sorted(a["vendor"] for a in antes.assets.values()),
                             sorted(a["vendor"] for a in despues.assets.values()), estilo)


class RechazosTest(Base):
    def test_mapa_dentro_del_repo(self):
        destino = RAIZ / "mapa_prueba_e5.json"
        try:
            self.assertEqual(correr(self.ent, "-o", self.d / "a", "--mapa", destino), 2)
            self.assertFalse(destino.exists())
        finally:
            if destino.exists():
                destino.unlink()

    def test_mapa_dentro_de_la_salida(self):
        self.assertEqual(correr(self.ent, "-o", self.d / "a", "--mapa", self.d / "a" / "m.json"), 2)

    def test_carpeta_igual_o_dentro_de_la_entrada(self):
        m = self.mapa()
        self.assertEqual(correr(self.ent, "-o", self.ent, "--mapa", m), 2)
        self.assertEqual(correr(self.ent, "-o", self.ent / "sub" / "x", "--mapa", m), 2)
        self.assertEqual(correr(self.ent / "inventario.csv", "-o", self.ent, "--mapa", m), 2)
        self.assertEqual(sorted(p.name for p in self.ent.iterdir()),
                         ["datos.json", "fw.cfg", "inventario.csv", "libro.xlsx", "sub"])

    def test_el_mapa_y_los_terminos_dentro_de_la_entrada_no_se_copian(self):
        m = self.ent / "mapa.json"
        m.write_text(json.dumps({"clave": CLAVE}))
        t = self.ent / "terminos.txt"
        t.write_text(TERMINOS)
        self.assertEqual(correr(self.ent, "-o", self.d / "a", "--mapa", m, "--terminos", t), 0)
        self.assertFalse((self.d / "a" / "mapa.json").exists())
        self.assertFalse((self.d / "a" / "terminos.txt").exists())


if __name__ == "__main__":
    unittest.main()


class NombreConIpTest(unittest.TestCase):
    """xDome pone la IP como nombre cuando no lo conoce; la celda IP no debe perder la direccion."""

    def test_nombre_con_ip_no_borra_la_ip(self):
        from ot_assess.anonimizar import Anonimizador, Mapa
        with tempfile.TemporaryDirectory() as d:
            an = Anonimizador(Mapa(Path(d) / "m.json"))
            filas = [["DEVICE NAME", "IP"], ["10.20.30.40 (Last Known IP)", "10.20.30.40 (Last Known IP)"],
                     ["plc-01", "10.20.30.41"]]
            out = an.tabla(filas)
            self.assertRegex(out[1][1], r"^10\.\d+\.\d+\.40 \(Last Known IP\)$")
            self.assertEqual(out[1][0], out[1][1])
            self.assertTrue(out[2][0].startswith("host-"))
