"""SEC1 (D138): redaccion de secretos en las salidas y escaneo de secretos de una carpeta. Sintetico."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import cli_entrega, cli_secretos, secretos
from ot_assess import entrega as ent
from ot_assess.detail.base import RowCtx
from ot_assess.detail.cleartext import texto_claro
from ot_assess.model import Capture

# Una linea por patron del punto 2 de la tarea: (tipo esperado, texto, valor que no debe salir completo).
MUESTRAS = [
    ("comunidad SNMP", "snmp-server community Comm0Sec1xyz RO", "Comm0Sec1xyz"),
    ("comunidad SNMP", "community = Comm1Sec1xyz", "Comm1Sec1xyz"),
    ("Authorization", "Authorization: Basic QWRtaW46U2VjMVBhc3M5", "QWRtaW46U2VjMVBhc3M5"),
    ("Authorization", "Authorization: Bearer abcDEF123tokenSec1", "abcDEF123tokenSec1"),
    ("contrasena", "password = Sec1Clave55", "Sec1Clave55"),
    ("contrasena", "passwd: Sec1Clave56", "Sec1Clave56"),
    ("contrasena", "pwd=Sec1Clave57", "Sec1Clave57"),
    ("contrasena", "secret: Sec1Clave58", "Sec1Clave58"),
    ("Cisco tipo 7", "username a password 7 0822455D0A16", "0822455D0A16"),
    ("Cisco tipo 7", "radius server r1 key 7 094F471A1A0A", "094F471A1A0A"),
    ("Cisco secret 5/8/9", "enable secret 9 Sec1HashNueve", "Sec1HashNueve"),
    ("hash crypt", "root:$6$salt1234$Sec1HashSeis:0:0", "$6$salt1234$Sec1HashSeis"),
    ("hash crypt", "x $y$j9T$Sec1HashYescrypt", "$y$j9T$Sec1HashYescrypt"),
    ("PSK", "pre-shared-key = Sec1PskUno", "Sec1PskUno"),
    ("PSK", "psk: Sec1PskDos", "Sec1PskDos"),
    ("llave TACACS/RADIUS", "tacacs-server key Sec1Tac0", "Sec1Tac0"),
    ("llave TACACS/RADIUS", "radius-server key Sec1Rad0", "Sec1Rad0"),
    ("llave TACACS/RADIUS", "tacacs server t1\n address ipv4 10.1.1.1\n key Sec1TacBloque", "Sec1TacBloque"),
    ("token JWT", "t=eyJhbGciOi.eyJzdWIiOiIxMjM.firmaSec1", "eyJhbGciOi.eyJzdWIiOiIxMjM.firmaSec1"),
    ("Cookie", "Cookie: sesion=Sec1Cookie9", "sesion=Sec1Cookie9"),
    ("Cookie", "Set-Cookie: sid=Sec1SetCookie; Path=/", "sid=Sec1SetCookie; Path=/"),
    ("llave privada", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"),
    ("llave de acceso AKIA", "id AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
]

_DOCX = '<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>{x}</w:t></w:r></w:p></w:body></w:document>'
_XLSX_SS = '<sst><si><t>{x}</t></si></sst>'


def _escribir_formatos(carpeta: Path, texto: str) -> None:
    """El mismo texto en cada formato que revisa el escaneo."""
    esc = texto.replace("&", "&amp;").replace("<", "&lt;")
    for ext in ("csv", "json", "md", "txt", "svg", "drawio", "html"):
        cuerpo = {"json": json.dumps({"x": texto}, indent=1), "html": f"<p>{esc}</p>\n"}.get(ext, texto + "\n")
        (carpeta / f"a.{ext}").write_text(cuerpo, encoding="utf-8")
    with zipfile.ZipFile(carpeta / "a.xlsx", "w") as z:
        z.writestr("xl/sharedStrings.xml", _XLSX_SS.format(x=esc))
    with zipfile.ZipFile(carpeta / "a.docx", "w") as z:
        z.writestr("word/document.xml", _DOCX.format(x=esc))


def _correr(main, argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class RedaccionColectorTest(unittest.TestCase):
    """El colector no guarda el valor: guarda el hecho."""

    CAMPOS = ("frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport",
              "snmp.community", "snmp.msgVersion", "http.authorization", "ftp.request.command",
              "ftp.request.arg", "telnet.data", "tftp.source_file")

    def _correr(self, **vals):
        idx = {c: i for i, c in enumerate(self.CAMPOS)}
        base = {"frame.number": "7", "frame.time_epoch": "1700000000.5", "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2"}
        base.update(vals)
        row = [base.get(c, "") for c in self.CAMPOS]
        cap = Capture(Path("x.pcap"))
        texto_claro(RowCtx(cap, row, idx))
        return cap.cleartext

    def test_snmp_http_ftp_telnet_sin_valor(self):
        casos = [
            ({"snmp.community": "ComunidadSec1", "snmp.msgVersion": "1", "udp.dstport": "161"}, "ComunidadSec1"),
            ({"http.authorization": "Basic QWRtaW46U2VjMQ==", "tcp.dstport": "80"}, "QWRtaW46U2VjMQ=="),
            ({"ftp.request.command": "PASS", "ftp.request.arg": "ClaveFtpSec1", "tcp.dstport": "21"}, "ClaveFtpSec1"),
            ({"ftp.request.command": "USER", "ftp.request.arg": "usuarioFtpSec1", "tcp.dstport": "21"},
             "usuarioFtpSec1"),
            ({"telnet.data": "ClaveTelnetSec1\r\n", "tcp.dstport": "23"}, "ClaveTelnetSec1"),
        ]
        for vals, literal in casos:
            with self.subTest(literal=literal):
                (e,) = self._correr(**vals)
                self.assertNotIn(literal, json.dumps(e))
                self.assertEqual((e["ip"], e["dst"], e["frame"]), ("10.0.0.1", "10.0.0.2", "7"))
                self.assertEqual(e["fecha_utc"], "2023-11-14 22:13:20 UTC")
                self.assertTrue(e["puerto"])

    def test_datos_no_secretos_se_conservan(self):
        (e,) = self._correr(**{"snmp.community": "abc", "snmp.msgVersion": "1"})
        self.assertIn("version=1", e["detalle"])
        (e,) = self._correr(**{"http.authorization": "Bearer zzzzzz"})
        self.assertIn("esquema=Bearer", e["detalle"])
        (e,) = self._correr(**{"ftp.request.command": "pass", "ftp.request.arg": "abcd"})
        self.assertIn("comando=PASS", e["detalle"])
        self.assertEqual(e["detalle"], "comando=PASS")      # sin el largo: revelaria el de la contrasena
        (e,) = self._correr(**{"tftp.source_file": "config.bin"})
        self.assertEqual(e["detalle"], "config.bin")


class PatronesTest(unittest.TestCase):
    def test_cada_patron_en_cada_formato_y_valor_enmascarado(self):
        for tipo, texto, literal in MUESTRAS:
            with self.subTest(texto=texto):
                tmp = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
                _escribir_formatos(tmp, texto)
                rc, salida, _ = _correr(cli_secretos.main, [str(tmp)])
                self.assertEqual(rc, 3)
                self.assertNotIn(literal, salida)
                for ext in ("csv", "json", "md", "txt", "svg", "drawio", "html", "xlsx", "docx"):
                    cs = [c for c in secretos.escanear(tmp) if c["archivo"] == f"a.{ext}" and c["tipo"] == tipo]
                    self.assertTrue(cs, f"{tipo} no detectado en {ext}")
                    for c in cs:
                        self.assertTrue(c["valor"].endswith("***"))
                        self.assertLessEqual(len(c["valor"]), 5)

    def test_codigos_0_3_2(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "a.md").write_text("Cambiar la password y la community por defecto.\n", encoding="utf-8")
        self.assertEqual(_correr(cli_secretos.main, [str(tmp)])[0], 0)
        (tmp / "b.txt").write_text("password = Sec1Clave55\n", encoding="utf-8")
        rc, salida, _ = _correr(cli_secretos.main, [str(tmp)])
        self.assertEqual(rc, 3)
        self.assertIn("b.txt | linea 1 | contrasena | Se***", salida)
        self.assertEqual(_correr(cli_secretos.main, [str(tmp / "no_existe")])[0], 2)

    def test_marcas_de_posicion_no_cuentan(self):
        txt = "password: ***\npassword = <redactado>\nsecret = {valor}\ncommunity: None\npassword: xxxx\n"
        self.assertEqual(secretos.escanear_texto(txt), [])

    def test_texto_de_playbooks_sin_valor_no_cuenta(self):
        txt = ("Cambiar la community por defecto (public/private) y las password de fabrica.\n"
               "Usar SNMPv3 en lugar de community strings; rotar el secret de TACACS.\n")
        self.assertEqual(secretos.escanear_texto(txt), [])


@unittest.skipUnless(HAY_SCAPY, "requiere scapy")
class PaqueteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.sal = self.tmp / "salida"
        self.sal.mkdir()
        (self.sal / "resultado.json").write_text('{"version": "x"}\n', encoding="utf-8")

    def test_empaquetar_se_niega_con_secretos_y_se_puede_omitir(self):
        (self.sal / "config.txt").write_text("snmp-server community Sec1CommPaquete RO\n", encoding="utf-8")
        destino = self.tmp / "entrega"
        rc, salida, err = _correr(cli_entrega.main, [str(self.sal), "-o", str(destino)])
        self.assertEqual(rc, 3)
        self.assertFalse(destino.exists())
        self.assertNotIn("Sec1CommPaquete", salida + err)
        self.assertIn("config.txt", salida)
        rc, _, _ = _correr(cli_entrega.main, [str(self.sal), "-o", str(destino), "--sin-escaneo-secretos"])
        self.assertEqual(rc, 0)
        man = json.loads((destino / "manifiesto.json").read_text(encoding="utf-8"))
        self.assertIn("omitido", man["escaneo_secretos"])

    def test_empaquetar_limpio_no_deja_linea(self):
        destino = self.tmp / "entrega"
        rc, _, _ = _correr(cli_entrega.main, [str(self.sal), "-o", str(destino)])
        self.assertEqual(rc, 0)
        man = json.loads((destino / "manifiesto.json").read_text(encoding="utf-8"))
        self.assertNotIn("escaneo_secretos", man)
        self.assertEqual(ent.verificar(destino)["modificados"], [])


@unittest.skipUnless(HAY_SCAPY and shutil.which("tshark"), "requiere tshark y scapy")
class CorridaCompletaTest(unittest.TestCase):
    """Captura con secretos + firewall + switch: ningun literal sale y el escaneo da cero coincidencias."""

    LITERALES = ("ComSec1Zq81", "Sec1UsuarioFtp", "Sec1ClaveFtp77", "Sec1ClaveTelnet88", "U2VjMUJhc2ljOXg",
                 "Sec1ClaveBasic9x", "SW1CommSec1", "SW1KeySec1", "SECRETOX", "SECRETOY")

    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        import test_firewalls_integracion as tfi
        import test_fwlog
        from scapy.all import IP, UDP, Ether
        from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        t = gen_pcaps.tcp
        pk = [
            t("eng", "gw", "10.10.1.30", "10.10.1.1", 43100, 21, b"USER Sec1UsuarioFtp\r\n"),
            t("eng", "gw", "10.10.1.30", "10.10.1.1", 43100, 21, b"PASS Sec1ClaveFtp77\r\n"),
            t("eng", "gw", "10.10.1.30", "10.10.1.1", 43101, 23, b"Sec1ClaveTelnet88\r\n"),
            t("eng", "gw", "10.10.1.30", "10.10.1.1", 43102, 80,
              b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic U2VjMUJhc2ljOXg6Sec1ClaveBasic9x\r\n\r\n"),
            Ether(src=gen_pcaps.MAC["eng"], dst=gen_pcaps.MAC["gw"]) / IP(src="10.10.1.30", dst="10.10.1.1")
            / UDP(sport=50100, dport=161)
            / SNMP(community="ComSec1Zq81", PDU=SNMPget(varbindlist=[
                SNMPvarbind(oid=gen_pcaps.ASN1_OID("1.3.6.1.2.1.1.1.0"))])),
        ]
        gen_pcaps.guardar(pk, pcaps / "secretos.pcap")
        sys.argv = ["gen", str(pcaps)]
        gen_pcaps.main()
        fw = cls.tmp / "fw.txt"
        fw.write_text(tfi._sesion(tfi.RUTAS, "access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc "
                                  "outside any eq 80 rule-id 1\n"), encoding="utf-8")
        sw = cls.tmp / "sw.txt"
        sw.write_text(test_fwlog.IOS.replace("SECRETOPRUEBA1", "SW1KeySec1").replace(
            "end\n", "snmp-server community SW1CommSec1 RO\nend\n"), encoding="utf-8")
        cls.out = cls.tmp / "out"
        cls.rc, cls.salida, cls.err = _correr(main, [str(pcaps), "-o", str(cls.out), "--firewall", str(fw),
                                                      "--switch", str(sw)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _json(self):
        return json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))

    def _archivos(self):
        for p in sorted(self.out.rglob("*")):
            if p.is_file():
                yield p

    def test_termina_bien(self):
        self.assertEqual(self.rc, 0, self.err[-500:])

    def test_ningun_literal_en_ningun_archivo(self):
        n = 0
        for p in self._archivos():
            bruto = p.read_bytes()
            contenido = [bruto]
            if zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as z:
                    contenido += [z.read(m) for m in z.namelist()]
            for lit in self.LITERALES:
                for b in contenido:
                    self.assertNotIn(lit.encode(), b, f"{lit} en {p.name}")
            n += 1
        self.assertGreater(n, 5)
        self.assertNotIn("ComSec1Zq81", self.salida + self.err)

    def test_resultado_json_lleva_el_hecho(self):
        res = [e for c in self._json()["capturas"] for e in c["texto_claro"]]
        tipos = {e["tipo"] for e in res}
        for tipo in ("SNMP community", "HTTP Authorization", "FTP USER", "FTP PASS", "Telnet"):
            self.assertIn(tipo, tipos)
        for e in res:
            for k in ("ip", "dst", "puerto", "frame", "fecha_utc"):
                self.assertTrue(e.get(k), (k, e))
        snmp = next(e for e in res if e["tipo"] == "SNMP community")
        self.assertEqual(snmp["puerto"], "161")
        self.assertEqual(snmp["dst"], "10.10.1.1")

    def test_hallazgo_de_texto_claro_igual(self):
        hs = [h for c in self._json()["capturas"] for h in c["hallazgos"]
              if h["titulo"] == "Credenciales o administracion en texto claro"]
        self.assertTrue(hs)
        for h in hs:
            self.assertEqual(h["severidad"], "Alta")
            self.assertTrue(h["activos"])
        self.assertIn("SNMP community: 1", " ".join(h["evidencia"] for h in hs))

    def test_cero_coincidencias_en_la_salida_completa(self):
        self.assertEqual(secretos.escanear(self.out), [])
        self.assertEqual(_correr(cli_secretos.main, [str(self.out)])[0], 0)


if __name__ == "__main__":
    unittest.main()
