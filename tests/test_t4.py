"""T4: OPC UA sin seguridad, TLS obsoleto o debil, Modbus FC8 que reinicia o silencia, DNP3 reinicio o paro.

Cada deteccion tiene su escenario sintetico (tests/gen_pcaps.py) y la prueba de que NO salta en el caso sano.
Requiere tshark y scapy; si faltan, se omite.
"""
from __future__ import annotations

import csv
import shutil
import sys
import tempfile
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

T_OPCUA = "OPC UA sin seguridad de mensajes (politica None)"
T_TLS = "TLS obsoleto o con suite debil negociado por el servidor"
T_MB_GRAVE = "Modbus FC8 que reinicia o silencia el equipo"
T_MB_DIAG = "Modbus FC8 de diagnostico (sin reinicio ni silencio)"
T_DNP3 = "DNP3 con reinicio o paro de aplicacion (Cold Restart, Warm Restart, Stop Application)"
TITULOS = (T_OPCUA, T_TLS, T_MB_GRAVE, T_MB_DIAG, T_DNP3)


def _csv(path: Path) -> list:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class DeteccionesT4Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g

        from ot_assess import i18n
        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        g.guardar(g.punto_opcua(True), pcaps / "opcua_escritura.pcap")
        g.guardar(g.punto_opcua(False), pcaps / "opcua_lectura.pcap")
        g.guardar(g.punto_opcua_seguro(), pcaps / "opcua_seguro.pcap")
        g.guardar(g.punto_tls(), pcaps / "tls.pcap")
        g.guardar(g.punto_modbus_diag(1), pcaps / "mb_sf1.pcap")
        g.guardar(g.punto_modbus_diag(4), pcaps / "mb_sf4.pcap")
        g.guardar(g.punto_modbus_diag(0), pcaps / "mb_sf0.pcap")
        g.guardar(g.punto_modbus_diag(1, solo_respuestas=True), pcaps / "mb_respuestas.pcap")
        g.guardar(g.punto_dnp3_reinicio(), pcaps / "dnp3_fc13.pcap")
        g.guardar(g.punto_dnp3_reinicio(solo_respuestas=True), pcaps / "dnp3_respuestas.pcap")
        i18n.FALTANTES.clear()
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "es")])
        cls.filas = _csv(cls.tmp / "es" / "hallazgos.csv")
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
        cls.faltantes_en = set(i18n.FALTANTES)
        i18n.usar("es")
        cls.plan = _csv(cls.tmp / "es" / "plan_remediacion.csv")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def hallazgos(self, captura: str, titulo: str) -> list:
        return [r for r in self.filas if r["captura"] == captura + ".pcap" and r["titulo"] == titulo]

    def unico(self, captura: str, titulo: str) -> dict:
        hs = self.hallazgos(captura, titulo)
        self.assertEqual(len(hs), 1, f"{captura}: {titulo}")
        return hs[0]

    def sin(self, captura: str, *titulos: str) -> None:
        for t in titulos:
            self.assertEqual(self.hallazgos(captura, t), [], f"{captura}: {t}")

    def test_termina_bien(self):
        self.assertEqual(self.rc, 0)

    # --- 1. OPC UA --------------------------------------------------------- #
    def test_opcua_none_con_escritura_es_alta(self):
        h = self.unico("opcua_escritura", T_OPCUA)
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("10.20.1.10 -> 10.20.1.20:4840", h["evidencia"])
        self.assertIn("SecurityPolicy#None", h["evidencia"])
        self.assertIn("modo None", h["evidencia"])
        self.assertIn("(1 aperturas de canal)", h["evidencia"])   # la respuesta no duplica
        self.assertIn("10.20.1.20:4840 tambien recibe Write o Call", h["evidencia"])
        self.assertNotIn("10.20.1.21", h["evidencia"])             # el canal Basic256Sha256 no entra

    def test_opcua_none_sin_escritura_es_media(self):
        self.assertEqual(self.unico("opcua_lectura", T_OPCUA)["severidad"], "Media")

    def test_opcua_basic256sha256_no_da_hallazgo(self):
        self.sin("opcua_seguro", T_OPCUA)

    # --- 2. TLS ------------------------------------------------------------ #
    def test_tls_solo_marca_lo_que_el_servidor_negocia(self):
        h = self.unico("tls", T_TLS)
        ev = h["evidencia"]
        self.assertIn("10.30.1.20:8443, version TLS 1.0, suite 0x002F, SNI vieja.example", ev)
        self.assertIn("10.30.1.22:8443, version TLS 1.2+, suite TLS_RSA_WITH_RC4_128_SHA, SNI rc4.example", ev)
        self.assertNotIn("10.30.1.21", ev)     # TLS 1.2 con suite fuerte, aunque el cliente ofrezca 1.0 y RC4
        self.assertNotIn("10.30.1.23", ev)     # TLS 1.3 (la version heredada del ServerHello es 1.2)
        self.assertNotIn("10.30.1.10:", ev)    # el ClientHello no se marca
        self.assertEqual(h["severidad"], "Alta")   # 10.30.1.22 atiende Modbus: equipo OT

    # --- 3. Modbus FC8 ----------------------------------------------------- #
    def test_modbus_fc8_subfuncion_1_y_4_son_altas(self):
        h = self.unico("mb_sf1", T_MB_GRAVE)
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("10.40.1.10 -> 10.40.1.20, unidad 7, subfuncion 1 Restart Communications Option "
                      "(2 solicitudes)", h["evidencia"])
        self.assertIn("subfuncion 4 Force Listen Only Mode (2 solicitudes)", self.unico("mb_sf4", T_MB_GRAVE)["evidencia"])
        self.sin("mb_sf1", T_MB_DIAG)

    def test_modbus_fc8_otra_subfuncion_es_baja(self):
        h = self.unico("mb_sf0", T_MB_DIAG)
        self.assertEqual(h["severidad"], "Baja")
        self.assertIn("subfuncion 0 (2 solicitudes)", h["evidencia"])
        self.sin("mb_sf0", T_MB_GRAVE)

    def test_modbus_fc8_solo_respuestas_no_cuenta(self):
        self.sin("mb_respuestas", T_MB_GRAVE, T_MB_DIAG)

    # --- 4. DNP3 ----------------------------------------------------------- #
    def test_dnp3_cold_restart_es_alta_y_la_respuesta_no_duplica(self):
        h = self.unico("dnp3_fc13", T_DNP3)
        self.assertEqual(h["severidad"], "Alta")
        self.assertIn("10.50.1.10 -> 10.50.1.20", h["evidencia"])
        self.assertIn("codigo 13 Cold Restart (2 solicitudes)", h["evidencia"])

    def test_dnp3_solo_respuestas_no_cuenta(self):
        self.sin("dnp3_respuestas", T_DNP3)

    # --- 5. reportes, plan, marcos e idioma -------------------------------- #
    def test_referencias_en_los_cinco_marcos(self):
        from ot_assess import standards as st
        for titulo in TITULOS:
            refs = st.referencias(titulo)
            self.assertEqual(set(refs), {"mitre-ics", "iec62443", "nist-800-82", "nerc-cip", "nist-csf"}, titulo)
        self.assertIn("T0816", st.referencias(T_DNP3)["mitre-ics"])
        self.assertIn("SC-13", st.referencias(T_TLS)["nist-800-82"])

    def test_aparecen_en_reporte_y_plan(self):
        md = (self.tmp / "es" / "reporte_ot.md").read_text(encoding="utf-8")
        for titulo in TITULOS:
            self.assertIn(titulo, md)
        titulos_plan = {r["titulo"] for r in self.plan}
        for titulo in (T_OPCUA, T_TLS, T_MB_GRAVE, T_DNP3):
            self.assertIn(titulo, titulos_plan)
        fila = next(r for r in self.plan if r["titulo"] == T_DNP3)
        self.assertIn("10.50.1.20", fila["activos"])

    def test_ingles_sin_claves_faltantes(self):
        self.assertEqual(self.faltantes_en, set(), sorted(self.faltantes_en))
        html = (self.tmp / "en" / "reporte_ot.html").read_text(encoding="utf-8")
        self.assertIn("OPC UA without message security (policy None)", html)
        self.assertNotIn(T_OPCUA, html)

    # --- 6. campo que tshark no conoce ------------------------------------- #
    def test_campo_inexistente_se_omite_y_el_resto_sigue(self):
        from ot_assess.fields import DETAIL_FIELDS
        from ot_assess.tools import Tshark
        pcap = self.tmp / "pcaps" / "mb_sf1.pcap"
        ts = Tshark("tshark", "capinfos", "editcap", self.tmp / ".probe")
        ts.make_probe(pcap)
        validos = ts.valid_fields(DETAIL_FIELDS + ["opcua.campo_que_no_existe"])
        self.assertNotIn("opcua.campo_que_no_existe", validos)
        for f in ("modbus.diagnostic_code", "tls.handshake.ciphersuite", "opcua.security.spu", "dnp3.al.func"):
            self.assertIn(f, validos)

    def test_colectores_sin_los_campos_no_fallan(self):
        """Si tshark no trae un campo, RowCtx.get devuelve vacio: ningun colector T4 genera eventos ni falla."""
        from ot_assess.detail.base import RowCtx
        from ot_assess.model import Capture
        cap = Capture(Path("x.pcap"))
        from ot_assess.detail import protocolos
        fila = ["1", "1.0", "10.0.0.1", "10.0.0.2", "502"]
        rc = RowCtx(cap, fila, {"frame.number": 0, "frame.time_epoch": 1, "ip.src": 2, "ip.dst": 3, "tcp.dstport": 4})
        for colector in (protocolos.opcua_seguridad, protocolos.tls_debil, protocolos.modbus_diagnostico,
                         protocolos.dnp3_reinicio):
            colector(rc)
        self.assertEqual(cap.protocolo_eventos, [])


if __name__ == "__main__":
    unittest.main()
