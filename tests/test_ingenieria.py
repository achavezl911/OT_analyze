"""D1 (D92): clase de ingenieria de las operaciones de control (descarga, carga, modo, reinicio, firmware, forzado,
configuracion, escritura), GE SRTP, UMAS y FINS, sesiones y hallazgo. Todo sintetico: IP 192.0.2.0/24.
Unitarias sin tshark; extremo a extremo con tshark y scapy (pcaps de gen_pcaps.py)."""
from __future__ import annotations

import contextlib
import csv
import io
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

from ot_assess import i18n
from ot_assess import ingenieria as ing
from ot_assess.cli import main
from ot_assess.detail import control as ctl
from ot_assess.fields import DETAIL_FIELDS, DETAIL_FILTER_PARTS
from ot_assess.model import Capture
from ot_assess.rules import control as regla

T0 = 1_700_000_000.0
ID_HALLAZGO = "H-9c3c60"       # el ID sale del titulo y no debe cambiar
TITULO = "Actividad de ingenieria sobre controladores (descarga, arranque o paro)"


def _leer(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def op(t, clase, nombre="Download Block", src="192.0.2.201", dst="192.0.2.202", proto="S7comm", frame=None):
    return {"frame": str(frame if frame is not None else int(t - T0) + 1), "t": t, "proto": proto, "src": src,
            "dst": dst, "op": nombre, "detalle": "", "clase": clase}


def setUpModule():
    i18n.usar("es")


def cap_con(*ops):
    c = Capture(Path("x.pcap"))
    c.control_ops = list(ops)
    return c


class SesionesTest(unittest.TestCase):
    def test_tres_operaciones_en_60_s_son_una_sesion(self):
        c = cap_con(op(T0, "descarga"), op(T0 + 30, "descarga"), op(T0 + 60, "descarga", "Request Download"))
        filas = ing.filas([c])
        self.assertEqual(len(filas), 1)
        f = dict(zip(ing.COLUMNAS, filas[0]))
        self.assertEqual((f["tramas"], f["primera_trama"], f["clase"]), (3, "1", "descarga"))
        self.assertEqual(f["operaciones"], "Download Block (2); Request Download (1)")
        self.assertEqual((f["inicio"], f["fin"]), ("2023-11-14T22:13:20Z", "2023-11-14T22:14:20Z"))
        self.assertEqual(f["tecnica_mitre"], "T0843 Program Download")

    def test_un_hueco_de_400_s_parte_la_sesion(self):
        c = cap_con(op(T0, "modo"), op(T0 + 10, "modo"), op(T0 + 410, "modo"))
        self.assertEqual([f[8] for f in ing.filas([c])], [2, 1])

    def test_300_s_exactos_no_parten(self):
        self.assertEqual(len(ing.filas([cap_con(op(T0, "modo"), op(T0 + 300, "modo"))])), 1)

    def test_escritura_y_sin_clase_no_son_sesiones(self):
        c = cap_con(op(T0, "escritura"), op(T0 + 1, ""), op(T0 + 2, "modo"))
        self.assertEqual([f[6] for f in ing.filas([c])], ["modo"])

    def test_sin_eventos_no_hay_filas(self):
        self.assertEqual(ing.filas([cap_con(op(T0, "escritura"))]), [])

    def test_tecnicas_y_orden_por_inicio(self):
        c = cap_con(op(T0 + 5, "firmware", proto="CIP"), op(T0, "configuracion", proto="CIP"),
                    op(T0 + 2, "forzado", proto="X"))
        self.assertEqual([(f[6], f[10]) for f in ing.filas([c])],
                         [("configuracion", ""), ("forzado", "T0836 Modify Parameter"),
                          ("firmware", "T0857 System Firmware")])


class HallazgoTest(unittest.TestCase):
    def _hallazgo(self, *ops):
        c = cap_con(*ops)
        regla.actividad_ingenieria(c)
        return c.findings

    def test_solo_carga_es_media(self):
        h = self._hallazgo(op(T0, "carga", "Upload"))
        self.assertEqual([(x["titulo"], x["severidad"], x["id"]) for x in h], [(TITULO, "Media", ID_HALLAZGO)])

    def test_con_un_paro_es_alta_y_conserva_el_id(self):
        h = self._hallazgo(op(T0, "carga", "Upload"), op(T0 + 5, "modo", "PLC Stop"))
        self.assertEqual([(x["severidad"], x["id"]) for x in h], [("Alta", ID_HALLAZGO)])
        self.assertIn("carga (1), modo (1)", h[0]["evidencia"])
        self.assertIn("192.0.2.201 -> 192.0.2.202: S7comm, modo (PLC Stop (1))", h[0]["evidencia"])
        self.assertEqual(h[0]["activos"], ["192.0.2.202"])

    def test_sin_ingenieria_no_hay_hallazgo(self):
        self.assertEqual(self._hallazgo(op(T0, "escritura", "Write Var"), op(T0, "", "Delete")), [])

    def test_una_descarga_ya_no_depende_de_la_palabra(self):
        # antes: "Write Tag" de un firmware no contaba; "Start" de cualquier cosa si. Ahora manda la clase.
        self.assertEqual(self._hallazgo(op(T0, "", "Start")), [])
        self.assertEqual(len(self._hallazgo(op(T0, "firmware", "Transferencia a memoria no volatil (clase 0xA1)"))), 1)

    def test_mas_de_diez_sesiones(self):
        h = self._hallazgo(*[op(T0 + 1000 * i, "modo", "PLC Stop") for i in range(12)])
        self.assertIn(" y 2 sesiones mas", h[0]["evidencia"])


class TablasTest(unittest.TestCase):
    def test_filtro_srtp_usa_igualdades_y_la_tabla(self):
        f = ctl.filtro_srtp()
        self.assertNotIn(" in {", f)
        for c in ctl.SRTP_CODIGOS:
            self.assertIn(f"tcp.payload[42] == 0x{c:02x}", f)
            self.assertIn(f"tcp.payload[50] == 0x{c:02x}", f)
        for lectura in (0x00, 0x04, 0x25, 0x38, 0x43):
            self.assertNotIn(lectura, ctl.SRTP_CODIGOS)

    def test_piezas_y_campos_nuevos(self):
        self.assertIn(ctl.filtro_srtp(), DETAIL_FILTER_PARTS)
        self.assertIn(ctl.filtro_umas(), DETAIL_FILTER_PARTS)
        self.assertIn(ctl.filtro_fins(), DETAIL_FILTER_PARTS)
        self.assertIn("cip.class == 0xa1", DETAIL_FILTER_PARTS)
        for campo in ("data.data", "modbus.data", "omron.command", "omron.icf", "cip.class",
                      "s7comm.param.pistart.servicename", "s7comm.data.blockcontrol.block_type",
                      "s7comm.data.blockcontrol.block_number"):
            self.assertIn(campo, DETAIL_FIELDS)

    def test_clases_s7_cip_dnp3_iec104_modbus(self):
        self.assertEqual({ctl.S7_CLASES[c] for c in (0x1A, 0x1B, 0x1C)}, {"descarga"})
        self.assertEqual({ctl.S7_CLASES[c] for c in (0x1D, 0x1E, 0x1F)}, {"carga"})
        self.assertEqual((ctl.CIP_CLASES[0x07], ctl.CIP_CLASES[0x05], ctl.CIP_CLASES[0x0D]),
                         ("modo", "reinicio", "configuracion"))
        self.assertNotIn(0x08, ctl.CIP_CLASES)
        self.assertEqual((ctl.DNP3_CLASES[13], ctl.DNP3_CLASES[18], ctl.DNP3_CLASES[31]),
                         ("reinicio", "modo", "configuracion"))
        self.assertEqual((ctl.IEC104_CLASES[105], ctl.IEC104_CLASES[103], ctl.IEC104_CLASES[45]),
                         ("reinicio", "escritura", "escritura"))
        for sin in (100, 101, 102):
            self.assertNotIn(sin, ctl.IEC104_CLASES)
        self.assertNotIn(8, ctl.MODBUS_ESCRITURAS)
        self.assertNotIn(43, ctl.MODBUS_ESCRITURAS)

    def test_mitre_de_ingenieria(self):
        import json
        d = json.loads((RAIZ / "ot_assess" / "marcos" / "mitre-ics.json").read_text(encoding="utf-8"))
        txt = next(v for sec in d.values() if isinstance(sec, dict) for kk, v in sec.items()
                   if kk == "actividad de ingenieria")
        self.assertEqual(txt, "T0843 Program Download; T0845 Program Upload; T0858 Change Operating Mode; "
                              "T0816 Device Restart/Shutdown; T0857 System Firmware")


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        cls.g = g
        cls.tmp = Path(tempfile.mkdtemp())
        pk = [
            # (1) GE SRTP
            g.srtp(0x23, T0 + 1), g.srtp(0x40, T0 + 2), g.srtp(0x09, T0 + 3, extendido=True),
            g.srtp(0x04, T0 + 4), g.srtp(0x23, T0 + 5, tipo=3), g.srtp(0x23, T0 + 6, desde_servidor=True),
            # (2) UMAS
            g.umas(0x30, T0 + 11), g.umas(0x34, T0 + 12), g.umas(0x41, T0 + 13), g.umas(0x20, T0 + 14),
            g.umas(0x41, T0 + 15, respuesta=True),
            # (3) FINS por UDP 9600
            g.fins(0x0402, T0 + 21), g.fins(0x0402, T0 + 22, icf=0xC0),
            # (4) CIP
            g.cip_servicio(0x4D, 0xA1, T0 + 31), g.cip_servicio(0x4D, 0x6B, T0 + 32),
            g.cip_servicio(0x07, 0x8E, T0 + 33), g.cip_servicio(0x4D, 0xA1, T0 + 34, respuesta=True),
            # (5) S7
            g.s7_pi("P_PROGRAM", T0 + 41), g.s7_pi("_INSE", T0 + 42), g.s7_pi("P_PROGRAM", T0 + 43, funcion=0x29),
        ]
        cls.entrada = cls.tmp / "pcaps"
        cls.entrada.mkdir()
        g.guardar_t(pk, cls.entrada / "ing.pcap")
        cls.out = cls.correr("o", cls.entrada)
        cls.ctl = _leer(cls.out / "control.csv")

    @classmethod
    def correr(cls, nombre, entrada, *extra):
        out = cls.tmp / nombre
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main([str(entrada), "-o", str(out), *extra])
        assert rc == 0, rc
        return out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def clases(self, proto):
        return [(f["operacion"], f["clase"]) for f in self.ctl if f["protocolo"] == proto]

    def test_columnas_de_control_csv(self):
        with open(self.out / "control.csv", newline="", encoding="utf-8-sig") as fh:
            cab = next(csv.reader(fh))
        self.assertEqual(cab, ["captura", "trama", "protocolo", "operacion", "origen", "destino", "detalle",
                               "clase"])

    def test_srtp(self):
        self.assertEqual(self.clases("GE SRTP"), [("SRTP 0x23 SET_PLC_RUN", "modo"),
                                                  ("SRTP 0x40 PROG_LOAD", "descarga"),
                                                  ("SRTP 0x09 WRITE_PROG_MEM", "descarga")])

    def test_umas(self):
        self.assertEqual(self.clases("Modbus/TCP (UMAS)"),
                         [("UMAS 0x30 transferencia al PLC", "descarga"),
                          ("UMAS 0x34 transferencia desde el PLC", "carga"),
                          ("UMAS 0x41 paro del PLC", "modo")])

    def test_fins(self):
        self.assertEqual(self.clases("Omron FINS"), [("FINS 0x0402 STOP", "modo")])

    def test_cip(self):
        self.assertEqual(self.clases("CIP / EtherNet/IP"),
                         [("Transferencia a memoria no volatil (clase 0xA1)", "firmware"),
                          ("Write Tag", "escritura"), ("Stop", "modo")])

    def test_s7(self):
        self.assertEqual(self.clases("S7comm"), [("PLC Control", "modo"), ("PLC Control", "descarga"),
                                                 ("PLC Stop", "modo")])
        self.assertIn("servicio=_INSE", next(f["detalle"] for f in self.ctl if f["clase"] == "descarga"
                                                    and f["protocolo"] == "S7comm"))

    def test_eventos_ingenieria_csv(self):
        filas = _leer(self.out / ing.ARCHIVO)
        self.assertEqual(list(filas[0].keys()), ing.COLUMNAS)
        self.assertEqual(sorted((f["protocolo"], f["clase"]) for f in filas),
                         sorted([("GE SRTP", "modo"), ("GE SRTP", "descarga"), ("Modbus/TCP (UMAS)", "descarga"),
                                 ("Modbus/TCP (UMAS)", "carga"), ("Modbus/TCP (UMAS)", "modo"),
                                 ("Omron FINS", "modo"), ("CIP / EtherNet/IP", "firmware"),
                                 ("CIP / EtherNet/IP", "modo"), ("S7comm", "modo"), ("S7comm", "descarga")]))
        self.assertEqual([f["inicio"] for f in filas], sorted(f["inicio"] for f in filas))
        srtp = next(f for f in filas if f["protocolo"] == "GE SRTP" and f["clase"] == "descarga")
        self.assertEqual(srtp["tramas"], "2")
        self.assertEqual(srtp["tecnica_mitre"], "T0843 Program Download")

    def test_hallazgo_en_la_corrida(self):
        h = [f for f in _leer(self.out / "hallazgos.csv") if f["titulo"] == TITULO]
        self.assertEqual([(f["severidad"], f["id"]) for f in h], [("Alta", ID_HALLAZGO)])

    def test_catalogo_en_ingles(self):
        try:
            out = self.correr("o_en", self.entrada, "--idioma", "en")
        finally:
            i18n.usar("es")
        filas = _leer(out / ing.ARCHIVO)
        self.assertEqual(list(filas[0].keys())[:3], ["capture", "start", "end"])
        clases = {f["class"] for f in filas}
        self.assertTrue({"firmware", "mode", "download", "upload"} <= clases, clases)
        self.assertEqual(_leer(out / "control.csv")[0].get("class"), "mode")
        h = next(f for f in _leer(out / "hallazgos.csv") if f["id"] == ID_HALLAZGO)
        self.assertIn("Classes:", h["evidence"])
        self.assertIn("Sessions:", h["evidence"])


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class DcpSetTest(unittest.TestCase):
    """PN1 (D102): PROFINET DCP Set como operacion de ingenieria; origen y destino son MAC."""
    ENG, DEV = "02:00:00:00:51:01", "02:00:00:00:51:02"
    PROTO = "PROFINET DCP"

    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        cls.tmp = Path(tempfile.mkdtemp())
        e, d = cls.ENG, cls.DEV
        pk = [
            g.dcp_set(e, d, [g.dcp_bloque_control(1), g.dcp_bloque_ip("192.0.2.77", "255.255.255.0"),
                             g.dcp_bloque_control(2)], T0 + 1),
            g.dcp_set(d, e, [(5, 4, b"\x01\x01\x00\x00")], T0 + 2, respuesta=True),
            g.dcp_set(e, d, [g.dcp_bloque_ip("192.0.2.78", "255.255.255.0", permanente=False)], T0 + 3),
            g.dcp_set(e, d, [g.dcp_bloque_nombre("estacion-test")], T0 + 4),
            g.dcp_set(e, d, [g.dcp_bloque_control(3)], T0 + 5),
            g.dcp_set(e, d, [g.dcp_bloque_control(5)], T0 + 6),
            g.dcp_identify(e, "01:0e:cf:00:00:00", [(0xFF, 0xFF, b"")], respuesta=False),
            g.dcp_identify(d, e, [(2, 2, b"\x00\x00estacion-test")], respuesta=True),
        ]
        cls.entrada = cls.tmp / "pcaps"
        cls.entrada.mkdir()
        g.guardar_t(pk, cls.entrada / "dcp.pcap")
        cls.out = cls.correr("o", cls.entrada)
        cls.ctl = [f for f in _leer(cls.out / "control.csv") if f["protocolo"] == cls.PROTO]

    @classmethod
    def correr(cls, nombre, entrada, *extra):
        out = cls.tmp / nombre
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main([str(entrada), "-o", str(out), *extra])
        assert rc == 0, rc
        return out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_operaciones_y_clases(self):
        self.assertEqual([(f["operacion"], f["clase"]) for f in self.ctl],
                         [("DCP Set IP", "configuracion"), ("DCP Set IP", "configuracion"),
                          ("DCP Set nombre de estacion", "configuracion"), ("DCP Signal", ""),
                          ("DCP restablecer a fabrica", "reinicio")])

    def test_detalle_origen_y_destino(self):
        self.assertEqual(self.ctl[0]["detalle"], "IP 192.0.2.77; mascara 255.255.255.0; permanente")
        self.assertIn("temporal", self.ctl[1]["detalle"])
        self.assertEqual(self.ctl[2]["detalle"], "nombre estacion-test")
        self.assertEqual({(f["origen"], f["destino"]) for f in self.ctl}, {(self.ENG, self.DEV)})

    def test_eventos_de_ingenieria(self):
        filas = _leer(self.out / ing.ARCHIVO)
        self.assertEqual(sorted((f["protocolo"], f["clase"]) for f in filas),
                         [(self.PROTO, "configuracion"), (self.PROTO, "reinicio")])
        rein = next(f for f in filas if f["clase"] == "reinicio")
        self.assertEqual(rein["tecnica_mitre"], "T0816 Device Restart/Shutdown")

    def test_identidad_dcp_sigue_igual(self):
        with open(self.out / "inventario.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertIn("estacion-test", fh.read())

    def test_en_ingles(self):
        try:
            out = self.correr("o_en", self.entrada, "--idioma", "en")
        finally:
            i18n.usar("es")
        filas = [f for f in _leer(out / "control.csv") if f["protocol"] == self.PROTO]
        self.assertEqual([f["operation"] for f in filas],
                         ["DCP Set IP", "DCP Set IP", "DCP Set station name", "DCP Signal", "DCP reset to factory"])
        self.assertEqual(filas[0]["detail"], "IP 192.0.2.77; mask 255.255.255.0; permanent")
        self.assertEqual(filas[2]["detail"], "name estacion-test")
        eventos = (out / ing.ARCHIVO).read_text(encoding="utf-8-sig")
        self.assertIn("DCP Set station name (1)", eventos)
        self.assertIn("DCP reset to factory (1)", eventos)
        hallazgos = (out / "hallazgos.csv").read_text(encoding="utf-8-sig")
        self.assertIn("PROFINET DCP: DCP Set station name (1)", hallazgos)
        self.assertNotIn("nombre de estacion", eventos + hallazgos)

    def test_equipo_propio_por_mac_quita_el_evento(self):
        from ot_assess.inventario_normalizado import Propios, excluir_captura
        cap = Capture(Path("x.pcap"))
        cap.control_ops.append({"frame": "1", "t": T0, "proto": self.PROTO, "src": self.ENG, "dst": self.DEV,
                                "op": "DCP Set IP", "detalle": "", "clase": "configuracion"})
        cap.control_ops.append({"frame": "2", "t": T0, "proto": self.PROTO, "src": "02:00:00:00:99:99",
                                "dst": "02:00:00:00:99:98", "op": "DCP Set IP", "detalle": "", "clase": "configuracion"})
        excluir_captura(cap, Propios([{"direccion": self.ENG, "etiqueta": "laptop"}]))
        self.assertEqual([o["frame"] for o in cap.control_ops], ["2"])


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturaDeSiempreTest(unittest.TestCase):
    def test_el_resto_de_hallazgos_no_cambia(self):
        import gen_pcaps as g
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "in").mkdir()
            g.guardar(g.punto_a(), tmp / "in" / "punto_a.pcap")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(tmp / "in"), "-o", str(tmp / "o")]), 0)
            hall = _leer(tmp / "o" / "hallazgos.csv")
            tit = [f for f in hall if f["titulo"] == TITULO]
            self.assertEqual([(f["severidad"], f["id"]) for f in tit], [("Alta", ID_HALLAZGO)])
            filas = _leer(tmp / "o" / "control.csv")
            self.assertIn(("PLC Stop", "modo"), [(f["operacion"], f["clase"]) for f in filas])
            self.assertTrue(all("clase" in f for f in filas))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
