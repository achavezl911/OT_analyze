"""D117: evidencia observable de IEC 62351 por protocolo (filas sinteticas de tshark, sin texto de la norma)."""
import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path

from ot_assess import i18n
from ot_assess import iec62351 as ie
from ot_assess.detail.base import COLLECTORS, RowCtx
from ot_assess.fields import DETAIL_FIELDS, DETAIL_FILTER_PARTS
from ot_assess.model import Capture

IDX = {f: i for i, f in enumerate(DETAIL_FIELDS)}


def _cap():
    return Capture(Path("x.pcap"))


def _fila(**kw):
    row = [""] * len(DETAIL_FIELDS)
    for k, v in kw.items():
        row[IDX[k.replace("__", ".")]] = str(v)
    return row


def _correr(cap, **kw):
    kw.setdefault("frame__number", 1)
    rc = RowCtx(cap, _fila(**kw), IDX)
    for colector in COLLECTORS:
        colector(rc)


def _flujo(cap, src, dst, dport, l4="tcp"):
    cap.flows[(src, dst, str(dport), l4)] = {
        "src": src, "dst": dst, "dport": str(dport), "l4": l4, "pkts": 1, "bytes": 60, "proto": "",
        "first": 1.0, "last": 1.0, "sports": set(), "min": None}


def _fila_de(cap, nombre):
    return next(f for f in ie.filas([cap]) if f[0] == nombre)


COL = {c: i for i, c in enumerate(ie.COLUMNAS)}
N104 = "IEC 60870-5-104"


class TablaTest(unittest.TestCase):
    def test_cinco_protocolos_y_roles_siempre(self):
        filas = ie.filas([_cap()])
        self.assertEqual([f[0] for f in filas], [
            N104, "DNP3", "MMS (IEC 61850 cliente-servidor)", "GOOSE (IEC 61850)",
            "SV (IEC 61850 Sampled Values)", "control de acceso por roles (IEC 62351-8)"])
        self.assertTrue(all(f[COL["observado"]] == "no" for f in filas))
        self.assertEqual(filas[-1][COL["evidencia"]], ie.NO_EVALUABLE)
        self.assertEqual(filas[0][COL["evidencia"]], ie.NO_VISTO)
        self.assertEqual(filas[0][COL["partes_62351"]], "IEC 62351-3; IEC 62351-5")

    def test_sin_capturas_no_hay_hoja(self):
        self.assertEqual(ie.tablas([]), [])

    def test_104_en_claro_dos_pares(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 2404)
        _flujo(cap, "10.0.0.2", "10.0.0.9", 2404)
        _flujo(cap, "10.0.0.9", "10.0.0.1", 50000)          # la respuesta no es un conducto
        f = _fila_de(cap, N104)
        self.assertEqual((f[COL["observado"]], f[COL["conductos_en_claro"]]), ("si", 2))
        self.assertEqual(f[COL["evidencia"]], ie.NO_OBSERVADA)
        self.assertEqual(f[COL["autenticacion_segura"]], "")
        self.assertNotIn("cumple", " ".join(map(str, f)).lower().replace("no es un dictamen", ""))

    def test_serverhello_desde_19998_confirma_tls(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 19998)
        _correr(cap, tls__handshake__type="2", tcp__srcport=19998, ip__src="10.0.0.9", ip__dst="10.0.0.1")
        _correr(cap, tls__handshake__type="1", tcp__srcport=50000, ip__src="10.0.0.1", ip__dst="10.0.0.9")
        f = _fila_de(cap, N104)
        self.assertEqual((f[COL["tls_confirmado"]], f[COL["conductos_puerto_seguro"]]), (1, 1))
        self.assertEqual(f[COL["evidencia"]], ie.OBSERVADA)

    def test_serverhello_de_otro_puerto_no_cuenta(self):
        cap = _cap()
        _correr(cap, tls__handshake__type="2", tcp__srcport=443, ip__src="10.0.0.9", ip__dst="10.0.0.1")
        self.assertEqual([e for e in cap.protocolo_eventos if e["tipo"] == "p62351_tls"], [])

    def test_conducto_seguro_sin_serverhello(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 19998)
        f = _fila_de(cap, N104)
        self.assertEqual((f[COL["conductos_puerto_seguro"]], f[COL["tls_confirmado"]]), (1, 0))
        self.assertEqual(f[COL["evidencia"]], ie.NO_OBSERVADA)
        self.assertIn("TLS no confirmado", f[COL["nota"]])

    def test_dnp3_autenticacion_segura(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.5", 20000)
        _correr(cap, dnp3__al__func="131", tcp__srcport=20000, tcp__dstport=50000,
                ip__src="10.0.0.5", ip__dst="10.0.0.1")
        _correr(cap, dnp3__al__func="32", tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
        ev = [e for e in cap.protocolo_eventos if e["tipo"] == "p62351_dnp3_auth"]
        self.assertEqual({(e["codigo"], e["maestro"], e["outstation"]) for e in ev},
                         {(131, "10.0.0.1", "10.0.0.5"), (32, "10.0.0.1", "10.0.0.5")})
        f = _fila_de(cap, "DNP3")
        self.assertEqual(f[COL["autenticacion_segura"]], 2)
        self.assertEqual(f[COL["evidencia"]], ie.OBSERVADA)
        self.assertEqual(f[COL["conductos_en_claro"]], 1)

    def test_mms_si_y_s7comm_no_en_102(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.7", 102)
        _flujo(cap, "10.0.0.2", "10.0.0.8", 102)
        _flujo(cap, "10.0.0.3", "10.0.0.8", 102)
        _correr(cap, _ws__col__protocol="MMS", ip__src="10.0.0.1", ip__dst="10.0.0.7")
        _correr(cap, _ws__col__protocol="S7COMM", ip__src="10.0.0.2", ip__dst="10.0.0.8")
        mms = _fila_de(cap, "MMS (IEC 61850 cliente-servidor)")
        self.assertEqual(mms[COL["conductos_en_claro"]], 1)
        self.assertIn("1 conductos a 102/tcp sin decodificar", mms[COL["nota"]])
        s7 = _fila_de(cap, "S7comm")
        self.assertEqual((s7[COL["conductos_en_claro"]], s7[COL["partes_62351"]], s7[COL["evidencia"]]),
                         (1, "no aplica", ie.NO_APLICA))

    def test_102_sin_decodificar_y_sin_mms_es_no_observado(self):
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 102)
        mms = next(f for f in ie.filas([cap]) if f[0].startswith("MMS"))
        self.assertEqual((mms[COL["observado"]], mms[COL["conductos_en_claro"]], mms[COL["evidencia"]]),
                         ("no", 0, ie.NO_VISTO))
        self.assertIn("1 conductos a 102/tcp sin decodificar", mms[COL["nota"]])

    def test_goose_no_evaluable(self):
        cap = _cap()
        _correr(cap, _ws__col__protocol="GOOSE", eth__src="aa:00:00:00:00:01", eth__dst="01:0c:cd:01:00:01")
        cap.l2_flows[("aa:00:00:00:00:02", "01:0c:cd:04:00:01")] += 5000
        cap.l2_flows[("aa:00:00:00:00:03", "01:0c:cd:01:00:09")] += 1
        cap.ethertypes["SV"] += 5000
        for n in ("GOOSE (IEC 61850)", "SV (IEC 61850 Sampled Values)"):
            f = _fila_de(cap, n)
            self.assertEqual((f[COL["observado"]], f[COL["conductos_en_claro"]], f[COL["evidencia"]]),
                             ("si", 1, ie.NO_EVALUABLE))
            self.assertIn("no se decodifica en esta version", f[COL["nota"]])

    def test_modbus_visto_es_no_aplica_y_no_visto_no_aparece(self):
        cap = _cap()
        self.assertEqual([f for f in ie.filas([cap]) if f[COL["evidencia"]] == "no aplica"], [])
        _flujo(cap, "10.0.0.1", "10.0.0.4", 502)
        extra = [f for f in ie.filas([cap])[6:]]
        self.assertEqual([(f[0], f[COL["partes_62351"]], f[COL["evidencia"]], f[COL["conductos_en_claro"]])
                          for f in extra], [("Modbus/TCP", "no aplica", "no aplica", 1)])

    def test_eventos_sobreviven_al_json(self):
        cap = _cap()
        _correr(cap, dnp3__al__func="33", tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
        _correr(cap, dnp3__al__func="33", tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
        self.assertEqual([e["n"] for e in cap.protocolo_eventos], [2])
        cap.protocolo_eventos = json.loads(json.dumps(cap.protocolo_eventos))
        self.assertEqual(_fila_de(cap, "DNP3")[COL["autenticacion_segura"]], 2)

    def test_tabla_sin_texto_de_la_norma_y_sin_revisar(self):
        cat = ie.cargar()
        self.assertEqual(cat["validacion"], "sin revisar")
        self.assertTrue(all(p["partes"] for p in cat["protocolos"]))


class FiltroTest(unittest.TestCase):
    def test_filtro_incluye_33_y_131_y_no_sv(self):
        dnp3 = next(p for p in DETAIL_FILTER_PARTS if p.startswith("dnp3.al.func in"))
        self.assertIn("32, 33, 131}", dnp3)
        # SV es ciclico de alta tasa: no pasa por el detalle; sus pares salen de l2_flows.
        self.assertNotIn("sv", DETAIL_FILTER_PARTS)

    def test_33_y_131_no_cambian_otros_colectores(self):
        base = _cap()
        _correr(base, tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
        otro = _cap()
        _correr(otro, dnp3__al__func="33|131", tcp__dstport=20000, ip__src="10.0.0.1", ip__dst="10.0.0.5")
        for nombre in ("control_ops", "identity", "cleartext", "arp_events", "dns_eventos"):
            self.assertEqual(getattr(otro, nombre), getattr(base, nombre), nombre)
        self.assertEqual([e["tipo"] for e in otro.protocolo_eventos],
                         ["p62351_dnp3_auth", "p62351_dnp3_auth"])

    def test_fila_sv_no_cambia_otros_colectores(self):
        base, sv = _cap(), _cap()
        _correr(base, eth__src="aa:00:00:00:00:02", eth__dst="01:0c:cd:04:00:01")
        _correr(sv, _ws__col__protocol="SV", eth__src="aa:00:00:00:00:02", eth__dst="01:0c:cd:04:00:01")
        self.assertEqual(copy.copy(vars(base)), copy.copy(vars(sv)))

    def test_acumulado_con_indice(self):
        cap = _cap()
        for _ in range(500):
            _correr(cap, _ws__col__protocol="MMS", ip__src="10.0.0.1", ip__dst="10.0.0.2")
            _correr(cap, _ws__col__protocol="MMS", ip__src="10.0.0.3", ip__dst="10.0.0.2")
        self.assertEqual(sorted((e["clave"], e["n"]) for e in cap.protocolo_eventos),
                         [(["MMS", "10.0.0.1", "10.0.0.2"], 500), (["MMS", "10.0.0.3", "10.0.0.2"], 500)])
        # Si la lista cambia de objeto (filtro de equipos propios, cache), el indice se rehace.
        cap.protocolo_eventos = json.loads(json.dumps(cap.protocolo_eventos))
        _correr(cap, _ws__col__protocol="MMS", ip__src="10.0.0.1", ip__dst="10.0.0.2")
        self.assertEqual(sorted(e["n"] for e in cap.protocolo_eventos), [500, 501])
        self.assertEqual(len(cap.protocolo_eventos), 2)


class SalidaTest(unittest.TestCase):
    def test_csv_y_hoja_en_ambos_idiomas(self):
        from ot_assess.model import Assessment
        from ot_assess.report import csvout
        cap = _cap()
        _flujo(cap, "10.0.0.1", "10.0.0.9", 2404)
        res = Assessment([cap], {}, [], None)
        for idioma, cab0, hoja in (("es", "protocolo", "IEC 62351 evidencia"), ("en", "protocol", "IEC 62351 evidence")):
            i18n.usar(idioma)
            try:
                with tempfile.TemporaryDirectory() as d:
                    csvout.write_csvs(res, Path(d))
                    with open(Path(d) / ie.ARCHIVO, newline="", encoding="utf-8-sig") as fh:
                        filas = list(csv.reader(fh))
                self.assertEqual(filas[0][0], cab0)
                self.assertEqual(len(filas), 1 + 6)
                self.assertEqual(csvout.nombre_hoja(ie.HOJA), hoja)
                self.assertEqual(i18n.FALTANTES, set())
            finally:
                i18n.usar("es")
                i18n.FALTANTES.clear()


if __name__ == "__main__":
    unittest.main()
