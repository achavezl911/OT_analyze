"""T5: periodicidad de las comunicaciones de control (D65).

Unitarias (sin tshark): estadistica en linea de flows.registrar_carga y clasificacion de periodicidad.py.
Extremo a extremo (tshark y scapy): capturas sinteticas de tests/gen_pcaps.py.
"""
from __future__ import annotations

import csv
import datetime
import math
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import flows
from ot_assess import periodicidad as pe
from ot_assess.catalog import OT_PORTS
from ot_assess.rules import periodicidad as rp

T0 = 1_700_000_000
T_PERDIDA = "Perdida de comunicacion en un conducto de control periodico"
T_IRREG = "Sondeo irregular en conductos de control"
T_ESCRITOR = "Escritor de control que aparece a mitad de la captura"
TITULOS = (T_PERDIDA, T_IRREG, T_ESCRITOR)


def flujo(instantes, dport="502", l4="tcp", src="10.0.0.1", dst="10.0.0.2"):
    f = {"src": src, "dst": dst, "dport": dport, "l4": l4, "pkts": len(instantes), "bytes": 0,
         "first": instantes[0], "last": instantes[-1], "proto": "", "sports": set()}
    for t in instantes:
        flows.registrar_carga(f, t)
    return f


def cap_de(*fs, ventana=(T0, T0 + 700), ops=()):
    return SimpleNamespace(name="x.pcap", flows={i: f for i, f in enumerate(fs)}, ventana=list(ventana),
                           control_ops=list(ops), hosts={}, findings=[])


def epoch(iso):
    return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


class EstadisticaTest(unittest.TestCase):
    def test_welford_media_y_varianza(self):
        ins = [T0, T0 + 1, T0 + 3, T0 + 4, T0 + 7]            # intervalos 1, 2, 1, 3
        f = flujo(ins)
        self.assertEqual(f["pl_n"], 4)
        self.assertAlmostEqual(f["pl_mean"], 1.75)
        self.assertAlmostEqual(f["pl_m2"], sum((x - 1.75) ** 2 for x in (1, 2, 1, 3)))
        self.assertEqual((f["pl_min"], f["pl_max"], f["pl_max_en"]), (1, 3, T0 + 4))
        self.assertEqual((f["pl_first"], f["pl_last"]), (T0, T0 + 7))

    def test_hueco_no_entra_en_media_ni_varianza(self):
        ins = [T0 + i for i in range(20)] + [T0 + 100 + i for i in range(20)]
        f = flujo(ins)
        self.assertEqual(f["pl_huecos"], 1)
        self.assertAlmostEqual(f["pl_mean"], 1.0)
        self.assertAlmostEqual(f["pl_m2"], 0.0)
        self.assertEqual((f["pl_max"], f["pl_max_en"]), (81, T0 + 19))

    def test_paquete_fuera_de_orden_no_da_intervalo_negativo(self):
        f = flujo([T0, T0 + 1, T0 + 0.5, T0 + 2])
        self.assertGreaterEqual(f["pl_min"], 0)

    def test_memoria_acotada_numeros_por_flujo(self):
        f = flujo([T0 + i for i in range(1000)])
        self.assertTrue(all(isinstance(v, (int, float)) or v is None for k, v in f.items() if k.startswith("pl_")))
        self.assertFalse(any(isinstance(v, (list, dict)) for v in f.values()))


class ClasificacionTest(unittest.TestCase):
    def clase(self, ins, **kw):
        return pe.conductos(cap_de(flujo(ins, **kw)))[0]

    def test_periodico(self):
        c = pe.conductos(cap_de(flujo([T0 + i * 1.0 + (0.03 if i % 2 else -0.03) for i in range(1, 400)]),
                                ventana=(T0, T0 + 400)))[0]
        self.assertEqual(c["patron"], "periodico")
        self.assertAlmostEqual(c["media"], 1.0, delta=0.02)
        self.assertLess(c["cv"], 0.1)
        self.assertEqual(c["marcas"], [])

    def test_variable_e_irregular_por_cv(self):
        alt = [T0]
        for i in range(200):                       # intervalos 0.5 y 1.5: CV = 0.5
            alt.append(alt[-1] + (0.5 if i % 2 else 1.5))
        c = self.clase(alt)
        self.assertEqual(c["patron"], "variable")
        self.assertAlmostEqual(c["cv"], 0.5, delta=0.02)
        raf = [T0]
        for i in range(200):                       # intervalos 0.2 y 1.8: CV = 0.8
            raf.append(raf[-1] + (0.2 if i % 2 else 1.8))
        c = self.clase(raf)
        self.assertEqual(c["patron"], "irregular")
        self.assertAlmostEqual(c["cv"], 0.8, delta=0.03)

    def test_esporadico_con_pocos_intervalos(self):
        self.assertEqual(self.clase([T0 + i for i in range(29)])["patron"], "esporadico")   # 28 intervalos
        self.assertEqual(self.clase([T0 + i for i in range(32)])["patron"], "periodico")     # 31

    def test_dnp3_y_104_no_se_clasifican_por_regularidad(self):
        for puerto in ("20000", "2404"):
            ins = [T0]
            for i in range(80):
                ins.append(ins[-1] + (0.2 if i % 2 else 1.8))
            c = self.clase(ins, dport=puerto)
            self.assertEqual(c["patron"], "evento")

    def test_puertos_de_sondeo_y_eventos_estan_en_el_catalogo(self):
        for clave in pe.SONDEO | pe.EVENTOS:
            self.assertIn(clave, OT_PORTS)

    def test_puerto_no_ot_no_se_clasifica(self):
        self.assertEqual(pe.conductos(cap_de(flujo([T0 + i for i in range(60)], dport="8080"))), [])

    def test_hueco_y_termina_antes_con_instante(self):
        ins = [T0 + i for i in range(100)] + [T0 + 200 + i for i in range(100)]     # hueco de 101 s
        c = pe.conductos(cap_de(flujo(ins), ventana=(T0, T0 + 700)))[0]
        self.assertIn("hueco", c["marcas"])
        self.assertEqual(c["hueco_en"], T0 + 99)
        self.assertIn("termina_antes", c["marcas"])           # ultimo paquete en +299 de 700
        self.assertEqual(c["ultima"], T0 + 299)

    def test_hueco_pequeno_o_final_cercano_no_marca(self):
        ins = [T0 + i for i in range(100)] + [T0 + 104 + i for i in range(100)]     # 5 s: no supera max(10, 5)
        c = pe.conductos(cap_de(flujo(ins), ventana=(T0, T0 + 203)))[0]
        self.assertEqual(c["marcas"], [])

    def test_aparece_tarde_solo_con_captura_de_10_minutos(self):
        ins = [T0 + 300 + i for i in range(100)]
        self.assertIn("aparece_tarde", pe.conductos(cap_de(flujo(ins), ventana=(T0, T0 + 700)))[0]["marcas"])
        self.assertNotIn("aparece_tarde", pe.conductos(cap_de(flujo(ins), ventana=(T0, T0 + 400)))[0]["marcas"])
        self.assertNotIn("aparece_tarde", pe.conductos(cap_de(flujo([T0 + 100 + i for i in range(500)]),
                                                              ventana=(T0, T0 + 700)))[0]["marcas"])

    def test_severidad_media_sin_escrituras_ni_nivel_bajo(self):
        ins = [T0 + i for i in range(100)] + [T0 + 200 + i for i in range(100)]
        cap = cap_de(flujo(ins))
        rp.perdida_comunicacion_periodica(cap)
        self.assertEqual(cap.findings[0]["severidad"], "Media")
        cap = cap_de(flujo(ins), ops=[{"src": "10.0.0.1", "dst": "10.0.0.2", "t": T0, "proto": "Modbus/TCP",
                                       "op": "FC6", "detalle": "", "frame": "1"}])
        rp.perdida_comunicacion_periodica(cap)
        self.assertEqual(cap.findings[0]["severidad"], "Alta")

    def test_evidencia_hasta_10_conductos(self):
        ins = [T0 + i for i in range(100)] + [T0 + 200 + i for i in range(100)]
        fs = [flujo(ins, dst=f"10.0.1.{i:02d}") for i in range(1, 13)]
        cap = cap_de(*fs)
        rp.perdida_comunicacion_periodica(cap)
        ev = cap.findings[0]["evidencia"]
        self.assertIn("12 conductos", ev)
        self.assertIn("10.0.1.10", ev)
        self.assertNotIn("10.0.1.11", ev)
        self.assertIn("y 2 mas", ev)

    def test_cv_formula(self):
        f = flujo([T0 + i * 2.0 for i in range(50)])
        self.assertEqual(pe._cv(f), 0.0)
        self.assertTrue(math.isfinite(pe._cv(flujo([T0]))))


def _csv(path: Path) -> list:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class PeriodicidadE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g

        from ot_assess import i18n
        from ot_assess.cli import main

        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        cls.pcaps = pcaps
        g.guardar_t(g.punto_t5_periodico(), pcaps / "t5_periodico.pcap")
        g.guardar_t(g.punto_t5_hueco(), pcaps / "t5_hueco.pcap")
        g.guardar_t(g.punto_t5_irregular(), pcaps / "t5_irregular.pcap")
        g.guardar_t(g.punto_t5_termina_antes(), pcaps / "t5_termina.pcap")
        g.guardar_t(g.punto_t5_escritor_tardio(), pcaps / "t5_escritor.pcap")
        g.guardar_t(g.punto_t5_dnp3_eventos(), pcaps / "t5_dnp3.pcap")
        g.guardar(g.punto_a(), pcaps / "viejo_a.pcap")
        g.guardar(g.punto_b(), pcaps / "viejo_b.pcap")
        g.guardar(g.punto_c(), pcaps / "viejo_c.pcap")
        g.guardar(g.punto_d(), pcaps / "viejo_d.pcap")
        i18n.FALTANTES.clear()
        cls.rc = main([str(pcaps), "-o", str(cls.tmp / "es"), "--cache", str(cls.tmp / "cache")])
        cls.per = _csv(cls.tmp / "es" / "periodicidad.csv")
        cls.hall = _csv(cls.tmp / "es" / "hallazgos.csv")
        i18n.FALTANTES.clear()
        main([str(pcaps), "-o", str(cls.tmp / "en"), "--idioma", "en"])
        cls.faltantes_en = set(i18n.FALTANTES)
        i18n.usar("es")
        cls.main = staticmethod(main)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def filas(self, captura, origen=None, destino=None):
        return [r for r in self.per if r["captura"] == captura + ".pcap"
                and (origen is None or r["origen_ip"] == origen) and (destino is None or r["destino_ip"] == destino)]

    def fila(self, captura, origen="10.60.1.10", destino="10.60.1.20"):
        fs = self.filas(captura, origen, destino)
        self.assertEqual(len(fs), 1, f"{captura} {origen}->{destino}")
        return fs[0]

    def hallazgos(self, captura, titulo):
        return [r for r in self.hall if r["captura"] == captura + ".pcap" and r["titulo"] == titulo]

    def test_termina_bien(self):
        self.assertEqual(self.rc, 0)

    def test_periodico_y_los_ack_no_cuentan(self):
        r = self.fila("t5_periodico")
        self.assertEqual(r["patron"], "periodico")
        self.assertAlmostEqual(float(r["periodo_medio_s"]), 1.0, delta=0.02)     # con ACK seria 0.5 o menos
        self.assertLess(float(r["cv"]), 0.1)
        self.assertAlmostEqual(int(r["peticiones"]), 700, delta=3)               # con ACK serian 1400 o mas
        self.assertEqual(r["marcas"], "")
        self.assertEqual((r["servicio"], r["l4"], r["puerto"]), ("Modbus/TCP", "tcp", "502"))
        for t in TITULOS:
            self.assertEqual(self.hallazgos("t5_periodico", t), [])

    def test_hueco_de_60_s(self):
        r = self.fila("t5_hueco")
        self.assertEqual(r["patron"], "periodico")                               # el hueco no rompe la clasificacion
        self.assertEqual(r["marcas"], "hueco")
        self.assertAlmostEqual(float(r["hueco_max_s"]), 61.0, delta=2.0)
        self.assertAlmostEqual(epoch(r["hueco_en"]), T0 + 299, delta=2)
        h = self.hallazgos("t5_hueco", T_PERDIDA)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["severidad"], "Alta")                              # el destino es un PLC de nivel 1
        self.assertIn("10.60.1.10 -> 10.60.1.20 Modbus/TCP", h[0]["evidencia"])
        self.assertIn("hueco maximo", h[0]["evidencia"])
        self.assertEqual(self.hallazgos("t5_hueco", T_IRREG), [])

    def test_irregular(self):
        r = self.fila("t5_irregular")
        self.assertEqual(r["patron"], "irregular")
        self.assertGreaterEqual(float(r["cv"]), 0.6)
        h = self.hallazgos("t5_irregular", T_IRREG)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["severidad"], "Baja")
        self.assertIn("10.60.1.10 -> 10.60.1.20 Modbus/TCP", h[0]["evidencia"])
        self.assertEqual(self.hallazgos("t5_irregular", T_PERDIDA), [])

    def test_termina_antes(self):
        r = self.fila("t5_termina")
        self.assertEqual(r["marcas"], "termina_antes")
        self.assertAlmostEqual(epoch(r["ultima"]), T0 + 200, delta=2)
        self.assertEqual(self.fila("t5_termina", destino="10.60.1.30")["marcas"], "")
        h = self.hallazgos("t5_termina", T_PERDIDA)
        self.assertEqual(len(h), 1)
        self.assertIn("10.60.1.20", h[0]["evidencia"])
        self.assertNotIn("10.60.1.30", h[0]["evidencia"])

    def test_escritor_que_aparece_tarde(self):
        h = self.hallazgos("t5_escritor", T_ESCRITOR)
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["severidad"], "Alta")
        self.assertIn("10.60.1.50 -> 10.60.1.20", h[0]["evidencia"])
        self.assertIn("3 operaciones", h[0]["evidencia"])
        self.assertNotIn("10.60.1.10", h[0]["evidencia"])                        # el HMI escribe, pero no es tardio
        self.assertIn("aparece_tarde", self.fila("t5_escritor", origen="10.60.1.50")["marcas"])

    def test_dnp3_con_eventos_no_sale_irregular(self):
        r = self.fila("t5_dnp3", "10.50.1.10", "10.50.1.20")
        self.assertEqual(r["patron"], "evento")
        self.assertEqual(self.hallazgos("t5_dnp3", T_IRREG), [])

    def test_capturas_existentes_sin_hallazgos_t5(self):
        for c in ("viejo_a", "viejo_b", "viejo_c", "viejo_d"):
            for t in TITULOS:
                self.assertEqual(self.hallazgos(c, t), [], f"{c}: {t}")

    def test_columnas_de_periodicidad_csv(self):
        with open(self.tmp / "es" / "periodicidad.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), pe.COLUMNAS)
        self.assertEqual(pe.COLUMNAS, ["captura", "origen", "origen_ip", "destino", "destino_ip", "servicio",
                                       "l4", "puerto", "peticiones", "periodo_medio_s", "cv", "hueco_max_s",
                                       "hueco_en", "primera", "ultima", "patron", "marcas"])

    def test_ingles_sin_textos_faltantes(self):
        self.assertEqual(sorted(self.faltantes_en), [])

    def test_con_cache_las_salidas_son_iguales(self):
        out = self.tmp / "es2"
        self.assertEqual(self.main([str(self.pcaps), "-o", str(out), "--cache", str(self.tmp / "cache")]), 0)
        for n in ("periodicidad.csv", "hallazgos.csv"):
            self.assertEqual((out / n).read_text(encoding="utf-8-sig"),
                             (self.tmp / "es" / n).read_text(encoding="utf-8-sig"), n)


if __name__ == "__main__":
    unittest.main()
