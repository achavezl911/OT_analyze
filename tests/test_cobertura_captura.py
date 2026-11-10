"""C1 (D80): validacion de la cobertura de la captura y subcomando validar-captura.

Las capturas son sinteticas (scapy, IP de documentacion RFC 5737) y de 25 h para que la sana cubra un ciclo diario.
Requiere tshark y scapy; si faltan, se omiten las pruebas que leen capturas.
"""
from __future__ import annotations

import csv
import io
import json
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import cache_capturas as cache  # noqa: E402
from ot_assess import cobertura_captura as cc  # noqa: E402
from ot_assess import i18n  # noqa: E402
from ot_assess.cli import main as main_completo  # noqa: E402
from ot_assess.cli_validar_captura import main as main_validar  # noqa: E402

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

LEE_CAPTURAS = unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
T0 = 1_700_000_000
PASO = 240                      # s entre lecturas: sin huecos de mas de 5 min
LECTURAS = 375                  # 25 h
MAC_C, MAC_S = "02:00:00:c1:00:01", "02:00:00:c1:00:02"


def _csv(path: Path) -> list:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _paquete(c2s, sport, flags, seq, ack, carga, t, vlan=None, ip_c="192.0.2.10", ip_s="192.0.2.20"):
    from scapy.all import IP, TCP, Dot1Q, Ether, Raw
    e = Ether(src=MAC_C if c2s else MAC_S, dst=MAC_S if c2s else MAC_C)
    if vlan:
        e = e / Dot1Q(vlan=vlan)
    ip = IP(src=ip_c, dst=ip_s) if c2s else IP(src=ip_s, dst=ip_c)
    tcp = TCP(sport=sport if c2s else 502, dport=502 if c2s else sport, flags=flags, seq=seq, ack=ack)
    p = e / ip / tcp / Raw(carga)
    p.time = t
    return p


def lecturas(n=LECTURAS, soltar=(), unidireccional=False, hueco=None, vlan=None, t0=T0, desde=0):
    """Lecturas Modbus/TCP (502) de la lectura `desde` a `n`. `soltar`: peticiones que el espejo pierde (no se
    escriben, pero la secuencia avanza). `unidireccional`: solo se ve al cliente, en 10 sesiones. `hueco`:
    (lectura, segundos) desplaza de ahi en adelante."""
    pk, extra = [], 0
    estado = {s: [1000, 5000] for s in range(10 if unidireccional else 1)}
    for i in range(desde, n):
        if hueco and i == hueco[0]:
            extra = hueco[1]
        t = t0 + i * PASO + extra
        sesion = i % 10 if unidireccional else 0
        sport = 40000 + sesion
        cs, ss = estado[sesion]
        if i < len(estado):
            pk += [_paquete(True, sport, "S", cs, 0, b"", t - 3, vlan),
                   _paquete(False, sport, "SA", ss, cs + 1, b"", t - 2, vlan),
                   _paquete(True, sport, "A", cs + 1, ss + 1, b"", t - 1, vlan)]
            cs, ss = cs + 1, ss + 1
        if unidireccional:
            pk.append(_paquete(True, sport, "PA", cs, ss, b"x" * 12, t, vlan))
            cs += 12
        else:
            if i not in soltar:
                pk.append(_paquete(True, sport, "PA", cs, ss, b"x" * 12, t, vlan))
            cs += 12
            pk.append(_paquete(False, sport, "PA", ss, cs, b"y" * 20, t + 0.01, vlan))
            ss += 20
            pk.append(_paquete(True, sport, "A", cs, ss, b"", t + 0.02, vlan))
        estado[sesion] = [cs, ss]
    return pk


def escribir(paquetes, ruta: Path) -> Path:
    from scapy.all import wrpcap
    ruta.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(ruta), paquetes)
    return ruta


def validar(entradas, salida: Path, *extra) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main_validar([str(e) for e in entradas] + ["-o", str(salida), *extra])
    i18n.usar("es")
    return rc, out.getvalue(), err.getvalue()


def punto(salida: Path) -> dict:
    return next(f for f in _csv(salida / "cobertura_captura.csv") if f["nivel"] == "punto")


class MetricasTest(unittest.TestCase):
    """Sin tshark: el calculo sobre filas armadas a mano."""

    def test_p95_por_minuto_a_mano(self):
        # 20 minutos: 19 a 1 Mbps (7 500 000 bytes por minuto) y uno a 10 Mbps. p95 = rango 19 = 1 Mbps; el maximo, 10.
        acum = cc.Acumulador({"frame.time_epoch": 0, "frame.len": 1})
        for m in range(20):
            acum.fila([str(T0 + m * 60 + 1), "75000000" if m == 7 else "7500000"])
        m = cc.metricas(cc.fusionar([acum.cerrar()]))
        self.assertAlmostEqual(m["mbps_p95"], 1.0)
        self.assertAlmostEqual(m["mbps_max"], 10.0)
        self.assertEqual(m["paquetes"], 20)

    def test_minutos_sin_trafico_cuentan_como_cero(self):
        self.assertEqual(cc.mbps_por_minuto({10: 7_500_000, 13: 7_500_000}, 10 * 60, 13 * 60), [1.0, 0.0, 0.0, 1.0])
        self.assertEqual(cc.p95([]), 0.0)

    def test_huecos_dentro_del_archivo_y_entre_archivos(self):
        a = cc.Acumulador({"frame.time_epoch": 0, "frame.len": 1})
        for s in (0, 10, 316, 320):        # un hueco de 306 s
            a.fila([str(T0 + s), "100"])
        b = cc.Acumulador({"frame.time_epoch": 0, "frame.len": 1})
        b.fila([str(T0 + 320 + 301), "100"])     # 301 s despues del ultimo del primer archivo
        d1, d2 = a.cerrar(), b.cerrar()
        self.assertEqual((d1["huecos_n"], round(d1["hueco_max"])), (1, 306))
        f = cc.fusionar([d2, d1])               # el orden de entrada no importa
        self.assertEqual((f["huecos_n"], round(f["hueco_max"])), (2, 306))
        self.assertEqual(f["paquetes"], 5)

    def test_umbrales_del_veredicto(self):
        base = {"ip_pkts": 10, "perdida_pct": 0.0, "un_sentido_pct": 0.0, "muestreada": False,
                "duracion_s": cc.DURACION_CICLO_S, "huecos": 0, "hueco_mayor_s": 0, "truncados": 0,
                "industriales": ["Modbus/TCP"], "sin_campos": [], "paquetes": 10}
        self.assertEqual(cc.veredicto(base, [], [])[0], cc.APTA)
        for clave, valor, esperado in (("perdida_pct", 1.0, cc.APTA), ("perdida_pct", 1.01, cc.LIMITADA),
                                       ("perdida_pct", 5.0, cc.LIMITADA), ("perdida_pct", 5.01, cc.NO_APTA),
                                       ("un_sentido_pct", 20.0, cc.APTA), ("un_sentido_pct", 20.1, cc.LIMITADA),
                                       ("un_sentido_pct", 50.0, cc.LIMITADA), ("un_sentido_pct", 50.1, cc.NO_APTA),
                                       ("duracion_s", cc.DURACION_CICLO_S - 1, cc.LIMITADA),
                                       ("duracion_s", 600, cc.LIMITADA), ("duracion_s", 599, cc.NO_APTA),
                                       ("ip_pkts", 0, cc.NO_APTA), ("truncados", 1, cc.LIMITADA),
                                       ("industriales", [], cc.LIMITADA)):
            self.assertEqual(cc.veredicto(dict(base, **{clave: valor}), [], [])[0], esperado, (clave, valor))
        self.assertEqual(cc.veredicto(base, ["10"], [])[0], cc.LIMITADA)
        self.assertEqual(cc.veredicto(base, [], ["Z"])[0], cc.LIMITADA)

    def test_columnas_y_hoja_estan_en_el_catalogo(self):
        cat = json.loads((RAIZ / "ot_assess" / "catalogos" / "en.json").read_text(encoding="utf-8"))["en"]
        faltan = [c for c in (*cc.COLUMNAS, *cc.COLUMNAS_ZONAS, cc.HOJA, "punto", "archivo") if c not in cat]
        self.assertEqual(faltan, [])

    def test_la_cache_guarda_y_recupera_la_cobertura(self):
        acum = cc.Acumulador({"frame.time_epoch": 0, "frame.len": 1, "vlan.id": 2, "ip.src": 3, "ip.dst": 4})
        acum.fila([str(T0), "100", "20", "192.0.2.1", "192.0.2.2"])
        dato = acum.cerrar()
        self.assertEqual(cache.decodificar(json.loads(json.dumps(cache.codificar(dato)))), dato)

    def test_sesiones_de_un_sentido(self):
        campos = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
                  "tcp.len"]
        acum = cc.Acumulador({c: i for i, c in enumerate(campos)})
        # sesion 0 en los dos sentidos; sesion 1 solo del cliente; sesion 2 sin datos (solo el saludo)
        for s, d, ps, pd, st, ln in (("192.0.2.1", "192.0.2.2", "5000", "502", "0", "5"),
                                     ("192.0.2.2", "192.0.2.1", "502", "5000", "0", "5"),
                                     ("192.0.2.1", "192.0.2.2", "5001", "502", "1", "5"),
                                     ("192.0.2.1", "192.0.2.2", "5002", "502", "2", "0")):
            acum.fila([str(T0), "60", s, d, st, ps, pd, ln])
        r = acum.cerrar()
        self.assertEqual((r["ses_datos"], r["ses_uno"]), (2, 1))


class PerfilTest(unittest.TestCase):
    def test_vlans_esperadas_del_perfil(self):
        from ot_assess import perfil
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        base = {"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}]}

        def cargar(extra):
            p = d / "p.json"
            p.write_text(json.dumps(dict(base, **extra)), encoding="utf-8")
            return perfil.cargar(p)

        self.assertEqual(cargar({"vlans_esperadas": [20, 10, 10]})["vlans_esperadas"], [10, 20])
        for malo in ([0], [4095], ["10"], [True], 10):
            with self.assertRaises(SystemExit):
                cargar({"vlans_esperadas": malo})


@LEE_CAPTURAS
class ValidarCapturaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def corrida(self, nombre, paquetes, *extra):
        entrada = escribir(paquetes, self.tmp / nombre / "sensor" / f"{nombre}.pcap")
        salida = self.tmp / nombre / "salida"
        rc, out, _err = validar([entrada], salida, *extra)
        self.assertEqual(rc, 0, out)
        return punto(salida), salida

    def test_1_captura_sana_es_apta(self):
        p, _ = self.corrida("sana", lecturas())
        self.assertEqual(p["veredicto"], "apta", p["motivos"])
        self.assertEqual(p["perdida_tcp_pct"], "0.00")
        self.assertEqual(p["sesiones_un_sentido_pct"], "0.0")
        self.assertIn("Modbus/TCP", p["protocolos_industriales"])

    def test_2_perdida_de_segmentos_tcp(self):
        p, _ = self.corrida("perdida_alta", lecturas(soltar=set(range(3, LECTURAS, 8))))
        self.assertEqual(p["veredicto"], "no apta")
        self.assertIn("perdida de segmentos TCP", p["motivos"])
        self.assertGreater(float(p["perdida_tcp_pct"]), 5)
        p, _ = self.corrida("perdida_media", lecturas(soltar=set(range(3, LECTURAS, 25))))
        self.assertEqual(p["veredicto"], "apta con limitaciones")
        self.assertIn("perdida de segmentos TCP", p["motivos"])
        self.assertTrue(1 < float(p["perdida_tcp_pct"]) <= 5, p["perdida_tcp_pct"])

    def test_3_sesiones_de_un_solo_sentido(self):
        p, _ = self.corrida("un_sentido", lecturas(unidireccional=True))
        self.assertEqual(p["veredicto"], "no apta")
        self.assertIn("un solo sentido", p["motivos"])
        self.assertEqual(float(p["sesiones_un_sentido_pct"]), 100.0)

    def test_4_hueco_de_seis_minutos(self):
        p, _ = self.corrida("hueco", lecturas(hueco=(100, 360 - PASO)))
        self.assertEqual(p["veredicto"], "apta con limitaciones")
        self.assertIn("huecos sin paquetes", p["motivos"])
        self.assertEqual(p["huecos"], "1")

    def test_5_zonas_y_vlans_esperadas(self):
        perfil = self.tmp / "perfil.json"
        perfil.write_text(json.dumps({
            "version": 1, "cliente": "Cliente de prueba", "marcos": [{"clave": "iec62443"}],
            "vlans_esperadas": [10],
            "zonas": [{"nombre": "Zona A", "redes": ["192.0.2.0/24"]},
                      {"nombre": "Zona B", "redes": ["198.51.100.0/24"]}]}), encoding="utf-8")
        p, salida = self.corrida("zonas", lecturas(vlan=20), "--perfil", str(perfil), "--vlans-esperadas", "20,30")
        self.assertEqual(p["veredicto"], "apta con limitaciones")
        self.assertIn("VLAN esperadas sin trafico: 10, 30", p["motivos"])
        self.assertIn("zonas declaradas sin trafico: Zona B", p["motivos"])
        self.assertEqual(p["vlans_vistas"], "20")
        estados = {f["nombre"]: f["estado"] for f in _csv(salida / "cobertura_zonas.csv")}
        self.assertEqual(estados["Zona A"], "vista")
        self.assertEqual(estados["Zona B"], "sin trafico")
        self.assertEqual(estados["192.0.2.0/24"], "vista")     # la subred inferida

    def test_5b_zona_solo_con_difusion(self):
        from scapy.all import IP, UDP, Ether, Raw
        pk = lecturas()
        for i in range(0, LECTURAS, 3):
            x = (Ether(src="02:00:00:c1:00:09", dst="ff:ff:ff:ff:ff:ff") / IP(src="203.0.113.9", dst="255.255.255.255")
                 / UDP(sport=40000, dport=5000) / Raw(b"hola"))
            x.time = T0 + i * PASO + 5
            pk.append(x)
        perfil = self.tmp / "perfil_dif.json"
        perfil.write_text(json.dumps({"version": 1, "cliente": "X", "marcos": [{"clave": "iec62443"}],
                                      "zonas": [{"nombre": "Zona C", "redes": ["203.0.113.0/24"]}]}), encoding="utf-8")
        p, salida = self.corrida("difusion", pk, "--perfil", str(perfil))
        self.assertEqual({f["nombre"]: f["estado"] for f in _csv(salida / "cobertura_zonas.csv")}["Zona C"],
                         "solo difusion")
        self.assertNotIn("zonas declaradas sin trafico", p["motivos"])    # hay difusion: no es "sin trafico"

    def test_6_dos_archivos_de_una_carpeta_son_un_punto(self):
        pk = lecturas()
        mitad = len(pk) // 2
        entrada = self.tmp / "rotados" / "sensor"
        escribir(pk[:mitad], entrada / "parte1.pcap")
        escribir(pk[mitad:], entrada / "parte2.pcap")
        salida = self.tmp / "rotados" / "salida"
        rc, _out, _err = validar([entrada], salida)
        self.assertEqual(rc, 0)
        filas = _csv(salida / "cobertura_captura.csv")
        self.assertEqual([f["nivel"] for f in filas], ["punto", "archivo", "archivo"])
        self.assertEqual(int(filas[0]["paquetes"]), int(filas[1]["paquetes"]) + int(filas[2]["paquetes"]))
        self.assertEqual(filas[0]["punto"], "sensor")
        self.assertEqual(filas[0]["veredicto"], "apta", filas[0]["motivos"])    # 25 h juntos, ninguno por separado
        self.assertEqual(filas[0]["huecos"], "0")

    def test_un_archivo_suelto_es_su_propio_punto(self):
        p, _ = self.corrida("suelto", lecturas(n=20))
        self.assertEqual(p["punto"], "suelto.pcap")
        self.assertEqual(p["veredicto"], "apta con limitaciones")     # 80 min: no cubre un ciclo diario
        self.assertIn("menos de un ciclo diario", p["motivos"])

    def test_truncados(self):
        pk = lecturas(n=40)
        pk[10].wirelen = len(pk[10]) + 100       # el archivo guarda menos que el largo original
        _, salida = self.corrida("truncada", pk)
        self.assertEqual(punto(salida)["truncados"], "1")

    def test_8_validar_no_escribe_inventario_ni_hallazgos_y_coincide_con_el_completo(self):
        entrada = self.tmp / "coincide" / "sensor"
        escribir(lecturas(soltar=set(range(3, LECTURAS, 25))), entrada / "a.pcap")
        salida = self.tmp / "coincide" / "rapido"
        i0 = time.monotonic()
        rc, out, _err = validar([entrada], salida)
        rapido = time.monotonic() - i0
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(p.name for p in salida.iterdir()),
                         ["cobertura_captura.csv", "cobertura_zonas.csv", "validacion_captura.html"])
        self.assertIn("Tiempo:", out)
        html = (salida / "validacion_captura.html").read_text(encoding="utf-8")
        self.assertIn("apta con limitaciones", html)
        completo = self.tmp / "coincide" / "completo"
        i0 = time.monotonic()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            main_completo([str(entrada), "-o", str(completo)])
        lento = time.monotonic() - i0
        i18n.usar("es")
        print(f"\n[C1] validar-captura {rapido:.1f} s frente a {lento:.1f} s del analisis completo", file=sys.stderr)
        self.assertLess(rapido, lento)
        rap, comp = punto(salida), json.loads((completo / "resultado.json").read_text("utf-8"))["cobertura_captura"]
        self.assertEqual(comp["puntos"][0]["veredicto"], rap["veredicto"])
        self.assertEqual(comp["puntos"][0]["motivos"], rap["motivos"].split("; "))
        self.assertEqual(comp["puntos"][0]["paquetes"], int(rap["paquetes"]))
        self.assertTrue((completo / "cobertura_zonas.csv").is_file())
        self.assertEqual(_csv(completo / "cobertura_captura.csv")[0]["veredicto"], rap["veredicto"])
        for n in ("reporte_ot.html", "reporte_ot.md"):
            texto = (completo / n).read_text(encoding="utf-8")
            self.assertIn("Validacion de la captura", texto)
            self.assertLess(texto.index("Validacion de la captura"), texto.index("Resumen"), n)

    def test_9_ingles_sin_claves_faltantes(self):
        entrada = escribir(lecturas(n=2, vlan=20), self.tmp / "ingles" / "sensor" / "a.pcap")
        i18n.FALTANTES.clear()
        rc, out, _err = validar([entrada], self.tmp / "ingles" / "salida", "--idioma", "en", "--vlans-esperadas", "10")
        faltan = set(i18n.FALTANTES)
        i18n.usar("es")
        self.assertEqual(rc, 0)
        self.assertEqual(faltan, set())
        self.assertIn("without traffic", out)
        filas = _csv(self.tmp / "ingles" / "salida" / "cobertura_captura.csv")
        self.assertEqual([(f["level"], f["verdict"]) for f in filas][0], ("point", "not suitable"))
        self.assertEqual(filas[1]["level"], "file")

    def test_captura_ilegible_no_detiene(self):
        malo = self.tmp / "mala" / "sensor" / "mala.pcap"
        malo.parent.mkdir(parents=True)
        malo.write_bytes(b"no es una captura")
        bueno = escribir(lecturas(n=30), self.tmp / "mala" / "sensor" / "buena.pcap")
        salida = self.tmp / "mala" / "salida"
        rc, _out, _err = validar([bueno, malo], salida)
        self.assertEqual(rc, 0)
        filas = _csv(salida / "cobertura_captura.csv")
        self.assertTrue(next(f for f in filas if f["archivo"] == "mala.pcap")["error"])
        rc, _out, _err = validar([malo], self.tmp / "mala" / "otra")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
