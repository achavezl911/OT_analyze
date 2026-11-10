"""Cache de lectura de capturas (E6, D63). Requiere tshark y scapy; si faltan, se omite."""
from __future__ import annotations

import collections
import contextlib
import gzip
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from ot_assess import cache_capturas as cc

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

HAY = bool(shutil.which("tshark") and HAY_SCAPY)
SALIDAS = ("inventario.csv", "comunicaciones.csv", "hallazgos.csv", "control.csv", "identidad.csv",
           "reporte_ot.md", "resultado.json")


def igual(a, b, ruta="cap"):
    """Igualdad estricta: mismo tipo, mismo contenido y mismo orden en dict/Counter."""
    assert type(a) is type(b), f"{ruta}: {type(a).__name__} != {type(b).__name__}"
    if isinstance(a, dict):
        assert list(a) == list(b), f"{ruta}: claves o su orden difieren"
        for k in a:
            igual(a[k], b[k], f"{ruta}[{k!r}]")
    elif isinstance(a, (list, tuple)):
        assert len(a) == len(b), f"{ruta}: largo"
        for i, (x, y) in enumerate(zip(a, b)):
            igual(x, y, f"{ruta}[{i}]")
    else:
        assert a == b, f"{ruta}: {a!r} != {b!r}"
    return True


class CodificadorTest(unittest.TestCase):
    """Sin tshark: el codificador reconstruye exactamente los mismos tipos."""

    def vuelta(self, x):
        return cc.decodificar(json.loads(json.dumps(cc.codificar(x))))

    def test_tipos_etiquetados(self):
        x = {"a": {1, 2}, "b": collections.Counter({("tcp", 502): 3, ("udp", 53): 1}),
             "c": (1, ("x", 2)), "d": {("s", "d", 80, "tcp"): {"n": 1}}, "e": Path("/x/y"),
             "f": frozenset({"q"}), 3: "clave int", "g": [None, True, 1.5, "ñ"],
             "__t": "trampa"}
        igual(x, self.vuelta(x))

    def test_dict_con_etiqueta_no_se_confunde(self):
        x = {"__t": "tuple", "v": [1, 2]}
        self.assertEqual(self.vuelta(x), x)

    def test_tipo_no_soportado_falla(self):
        with self.assertRaises(cc.NoSoportado):
            cc.codificar({"a": object()})
        with self.assertRaises(cc.NoSoportado):
            cc.codificar(collections.defaultdict(int))

    def test_etiqueta_desconocida_falla(self):
        with self.assertRaises(ValueError):
            cc.decodificar({"__t": "pickle", "v": "x"})


@unittest.skipUnless(HAY, "requiere tshark y scapy")
class CacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pcaps = cls.tmp / "pcaps"
        cls.pcaps.mkdir()
        for n, pk in (("punto_a", g.punto_a()), ("punto_b", g.punto_b()), ("punto_dns", g.punto_dns()),
                      ("punto_opcua", g.punto_opcua()), ("punto_dnp3", g.punto_dnp3_reinicio())):
            g.guardar(pk, cls.pcaps / f"{n}.pcap")
        cls.n = 5
        cls.cache0 = cls.tmp / "cache0"
        cls.rc, cls.out0, _, _ = cls.correr("o0", "--cache", str(cls.cache0))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, nombre, *extra, pcaps=None):
        from ot_assess.cli import main
        out = cls.tmp / nombre
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            rc = main([str(pcaps or cls.pcaps), "-o", str(out), "--no-diagrams", *extra])
        return rc, out, so.getvalue(), se.getvalue()

    def setUp(self):
        self.cache = self.tmp / f"c_{self._testMethodName}"
        shutil.copytree(self.cache0, self.cache)
        self.addCleanup(shutil.rmtree, self.cache, ignore_errors=True)

    @staticmethod
    def leidos(salida):
        return salida.count("    leida"), salida.count("desde cache (sin leer")

    def norm(self, out):
        """Contenido de las salidas sin lo que cambia entre corridas (fechas, duraciones, rutas)."""
        import re
        res = {}
        for n in SALIDAS:
            t = (out / n).read_text(encoding="utf-8-sig")
            t = t.replace(str(out), "OUT").replace(str(self.pcaps), "PCAPS")
            t = re.sub(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?", "FECHA", t)
            t = re.sub(r"\d\d:\d\d [A-Z]{2,5}\b", "HORA", t)
            # fecha suelta del encabezado ("Generado el AAAA-MM-DD HORA"): la CI puede cruzar la medianoche
            # entre la corrida de referencia y la cacheada (fallo real en la CI de v0.22.0)
            t = re.sub(r"\d{4}-\d\d-\d\d", "DIA", t)
            t = re.sub(r'"(duracion|duracion_s|elapsed)[^"]*": [\d.]+', '"DUR": 0', t)
            res[n] = t
        return res

    # (1) ida y vuelta sobre capturas reales de tshark
    def test_ida_y_vuelta_de_capture(self):
        from ot_assess.cli import FLOW_FIELDS, analyze_detail, analyze_flows
        from ot_assess.fields import DETAIL_FIELDS, DETAIL_FILTER_PARTS
        from ot_assess.model import Capture
        from ot_assess.tools import Tshark, find_tool
        ts = Tshark(find_tool("tshark"), find_tool("capinfos"), find_tool("editcap"), self.tmp / "pr")
        archivos = sorted(self.pcaps.glob("*.pcap"))
        ts.make_probe(archivos[0])
        ff, df = ts.valid_fields(FLOW_FIELDS), ts.valid_fields(DETAIL_FIELDS)
        filtro = ts.valid_filter(DETAIL_FILTER_PARTS)
        tipos = set()
        for f in archivos:
            cap = Capture(f)
            cap.info = ts.capinfos(f)
            cap.protos = ts.phs(f)
            analyze_flows(ts, cap, ff, 0)
            analyze_detail(ts, cap, df, filtro)
            d = json.loads(json.dumps(cc.capture_a_dict(cap)))
            cap2 = cc.capture_desde_dict(d, f)
            self.assertTrue(igual(vars(cap), vars(cap2)), f.name)
            tipos.update(type(v).__name__ for v in vars(cap).values())
            tipos.update(type(k).__name__ for k in cap.flows)
        self.assertIn("tuple", tipos)       # flows con claves tupla
        self.assertIn("Counter", tipos)

    # (2) segunda corrida sin tshark y con las mismas salidas
    def test_segunda_corrida_no_invoca_tshark(self):
        from ot_assess.tools import Tshark

        def falla(*a, **k):
            raise AssertionError("se invoco tshark/capinfos/editcap para leer una captura en cache")
        with mock.patch.object(Tshark, "phs", falla), mock.patch.object(Tshark, "fields_pass", falla), \
                mock.patch.object(Tshark, "capinfos", falla), mock.patch.object(Tshark, "duplicados", falla):
            rc, out, so, _ = self.correr("o_hit", "--cache", str(self.cache))
        self.assertEqual(rc, 0)
        self.assertEqual(self.leidos(so), (0, self.n))
        self.assertIn(f"{self.n} de {self.n} capturas desde cache", so)
        self.assertEqual(self.norm(out), self.norm(self.out0))

    def test_primera_corrida_lee_y_cache_igual_a_sin_cache(self):
        self.assertEqual(self.rc, 0)
        rc, out, so, _ = self.correr("o_sin")
        self.assertEqual(rc, 0)
        self.assertEqual(self.leidos(so), (0, 0))
        self.assertEqual(self.norm(out), self.norm(self.out0))

    # (3) cualquier cambio de la clave es fallo de cache
    def test_byte_distinto_del_pcap(self):
        copia = self.tmp / "pcaps_mod"
        shutil.copytree(self.pcaps, copia, dirs_exist_ok=True)
        p = copia / "punto_b.pcap"
        datos = bytearray(p.read_bytes())
        datos[-1] ^= 0x01
        p.write_bytes(bytes(datos))
        self.addCleanup(shutil.rmtree, copia, ignore_errors=True)
        rc, _, so, _ = self.correr("o_byte", "--cache", str(self.cache), pcaps=copia)
        self.assertEqual(rc, 0)
        self.assertEqual(self.leidos(so), (1, self.n - 1))

    def test_version_distinta(self):
        with mock.patch.object(cc, "__version__", "9.9.9"):
            _, _, so, _ = self.correr("o_ver", "--cache", str(self.cache))
        self.assertEqual(self.leidos(so), (self.n, 0))

    def test_max_packets_y_no_detail_distintos(self):
        _, _, so, _ = self.correr("o_mp", "--cache", str(self.cache), "--max-packets", "50")
        self.assertEqual(self.leidos(so), (self.n, 0))
        _, _, so, _ = self.correr("o_nd", "--cache", str(self.cache), "--no-detail")
        self.assertEqual(self.leidos(so), (self.n, 0))

    def test_cache_renovar_relee_y_reescribe(self):
        _, _, so, _ = self.correr("o_ren", "--cache", str(self.cache), "--cache-renovar")
        self.assertEqual(self.leidos(so), (self.n, 0))
        _, _, so, _ = self.correr("o_ren2", "--cache", str(self.cache))
        self.assertEqual(self.leidos(so), (0, self.n))

    # (4) archivos danados
    def test_archivo_corrupto_avisa_y_relee(self):
        victima = sorted(self.cache.glob("*.json.gz"))[0]
        victima.write_bytes(b"esto no es gzip")
        rc, out, so, se = self.correr("o_corr", "--cache", str(self.cache))
        self.assertEqual(rc, 0)
        self.assertEqual(self.leidos(so), (1, self.n - 1))
        self.assertIn("[!] cache:", se)
        self.assertEqual(self.norm(out), self.norm(self.out0))

    def test_formato_o_clave_distintos_avisan_y_releen(self):
        a, b = sorted(self.cache.glob("*.json.gz"))[:2]
        for arch, cambio in ((a, {"formato": 99}), (b, {"clave": "otra"})):
            doc = json.loads(gzip.open(arch).read())
            doc.update(cambio)
            arch.write_bytes(gzip.compress(json.dumps(doc).encode()))
        _, _, so, se = self.correr("o_fmt", "--cache", str(self.cache))
        self.assertEqual(self.leidos(so), (2, self.n - 2))
        self.assertEqual(se.count("[!] cache:"), 2)

    def test_tipo_no_soportado_en_archivo_no_ejecuta_nada(self):
        victima = sorted(self.cache.glob("*.json.gz"))[0]
        doc = json.loads(gzip.open(victima).read())
        doc["captura"]["hosts"] = {"__t": "__reduce__", "v": ["os.system", "x"]}
        victima.write_bytes(gzip.compress(json.dumps(doc).encode()))
        _, _, so, se = self.correr("o_mal", "--cache", str(self.cache))
        self.assertEqual(self.leidos(so), (1, self.n - 1))
        self.assertIn("[!] cache:", se)

    # (5) el perfil actual manda: las reglas corren de nuevo
    def test_perfil_distinto_con_cache_igual_que_sin_cache(self):
        perfil = json.loads((RAIZ / "docs" / "ejemplos" / "perfil.json").read_text(encoding="utf-8"))
        perfil["dominios_internos"] = ["example.com"]
        p = self.tmp / "perfil_dns.json"
        p.write_text(json.dumps(perfil), encoding="utf-8")
        _, out_c, so, _ = self.correr("o_pc", "--cache", str(self.cache), "--perfil", str(p))
        self.assertEqual(self.leidos(so), (0, self.n))
        _, out_s, _, _ = self.correr("o_ps", "--perfil", str(p))
        self.assertEqual(self.norm(out_c)["hallazgos.csv"], self.norm(out_s)["hallazgos.csv"])
        self.assertEqual(self.norm(out_c)["resultado.json"], self.norm(out_s)["resultado.json"])
        # y difiere de la corrida sin ese dominio interno: las reglas se reevaluaron
        self.assertNotEqual(self.norm(out_c)["hallazgos.csv"], self.norm(self.out0)["hallazgos.csv"])

    # (6) permisos y ubicacion
    def test_archivos_600_y_solo_en_la_carpeta(self):
        if os.name != "posix":
            return
        archivos = list(self.cache0.iterdir())
        self.assertEqual(len(archivos), self.n)
        for a in archivos:
            self.assertTrue(a.name.endswith(".json.gz"), a.name)
            self.assertEqual(stat.S_IMODE(a.stat().st_mode), 0o600, a.name)
        self.assertEqual(sorted(p.name for p in self.pcaps.iterdir()),
                         sorted(f"{n}.pcap" for n in
                                ("punto_a", "punto_b", "punto_dns", "punto_opcua", "punto_dnp3")))
        self.assertEqual(list(self.out0.rglob("*.json.gz")), [])

    def test_cache_renovar_sin_cache_es_error(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.correr("o_err", "--cache-renovar")


if __name__ == "__main__":
    unittest.main()
