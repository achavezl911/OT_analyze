"""T6: catalogo KEV y avisos ICS (CSAF) de CISA, desde archivos locales, cruzados por CVE (D66).

Todos los datos son FICTICIOS (CVE-2099-xxxx, avisos ICSA-99-...), generados aqui.
Unitarias sin tshark; extremo a extremo por `diagrama` (exportaciones) y por capturas (tshark y scapy).
"""
from __future__ import annotations

import contextlib
import csv
import datetime
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

import gen_exports

from ot_assess import avisos_cisa as ac
from ot_assess import i18n
from ot_assess import vulnerabilidades as vu
from ot_assess.cli import main
from ot_assess.model import Capture

EJEMPLOS = RAIZ / "docs" / "ejemplos"
CAMPOS_KEV = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
              "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes"]
KEV = [
    ("CVE-2099-0001", "2099-01-05", "2099-01-26", "Known"),
    ("CVE-2099-0002", "2099-02-01", "2099-02-22", "Unknown"),
    ("CVE-2099-0009", "2099-02-03", "2099-02-24", "Unknown"),
]
ACTIVOS = {"k1": {"nombre": "PLC-UNO", "ips": ["10.0.0.1"], "mac": "k1"},
           "k2": {"nombre": "PLC-DOS", "ips": ["10.0.0.2"], "mac": "k2"}}


def kev_filas():
    return [{"cveID": c, "vendorProject": "Fab ficticio", "product": "Producto", "vulnerabilityName": f"Falla {c}",
             "dateAdded": a, "shortDescription": "d", "requiredAction": "Aplicar", "dueDate": d,
             "knownRansomwareCampaignUse": r, "notes": ""} for c, a, d, r in KEV]


def escribir_kev_json(path, fecha="2099-02-10"):
    path.write_text(json.dumps({"title": "x", "catalogVersion": "2099.02.10", "dateReleased": fecha + "T10:00:00.000Z",
                                "count": len(KEV), "vulnerabilities": kev_filas()}), encoding="utf-8")
    return path


def escribir_kev_csv(path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CAMPOS_KEV)
        w.writeheader()
        w.writerows(kev_filas())
    return path


def csaf(aid, cves, titulo=None, actual="2099-02-01T00:00:00Z"):
    """cves: {cve: (cvss, [categorias])}."""
    return {"document": {"category": "csaf_security_advisory", "csaf_version": "2.0",
                         "title": titulo or f"Aviso {aid}",
                         "tracking": {"id": aid, "initial_release_date": "2099-01-01T00:00:00Z",
                                      "current_release_date": actual},
                         "references": [{"category": "external", "url": "https://x.example/otro"},
                                        {"category": "self", "summary": aid, "url": f"https://x.example/{aid}"}]},
            "vulnerabilities": [{"cve": cve,
                                 "scores": [{"cvss_v3": {"baseScore": cv}}],
                                 "remediations": [{"category": c, "details": f"Detalle {c} " + "x" * 400}
                                                  for c in cats]}
                                for cve, (cv, cats) in cves.items()]}


def carpeta_avisos(base: Path) -> Path:
    d = base / "avisos"
    (d / "sub").mkdir(parents=True)
    esc = lambda p, o: p.write_text(json.dumps(o), encoding="utf-8")
    esc(d / "ICSA-99-001-01.json", csaf("ICSA-99-001-01", {"CVE-2099-0001": (9.8, ["vendor_fix"]),
                                                          "CVE-2099-0002": (5.0, ["mitigation"])}))
    esc(d / "sub" / "ICSA-99-002-01.json", csaf("ICSA-99-002-01", {"cve-2099-0001": (7.5, ["workaround", "none_available"])}))
    esc(d / "sub" / "ICSA-99-003-01.json", csaf("ICSA-99-003-01", {"CVE-2099-7777": (9.0, ["vendor_fix"])}))
    esc(d / "no_es_csaf.json", {"a": 1})
    (d / "grande.json").write_text(json.dumps({"relleno": "z" * 9000}), encoding="utf-8")
    try:
        os.symlink(d / "ICSA-99-001-01.json", d / "enlace.json")
    except (OSError, NotImplementedError):
        pass
    return d


def cruces(vulns):
    c = vu.cruzar(vulns, ACTIVOS)
    return c


def v(cve, ip, estado="abierta", sev="Alta", cvss=7.5):
    return {"cve": cve, "severidad": sev, "cvss": cvss, "estado": estado, "activo": "", "ip": ip, "mac": "",
            "producto": "", "version": "", "fuente": ""}


class KevTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_json_y_csv_dan_el_mismo_cruce(self):
        j = ac.cargar_kev(escribir_kev_json(self.tmp / "kev.json"))
        c = ac.cargar_kev(escribir_kev_csv(self.tmp / "kev.dat"))      # extension distinta: se detecta por contenido
        self.assertEqual(j["por_cve"], c["por_cve"])
        self.assertEqual((j["version"], j["fecha"]), ("2099.02.10", "2099-02-10"))
        vulns = [v("CVE-2099-0001", "10.0.0.1"), v("CVE-2099-0005", "10.0.0.2")]
        filas = []
        for kev in (j, c):
            cr = cruces(vulns)
            ac.anotar(cr, kev, None)
            filas.append({f[2]: f[-6:] for f in vu.filas_tabla(cr, ACTIVOS)})
        self.assertEqual(filas[0], filas[1])
        self.assertEqual(filas[0]["CVE-2099-0001"], ["si", "2099-01-05", "2099-01-26", "si", "", ""])
        self.assertEqual(filas[0]["CVE-2099-0005"], ["no", "", "", "", "", ""])

    def test_columnas_nuevas_al_final_y_vacias_sin_kev(self):
        self.assertEqual(vu.COLUMNAS[-6:], ac.COLUMNAS_KEV)
        cr = cruces([v("CVE-2099-0001", "10.0.0.1")])
        ac.anotar(cr, None, None)
        self.assertEqual(vu.filas_tabla(cr, ACTIVOS)[0][-6:], [""] * 6)
        self.assertEqual(len(vu.filas_tabla(cr, ACTIVOS)[0]), len(vu.COLUMNAS))

    def test_errores_claros_sin_ruta_absoluta(self):
        malo = self.tmp / "malo.json"
        malo.write_text('{"otra": 1}', encoding="utf-8")
        roto = self.tmp / "roto.json"
        roto.write_text("{no es json", encoding="utf-8")
        csv_otro = self.tmp / "otro.csv"
        csv_otro.write_text("a,b\n1,2\n", encoding="utf-8")
        for p in (malo, roto, csv_otro, self.tmp / "no_existe.json"):
            with self.assertRaises(SystemExit) as cm:
                ac.cargar_kev(p)
            self.assertIn(p.name, str(cm.exception))
            self.assertNotIn(str(self.tmp), str(cm.exception))


class AvisosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.dir = carpeta_avisos(cls.tmp)
        with mock.patch.object(ac, "MAX_BYTES_AVISO", 5000):
            cls.av = ac.cargar_avisos(cls.dir, {"CVE-2099-0001", "CVE-2099-0002"})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_conteos(self):
        av = self.av
        self.assertEqual(av["leidos"], 4)           # 3 CSAF + 1 JSON que no lo es; el enlace no se sigue
        self.assertEqual((av["avisos_csaf"], av["saltados"], av["sobre_tamano"], av["sobrantes"]), (3, 1, 1, 0))
        self.assertEqual(sorted(av["avisos"]), ["ICSA-99-001-01", "ICSA-99-002-01"])
        self.assertEqual(av["ultimo"], "2099-02-01")
        self.assertEqual(av["entrada"]["archivo"], "avisos")
        self.assertEqual(av["entrada"]["json_leidos"], 4)
        self.assertEqual(len(av["entrada"]["sha256"]), 64)
        msgs = ac.avisos_de_carga(av)
        self.assertEqual(len(msgs), 2)               # uno por tema, no uno por archivo
        for m in msgs:
            self.assertNotIn(str(self.tmp), m)

    def test_se_guarda_solo_lo_de_los_cve_de_la_red_y_acotado(self):
        a = self.av["avisos"]["ICSA-99-001-01"]
        self.assertEqual(sorted(a["cves"]), ["CVE-2099-0001", "CVE-2099-0002"])
        self.assertLessEqual(len(a["cves"]["CVE-2099-0001"]["extracto"]), ac.EXTRACTO)
        self.assertEqual(a["url"], "https://x.example/ICSA-99-001-01")
        self.assertEqual(self.av["avisos"]["ICSA-99-002-01"]["cves"]["CVE-2099-0001"]["categorias"],
                         ["none_available", "workaround"])

    def test_hash_estable_y_cambia_con_el_contenido(self):
        otra = ac.cargar_avisos(self.dir, set())
        self.assertNotEqual(otra["entrada"]["sha256"], self.av["entrada"]["sha256"])   # grande.json cuenta aqui
        con = ac.cargar_avisos(self.dir, {"CVE-2099-0001"})
        self.assertEqual(con["entrada"]["sha256"], otra["entrada"]["sha256"])

    def test_limite_de_archivos(self):
        with mock.patch.object(ac, "MAX_ARCHIVOS", 2), mock.patch.object(ac, "MAX_BYTES_AVISO", 5000):
            av = ac.cargar_avisos(self.dir, {"CVE-2099-0001"})
        self.assertEqual(av["sobrantes"], 3)
        self.assertEqual(av["leidos"] + av["sobre_tamano"], 2)
        self.assertTrue(any("limite" in m for m in ac.avisos_de_carga(av)))

    def test_filas_avisos_orden_y_columnas(self):
        cr = cruces([v("CVE-2099-0001", "10.0.0.1"), v("CVE-2099-0002", "10.0.0.2", estado="mitigada"),
                     v("CVE-2099-0001", "10.0.0.9")])
        ac.anotar(cr, None, self.av)
        filas = ac.filas_avisos(cr, ACTIVOS)
        self.assertEqual(len(ac.COLUMNAS_AVISOS), len(filas[0]))
        self.assertEqual([f[0] for f in filas], ["ICSA-99-001-01", "ICSA-99-002-01"])     # cvss_max 9.8 y 7.5
        f1 = dict(zip(ac.COLUMNAS_AVISOS, filas[0]))
        self.assertEqual((f1["cves"], f1["activos"], f1["abiertas"], f1["cvss_max"], f1["remediaciones"]),
                         ("CVE-2099-0001;CVE-2099-0002", "PLC-DOS;PLC-UNO", 1, 9.8, "mitigation;vendor_fix"))
        self.assertEqual((f1["publicado"], f1["actualizado"], f1["titulo"]),
                         ("2099-01-01", "2099-02-01", "Aviso ICSA-99-001-01"))
        f2 = dict(zip(ac.COLUMNAS_AVISOS, filas[1]))
        self.assertEqual((f2["cves"], f2["remediaciones"]), ("CVE-2099-0001", "none_available;workaround"))
        # en vulnerabilidades.csv: ids de aviso y categorias por CVE
        tabla = {(f[2], f[1]): f[-2:] for f in vu.filas_tabla(cr, ACTIVOS)}
        self.assertEqual(tabla[("CVE-2099-0001", "10.0.0.1")],
                         ["ICSA-99-001-01;ICSA-99-002-01", "none_available;vendor_fix;workaround"])

    def test_un_json_que_no_es_csaf_solo_es_error(self):
        with self.assertRaises(SystemExit) as cm:
            ac.cargar_avisos(self.dir / "no_es_csaf.json", {"CVE-2099-0001"})
        self.assertNotIn(str(self.tmp), str(cm.exception))


class HallazgoTest(unittest.TestCase):
    def kev(self, fecha="2099-02-10"):
        return {"archivo": "k.json", "version": "2099.02.10", "fecha": fecha,
                "por_cve": {c: {"agregada": a, "limite": d, "ransomware": r, "producto": "", "nombre": "", "accion": ""}
                            for c, a, d, r in KEV}}

    def hallazgos(self, vulns, hoy=None, kev=None):
        cr = cruces(vulns)
        kev = kev or self.kev()
        ac.anotar(cr, kev, None)
        cap = Capture(Path("vulnerabilidades x"))
        ac.agregar_hallazgo_kev(cap, cr, ACTIVOS, kev, hoy)
        return cap.findings

    def test_alta_con_evidencia(self):
        h = self.hallazgos([v("CVE-2099-0001", "10.0.0.1"), v("CVE-2099-0005", "10.0.0.2")],
                           hoy=datetime.date(2099, 2, 20))
        self.assertEqual(len(h), 1)
        f = h[0]
        self.assertEqual((f["severidad"], f["titulo"]), ("Alta", ac.TITULO_KEV))
        for texto in ("2099.02.10", "2099-02-10", "PLC-UNO", "CVE-2099-0001", "2099-01-05", "ransomware: si",
                      "BOD 22-01", "no una obligacion"):
            self.assertIn(texto, f["evidencia"])
        self.assertNotIn("PLC-DOS", f["evidencia"])
        self.assertNotIn("desactualizado", f["evidencia"])
        self.assertEqual(f["activos"], ["10.0.0.1"])
        for marco in ("mitre-ics", "iec62443", "nerc-cip", "nist-800-82", "nist-csf"):
            self.assertIn(marco, f["referencias"])
        for prohibido in ("cumple", "no cumple"):
            self.assertNotIn(prohibido, (f["evidencia"] + f["por_que_importa"] + f["recomendacion"]).lower())

    def test_solo_abiertas_asociadas(self):
        self.assertEqual(self.hallazgos([v("CVE-2099-0001", "10.0.0.1", estado="mitigada")]), [])
        self.assertEqual(self.hallazgos([v("CVE-2099-0001", "10.0.0.1", estado="aceptada")]), [])
        self.assertEqual(self.hallazgos([v("CVE-2099-0001", "10.9.9.9")]), [])         # sin activo
        self.assertEqual(self.hallazgos([v("CVE-2099-0005", "10.0.0.1")]), [])         # abierta pero fuera del KEV
        # mitigada en KEV + abierta fuera del KEV: tampoco
        self.assertEqual(self.hallazgos([v("CVE-2099-0001", "10.0.0.1", estado="mitigada"),
                                         v("CVE-2099-0005", "10.0.0.1")]), [])

    def test_catalogo_viejo_con_fecha_de_corrida_fija(self):
        kev = self.kev("2099-01-01")
        self.assertEqual(ac.avisos_de_antiguedad(kev, None, datetime.date(2099, 1, 31)), [])        # 30 dias: no
        viejo = ac.avisos_de_antiguedad(kev, None, datetime.date(2099, 2, 1))                       # 31 dias
        self.assertEqual(len(viejo), 1)
        self.assertIn("2099-01-01", viejo[0])
        h = self.hallazgos([v("CVE-2099-0001", "10.0.0.1")], hoy=datetime.date(2099, 6, 1), kev=kev)
        self.assertIn("Catalogo del 2099-01-01; puede estar desactualizado", h[0]["evidencia"])
        h = self.hallazgos([v("CVE-2099-0001", "10.0.0.1")], hoy=datetime.date(2099, 1, 10), kev=kev)
        self.assertNotIn("desactualizado", h[0]["evidencia"])
        av = {"ultimo": "2099-01-01"}
        self.assertEqual(len(ac.avisos_de_antiguedad(None, av, datetime.date(2099, 3, 1))), 1)

    def test_hallazgo_de_vulnerabilidades_suma_n_en_kev(self):
        cr = cruces([v("CVE-2099-0001", "10.0.0.1"), v("CVE-2099-0005", "10.0.0.2")])
        cap = Capture(Path("x"))
        vu.agregar_hallazgo(cap, cr, ACTIVOS)
        self.assertNotIn("KEV", cap.findings[0]["evidencia"])      # sin --kev no cambia
        ac.anotar(cr, self.kev(), None)
        cap = Capture(Path("x"))
        vu.agregar_hallazgo(cap, cr, ACTIVOS)
        self.assertEqual(cap.findings[0]["titulo"], vu.TITULO)
        self.assertEqual(cap.findings[0]["severidad"], "Alta")
        self.assertIn("(1 en KEV)", cap.findings[0]["evidencia"])


class EjemplosTest(unittest.TestCase):
    def test_ejemplos_cargan(self):
        kev = ac.cargar_kev(EJEMPLOS / "kev_ejemplo.json")
        self.assertIn("CVE-2099-0001", kev["por_cve"])
        av = ac.cargar_avisos(EJEMPLOS / "avisos_ics", {"CVE-2099-0001", "CVE-2099-0003"})
        self.assertTrue(av["avisos"])


def _leer(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


class DiagramaE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        cls.vul = cls.tmp / "vul.csv"
        cls.vul.write_text("ip,cve,severidad,cvss,estado,producto,version,fuente\n"
                           "10.20.1.11,CVE-2099-0001,Critical,9.8,open,Firmware,1.0,Escaner\n"
                           "10.20.1.12,CVE-2099-0002,High,7.5,mitigated,Firmware,1.0,Escaner\n"
                           "10.20.1.13,CVE-2099-0005,Low,3.0,open,Firmware,1.0,Escaner\n", encoding="utf-8")
        cls.kev = escribir_kev_json(cls.tmp / "kev.json")
        cls.avisos = carpeta_avisos(cls.tmp)
        cls.base = ["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"])]
        cls.out = cls.correr("es", "--vulnerabilidades", str(cls.vul), "--kev", str(cls.kev),
                             "--avisos-ics", str(cls.avisos))
        i18n.FALTANTES.clear()
        cls.en = cls.correr("en", "--vulnerabilidades", str(cls.vul), "--kev", str(cls.kev),
                            "--avisos-ics", str(cls.avisos), "--idioma", "en")
        cls.faltantes = set(i18n.FALTANTES)
        i18n.usar("es")

    @classmethod
    def tearDownClass(cls):
        i18n.usar("es")
        i18n.FALTANTES.clear()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def correr(cls, nombre, *extra):
        out = cls.tmp / nombre
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([*cls.base, *extra, "-o", str(out)])
        cls.salida = buf.getvalue()
        assert rc == 0
        return out

    def test_hallazgo_y_csv(self):
        hall = [h for h in _leer(self.out / "hallazgos.csv") if ac.TITULO_KEV in h["titulo"]]
        self.assertEqual(len(hall), 1)
        self.assertEqual(hall[0]["severidad"], "Alta")
        self.assertIn("2099.02.10", hall[0]["evidencia"])
        vul = {r["cve"]: r for r in _leer(self.out / "vulnerabilidades.csv")}
        self.assertEqual((vul["CVE-2099-0001"]["kev"], vul["CVE-2099-0001"]["kev_ransomware"]), ("si", "si"))
        self.assertEqual(vul["CVE-2099-0005"]["kev"], "no")
        self.assertEqual(vul["CVE-2099-0001"]["avisos_ics"], "ICSA-99-001-01;ICSA-99-002-01")
        avisos = _leer(self.out / "avisos_ics.csv")
        self.assertEqual([a["aviso"] for a in avisos], ["ICSA-99-001-01", "ICSA-99-002-01"])
        self.assertEqual(avisos[0]["cvss_max"], "9.8")
        self.assertEqual(avisos[0]["activos"], "PLC-BOMBAS;PLC-TURBINA")

    def test_resultado_y_entorno_sin_rutas(self):
        res = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        r = res["vulnerabilidades"]
        self.assertEqual(r["kev"], {"archivo": "kev.json", "version": "2099.02.10", "fecha": "2099-02-10",
                                    "en_kev": 2, "abiertas_en_kev": 1})
        self.assertEqual(r["avisos_ics"], {"archivo": "avisos", "archivos_leidos": 5, "saltados": 2,
                                           "avisos_con_cruce": 2})
        e = res["entorno"]
        self.assertEqual(e["kev"]["archivo"], "kev.json")
        self.assertEqual(len(e["kev"]["sha256"]), 64)
        self.assertEqual((e["avisos_ics"]["archivo"], e["avisos_ics"]["json_leidos"]), ("avisos", 5))
        for archivo in ("resultado.json", "importacion.json"):
            self.assertNotIn(str(self.tmp), (self.out / archivo).read_text(encoding="utf-8"), archivo)

    def test_ingles_sin_faltantes_de_t6(self):
        self.maxDiff = None
        self.assertEqual(sorted(x for x in self.faltantes if "KEV" in x or "ICS" in x or "CISA" in x), [])
        titulos = [next(v for k, v in h.items() if k in ("title", "titulo")) for h in _leer(self.en / "hallazgos.csv")]
        self.assertIn("Actively exploited vulnerabilities (CISA KEV catalog) in assets", titulos)
        self.assertFalse([x for x in titulos if "Vulnerabilidades explotadas" in x])

    def test_sin_vulnerabilidades_avisa_y_sigue(self):
        out = self.correr("sin", "--kev", str(self.kev), "--avisos-ics", str(self.avisos))
        self.assertIn("no hay vulnerabilidades importadas que cruzar", self.salida)
        self.assertEqual(self.salida.count("no hay vulnerabilidades importadas"), 1)
        self.assertFalse((out / "avisos_ics.csv").exists())
        self.assertFalse((out / "vulnerabilidades.csv").exists())
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        # V1a (D89) si usa --kev y --avisos-ics aunque no haya vulnerabilidades: quedan en el entorno
        self.assertEqual(res["entorno"]["kev"]["archivo"], "kev.json")

    def test_solo_kev_no_crea_avisos_ics_csv(self):
        out = self.correr("solo_kev", "--vulnerabilidades", str(self.vul), "--kev", str(self.kev))
        self.assertFalse((out / "avisos_ics.csv").exists())
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("avisos_ics", res["vulnerabilidades"])

    def test_kev_ilegible_falla_con_mensaje(self):
        mal = self.tmp / "mal.json"
        mal.write_text("[1, 2]", encoding="utf-8")
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(io.StringIO()):
            main([*self.base, "--vulnerabilidades", str(self.vul), "--kev", str(mal), "-o", str(self.tmp / "m")])
        self.assertIn("mal.json", str(cm.exception))
        self.assertNotIn(str(self.tmp), str(cm.exception))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        g.guardar(g.punto_a(), pcaps / "a.pcap")
        vul = cls.tmp / "vul.csv"
        vul.write_text("ip,cve,severidad,cvss,estado\n10.10.1.20,CVE-2099-0001,Critical,9.8,open\n"
                       "10.10.1.40,CVE-2099-0002,High,7.5,mitigated\n", encoding="utf-8")
        kev = escribir_kev_csv(cls.tmp / "kev.csv")
        avisos = carpeta_avisos(cls.tmp)
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.rc = main([str(pcaps), "-o", str(cls.out), "--cache", str(cls.tmp / "cache"),
                           "--vulnerabilidades", str(vul), "--kev", str(kev), "--avisos-ics", str(avisos)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hallazgo_csv_y_entorno(self):
        self.assertEqual(self.rc, 0)
        hall = [h for h in _leer(self.out / "hallazgos.csv") if ac.TITULO_KEV in h["titulo"]]
        self.assertEqual(len(hall), 1)
        self.assertIn("2099-01-05", hall[0]["evidencia"])      # fecha agregada (CSV sin dateReleased)
        vul = {r["cve"]: r for r in _leer(self.out / "vulnerabilidades.csv")}
        self.assertEqual(vul["CVE-2099-0001"]["kev"], "si")
        self.assertEqual(vul["CVE-2099-0002"]["kev"], "si")
        self.assertEqual(len(_leer(self.out / "avisos_ics.csv")), 2)
        res = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["vulnerabilidades"]["kev"]["abiertas_en_kev"], 1)
        self.assertEqual(res["entorno"]["kev"]["archivo"], "kev.csv")
        self.assertEqual(res["entorno"]["avisos_ics"]["archivo"], "avisos")
        self.assertNotIn(str(self.tmp), json.dumps(res["entorno"]))
        self.assertNotIn(str(self.tmp), json.dumps(res["vulnerabilidades"]))


if __name__ == "__main__":
    unittest.main()
