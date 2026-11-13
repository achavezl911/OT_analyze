"""ESTADO1 (D140): salidas de solo estado, candidatos a hallazgo y ciclo de vida solo con URL oficial. Sintetico.

El modo captura requiere tshark y scapy (se omite sin ellos); el resto corre sin ellos.
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_cobertura_captura import LEE_CAPTURAS
from test_ent1 import _ent, _validar
from test_fwlog import FTD, IOS
from test_obsolescencia import REF, _activo, _tabla
from test_rm1 import _error
from test_zonas import _inventario_xdome

from ot_assess import entregables as en
from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import obsolescencia as ob
from ot_assess import solo_estado as se
from ot_assess.cli import main as main_completo
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture

PALABRAS = ("riesgo", "risk", "hallazgo", "finding", "recomend", "recommend", "vulnerab", "insegur", "insecure",
            "severidad", "severity")
CAB = ("fabricante", "producto", "version", "fecha_fin_soporte", "fecha_fin_venta", "fuente")


EN_COLUMNAS = ["finding_id", "category", "title", "severity", "source_of_data", "confidence", "evidence", "assets",
               "dataset_id", "target_deliverable", "review_status", "reviewed_by", "date", "comment"]


ZONAS = {"sl_objetivo": {"Control de proceso": "SL2"},
         "zonas": [{"nombre": "Control de proceso", "redes": ["10.10.1.16/28", "10.10.2.0/24"], "sl_t": "SL2"},
                   {"nombre": "Supervision", "redes": ["10.10.1.0/28"], "sl_t": "SL2", "inferida": True},
                   {"nombre": "Ingenieria", "redes": ["10.10.1.32/27"], "sl_t": "SL2", "inferida": True}]}


def _csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _lineas(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.reader(fh))


def _celdas(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [c for fila in csv.reader(fh) for c in fila]


def _xlsx_hojas(path):
    """(nombres de hoja, texto completo de las hojas)."""
    with zipfile.ZipFile(path) as z:
        wb = z.read("xl/workbook.xml").decode("utf-8")
        texto = " ".join(z.read(n).decode("utf-8") for n in z.namelist() if n.startswith("xl/worksheets/"))
    return re.findall(r'<sheet name="([^"]*)"', wb), texto


def _perfil_json(tmp, extra):
    p = Path(tmp) / "perfil.json"
    p.write_text(json.dumps({"version": 1, "cliente": "ACME", "marcos": [{"clave": "iec62443"}], **extra}),
                 encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Perfil
# --------------------------------------------------------------------------- #

class PerfilTest(unittest.TestCase):
    def test_valido_y_por_omision(self):
        from test_rm1 import _perfil
        self.assertEqual(_perfil({"solo_estado": {}})["solo_estado"], {"carpeta": "estado"})
        p = _perfil({"solo_estado": {"carpeta": "Solo_estado-1", "salidas": ["flujos.csv", "zonas.csv", "flujos.csv"],
                                     "entregable_destino": " Informe de hallazgos "}})["solo_estado"]
        self.assertEqual(p, {"carpeta": "Solo_estado-1", "salidas": ["flujos.csv", "zonas.csv"],
                             "entregable_destino": "Informe de hallazgos"})

    def test_cada_error(self):
        casos = [("lista", "debe ser un objeto"), ({"otra": 1}, "clave desconocida"),
                 ({"carpeta": ""}, "carpeta"), ({"carpeta": "a/b"}, "carpeta"), ({"carpeta": "x" * 41}, "carpeta"),
                 ({"carpeta": "con espacio"}, "carpeta"), ({"carpeta": 3}, "carpeta"),
                 ({"salidas": []}, "1 a 50"), ({"salidas": "flujos.csv"}, "1 a 50"),
                 ({"salidas": ["flujos.csv"] * 51}, "1 a 50"), ({"salidas": ["hallazgos.csv"]}, "hallazgos.csv"),
                 ({"salidas": ["flujos"]}, "flujos"), ({"salidas": [3]}, "salidas"),
                 ({"entregable_destino": ""}, "1 a 100"), ({"entregable_destino": "  "}, "1 a 100"),
                 ({"entregable_destino": "x" * 101}, "1 a 100"), ({"entregable_destino": 4}, "1 a 100")]
        for v, frag in casos:
            with self.subTest(v=v):
                self.assertIn(frag, _error({"solo_estado": v}))

    def test_errores_de_obsolescencia(self):
        casos = [({"exigir_url": "si"}, "exigir_url"), ({"exigir_url": 1}, "exigir_url"),
                 ({"dominios_oficiales": ["a.com"]}, "exigir_url"),
                 ({"exigir_url": False, "dominios_oficiales": ["a.com"]}, "exigir_url"),
                 ({"exigir_url": True, "dominios_oficiales": []}, "1 a 100"),
                 ({"exigir_url": True, "dominios_oficiales": "a.com"}, "1 a 100"),
                 ({"exigir_url": True, "dominios_oficiales": [f"d{i}.com" for i in range(101)]}, "1 a 100"),
                 ({"exigir_url": True, "dominios_oficiales": ["https://a.com"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["sinpunto"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["A.com"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["a..com"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["a.com/x"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["ab"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": ["a" * 250 + ".com"]}, "dominio valido"),
                 ({"exigir_url": True, "dominios_oficiales": [3]}, "dominio valido")]
        for v, frag in casos:
            with self.subTest(v=v):
                self.assertIn(frag, _error({"obsolescencia": v}))

    def test_obsolescencia_valida(self):
        from test_rm1 import _perfil
        o = _perfil({"obsolescencia": {"exigir_url": True, "dominios_oficiales": ["cisco.com", "a-b.example.org"],
                                       "clases": {"sin fuente oficial": "Pendiente"}}})["obsolescencia"]
        self.assertEqual(o["dominios_oficiales"], ["cisco.com", "a-b.example.org"])
        self.assertEqual(o["clases"], {"sin fuente oficial": "Pendiente"})
        self.assertIn("clases", _error({"obsolescencia": {"clases": {"sin fuente oficial": "X"}}}))


# --------------------------------------------------------------------------- #
# Obsolescencia con URL oficial
# --------------------------------------------------------------------------- #

def _rep(config, filas, activos=None):
    """`filas`: [(producto, fin, fuente)]; un activo Acme por producto."""
    tmp = tempfile.mkdtemp()
    try:
        tabla = _tabla(tmp, [["Acme", p, "", fin, "2020-01-01", f] for p, fin, f in filas], cab=CAB)
        analista, _ = ob.cargar_analista(tabla)
    finally:
        shutil.rmtree(tmp, True)
    activos = activos or [_activo(i + 1, fabricante="Acme", modelo=p, firmware="1.0")
                          for i, (p, _f, _s) in enumerate(filas)]
    return ob.construir(inv.construir(activos), analista, REF, "fin de la captura", config)


class ObsolescenciaTest(unittest.TestCase):
    FILAS: ClassVar[list] = [("CON-URL", "2020-01-01", "Cisco EoL https://www.cisco.com/c/eol-1.html"),
                             ("SIN-URL", "2020-01-01", "boletin interno"),
                             ("OTRO-DOM", "2020-01-01", "https://fabricante-falso.example.net/cisco.com")]

    def estados(self, config, filas=None):
        return {f["producto"]: f for f in _rep(config, filas or self.FILAS)["filas"]}

    def test_con_url_clasifica_y_sin_url_queda_sin_fuente_oficial(self):
        e = self.estados({"exigir_url": True})
        self.assertEqual(e["CON-URL"]["estado"], ob.F_VENCIDO)
        self.assertEqual(e["OTRO-DOM"]["estado"], ob.F_VENCIDO)         # sin lista de dominios basta una URL
        s = e["SIN-URL"]
        self.assertEqual(s["estado"], "sin fuente oficial")
        self.assertEqual((s["fin"], s["dias"], s["venta"]), ("", None, ""))
        self.assertEqual(s["fuente"], "boletin interno (sin URL oficial)")
        i = ob.COLUMNAS.index
        self.assertEqual([s["celdas"][i(c)] for c in ("fecha_fin_soporte", "dias", "reemplazo_sugerido")],
                         ["", "", ""])

    def test_sin_fuente_oficial_no_genera_hallazgo(self):
        rep = _rep({"exigir_url": True}, [("SIN-URL", "2020-01-01", "boletin interno")])
        self.assertIsNone(ob.agregar_hallazgos([], rep))
        sin = _rep({}, [("SIN-URL", "2020-01-01", "boletin interno")])
        self.assertIsNotNone(ob.agregar_hallazgos([], sin))      # sin la subclave si genera el hallazgo
        self.assertEqual(rep["resumen"]["por_estado"]["sin fuente oficial"], 1)

    def test_dominios_oficiales_por_el_host(self):
        e = self.estados({"exigir_url": True, "dominios_oficiales": ["cisco.com"]})
        self.assertEqual(e["CON-URL"]["estado"], ob.F_VENCIDO)          # www.cisco.com es subdominio
        self.assertEqual(e["OTRO-DOM"]["estado"], "sin fuente oficial")      # cisco.com solo esta en la ruta
        self.assertEqual(e["SIN-URL"]["estado"], "sin fuente oficial")
        raro = self.estados({"exigir_url": True, "dominios_oficiales": ["cisco.com"]},
                            [("A", "2020-01-01", "https://notcisco.com/x"), ("B", "2020-01-01", "https://cisco.com.x.net/")])
        self.assertEqual({p: f["estado"] for p, f in raro.items()}, {"A": "sin fuente oficial", "B": "sin fuente oficial"})

    def test_tabla_integrada_sin_url_queda_sin_fuente_oficial(self):
        so = {"macs": [], "ips": ["192.0.2.9"], "entradas": [("ips", "192.0.2.9", "plataforma:generico", ""),
                                                             ("nombre", "PC-1", "plataforma:generico", ""),
                                                             ("sistema_operativo", "Windows 7 Professional",
                                                              "plataforma:generico", "")]}
        normal = ob.construir(inv.construir([so]), [], REF, "fin de la captura", {})
        exigida = ob.construir(inv.construir([so]), [], REF, "fin de la captura", {"exigir_url": True})
        self.assertEqual(normal["filas"][0]["estado"], ob.F_VENCIDO)
        f = exigida["filas"][0]
        self.assertEqual(f["estado"], "sin fuente oficial")
        self.assertTrue(f["fuente"].endswith(" (sin URL oficial)"))
        self.assertIn("Microsoft", f["fuente"])

    def test_clases_aceptan_el_estado_nuevo(self):
        rep = _rep({"exigir_url": True, "clases": {"sin fuente oficial": "Pendiente de fuente"}},
                   [("SIN-URL", "2020-01-01", "x")])
        self.assertEqual(rep["filas"][0]["celdas"][len(ob.COLUMNAS)], "Pendiente de fuente")

    def test_sin_las_subclaves_el_csv_es_identico(self):
        a, b = _rep({}, self.FILAS), _rep({"exigir_url": False}, self.FILAS)
        self.assertEqual(ob.tablas(a), ob.tablas(b))
        self.assertNotIn("sin fuente oficial", a["resumen"]["por_estado"])
        self.assertEqual(a["resumen"]["por_estado"], b["resumen"]["por_estado"])

    def test_ingles(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        rep = _rep({"exigir_url": True}, [("SIN-URL", "2020-01-01", "x")])
        self.assertEqual(ob.tablas(rep)[0][3][0][ob.COLUMNAS.index("estado")], "no official source")


# --------------------------------------------------------------------------- #
# Candidatos
# --------------------------------------------------------------------------- #

def _hallazgo(titulo, fuente, evidencia="ev", sev="Media", **extra):
    return {"id": "H-" + titulo[:4], "severidad": sev, "titulo": titulo, "categoria": "Higiene",
            "evidencia": evidencia, "por_que_importa": "p", "recomendacion": "r", "captura": fuente,
            "referencias": {"iec62443": "SR 1.1"}, **extra}


def _res(perfil, hallazgos, caps=("a.pcap",), manifiesto=None):
    cs = [Capture(Path(n)) for n in caps]
    extra = {}
    for h in hallazgos:
        extra.setdefault(h["captura"], []).append(h)
    res = SimpleNamespace(caps=[], extras=[], perfil=perfil, manifiesto=manifiesto)
    for n, lista in extra.items():
        c = next((x for x in cs if x.name == n), None)
        destino = res.caps if c is not None else res.extras
        c = c or Capture(Path(n))
        c.name = n
        c.findings = lista
        destino.append(c)
    res.caps += [c for c in cs if c not in res.caps]
    return res


class CandidatosTest(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def test_clases_de_confianza(self):
        caps = {"a.pcap"}
        for fuente, esperado in [("a.pcap", "observado en trafico"), ("firewall fw.csv", "segun configuracion"),
                                 ("switches sw.txt", "segun configuracion"),
                                 ("salud de la red (switches)", "segun configuracion"),
                                 ("registro en firewalls y switches", "segun configuracion"),
                                 ("exportacion xdome", "segun plataforma"), ("vulnerabilidades v.csv", "segun plataforma"),
                                 ("alertas al.csv", "segun plataforma"),
                                 ("vulnerabilidades por firmware", "inferido por version"),
                                 ("reporte de obsolescencia", "inferido por version"),
                                 ("conductos entre zonas", "derivado"), ("rutas de ataque", "derivado")]:
            self.assertEqual(se.confianza(fuente, caps), esperado, fuente)

    def test_filas_orden_secreto_activos_y_destino(self):
        hs = [_hallazgo("Baja uno", "a.pcap", sev="Baja", activos=["10.0.0.2", "10.0.0.1"]),
              _hallazgo("Alta dos", "firewall fw.csv", sev="Alta", evidencia="enable secret 5 $1$abcd$Zxcvbnm123"),
              _hallazgo("Media tres", "conductos entre zonas")]
        res = _res({"solo_estado": {"entregable_destino": "Informe de hallazgos"}}, hs)
        filas = se.filas_candidatos(res, res.perfil["solo_estado"])
        por_id = {f[0]: f for f in filas}
        self.assertEqual(len(filas), 3)
        alta = por_id["H-Alta"]
        self.assertTrue(alta[6].startswith("[evidencia retenida: posible secreto ("), alta[6])
        self.assertNotIn("abcd", alta[6])
        self.assertNotIn("Zxcvbnm123", alta[6])
        baja = por_id["H-Baja"]
        self.assertEqual((baja[7], baja[5], baja[9], baja[8]), ("10.0.0.1;10.0.0.2", "observado en trafico",
                                                                 "Informe de hallazgos", ""))
        self.assertEqual(baja[10:], ["", "", "", ""])
        self.assertEqual(por_id["H-Medi"][5], "derivado")
        self.assertEqual(por_id["H-Alta"][5], "segun configuracion")
        self.assertEqual([f[3] for f in filas], ["Baja", "Alta", "Media"])      # el orden de hallazgos.csv

    def test_destino_desde_entregables_y_si_no_el_del_perfil(self):
        ent = _validar(_ent({"iec62443:SR 1.*": ["D-02"]}))
        hs = [_hallazgo("Con mapeo", "a.pcap"), _hallazgo("Sin mapeo", "a.pcap")]
        hs[1]["referencias"] = {"iec62443": "SR 7.1"}
        res = _res({"entregables": ent, "solo_estado": {"entregable_destino": "Informe"}}, hs)
        self.assertTrue(en.plan(res.perfil))
        filas = {f[2]: f for f in se.filas_candidatos(res, res.perfil["solo_estado"])}
        self.assertEqual(filas["Con mapeo"][9], "D-02")
        self.assertEqual(filas["Sin mapeo"][9], "Informe")
        sin = _res({"solo_estado": {}}, hs)
        self.assertEqual({f[9] for f in se.filas_candidatos(sin, {})}, {""})

    def test_dataset_id_desde_el_manifiesto(self):
        man = {"filas": [{"dataset_id": "DS-AAA", "archivos": ["a.pcap", "x.pcap"]},
                         {"dataset_id": "DS-BBB", "archivos": ["fw.csv"]}]}
        hs = [_hallazgo("Uno", "a.pcap"), _hallazgo("Dos", "firewall fw.csv"), _hallazgo("Tres", "rutas de ataque")]
        res = _res({"solo_estado": {}}, hs, manifiesto=man)
        filas = {f[2]: f[8] for f in se.filas_candidatos(res, {})}
        self.assertEqual(filas, {"Uno": "DS-AAA", "Dos": "DS-BBB", "Tres": ""})
        self.assertEqual({f[8] for f in se.filas_candidatos(_res({"solo_estado": {}}, hs), {})}, {""})


# --------------------------------------------------------------------------- #
# Corridas
# --------------------------------------------------------------------------- #

def _sin_variables(texto):
    """El texto sin los SHA-256 (el del perfil cambia con la clave) ni la hora de la corrida."""
    return re.sub(r"\d{2}:\d{2}(:\d{2})?", "HORA", re.sub("[0-9a-f]{64}", "SHA", texto))


def _sin_perfil(d):
    return {k: v for k, v in d.items() if k not in ("perfil", "solo_estado", "entorno")}


@LEE_CAPTURAS
class CapturaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pcaps = cls.tmp / "pcaps"
        argv, sys.argv = sys.argv, ["gen", str(cls.pcaps)]
        try:
            gen_pcaps.main()
        finally:
            sys.argv = argv
        cls.sw = cls.tmp / "sw.txt"
        cls.sw.write_text(IOS, encoding="utf-8")
        cls.fw = cls.tmp / "fw.txt"
        cls.fw.write_text(FTD, encoding="utf-8")
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, extra=None, **cfg):
        type(self).n += 1
        out = self.tmp / f"out{self.n}"
        args = [str(self.pcaps), "-o", str(out), "--firewall", str(self.fw), "--switch", str(self.sw)]
        if extra is not None:
            args += ["--perfil", str(_perfil_json(self.tmp, {**ZONAS, **extra, **cfg}))]
        sal = io.StringIO()
        with contextlib.redirect_stdout(sal), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_completo(args), 0)
        self.consola = sal.getvalue()
        i18n.usar("es")
        return out

    def test_copia_de_estado_sin_columnas_de_juicio(self):
        o = self.correr({"solo_estado": {}, "manifiesto": {"sitios": ["S1"], "datasets": [
            {"sitio": "S1", "punto": "pcaps"}]}})
        carpeta = o / "estado"
        copias = sorted(p.name for p in carpeta.glob("*.csv"))
        self.assertTrue(copias)
        self.assertTrue(set(copias) <= set(se.SALIDAS))
        self.assertEqual(copias, sorted(n for n in se.SALIDAS if (o / n).is_file() and n in copias))
        nombres = {x.lower() for n in se.JUICIO for x in (n, i18n.t(n))}
        for n in copias:
            origen, copia = _lineas(o / n), _lineas(carpeta / n)
            self.assertEqual(len(origen), len(copia), n)
            cab = _csv(carpeta / n)
            for c in (cab[0].keys() if cab else _celdas(carpeta / n)):
                self.assertNotIn(c.lower(), nombres, n)
                self.assertFalse(c.lower().startswith(("criticidad", "riesgo")), n)
            for c in _celdas(carpeta / n):
                for p in PALABRAS:
                    self.assertNotIn(p, c.lower(), f"{n}: {c}")
        self.assertIn("inventario.csv", copias)
        self.assertIn("firewall_reglas.csv", copias)
        self.assertIn("manifiesto.csv", copias)
        hojas, texto = _xlsx_hojas(carpeta / "estado.xlsx")
        q = json.loads((o / "resultado.json").read_text(encoding="utf-8"))["solo_estado"]
        self.assertEqual(hojas, [x["archivo"][:-4][:31] for x in q["tablas"]])
        self.assertEqual(len(hojas), len(copias))
        for p in PALABRAS:
            self.assertNotIn(p, texto.lower())
        # las salidas completas siguen con sus columnas de juicio
        self.assertEqual(q["carpeta"], "estado")
        self.assertEqual(sorted(x["archivo"] for x in q["tablas"]), copias)
        self.assertEqual(q["candidatos"], len(_csv(o / "candidatos_hallazgo.csv")))
        self.assertTrue(any(x["columnas_quitadas"] for x in q["tablas"]))
        self.assertIn(f"[*] solo estado: {len(copias)} tablas en estado/, {q['candidatos']} candidatos a hallazgo",
                      self.consola)
        self.assertFalse((carpeta / "candidatos_hallazgo.csv").exists())

    def test_salidas_y_carpeta_limitan_la_copia(self):
        o = self.correr({"solo_estado": {"carpeta": "Entrega-1", "salidas": ["flujos.csv", "zonas.csv", "plan_captura.csv"]}})
        self.assertFalse((o / "estado").exists())
        existen = sorted(p.name for p in (o / "Entrega-1").glob("*.csv"))
        self.assertEqual(existen, sorted(n for n in ("flujos.csv", "zonas.csv", "plan_captura.csv") if (o / n).is_file()))
        self.assertIn("flujos.csv", existen)
        self.assertEqual(sorted(x["archivo"] for x in json.loads(
            (o / "resultado.json").read_text(encoding="utf-8"))["solo_estado"]["tablas"]), existen)

    def test_candidatos_de_la_corrida(self):
        o = self.correr({"solo_estado": {"entregable_destino": "Informe de hallazgos"},
                         "manifiesto": {"sitios": ["S1"], "datasets": [{"sitio": "S1", "punto": "pcaps"}]}})
        filas = _csv(o / "candidatos_hallazgo.csv")
        hall = _csv(o / "hallazgos.csv")
        self.assertEqual([f["id_hallazgo"] for f in filas], [h["id"] for h in hall])
        self.assertEqual(list(filas[0]), se.COLUMNAS_CAND)
        clases = {f["confianza"] for f in filas}
        self.assertLessEqual({"observado en trafico", "segun configuracion", "derivado"}, clases,
                             sorted({f["fuente"] for f in filas}))
        self.assertTrue(clases <= set(se.CONFIANZAS))
        self.assertEqual({f["entregable_destino"] for f in filas}, {"Informe de hallazgos"})
        con_ds = {f["dataset_id"] for f in filas if f["confianza"] == "observado en trafico"}
        self.assertTrue(all(d.startswith("DS-") for d in con_ds), con_ds)
        for f, h in zip(filas, hall):
            self.assertEqual((f["estado_revision"], f["revisado_por"], f["fecha"], f["comentario"]), ("", "", "", ""))
            self.assertEqual((f["fuente"], f["titulo"]), (h["captura"], h["titulo"]))

    def test_sin_las_claves_las_salidas_no_cambian(self):
        ninguno = self.correr(None)
        self.assertFalse((ninguno / "estado").exists())
        self.assertFalse((ninguno / "candidatos_hallazgo.csv").exists())
        sin = self.correr({})
        con = self.correr({"solo_estado": {}})
        self.assertFalse((sin / "estado").exists())
        self.assertFalse((sin / "candidatos_hallazgo.csv").exists())
        self.assertEqual((sin / "hallazgos.csv").read_bytes(), (con / "hallazgos.csv").read_bytes())
        a = json.loads((sin / "resultado.json").read_text(encoding="utf-8"))
        b = json.loads((con / "resultado.json").read_text(encoding="utf-8"))
        self.assertNotIn("solo_estado", a)
        self.assertEqual(_sin_perfil(a), _sin_perfil(b))
        for n in ("reporte_ot.html", "reporte_ot.md"):
            ta = (sin / n).read_text(encoding="utf-8")
            tb = (con / n).read_text(encoding="utf-8")
            self.assertEqual(_sin_variables(ta), _sin_variables(tb), n)
        for p in sin.iterdir():
            if p.is_file() and p.suffix == ".csv":
                self.assertEqual(p.read_bytes(), (con / p.name).read_bytes(), p.name)

    def test_ingles(self):
        o = self.correr({"solo_estado": {}}, idioma="en")
        filas = _csv(o / "candidatos_hallazgo.csv")
        self.assertEqual(list(filas[0]), EN_COLUMNAS)
        for c in ("confidence", "target_deliverable", "review_status", "finding_id"):
            self.assertIn(c, filas[0])
        self.assertTrue({f["confidence"] for f in filas} <= {"observed in traffic", "per configuration", "derived",
                                                              "per platform", "inferred from version"})
        i18n.usar("en")
        nombres = {x.lower() for n in se.JUICIO for x in (n, i18n.t(n))}
        i18n.usar("es")
        self.assertIn("severity", nombres)
        for p in (o / "estado").glob("*.csv"):
            cab = _csv(p)
            for c in (cab[0].keys() if cab else _celdas(p)):
                self.assertNotIn(c.lower(), nombres, p.name)
                self.assertFalse(c.lower().startswith(("criticality", "criticidad", "risk", "riesgo")), p.name)
            for c in _celdas(p):
                for pal in PALABRAS:
                    self.assertNotIn(pal, c.lower(), f"{p.name}: {c}")

    def test_el_filtro_de_juicio_es_el_que_quita_las_columnas(self):
        o = self.correr({"solo_estado": {"salidas": ["zonas.csv", "inventario.csv", "salud_red.csv", "activos.csv",
                                                     "firewall_matriz.csv", "switch_puertos.csv"]}})
        quitadas = set()
        for x in json.loads((o / "resultado.json").read_text(encoding="utf-8"))["solo_estado"]["tablas"]:
            quitadas |= set(x["columnas_quitadas"])
            quedan = _lineas(o / "estado" / x["archivo"])[0]
            self.assertFalse(any(se.es_juicio(c, {j.lower() for j in se.JUICIO}) for c in quedan), x["archivo"])
            self.assertEqual(len(quedan) + len(x["columnas_quitadas"]), len(_lineas(o / x["archivo"])[0]))
        self.assertTrue(quitadas, "ninguna copia quito columnas de juicio")


class DiagramaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.com = gen_exports.xd_escribir_comunicaciones(cls.tmp / "com.csv", [
            gen_exports.xd_fila("10.10.1.10", "10.10.2.20", "From A to B", 23, "Telnet", tipo_a="HMI", tipo_b="PLC")])
        cls.inv = _inventario_xdome(cls.tmp / "inv.csv", [("HMI-1", "10.10.1.10", "Operacion"),
                                                          ("PLC-1", "10.10.2.20", "Campo")])
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")

    def correr(self, extra=None):
        type(self).n += 1
        out = self.tmp / f"out{self.n}"
        args = ["--activos", str(self.inv), "--enlaces", str(self.com), "--formato", "xdome", "-o", str(out)]
        if extra is not None:
            args += ["--perfil", str(_perfil_json(self.tmp, extra))]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main_diagrama(args), 0)
        i18n.usar("es")
        return out

    def test_copia_y_candidatos_segun_plataforma(self):
        o = self.correr({"solo_estado": {"entregable_destino": "Informe"}, "manifiesto": {
            "sitios": ["S1"], "datasets": [{"sitio": "S1", "archivos": ["inv.csv", "com.csv"]}]}})
        copias = sorted(p.name for p in (o / "estado").glob("*.csv"))
        self.assertTrue(copias)
        self.assertIn("manifiesto.csv", copias)
        for n in copias:
            self.assertEqual(len(_lineas(o / n)), len(_lineas(o / "estado" / n)), n)
            for c in _celdas(o / "estado" / n):
                for p in PALABRAS:
                    self.assertNotIn(p, c.lower(), f"{n}: {c}")
        self.assertTrue((o / "estado" / "estado.xlsx").is_file())
        filas = _csv(o / "candidatos_hallazgo.csv")
        self.assertTrue(filas)
        self.assertIn("segun plataforma", {f["confianza"] for f in filas})
        self.assertTrue(any(f["dataset_id"].startswith("DS-") for f in filas))
        self.assertEqual({f["entregable_destino"] for f in filas}, {"Informe"})
        self.assertIn("solo_estado", json.loads((o / "resultado.json").read_text(encoding="utf-8")))

    def test_sin_la_clave_nada_cambia(self):
        sin, con = self.correr(None), self.correr({"solo_estado": {}})
        self.assertFalse((sin / "estado").exists())
        self.assertFalse((sin / "candidatos_hallazgo.csv").exists())
        self.assertEqual((sin / "hallazgos_importados.csv").read_bytes(), (con / "hallazgos_importados.csv").read_bytes())
        self.assertEqual((sin / "hallazgos.csv").read_bytes(), (con / "hallazgos.csv").read_bytes())


if __name__ == "__main__":
    unittest.main()
