"""VCONF (D128): confirmacion de vulnerabilidades por el analista. Los CLI de exportaciones no usan tshark."""
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

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

from test_vuln_firmware import csaf

from ot_assess import confirmacion_vulns as vc
from ot_assess import i18n
from ot_assess.cli_diagrama import main as main_diagrama

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

COMUN = "CVE-2099-14001"       # plataforma y firmware sobre PLC-1
SOLO_FW = "CVE-2099-14002"
SOLO_PLAT = "CVE-2099-14003"   # HMI-1, solo plataforma


def _leer(ruta):
    with open(ruta, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _escribir(ruta, cab, filas, sep=","):
    with open(ruta, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=sep)
        w.writerow(cab)
        w.writerows(filas)
    return ruta


def _fallo(msg):
    raise ValueError(msg)


def _validar(v):
    try:
        return vc.validar(v, _fallo)
    except ValueError as e:
        return str(e)


class PerfilTest(unittest.TestCase):
    def test_true_y_objeto_completo(self):
        d = _validar(True)
        self.assertEqual(d, {"estados": ["candidato", "confirmado", "descartado"], "inicial": "candidato",
                             "descartados": "descartado", "hallazgos": "todas"})
        self.assertIsNone(_validar(False))
        d = _validar({"estados": ["abierta", "real", "falso positivo"], "inicial": "abierta",
                      "descartados": "falso positivo", "hallazgos": "sin_descartadas"})
        self.assertEqual((d["inicial"], d["descartados"], d["hallazgos"]),
                         ("abierta", "falso positivo", "sin_descartadas"))
        # sin 'descartado' en la lista y sin clave: ningun estado descarta
        self.assertIsNone(_validar({"estados": ["a", "b"]})["descartados"])
        self.assertEqual(_validar({"estados": ["a", "b"]})["inicial"], "a")

    def test_cada_error(self):
        malos = [5, "si", [], {"x": 1}, {"estados": ["a"]}, {"estados": ["a"] * 2},
                 {"estados": [str(i) for i in range(11)]}, {"estados": ["a", ""]}, {"estados": ["a", "b" * 41]},
                 {"estados": ["a", "b\nc"]}, {"estados": ["a", 3]}, {"estados": "ab"},
                 {"inicial": "otro"}, {"inicial": 3}, {"descartados": "otro"}, {"hallazgos": "ninguna"},
                 {"hallazgos": 1}, {"estados": ["a", " b"]}]
        for v in malos:
            self.assertIsInstance(_validar(v), str, v)

    def test_el_perfil_la_acepta_y_la_rechaza(self):
        from ot_assess import perfil as pf
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        p = tmp / "p.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "confirmacion_vulnerabilidades":
                                 {"hallazgos": "sin_descartadas"}}), encoding="utf-8")
        self.assertEqual(pf.cargar(str(p))["confirmacion_vulnerabilidades"]["hallazgos"], "sin_descartadas")
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "confirmacion_vulnerabilidades": {"hallazgos": "x"}}),
                     encoding="utf-8")
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            pf.cargar(str(p))


class IdTest(unittest.TestCase):
    def test_estable_y_por_activo(self):
        a = vc.id_de("cve-2099-1", "10.0.0.1")
        self.assertEqual(a, vc.id_de("CVE-2099-1", "10.0.0.1"))
        self.assertRegex(a, r"^VU-[0-9a-f]{10}$")
        self.assertNotEqual(a, vc.id_de("CVE-2099-1", "10.0.0.2"))
        self.assertNotEqual(a, vc.id_de("CVE-2099-2", "10.0.0.1"))

    def test_clave_de_la_fila(self):
        v = {"ip": "10.0.0.1", "mac": "aa", "activo": "X", "producto": "P", "version": "1"}
        self.assertEqual(vc.clave_plataforma(v), "10.0.0.1")
        v["ip"] = ""
        self.assertEqual(vc.clave_plataforma(v), "aa")
        v["mac"] = ""
        self.assertEqual(vc.clave_plataforma(v), "X")
        v["activo"] = ""
        self.assertEqual(vc.clave_plataforma(v), "P 1")


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.a = _escribir(self.tmp / "activos.csv", ["Name", "IP", "MAC", "Vendor", "Model", "Firmware", "Type"], [
            ["PLC-1", "192.0.2.10", "02:00:00:00:00:01", "ACME Automation Inc.", "PLC-5000", "V2.3.0", "PLC"],
            ["HMI-1", "192.0.2.11", "02:00:00:00:00:02", "Otro", "", "", "HMI"]])
        self.e = _escribir(self.tmp / "enlaces.csv", ["Source", "Destination", "Port", "Protocol", "Packets"], [
            ["192.0.2.11", "192.0.2.10", "502", "Modbus", "100"]])
        self.d = self.tmp / "avisos"
        self.d.mkdir()
        (self.d / "a.json").write_text(json.dumps(csaf("ICSA-99-40", {COMUN: (9.8, [], []), SOLO_FW: (5.0, [], [])})),
                                       encoding="utf-8")
        self.vul = _escribir(self.tmp / "vul.csv", ["ip", "cve", "severidad", "cvss", "estado"], [
            ["192.0.2.10", COMUN, "Critical", "9.8", "open"],
            ["192.0.2.11", SOLO_PLAT, "High", "7.5", "open"]])
        self.n = 0

    def perfil(self, cfg):
        p = self.tmp / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "confirmacion_vulnerabilidades": cfg}),
                     encoding="utf-8")
        return ["--perfil", str(p)]

    def correr(self, *extra, idioma="es", sin_vul=False):
        self.n += 1
        out = self.tmp / f"o{self.n}"
        args = ["--activos", str(self.a), "--enlaces", str(self.e), "--formato", "generico", "-o", str(out),
                "--avisos-ics", str(self.d), "--idioma", idioma, *extra]
        if not sin_vul:
            args += ["--vulnerabilidades", str(self.vul)]
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_diagrama(args)
        self.assertEqual(rc, 0)
        self.consola = buf.getvalue()
        return out

    def error2(self, *extra):
        n = self.n + 1
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as cm:
            self.correr(*extra)
        self.n = n
        self.assertEqual(cm.exception.code, 2)
        self.assertFalse((self.tmp / f"o{n}").exists())
        return err.getvalue()

    def json(self, out):
        return json.loads((out / "resultado.json").read_text(encoding="utf-8"))


class CorridaTest(Base):
    def test_columnas_tabla_consolidada_y_json(self):
        out = self.correr(*self.perfil(True))
        plat = _leer(out / "vulnerabilidades.csv")
        self.assertEqual(list(plat[0])[-2:], ["id_vulnerabilidad", "estado_confirmacion"])
        fw = _leer(out / "vulnerabilidades_firmware.csv")
        self.assertEqual(list(fw[0])[-5:], ["estado_revision", "revisado_por", "fecha", "comentario",
                                            "id_vulnerabilidad"])
        self.assertEqual({f["estado_revision"] for f in fw}, {"candidato"})
        self.assertEqual({f["estado_confirmacion"] for f in plat}, {"candidato"})
        ids_plat = {f["cve"]: f["id_vulnerabilidad"] for f in plat}
        ids_fw = {f["cve"]: f["id_vulnerabilidad"] for f in fw}
        self.assertEqual(ids_plat[COMUN], ids_fw[COMUN])                 # misma pareja, mismo id
        self.assertEqual(ids_plat[COMUN], vc.id_de(COMUN, "192.0.2.10"))
        self.assertNotEqual(ids_plat[COMUN], ids_plat[SOLO_PLAT])
        rev = _leer(out / "vulnerabilidades_revision.csv")
        self.assertEqual(list(rev[0]), vc.COLUMNAS)
        por_cve = {r["cve"]: r for r in rev}
        self.assertEqual(len(rev), 3)
        self.assertEqual(por_cve[COMUN]["fuentes"], "plataforma; firmware")
        self.assertEqual(por_cve[SOLO_FW]["fuentes"], "firmware")
        self.assertEqual(por_cve[SOLO_PLAT]["fuentes"], "plataforma")
        self.assertEqual(rev[0]["cve"], COMUN)                            # Critica primero
        self.assertEqual(por_cve[COMUN]["activo"], "PLC-1")
        self.assertEqual(por_cve[COMUN]["estado_confirmacion"], "candidato")
        j = self.json(out)["confirmacion_vulnerabilidades"]
        self.assertEqual(j, {"filas": 3, "estados": ["candidato", "confirmado", "descartado"],
                             "por_estado": {"candidato": 3, "confirmado": 0, "descartado": 0}, "importados": 0,
                             "ids_no_encontrados": 0, "hallazgos": "todas", "excluidas_de_hallazgos": 0})
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Revision de vulnerabilidades", hojas)

    def test_ingles(self):
        out = self.correr(*self.perfil(True), idioma="en")
        rev = _leer(out / "vulnerabilidades_revision.csv")
        self.assertIn("confirmation_status", rev[0])
        self.assertEqual({r["confirmation_status"] for r in rev}, {"candidate"})
        self.assertEqual(rev[0]["sources"], "platform; firmware")
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            hojas = re.findall(r'<sheet name="([^"]+)"', z.read("xl/workbook.xml").decode("utf-8"))
        self.assertIn("Vulnerability review", hojas)
        self.assertEqual(i18n.FALTANTES - set(), i18n.FALTANTES)

    def test_sin_clave_ni_opcion_todo_igual(self):
        base = self.correr()
        self.assertFalse((base / "vulnerabilidades_revision.csv").exists())
        self.assertNotIn("confirmacion_vulnerabilidades", self.json(base))
        self.assertEqual(list(_leer(base / "vulnerabilidades.csv")[0]),
                         ["activo", "ip", "cve", "severidad", "cvss", "estado", "producto", "version", "fuente",
                          "asociado_por", "kev", "kev_fecha_agregada", "kev_fecha_limite", "kev_ransomware",
                          "avisos_ics", "remediacion_fabricante"])
        fw = _leer(base / "vulnerabilidades_firmware.csv")
        self.assertEqual(list(fw[0])[-4:], ["estado_revision", "revisado_por", "fecha", "comentario"])
        self.assertEqual({(f["estado_revision"], f["revisado_por"], f["fecha"], f["comentario"]) for f in fw},
                         {("", "", "", "")})
        # con la clave y 'todas' los hallazgos son los mismos y los archivos de mas son solo los nuevos
        con = self.correr(*self.perfil({"hallazgos": "todas"}))
        self.assertEqual((base / "hallazgos.csv").read_text(encoding="utf-8-sig"),
                         (con / "hallazgos.csv").read_text(encoding="utf-8-sig"))
        self.assertEqual(sorted(p.name for p in con.iterdir()) , sorted(
            [p.name for p in base.iterdir()] + ["vulnerabilidades_revision.csv"]))

    def test_sin_descartadas_quita_de_los_hallazgos_y_conserva_las_tablas(self):
        # una revision que descarta lo comun y lo solo-plataforma
        rev0 = self.correr(*self.perfil(True))
        ids = {r["cve"]: r["id_vulnerabilidad"] for r in _leer(rev0 / "vulnerabilidades_revision.csv")}
        arch = _escribir(self.tmp / "rev.csv", ["id_vulnerabilidad", "estado_confirmacion", "confirmado_por",
                                                 "fecha", "motivo"],
                         [[ids[COMUN], "descartado", "ana", "2099-01-02", "falso positivo"],
                          [ids[SOLO_PLAT], "confirmado", "luis", "2099-01-03", "visto"]])

        def hallazgos(out):
            return " ".join(" ".join(h.values()) for h in _leer(out / "hallazgos.csv"))
        todas = self.correr(*self.perfil({"hallazgos": "todas"}), "--vulnerabilidades-revision", str(arch))
        self.assertIn(COMUN, hallazgos(todas))
        sin = self.correr(*self.perfil({"hallazgos": "sin_descartadas"}), "--vulnerabilidades-revision", str(arch))
        self.assertNotIn(COMUN, hallazgos(sin))
        self.assertIn(SOLO_PLAT, hallazgos(sin))
        self.assertIn(SOLO_FW, hallazgos(sin))          # el hallazgo de firmware sigue por la otra CVE
        self.assertNotIn("(CVSS 9.8; PLC-1)", hallazgos(sin))
        self.assertEqual({f["cve"] for f in _leer(sin / "vulnerabilidades.csv")}, {COMUN, SOLO_PLAT})
        self.assertEqual({f["cve"] for f in _leer(sin / "vulnerabilidades_firmware.csv")}, {COMUN, SOLO_FW})
        filas = {r["cve"]: r for r in _leer(sin / "vulnerabilidades_revision.csv")}
        self.assertEqual(len(filas), 3)
        self.assertEqual((filas[COMUN]["estado_confirmacion"], filas[COMUN]["confirmado_por"],
                          filas[COMUN]["fecha"], filas[COMUN]["motivo"]),
                         ("descartado", "ana", "2099-01-02", "falso positivo"))
        j = self.json(sin)["confirmacion_vulnerabilidades"]
        self.assertEqual((j["excluidas_de_hallazgos"], j["importados"], j["hallazgos"]), (1, 2, "sin_descartadas"))
        self.assertEqual(self.json(todas)["confirmacion_vulnerabilidades"]["excluidas_de_hallazgos"], 0)
        # los hallazgos de la corrida 'todas' son los de una corrida sin la clave
        base = self.correr()
        self.assertEqual(hallazgos(base), hallazgos(todas))


class ImportacionTest(Base):
    def ids(self):
        out = self.correr(*self.perfil(True))
        return {r["cve"]: r["id_vulnerabilidad"] for r in _leer(out / "vulnerabilidades_revision.csv")}

    def test_punto_y_coma_ingles_y_celda_vacia_no_pisa(self):
        ids = self.ids()
        previo = _escribir(self.tmp / "p1.csv", ["vulnerability_id", "confirmation_status", "confirmed_by", "date",
                                                  "reason"],
                           [[ids[COMUN], "confirmed", "ana", "2099-02-01", "visto en sitio"],
                            [ids[SOLO_FW], "", "", "", ""]], sep=";")
        out = self.correr(*self.perfil(True), "--vulnerabilidades-revision", str(previo))
        r = {x["cve"]: x for x in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertEqual((r[COMUN]["estado_confirmacion"], r[COMUN]["confirmado_por"], r[COMUN]["motivo"]),
                         ("confirmado", "ana", "visto en sitio"))
        self.assertEqual(r[SOLO_FW]["estado_confirmacion"], "candidato")       # vacio no pisa
        fw = {x["cve"]: x for x in _leer(out / "vulnerabilidades_firmware.csv")}
        self.assertEqual((fw[COMUN]["estado_revision"], fw[COMUN]["revisado_por"], fw[COMUN]["fecha"],
                          fw[COMUN]["comentario"]), ("confirmado", "ana", "2099-02-01", "visto en sitio"))
        plat = {x["cve"]: x for x in _leer(out / "vulnerabilidades.csv")}
        self.assertEqual(plat[COMUN]["estado_confirmacion"], "confirmado")

    def test_sin_la_clave_la_opcion_activa_con_estados_por_defecto(self):
        ids = self.ids()
        previo = _escribir(self.tmp / "p2.csv", ["id_vulnerabilidad", "estado_confirmacion"],
                           [[ids[COMUN], "descartado"]])
        out = self.correr("--vulnerabilidades-revision", str(previo))
        r = {x["cve"]: x for x in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertEqual(r[COMUN]["estado_confirmacion"], "descartado")
        self.assertEqual(self.json(out)["confirmacion_vulnerabilidades"]["hallazgos"], "todas")

    def test_alias_de_firmware_y_archivo_de_la_tabla_de_plataforma(self):
        ids = self.ids()
        previo = _escribir(self.tmp / "p3.csv", ["id_vulnerabilidad", "estado_revision", "revisado_por", "fecha",
                                                  "comentario"],
                           [[ids[SOLO_FW], "confirmado", "eva", "2099-03-03", "ok"]])
        out = self.correr(*self.perfil(True), "--vulnerabilidades-revision", str(previo))
        r = {x["cve"]: x for x in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertEqual((r[SOLO_FW]["confirmado_por"], r[SOLO_FW]["motivo"]), ("eva", "ok"))
        # vulnerabilidades.csv de la corrida anterior, tal cual, tambien sirve
        out2 = self.correr(*self.perfil(True), "--vulnerabilidades-revision", str(out / "vulnerabilidades.csv"))
        self.assertEqual(self.json(out2)["confirmacion_vulnerabilidades"]["ids_no_encontrados"], 0)

    def test_formula_neutralizada_e_id_inexistente_avisado(self):
        ids = self.ids()
        previo = _escribir(self.tmp / "p4.csv", ["id_vulnerabilidad", "estado_confirmacion", "confirmado_por",
                                                  "motivo"],
                           [[ids[COMUN], "confirmado", "=cmd|calc", "+cmd"],
                            ["VU-0000000000", "confirmado", "x", "y"]])
        out = self.correr(*self.perfil(True), "--vulnerabilidades-revision", str(previo))
        r = {x["cve"]: x for x in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertFalse(r[COMUN]["confirmado_por"].startswith("="))
        self.assertIn("cmd", r[COMUN]["confirmado_por"])
        self.assertFalse(r[COMUN]["motivo"].startswith("+"))
        j = self.json(out)["confirmacion_vulnerabilidades"]
        self.assertEqual((j["importados"], j["ids_no_encontrados"]), (1, 1))
        self.assertIn("1 id_vulnerabilidad", self.consola)

    def test_errores_terminan_con_codigo_2_sin_salidas(self):
        ids = self.ids()
        cab = ["id_vulnerabilidad", "estado_confirmacion", "motivo"]
        self.error2(*self.perfil(True), "--vulnerabilidades-revision", str(self.tmp / "no_existe.csv"))
        self.error2(*self.perfil(True), "--vulnerabilidades-revision",
                    str(_escribir(self.tmp / "s1.csv", ["cve", "estado_confirmacion"], [[COMUN, "confirmado"]])))
        self.error2(*self.perfil(True), "--vulnerabilidades-revision",
                    str(_escribir(self.tmp / "s2.csv", cab, [[ids[COMUN], "quizas", ""]])))
        self.error2(*self.perfil(True), "--vulnerabilidades-revision",
                    str(_escribir(self.tmp / "s3.csv", cab, [[ids[COMUN], "confirmado", "a"],
                                                              [ids[COMUN], "descartado", "a"]])))
        self.error2(*self.perfil(True), "--vulnerabilidades-revision",
                    str(_escribir(self.tmp / "s4.csv", cab, [[ids[COMUN], "confirmado", "x" * 201]])))
        bin_ = self.tmp / "s5.csv"
        bin_.write_bytes(b"\xff\xfe\x00")
        self.error2("--vulnerabilidades-revision", str(bin_))        # sin la clave tambien
        # un id repetido con los mismos valores no es error
        ok = _escribir(self.tmp / "s6.csv", cab, [[ids[COMUN], "confirmado", "a"], [ids[COMUN], "confirmado", "a"]])
        self.correr(*self.perfil(True), "--vulnerabilidades-revision", str(ok))

    def test_estados_propios_del_perfil(self):
        ids = self.ids()
        cfg = {"estados": ["abierta", "real", "falso positivo"], "descartados": "falso positivo",
               "hallazgos": "sin_descartadas"}
        previo = _escribir(self.tmp / "p5.csv", ["id_vulnerabilidad", "estado_confirmacion"],
                           [[ids[COMUN], "falso positivo"]])
        out = self.correr(*self.perfil(cfg), "--vulnerabilidades-revision", str(previo))
        r = {x["cve"]: x for x in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertEqual((r[COMUN]["estado_confirmacion"], r[SOLO_FW]["estado_confirmacion"]),
                         ("falso positivo", "abierta"))
        self.error2(*self.perfil(cfg), "--vulnerabilidades-revision",
                    str(_escribir(self.tmp / "p6.csv", ["id_vulnerabilidad", "estado_confirmacion"],
                                  [[ids[COMUN], "descartado"]])))


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturaTest(unittest.TestCase):
    def test_cli_de_capturas_con_plataforma(self):
        import gen_pcaps

        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        sys.argv = ["gen", str(tmp / "pcaps")]
        gen_pcaps.main()
        vul = RAIZ / "docs" / "ejemplos" / "vulnerabilidades.csv"
        ident = vc.id_de("CVE-2099-0001", "10.10.1.20")
        previo = _escribir(tmp / "rev.csv", ["id_vulnerabilidad", "estado_confirmacion"], [[ident, "descartado"]])
        perfil = tmp / "perfil.json"
        perfil.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                      "confirmacion_vulnerabilidades": {"hallazgos": "sin_descartadas"}}),
                          encoding="utf-8")
        out = tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            main([str(tmp / "pcaps"), "-o", str(out), "--vulnerabilidades", str(vul), "--perfil", str(perfil),
                  "--vulnerabilidades-revision", str(previo)])
        h = [f for f in _leer(out / "hallazgos.csv") if f["categoria"] == "Vulnerabilidades"]
        self.assertEqual(len(h), 1)
        self.assertNotIn("CVE-2099-0001", h[0]["evidencia"])
        self.assertIn("CVE-2099-0002", h[0]["evidencia"])
        self.assertEqual(len(_leer(out / "vulnerabilidades.csv")), 5)
        rev = {r["cve"]: r for r in _leer(out / "vulnerabilidades_revision.csv")}
        self.assertEqual(rev["CVE-2099-0001"]["estado_confirmacion"], "descartado")
        j = json.loads((out / "resultado.json").read_text(encoding="utf-8"))["confirmacion_vulnerabilidades"]
        self.assertEqual((j["importados"], j["excluidas_de_hallazgos"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
