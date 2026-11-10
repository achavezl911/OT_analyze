"""E1e: descarga por API de xDome y conversion a CSV. Sin red: la peticion es una funcion falsa."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ot_assess import alertas as al  # noqa: E402
from ot_assess import cli_xdome  # noqa: E402
from ot_assess import vulnerabilidades as vu  # noqa: E402
from ot_assess.importers import importar  # noqa: E402
from ot_assess.importers import xdome_api as xa  # noqa: E402
from tests import gen_exports  # noqa: E402

TOKEN = "tok-SECRETO-1234567890"
RUTAS = {r: (k, o) for r, k, o in (v for v in xa.CONJUNTOS.values())}

DEVICES = [
    {"uid": "d1", "device_name": "PLC-1", "ip_list": ["10.10.2.20"], "mac_list": ["aa:bb:cc:00:00:02"],
     "category": "OT", "subcategory": "Controller", "type": "PLC", "manufacturer": "Acme", "model": "P200",
     "software_or_firmware_version": "1.2", "purdue_level": "Level 1", "site_name": "S1",
     "network_list": ["Net1"], "retired": False},
    {"uid": "d2", "device_name": "SRV-1", "ip_list": ["10.10.3.30", "10.10.3.31"],
     "mac_list": ["aa:bb:cc:00:00:03"], "category": "IT", "subcategory": "Server", "type": "Server",
     "manufacturer": "Acme", "model": "", "purdue_level": "Level 3", "site_name": "S1", "retired": False},
]
REL_V = [
    {"device_uid": "d1", "vulnerability_id": "v1", "device_name": "PLC-1", "device_ip_list": ["10.10.2.20"],
     "device_mac_list": ["aa:bb:cc:00:00:02"], "device_model": "P200",
     "device_software_or_firmware_version": "1.2", "vulnerability_cve_ids": ["CVE-2020-0001", "CVE-2020-0002"],
     "vulnerability_adjusted_vulnerability_score_level": "High", "vulnerability_cvss_v3_score": 7.5,
     "vulnerability_relevance": "Confirmed", "vulnerability_is_known_exploited": True},
    {"device_uid": "d2", "vulnerability_id": "v2", "device_name": "SRV-1",
     "device_ip_list": ["10.10.3.30", "10.10.3.31"], "device_mac_list": ["aa:bb:cc:00:00:03"],
     "vulnerability_cve_ids": ["CVE-2021-0003"], "vulnerability_adjusted_vulnerability_score_level": "Low",
     "vulnerability_cvss_v3_score": 3.1, "vulnerability_relevance": "Fixed",
     "vulnerability_is_known_exploited": False},
    {"device_uid": "d2", "vulnerability_id": "v3", "device_name": "SRV-1", "vulnerability_cve_ids": [],
     "vulnerability_adjusted_vulnerability_score_level": None, "vulnerability_relevance": "Confirmed"},
]
ALERTAS = [{"id": 1, "alert_name": "Escritura no autorizada", "category": "Security", "severity": "High"},
           {"id": 2, "alert_name": "Equipo nuevo", "category": "Inventory"}]
EVENTOS = [{"id": 10, "alert_id": 1, "timestamp": "2026-11-02T10:00:00", "side_a_ip": "10.10.1.10",
            "side_b_ip": "10.10.2.20", "side_b_port": 502, "protocol": "Modbus", "event_type": "x"}]
REL_A = [{"alert_id": 1, "device_uid": "d1"}, {"alert_id": 2, "device_uid": "d2"}]


class Falsa:
    """API falsa. `datos[ruta]` son los registros; `validos[ruta]` los campos que acepta."""

    def __init__(self):
        rel_v = sorted({k for r in REL_V for k in r} | set(xa.DEVICE_EN_RELACIONES) | {"vulnerability_x"})
        self.datos = {"devices/": DEVICES, "device_vulnerability_relations/": REL_V, "alerts/": ALERTAS,
                      "device_alert_relations/": REL_A, "events/": EVENTOS, "vulnerabilities/": []}
        self.validos = {
            "device_vulnerability_relations/": rel_v,
            "device_alert_relations/": ["alert_id", "device_uid", "device_name", "device_ip_list"],
            "alerts/": ["id", "alert_name", "category", "severity"],
            "events/": sorted({k for r in EVENTOS for k in r} | {"login_password_length"}),
            "vulnerabilities/": ["name", "id"],
            "devices/": sorted({k for r in DEVICES for k in r}),
        }
        self.prohibidos = {}
        self.llamadas = []
        self.respuestas_429 = 0
        self.forzar = None             # (codigo, datos) para toda peticion

    def __call__(self, base, ruta, token, cuerpo):
        assert token == TOKEN
        self.llamadas.append((ruta, cuerpo))
        if self.forzar:
            return self.forzar[0], self.forzar[1], {}
        if self.respuestas_429 > 0:
            self.respuestas_429 -= 1
            return 429, {}, {"retry-after": "2"}
        campos = cuerpo["fields"]
        validos = self.validos[ruta]
        if ruta == "devices/":
            malos = [i for i, c in enumerate(campos) if c not in validos]
            if malos:
                return 422, {"detail": [{"loc": ["body", "fields", i], "msg": "bad"} for i in malos]}, {}
        else:
            if any(c not in validos for c in campos):
                esp = ", ".join("'" + v + "'" for v in validos)
                return 422, {"detail": [{"loc": ["body", "fields", 0], "ctx": {"expected": esp}}]}, {}
        prohib = [c for c in campos if c in self.prohibidos.get(ruta, ())]
        if prohib:
            return 403, {"detail": "Got forbidden fields: [" +
                         ", ".join("<F: '" + c + "'>" for c in prohib) + "]"}, {}
        regs = self.datos[ruta]
        pag = [{c: r.get(c) for c in campos} for r in regs[cuerpo["offset"]:cuerpo["offset"] + cuerpo["limit"]]]
        return 200, {RUTAS[ruta][0]: pag}, {}


def correr(fn, *a, **k):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        r = fn(*a, **k)
    return r, out.getvalue(), err.getvalue()


class TestDepurar(unittest.TestCase):
    def test_invalido_por_indice_por_expected_y_prohibidos(self):
        f = Falsa()
        cli = xa.Cliente("https://x", TOKEN, peticion=f)
        # devices: el 422 da el indice del campo invalido
        self.assertEqual(cli.depurar("devices/", ["uid", "no_existe", "device_name"]), ["uid", "device_name"])
        # otros conjuntos: el 422 lista los validos
        self.assertEqual(cli.depurar("alerts/", ["id", "basura", "category"]), ["id", "category"])
        # 403: se quitan los campos fuera de la licencia
        f.prohibidos["alerts/"] = ["category"]
        self.assertEqual(cli.depurar("alerts/", ["id", "category", "alert_name"]), ["id", "alert_name"])

    def test_campos_validos_del_sondeo(self):
        cli = xa.Cliente("https://x", TOKEN, peticion=Falsa())
        self.assertEqual(cli.campos_validos("alerts/"), ["id", "alert_name", "category", "severity"])
        self.assertIsNone(cli.campos_validos("devices/"))


class TestRed(unittest.TestCase):
    def test_paginacion_2500_en_3_paginas(self):
        f = Falsa()
        f.datos["alerts/"] = [{"id": i} for i in range(2500)]
        cli = xa.Cliente("https://x", TOKEN, peticion=f)
        regs = cli.descargar("alerts/", "alerts", ["id"], ["id"])
        self.assertEqual(len(regs), 2500)
        self.assertEqual([c["offset"] for _r, c in f.llamadas], [0, 1000, 2000])
        self.assertTrue(all(c["limit"] == 1000 and c["sort_by"] for _r, c in f.llamadas))

    def test_429_reintenta_con_retry_after_sin_dormir(self):
        f = Falsa()
        f.respuestas_429 = 2
        esperas = []
        cli = xa.Cliente("https://x", TOKEN, peticion=f, dormir=esperas.append)
        self.assertEqual(len(cli.descargar("alerts/", "alerts", ["id"], ["id"])), 2)
        self.assertEqual(esperas, [2.0, 2.0])

    def test_429_sin_fin_se_rinde(self):
        f = Falsa()
        f.respuestas_429 = 99
        cli = xa.Cliente("https://x", TOKEN, peticion=f, dormir=lambda s: None)
        with self.assertRaises(xa.ErrorApi):
            cli.descargar("alerts/", "alerts", ["id"], ["id"])
        self.assertEqual(len(f.llamadas), xa.MAX_REINTENTOS_429 + 1)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.tok = self.d / "token"
        self.tok.write_text(TOKEN + "\n")
        os.chmod(self.tok, 0o600)
        self.out = self.d / "salida"

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _correr(self, f, extra=()):
        return correr(cli_xdome.main, ["-o", str(self.out), "--token-archivo", str(self.tok), *extra],
                      peticion=f, dormir=lambda s: None)

    def test_token_no_aparece_en_salidas_archivos_ni_errores(self):
        f = Falsa()
        f.forzar = (500, {"detail": "fallo con " + TOKEN})
        r, o, e = self._correr(f)
        self.assertEqual(r, 2)
        self.assertNotIn(TOKEN, o + e)
        f = Falsa()
        r, o, e = self._correr(f)
        self.assertEqual(r, 0, e)
        self.assertNotIn(TOKEN, o + e)
        for p in self.out.rglob("*"):
            if p.is_file():
                self.assertNotIn(TOKEN, p.read_text(encoding="utf-8"), p.name)
        modos = {p.name: p.stat().st_mode & 0o777 for p in self.out.rglob("*.csv")}
        self.assertEqual(set(modos.values()), {0o600})
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)

    def test_permisos_del_token(self):
        os.chmod(self.tok, 0o644)
        r, o, e = self._correr(Falsa())
        self.assertEqual(r, 2)
        self.assertNotIn(TOKEN, o + e)
        self.assertFalse(self.out.exists())

    def test_carpeta_dentro_del_repo(self):
        dentro = cli_xdome.RAIZ_REPO / "salida_xdome_prueba"
        r, _o, e = correr(cli_xdome.main, ["-o", str(dentro), "--token-archivo", str(self.tok)],
                          peticion=Falsa())
        self.assertEqual(r, 2)
        self.assertIn("repositorio", e)
        self.assertFalse(dentro.exists())

    def test_base_sin_https(self):
        r, _o, _e = self._correr(Falsa(), ["--base", "http://api.claroty.com"])
        self.assertEqual(r, 2)

    def test_crudo_y_resumen(self):
        f = Falsa()
        f.prohibidos["alerts/"] = ["category"]
        r, o, e = self._correr(f)
        self.assertEqual(r, 0, e)
        lineas = (self.out / "crudo" / "relaciones_vulnerabilidades.jsonl").read_text().splitlines()
        self.assertEqual(len(lineas), 3)
        self.assertIn("relaciones_vulnerabilidades: 3 registros", o)
        self.assertIn("pares sin CVE omitidos: 1", o)
        self.assertNotIn("login_password_length", (self.out / "crudo" / "eventos.jsonl").read_text())


class TestConversion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        tok = cls.d / "token"
        tok.write_text(TOKEN)
        os.chmod(tok, 0o600)
        cls.out = cls.d / "salida"
        r, _o, e = correr(cli_xdome.main, ["-o", str(cls.out), "--token-archivo", str(tok)],
                          peticion=Falsa(), dormir=lambda s: None)
        assert r == 0, e
        cls.xd = gen_exports.xdome(cls.d / "gen")
        cls.imp = importar([cls.out / "activos_xdome.csv"], cls.xd["comunicaciones"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _activo(self, ip):
        return next(a for a in self.imp.assets.values() if ip in a["ips"])

    def test_activos_con_el_perfil_xdome(self):
        self.assertEqual(self.imp.perfil, "xdome")
        plc = self._activo("10.10.2.20")
        self.assertEqual((plc["mac"], plc["vendor"]), ("aa:bb:cc:00:00:02", "Acme"))
        ui = next(a for a in importar([self.xd["inventario"]], self.xd["comunicaciones"]).assets.values()
                  if "10.10.2.20" in a["ips"])           # la exportacion de la interfaz, mismo equipo
        for campo in ("mac", "ips", "tipo", "vendor"):
            self.assertEqual(plc[campo], ui[campo], campo)
        srv = self._activo("10.10.3.31")
        self.assertIn("10.10.3.30", srv["ips"])
        self.assertEqual(srv["mac"], "aa:bb:cc:00:00:03")

    def test_vulnerabilidades_una_fila_por_cve_y_estado(self):
        vulns = vu.cargar(self.out / "vulnerabilidades_xdome.csv")
        self.assertEqual(sorted(v["cve"] for v in vulns), ["CVE-2020-0001", "CVE-2020-0002", "CVE-2021-0003"])
        por_cve = {v["cve"]: v for v in vulns}
        self.assertEqual(por_cve["CVE-2021-0003"]["estado"], "mitigada")
        self.assertEqual(por_cve["CVE-2020-0001"]["estado"], "abierta")
        self.assertEqual((por_cve["CVE-2020-0001"]["severidad"], por_cve["CVE-2020-0001"]["cvss"]), ("Alta", 7.5))
        self.assertIn("explotada activamente", por_cve["CVE-2020-0001"]["fuente"])
        self.assertEqual(por_cve["CVE-2021-0003"]["ip"], "10.10.3.30")
        cruces = vu.cruzar(vulns, self.imp.assets)
        self.assertEqual(len(cruces), 3)
        self.assertTrue(all(c["por"] == "ip" for c in cruces))
        self.assertEqual(sorted(c["activo"] for c in cruces),
                         ["aa:bb:cc:00:00:02"] * 2 + ["aa:bb:cc:00:00:03"])

    def test_alertas_evento_y_relacion_sin_evento(self):
        alertas = al.cargar(self.out / "alertas_xdome.csv")
        self.assertEqual(len(alertas), 2)
        ev = next(a for a in alertas if a["firma"] == "Escritura no autorizada")
        self.assertEqual((ev["origen"], ev["destino"], ev["puerto"], ev["protocolo"]),
                         ("10.10.1.10", "10.10.2.20", 502, "Modbus"))
        rel = next(a for a in alertas if a["firma"] == "Equipo nuevo")
        self.assertEqual((rel["origen"], rel["destino"]), ("10.10.3.30", ""))
        self.assertEqual(json.loads(json.dumps(ev["severidad"])), "Alta")


if __name__ == "__main__":
    unittest.main()


class CuerpoSinOrdenTest(unittest.TestCase):
    def test_sin_orden_no_manda_sort_by_vacio(self):
        from ot_assess.importers.xdome_api import Cliente
        c = Cliente._cuerpo(["zz"], [], 0, 1)
        self.assertNotIn("sort_by", c)
        c = Cliente._cuerpo(["id", "name"], ["id"], 0, 1000)
        self.assertEqual(c["sort_by"], [{"field": "id", "order": "asc"}])
