"""IDS1 (D136): ids estables (recomendacion, vulnerabilidad, flujo) y matriz de trazabilidad. Sin tshark."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import test_allow1
import test_vconf

from ot_assess import allowlist_proyecto as ap
from ot_assess import confirmacion_vulns as vc
from ot_assess import entregables as en
from ot_assess import i18n
from ot_assess import remediacion as rem
from ot_assess import trazabilidad as tz
from ot_assess.model import Assessment, Capture
from ot_assess.riesgo import id_hallazgo
from ot_assess.standards import ESTANDARES


def _leer(ruta):
    with open(ruta, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _fallo(msg):
    raise ValueError(msg)


def _validar(v):
    try:
        return tz.validar(v, _fallo)
    except ValueError as e:
        return str(e)


def _h(titulo, sev="Alta", rec="Cerrar el puerto.", activos=None, categoria="Control de acceso", evid="e"):
    return {"titulo": titulo, "severidad": sev, "categoria": categoria, "evidencia": evid,
            "por_que_importa": "p", "recomendacion": rec, "captura": "a.pcap",
            "referencias": {"iec62443": "SR 7.1 DoS"}, **({"activos": activos} if activos else {})}


class PerfilTest(unittest.TestCase):
    def test_validos(self):
        self.assertEqual(tz.validar({}, _fallo), {"por_activo": True, "max_filas": 20000})
        self.assertEqual(tz.validar({"por_activo": False, "max_filas": 100}, _fallo),
                         {"por_activo": False, "max_filas": 100})

    def test_cada_error(self):
        self.assertIn("objeto", _validar([]))
        self.assertIn("objeto", _validar("x"))
        self.assertIn("clave desconocida", _validar({"otra": 1}))
        self.assertIn("por_activo", _validar({"por_activo": "si"}))
        self.assertIn("por_activo", _validar({"por_activo": 1}))
        for malo in (99, 100001, True, "20000", 1.5, None):
            self.assertIn("max_filas", _validar({"max_filas": malo}), malo)
        self.assertEqual(tz.validar({"max_filas": 100000}, _fallo)["max_filas"], 100000)


class IdRecomendacionTest(unittest.TestCase):
    def test_estable_colapsa_espacios_y_se_comparte(self):
        a = tz.id_recomendacion("Cerrar el   puerto.\n")
        self.assertRegex(a, r"^REC-[0-9a-f]{8}$")
        self.assertEqual(a, tz.id_recomendacion(" Cerrar el puerto. "))
        self.assertNotEqual(a, tz.id_recomendacion("Cerrar el puerto 23."))
        self.assertEqual(a, "REC-" + __import__("hashlib").sha256(b"Cerrar el puerto.").hexdigest()[:8])

    def test_igual_entre_idiomas(self):
        i18n.usar("en")
        self.addCleanup(i18n.usar, "es")
        self.assertEqual(tz.id_recomendacion("Cerrar el puerto."),
                         "REC-" + __import__("hashlib").sha256(b"Cerrar el puerto.").hexdigest()[:8])


MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def _res(perfil, registro=True, ent=False):
    cap = Capture(Path("a.pcap"))
    cap.findings = [_h("Telnet", activos=["10.0.0.1", "10.0.0.2", "10.9.9.9"]),
                    _h("Sin activo", sev="Media"),
                    _h("Vulnerabilidad X", categoria="Vulnerabilidades", activos=["10.0.0.2"],
                       rec="Parchear.")]
    assets = {MAC1: {"nombre": "HMI-1", "ips": {"10.0.0.1"}, "role": "HMI"},
              MAC2: {"nombre": "PLC-1", "ips": {"10.0.0.2"}, "role": "Controlador"}}
    args = SimpleNamespace(registro_evidencias_tabla={
        "filas": [["EV-aaaaaaaaaa", "a.pcap; copia.pcap"], ["EV-bbbbbbbbbb", "otra.pcap"]], "json": {}}
    ) if registro else None
    h1 = id_hallazgo("Telnet")
    res = Assessment([cap], assets, [], args, estandares=[ESTANDARES["iec62443"]], perfil=perfil)
    res.riesgos = {"filas": [{"id_hallazgo": h1, "id_riesgo": "R-" + h1[2:]}], "avisos": []}
    res.inventario_normalizado = {"filas": [{"id": "A-11111111", "campos": {"ips": {"valor": "10.0.0.1"}}}]}
    res.tobe = {"filas": [{"zona_origen": "Z1", "zona_destino": "Z2", "servicio": "Telnet", "ids_hallazgo": [h1]},
                          {"zona_origen": "Z1", "zona_destino": "Z3", "servicio": "Telnet", "ids_hallazgo": [h1]}]}
    res.vulns_cruces = [{"vuln": {"cve": "CVE-2099-1", "ip": "10.0.0.2", "severidad": "Alta", "cvss": 8.0,
                                  "estado": "open", "producto": "", "version": "", "fuente": ""},
                         "activo": MAC2, "por": "ip"}]
    if ent:
        res.perfil = dict(perfil, entregables=en.validar(
            {"catalogo": [{"id": "D-02", "nombre": "Inventario"}], "mapeo": {"iec62443:SR 7.*": ["D-02"]}}, _fallo))
    return res


class Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.addCleanup(i18n.usar, "es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class FilasTest(Base):
    def filas(self, res):
        with contextlib.redirect_stderr(io.StringIO()):
            return tz.construir(res)["filas"]

    def test_una_fila_por_activo_con_toda_la_cadena(self):
        filas = self.filas(_res({"trazabilidad": tz.validar({}, _fallo)}, ent=True))
        self.assertEqual([(f["titulo"], f["activo"]) for f in filas],
                         [("Telnet", "HMI-1"), ("Telnet", "PLC-1"), ("Vulnerabilidad X", "PLC-1"),
                          ("Sin activo", "")])
        hmi, plc, vul, sin = filas
        h1 = id_hallazgo("Telnet")
        self.assertEqual((hmi["id_activo"], plc["id_activo"]), ("A-11111111", ""))
        self.assertEqual(hmi["ips"], "10.0.0.1")
        self.assertEqual(hmi["evidencias"], "EV-aaaaaaaaaa")
        self.assertEqual((hmi["id_hallazgo"], hmi["id_riesgo"]), (h1, "R-" + h1[2:]))
        self.assertEqual(sin["id_riesgo"], "")
        self.assertEqual(hmi["controles"], "iec62443: SR 7.1 DoS")
        self.assertEqual(hmi["entregables"], "D-02")
        self.assertEqual(hmi["id_recomendacion"], tz.id_recomendacion("Cerrar el puerto."))
        self.assertEqual(hmi["id_recomendacion"], sin["id_recomendacion"])          # misma recomendacion
        self.assertNotEqual(hmi["id_recomendacion"], vul["id_recomendacion"])
        self.assertEqual(hmi["ids_flujo"], "; ".join(sorted({ap.id_flujo("Z1", "Z2", "Telnet"),
                                                              ap.id_flujo("Z1", "Z3", "Telnet")})))
        self.assertEqual(sin["ids_flujo"], "")
        self.assertEqual(vul["ids_vulnerabilidad"], vc.id_de("CVE-2099-1", "10.0.0.2"))
        self.assertEqual(hmi["ids_vulnerabilidad"], "")                  # el hallazgo no es de vulnerabilidades
        self.assertEqual(sin["ips"], "")

    def test_sin_registro_van_los_nombres_de_origen(self):
        filas = self.filas(_res({"trazabilidad": {}}, registro=False))
        self.assertEqual({f["evidencias"] for f in filas}, {"a.pcap"})
        r = tz.construir(_res({"trazabilidad": {}}, registro=False))["resumen"]
        self.assertEqual(r["sin_evidencia_registrada"], 4)

    def test_registro_sin_coincidencia_queda_vacio(self):
        res = _res({"trazabilidad": {}})
        res.args.registro_evidencias_tabla["filas"] = [["EV-cccccccccc", "ninguna.pcap"]]
        with contextlib.redirect_stderr(io.StringIO()):
            r = tz.construir(res)
        self.assertEqual({f["evidencias"] for f in r["filas"]}, {""})
        self.assertEqual(r["resumen"]["sin_evidencia_registrada"], 4)

    def test_resumen(self):
        res = _res({"trazabilidad": {}})
        with contextlib.redirect_stderr(io.StringIO()):
            r = tz.construir(res)["resumen"]
        self.assertEqual(r, {"cantidad_filas": 4, "filas_totales": 4, "cortado": False, "hallazgos": 3, "activos": 2,
                             "sin_evidencia_registrada": 0, "sin_riesgo": 2, "sin_entregable": 4})

    def test_por_activo_false_una_fila_por_hallazgo(self):
        filas = self.filas(_res({"trazabilidad": {"por_activo": False}}))
        self.assertEqual([f["titulo"] for f in filas], ["Telnet", "Vulnerabilidad X", "Sin activo"])
        self.assertEqual((filas[0]["activo"], filas[0]["id_activo"], filas[0]["ips"]),
                         ("HMI-1; PLC-1", "A-11111111", "10.0.0.1;10.0.0.2"))
        self.assertEqual(filas[1]["ids_vulnerabilidad"], vc.id_de("CVE-2099-1", "10.0.0.2"))

    def test_max_filas_corta_y_avisa(self):
        res = _res({"trazabilidad": {"max_filas": 100}})
        cap = res.caps[0]
        cap.findings = [_h(f"Hallazgo {i:03d}") for i in range(150)]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            r = tz.construir(res)
        self.assertEqual((len(r["filas"]), r["resumen"]["filas_totales"], r["resumen"]["cortado"]), (100, 150, True))
        self.assertIn("max_filas=100", err.getvalue())
        j = tz.para_json(res)
        self.assertEqual((j["cortado"], j["filas_totales"], len(j["filas"]), j["max_filas"]), (True, 150, 100, 100))
        self.assertEqual(j["cantidad_filas"], 100)

    def test_sin_clave_no_hay_nada(self):
        res = _res({})
        self.assertEqual(rem.columnas(res), rem.COLUMNAS)
        self.assertEqual(tz.tablas(res), [])
        self.assertIsNone(tz.para_json(res))
        self.assertFalse(tz.hay(res))

    def test_remediacion_con_clave_agrega_id_al_final_y_lo_comparte(self):
        sin, con = _res({}), _res({"trazabilidad": {}})
        self.assertEqual(rem.columnas(con), rem.COLUMNAS + ["id_recomendacion"])
        fa, fb = rem.tabla(sin), rem.tabla(con)
        self.assertEqual([f[:-1] for f in fb], fa)
        ci = rem.COLUMNAS.index("titulo")
        ids = {f[ci]: f[-1] for f in fb}
        self.assertEqual(ids["Telnet"], tz.id_recomendacion("Cerrar el puerto."))
        self.assertEqual(ids["Telnet"], ids["Sin activo"])
        self.assertNotEqual(ids["Telnet"], ids["Vulnerabilidad X"])

    def test_ingles_encabezados(self):
        i18n.usar("en")
        self.assertEqual([i18n.t(c) for c in tz.COLUMNAS],
                         ["asset_id", "asset", "ips", "evidence", "finding_id", "title", "severity", "risk_id",
                          "controls", "recommendation_id", "playbook", "deliverables", "flow_ids",
                          "vulnerability_ids"])
        self.assertEqual(i18n.t(tz.HOJA), "Traceability")
        self.assertEqual(i18n.FALTANTES & {tz.NOTA, tz.HOJA}, set())

    def test_seccion(self):
        res = _res({"trazabilidad": {}})
        with contextlib.redirect_stderr(io.StringIO()):
            s = tz.seccion(res)
        self.assertEqual(s["nota"], "Cadena para trazar cada hallazgo hasta su entregable; no es una determinacion "
                                    "de cumplimiento.")
        self.assertIn("Filas: 4; hallazgos: 3; activos: 2; sin evidencia registrada: 0; sin riesgo: 2; "
                      "sin entregable: 4", s["resumen"])
        i18n.usar("en")
        s = tz.seccion(res)
        self.assertIn("without registered evidence", s["resumen"])
        self.assertIn("not a compliance determination", s["nota"])


class DiagramaVulnTest(test_vconf.Base):
    def perfil_tz(self, **extra):
        p = self.tmp / "perfil_tz.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                 "trazabilidad": {}, **extra}), encoding="utf-8")
        return ["--perfil", str(p)]

    def test_id_vulnerabilidad_igual_al_de_vconf_y_secciones(self):
        out = self.correr(*self.perfil_tz())
        plat = _leer(out / "vulnerabilidades.csv")
        fw = _leer(out / "vulnerabilidades_firmware.csv")
        self.assertEqual(list(plat[0])[-1], "id_vulnerabilidad")
        self.assertEqual(list(fw[0])[-1], "id_vulnerabilidad")
        self.assertNotIn("estado_confirmacion", plat[0])
        ids_plat = {f["cve"]: f["id_vulnerabilidad"] for f in plat}
        ids_fw = {f["cve"]: f["id_vulnerabilidad"] for f in fw}
        self.assertEqual(ids_plat[test_vconf.COMUN], vc.id_de(test_vconf.COMUN, "192.0.2.10"))
        self.assertEqual(ids_plat[test_vconf.COMUN], ids_fw[test_vconf.COMUN])
        # el mismo id que da VCONF para la misma fila
        con = self.correr(*self.perfil({"hallazgos": "todas"}))
        self.assertEqual({f["cve"]: f["id_vulnerabilidad"] for f in _leer(con / "vulnerabilidades.csv")}, ids_plat)
        # trazabilidad.csv, resultado.json, reportes
        tr = _leer(out / "trazabilidad.csv")
        self.assertEqual(list(tr[0]), tz.COLUMNAS)
        usados = {i for f in tr for i in f["ids_vulnerabilidad"].split("; ") if i}
        self.assertIn(ids_plat[test_vconf.COMUN], usados)
        self.assertTrue(usados <= set(ids_plat.values()) | set(ids_fw.values()))
        j = self.json(out)["trazabilidad"]
        self.assertEqual(j["cantidad_filas"], len(tr))
        self.assertEqual(len(j["filas"]), len(tr))
        self.assertIn("Cadena para trazar cada hallazgo", (out / "reporte_ot.html").read_text(encoding="utf-8"))
        self.assertIn("Cadena para trazar cada hallazgo", (out / "reporte_ot.md").read_text(encoding="utf-8"))
        import zipfile
        with zipfile.ZipFile(out / "informe_ot.docx") as z:
            self.assertIn("Cadena para trazar cada hallazgo", z.read("word/document.xml").decode("utf-8"))
        with zipfile.ZipFile(out / "reporte_ot.xlsx") as z:
            self.assertIn('name="Trazabilidad"', z.read("xl/workbook.xml").decode("utf-8"))

    def test_con_las_dos_claves_no_se_duplica(self):
        p = self.tmp / "dos.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}],
                                 "trazabilidad": {}, "confirmacion_vulnerabilidades": True}), encoding="utf-8")
        out = self.correr("--perfil", str(p))
        plat = list(_leer(out / "vulnerabilidades.csv")[0])
        fw = list(_leer(out / "vulnerabilidades_firmware.csv")[0])
        self.assertEqual(plat.count("id_vulnerabilidad"), 1)
        self.assertEqual(fw.count("id_vulnerabilidad"), 1)
        self.assertEqual(plat[-2:], ["id_vulnerabilidad", "estado_confirmacion"])

    def test_sin_clave_las_salidas_no_cambian(self):
        base = self.correr()
        self.assertFalse((base / "trazabilidad.csv").exists())
        self.assertNotIn("trazabilidad", self.json(base))
        self.assertNotIn("id_vulnerabilidad", _leer(base / "vulnerabilidades.csv")[0])
        self.assertNotIn("id_vulnerabilidad", _leer(base / "vulnerabilidades_firmware.csv")[0])
        self.assertNotIn("id_recomendacion", _leer(base / "hallazgos.csv")[0])
        self.assertNotIn("id_recomendacion", _leer(base / "plan_remediacion.csv")[0])
        self.assertNotIn("Trazabilidad", (base / "reporte_ot.html").read_text(encoding="utf-8"))
        con = self.correr(*self.perfil_tz())
        for n in ("hallazgos.csv", "plan_remediacion.csv", "vulnerabilidades.csv", "vulnerabilidades_firmware.csv"):
            a, b = _leer(base / n), _leer(con / n)
            extra = {"id_recomendacion", "id_vulnerabilidad", "id_flujo"}
            self.assertEqual([{k: v for k, v in r.items() if k not in extra} for r in b], a, n)

    def test_ingles(self):
        out = self.correr(*self.perfil_tz(), idioma="en")
        tr = _leer(out / "trazabilidad.csv")
        self.assertIn("recommendation_id", tr[0])
        self.assertIn("not a compliance determination", (out / "reporte_ot.html").read_text(encoding="utf-8"))


class DiagramaFlujoTest(test_allow1.Base):
    def test_id_flujo_en_zcr_y_allowlist_sin_allow1(self):
        o = self.correr("--perfil", self.perfil(trazabilidad={}))
        filas = _leer(o / "allowlist_tobe.csv")
        self.assertEqual(list(filas[0])[-1], "id_flujo")
        for f in filas:
            self.assertEqual(f["id_flujo"], ap.id_flujo(f["zona_origen"], f["zona_destino"], f["servicio"]))
        zcr = _leer(o / "conductos_zcr.csv")
        self.assertEqual(list(zcr[0])[-1], "id_flujo")
        self.assertTrue(all(f["id_flujo"].startswith("FL-") for f in zcr))
        ids_tr = {i for f in _leer(o / "trazabilidad.csv") for i in f["ids_flujo"].split("; ") if i}
        self.assertTrue(ids_tr <= {f["id_flujo"] for f in filas})

    def test_con_allow1_no_se_duplica_y_es_el_mismo(self):
        solo = self.correr("--perfil", self.perfil(allowlist_tobe={}))
        ambas = self.correr("--perfil", self.perfil(allowlist_tobe={}, trazabilidad={}))
        cab = list(_leer(ambas / "allowlist_tobe.csv")[0])
        self.assertEqual(cab.count("id_flujo"), 1)
        self.assertEqual(cab, list(_leer(solo / "allowlist_tobe.csv")[0]))
        self.assertEqual([f["id_flujo"] for f in _leer(ambas / "allowlist_tobe.csv")],
                         [f["id_flujo"] for f in _leer(solo / "allowlist_tobe.csv")])

    def test_sin_clave_no_hay_id_flujo(self):
        o = self.correr("--perfil", self.perfil())
        self.assertNotIn("id_flujo", _leer(o / "allowlist_tobe.csv")[0])
        self.assertNotIn("id_flujo", _leer(o / "conductos_zcr.csv")[0])


if __name__ == "__main__":
    unittest.main()
