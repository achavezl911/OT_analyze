"""V1a (D89): vulnerabilidades candidatas por fabricante, modelo y firmware contra avisos CSAF locales y un catalogo.

Todo sintetico: fabricantes y productos inventados (Acme Automation, PLC-5000), CVE-2099-xxxxx inexistentes e IP de
documentacion (192.0.2.0/24). Unitarias sin tshark; extremo a extremo por `diagrama` y por capturas (tshark y scapy).
"""
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
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

from ot_assess import avisos_cisa as ac
from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import vuln_firmware as vf
from ot_assess.cli import main
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture


def ent(ip, fab, modelo, fw):
    e = [("ips", ip, "manual", ""), ("fabricante", fab, "manual", ""), ("modelo", modelo, "manual", "")]
    if fw:
        e.append(("firmware", fw, "manual", ""))
    return {"macs": [], "ips": [ip], "entradas": e}


def inventario(*regs):
    return inv.construir(list(regs), None, True)


def csaf(aviso, cves, vendor="Acme Automation", producto="PLC-5000", version="vers:intdot/<2.4.1", extra=None,
         arbol=None):
    """cves: {cve: (cvss, fixed, not_affected)}; el producto afectado es el id 'P1' (hoja de la rama)."""
    arbol = arbol or {"branches": [{"category": "vendor", "name": vendor, "branches": [
        {"category": "product_name", "name": producto, "branches": [
            {"category": "product_version_range", "name": version,
             "product": {"name": f"{producto} {version}", "product_id": "P1"}}]}]}]}
    if extra:
        arbol.update(extra)
    vulns = []
    for cve, (cvss, fixed, no_afectado) in cves.items():
        estado = {"known_affected": ["P1"]}
        if fixed:
            estado["fixed"] = fixed
        if no_afectado:
            estado["known_not_affected"] = no_afectado
        vulns.append({"cve": cve, "product_status": estado,
                      "scores": [{"products": ["P1"], "cvss_v3": {"baseScore": cvss}}],
                      "remediations": [{"category": "vendor_fix", "details": f"Actualizar a 2.4.1 ({cve})",
                                        "product_ids": ["P1"]}]})
    return {"document": {"title": f"Aviso {aviso}", "tracking": {
        "id": aviso, "initial_release_date": "2099-03-01T00:00:00Z", "current_release_date": "2099-03-02T00:00:00Z"},
        "references": [{"category": "self", "url": f"https://ejemplo.invalid/{aviso}"}]},
        "product_tree": arbol, "vulnerabilities": vulns}


def correr(registros, avisos=(), catalogo=None, kev=None, cruces=None, assets=None, tmp=None):
    """Indice + construir sin pasar por el CLI. `avisos`: lista de objetos CSAF."""
    ind = vf.Indice(vf.fabricantes_de(registros))
    for i, a in enumerate(avisos):
        ind.visitar(a, f"a{i}.json")
    if catalogo is not None:
        p = Path(tmp) / "catalogo.csv"
        p.write_text(catalogo, encoding="utf-8")
        ind.cargar_catalogo(p)
    return vf.construir(ind, inventario(*registros), cruces, assets or {}, kev)


def estados(res):
    return {(x["ips"][0], x["cve"]): x["estado"] for x in res["filas"]}


class _Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class VersionTest(unittest.TestCase):
    def test_rangos_y_formas(self):
        casos = [
            ("<=V5.1", "5.0", "si"), ("<=V5.1", "5.1", "si"), ("<=V5.1", "5.2", "no"),
            ("<=Firmware 2.1", "2.0.9", "si"), ("<=Firmware 2.1", "2.1.1", "no"),
            (">=V1.0", "1.0", "si"), (">=V1.0", "0.9", "no"),
            ("vers:intdot/>=1.0|<1.5", "1.2", "si"), ("vers:intdot/>=1.0|<1.5", "1.5", "no"),
            ("vers:intdot/>=1.0|<1.5", "0.9", "no"), ("vers:intdot/<2.4.1", "V02.03.00", "si"),
            ("vers:intdot/<2.4.1", "2.4.1", "no"), ("vers:all/*", "9.9", "si"), ("All versions", "9.9", "si"),
            ("*", "1", "si"), ("vers:intdot/<2.4.1", "sin numeros", "nc"), ("vers:intdot/<sinnumero", "1.0", "nc"),
            ("segun el modelo", "1.0", "nc"), ("V04.04.00", "4.4", "si"), ("2.0", "2.1", "no"),
            ("vers:semver/1.0.0|1.0.2", "1.0.2", "si"), ("vers:semver/!=1.0.0", "1.0.0", "no"),
            ("<20.011", "20.010", "si"),
        ]
        for expr, fw, esperado in casos:
            with self.subTest(expr=expr, fw=fw):
                self.assertEqual(vf.evaluar(expr, fw), esperado)

    def test_ceros_a_la_izquierda_y_relleno(self):
        self.assertEqual(vf._cmp(vf._tupla("V04.04.00"), vf._tupla("4.4")), 0)
        self.assertLess(vf._cmp(vf._tupla("4.4"), vf._tupla("4.4.1")), 0)


class FabricanteYProductoTest(unittest.TestCase):
    def test_normalizacion_y_alias(self):
        self.assertEqual(vf.clave_fabricante("ACME Automation Inc."), vf.clave_fabricante("Acme Automation"))
        self.assertEqual(vf.clave_fabricante("Allen-Bradley"), vf.clave_fabricante("Rockwell Automation"))
        self.assertEqual(vf.clave_fabricante("Modicon"), vf.clave_fabricante("Schneider Electric Inc."))
        self.assertEqual(vf.clave_fabricante("GE Vernova"), vf.clave_fabricante("General Electric Co."))
        self.assertEqual(vf.clave_fabricante("Hirschmann"), vf.clave_fabricante("Belden"))
        self.assertEqual(vf.clave_fabricante("Fisher-Rosemount"), vf.clave_fabricante("Emerson"))
        self.assertNotEqual(vf.clave_fabricante("Acme"), vf.clave_fabricante("Siemens AG"))
        self.assertEqual(vf.clave_fabricante("Siemens AG"), vf.clave_fabricante("SIEMENS"))

    def test_producto(self):
        self.assertTrue(vf.producto_casa("1756-L71", "1756-L71/B"))
        self.assertTrue(vf.producto_casa("PLC 5000", "plc_5000"))
        self.assertFalse(vf.producto_casa("controller", "Logix Controller X"))
        self.assertFalse(vf.producto_casa("switch", "Switch Gigabit"))
        self.assertFalse(vf.producto_casa("PLC-5000", "PLC-6000"))
        self.assertFalse(vf.producto_casa("PLC-500", "PLC-5000"))        # tokens completos, no subcadenas
        self.assertEqual(vf.nivel_producto("1756-L71", "1756-L71/B"), "modelo exacto")
        self.assertEqual(vf.nivel_producto("Acme ControlLogix Communications Modules 1756-EN", "ControlLogix"),
                         "familia (sin numero de modelo)")
        self.assertEqual(vf.evaluar("5.5|5.0|5.1", "5.0"), "si")
        fam, exacto = "familia (sin numero de modelo)", "modelo exacto"
        for producto, esperado in (("PX-1500 TM MFP - GNU/Linux subsystem", fam),
                                   ("PX-1500 CPU 1511-1 PN (6AB1511-1XX02)", fam),
                                   ("PX-1500 Software Controller", fam),
                                   ("PX-1500 CPU family (incl. related ET200 CPUs and variants)", exacto),
                                   ("PX-1500", exacto)):
            with self.subTest(producto=producto):
                self.assertEqual(vf.nivel_producto(producto, "PX-1500"), esperado)
        self.assertEqual(vf.nivel_producto("Acme Stratus 5410 Industrial Distribution Switches", "Stratus 5410",
                                           ["acme"]), exacto)
        self.assertEqual(vf.nivel_producto("PX-1500", "PX-1500 CPU 1511"), exacto)   # el aviso cabe en el modelo
        self.assertEqual(vf.evaluar("5.5|5.0|5.1", "5.2"), "no")
        self.assertTrue(vf.producto_casa("Acme PLC-5000", "PLC-5000", ["acme"]))     # sin el nombre del fabricante


class CruceTest(_Base):
    def test_rango_intdot_tres_firmwares(self):
        regs = [ent("192.0.2.1", "ACME Automation Inc.", "PLC-5000", "V2.3.0"),
                ent("192.0.2.2", "ACME Automation Inc.", "PLC-5000", "2.4.1"),
                ent("192.0.2.3", "ACME Automation Inc.", "PLC-5000", "")]
        res = correr(regs, [csaf("ICSA-99-100-01", {"CVE-2099-10001": (9.8, [], [])})])
        self.assertEqual(estados(res), {("192.0.2.1", "CVE-2099-10001"): "version afectada",
                                        ("192.0.2.3", "CVE-2099-10001"): "sin firmware: posible"})
        self.assertEqual(res["resumen"]["firmware_fuera_de_rango"], 1)
        self.assertEqual(res["resumen"]["activos_con_fabricante_y_modelo"], 3)
        self.assertEqual(res["resumen"]["activos_con_firmware"], 2)
        fila = res["filas"][0]
        self.assertEqual(fila["celdas"][vf.COLUMNAS.index("severidad")], "Critica")
        self.assertEqual(fila["celdas"][vf.COLUMNAS.index("coincidencia")], "modelo exacto")
        self.assertEqual(fila["celdas"][vf.COLUMNAS.index("aviso")], "ICSA-99-100-01")
        self.assertIn("Actualizar a 2.4.1", fila["celdas"][vf.COLUMNAS.index("remediacion")])
        self.assertEqual(fila["celdas"][vf.COLUMNAS.index("fuente")], "a0.json")
        self.assertEqual(fila["celdas"][vf.COLUMNAS.index("kev")], "")
        self.assertEqual(fila["celdas"][-4:], ["", "", "", ""])

    def test_familia_se_lista_pero_no_da_hallazgo(self):
        regs = [ent("192.0.2.1", "Acme Automation", "ControlLogix", "1.0")]
        res = correr(regs, [csaf("ICSA-99-7", {"CVE-2099-17001": (9.8, [], [])},
                                 producto="ControlLogix Communications Modules 1756-EN", version="vers:all/*")])
        self.assertEqual([(x["estado"], x["coinc"]) for x in res["filas"]],
                         [("version afectada", "familia (sin numero de modelo)")])
        self.assertEqual(res["filas"][0]["celdas"][vf.COLUMNAS.index("coincidencia")], "familia (sin numero de modelo)")
        self.assertEqual(vf._candidatas(res), [])

    def test_estados_por_tipo_de_rango(self):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "5.0"),
                ent("192.0.2.2", "Acme Automation", "PLC-5000", "")]
        for version, fw_esperado in (("<=V5.1", "version afectada"), (">=1.0|<1.5", "version afectada"),
                                     ("vers:all/*", "version afectada"), ("All versions", "version afectada"),
                                     ("sin numeros aqui", "version no comparable: revisar")):
            with self.subTest(version=version):
                res = correr(regs[:1], [csaf("ICSA-99-1", {"CVE-2099-10002": (7.5, [], [])}, version=version)])
                if version.startswith(">=1.0"):
                    self.assertEqual(res["filas"], [])          # 5.0 fuera de 1.0-1.5
                    self.assertEqual(res["resumen"]["firmware_fuera_de_rango"], 1)
                else:
                    self.assertEqual([x["estado"] for x in res["filas"]], [fw_esperado])
        res = correr(regs[1:], [csaf("ICSA-99-1", {"CVE-2099-10002": (7.5, [], [])}, version="All versions")])
        self.assertEqual([x["estado"] for x in res["filas"]], ["version afectada"])   # no depende del firmware

    def test_fixed_y_no_afectado_se_excluyen_y_el_orden(self):
        a = csaf("ICSA-99-2", {"CVE-2099-20001": (5.0, ["P1"], []), "CVE-2099-20002": (6.0, [], ["P1"]),
                               "CVE-2099-20003": (9.0, [], []), "CVE-2099-20004": (4.0, [], [])})
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0")]
        res = correr(regs, [a])
        self.assertEqual([x["cve"] for x in res["filas"]], ["CVE-2099-20003", "CVE-2099-20004"])

    def test_relationships_y_product_groups(self):
        arbol = {"branches": [{"category": "vendor", "name": "Acme Automation", "branches": [
            {"category": "product_name", "name": "PLC-5000", "branches": [
                {"category": "product_version_range", "name": "vers:intdot/<3.0",
                 "product": {"name": "PLC-5000 <3.0", "product_id": "BASE"}}]}]}],
            "relationships": [{"category": "default_component_of", "product_reference": "BASE",
                               "relates_to_product_reference": "OTRO",
                               "full_product_name": {"name": "PLC-5000 <3.0 como componente", "product_id": "REL"}}],
            "product_groups": [{"group_id": "G1", "product_ids": ["REL"]}]}
        a = csaf("ICSA-99-3", {}, arbol=arbol)
        a["vulnerabilities"] = [{"cve": "CVE-2099-30001", "product_status": {"known_affected": ["G1"]},
                                 "scores": [{"cvss_v3": {"baseScore": 7.5}}]}]
        res = correr([ent("192.0.2.1", "Acme Automation", "PLC-5000", "2.0")], [a])
        self.assertEqual([x["cve"] for x in res["filas"]], ["CVE-2099-30001"])
        self.assertEqual(res["filas"][0]["reg"]["producto"], "PLC-5000")

    def test_solo_se_guardan_avisos_de_fabricantes_del_inventario(self):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0")]
        ind = vf.Indice(vf.fabricantes_de(regs))
        ind.visitar(csaf("ICSA-99-4", {"CVE-2099-40001": (5.0, [], [])}, vendor="Otro Fabricante"), "o.json")
        ind.visitar(csaf("ICSA-99-5", {"CVE-2099-40002": (5.0, [], [])}), "a.json")
        self.assertEqual(ind.avisos_leidos, 2)
        self.assertEqual(ind.avisos_con_fabricante, 1)
        self.assertEqual(sum(len(v) for v in ind.por_fabricante.values()), 1)

    def test_sin_modelo_no_hay_cruce(self):
        reg = {"macs": [], "ips": ["192.0.2.9"], "entradas": [("ips", "192.0.2.9", "manual", ""),
                                                              ("fabricante", "Acme Automation", "manual", ""),
                                                              ("firmware", "1.0", "manual", "")]}
        res = correr([reg], [csaf("ICSA-99-6", {"CVE-2099-50001": (9.9, [], [])})])
        self.assertEqual(res["filas"], [])
        self.assertEqual(res["resumen"]["activos_con_fabricante_y_modelo"], 0)

    def test_catalogo_alias_y_producto_generico(self):
        cat = ("fabricante,producto,version_afectada,cve,cvss,aviso,remediacion,fuente\n"
               "Allen-Bradley,1756-L71,<20.011,CVE-2099-60001,8.1,AV-1,Actualizar,Analista\n"
               "Allen-Bradley,controller,All versions,CVE-2099-60002,9.0,AV-2,x,Analista\n")
        regs = [ent("192.0.2.1", "Rockwell Automation", "1756-L71/B", "20.010"),
                ent("192.0.2.2", "Rockwell Automation", "Logix Controller X", "1.0")]
        res = correr(regs, catalogo=cat, tmp=self.tmp)
        self.assertEqual(estados(res), {("192.0.2.1", "CVE-2099-60001"): "version afectada"})
        fila = res["filas"][0]["celdas"]
        self.assertEqual(fila[vf.COLUMNAS.index("fuente")], "catalogo.csv (Analista)")
        self.assertEqual(fila[vf.COLUMNAS.index("severidad")], "Alta")
        self.assertEqual(fila[vf.COLUMNAS.index("aviso")], "AV-1")

    def test_catalogo_con_encabezados_en_ingles_y_sin_columnas(self):
        cat = ("Vendor,Model,Affected Versions,CVE\nAcme,PLC-5000,<2.0,CVE-2099-70001\n")
        res = correr([ent("192.0.2.1", "Acme", "PLC-5000", "1.0")], catalogo=cat, tmp=self.tmp)
        self.assertEqual(len(res["filas"]), 1)
        self.assertEqual(res["filas"][0]["celdas"][vf.COLUMNAS.index("cvss")], "")
        p = self.tmp / "mal.csv"
        p.write_text("a,b\n1,2\n", encoding="utf-8")
        with self.assertRaises(SystemExit) as cm:
            vf.Indice(set()).cargar_catalogo(p)
        self.assertIn("mal.csv", str(cm.exception))
        self.assertNotIn(str(self.tmp), str(cm.exception))

    def test_ya_en_la_plataforma_no_cuenta_para_el_hallazgo(self):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0"),
                ent("192.0.2.2", "Acme Automation", "PLC-5000", "1.0")]
        assets = {"k1": {"nombre": "PLC-UNO", "ips": ["192.0.2.1"], "mac": "k1"}}
        cruces = [{"vuln": {"cve": "CVE-2099-80001", "ip": "192.0.2.1"}, "activo": "k1"}]
        res = correr(regs, [csaf("ICSA-99-8", {"CVE-2099-80001": (9.8, [], [])})], cruces=cruces, assets=assets)
        por_ip = {x["ips"][0]: x["celdas"][vf.COLUMNAS.index("en_plataforma")] for x in res["filas"]}
        self.assertEqual(por_ip, {"192.0.2.1": "si", "192.0.2.2": "no"})
        cap = Capture(Path("x"))
        vf.agregar_hallazgo(cap, res)
        self.assertEqual(len(cap.findings), 1)
        self.assertEqual(cap.findings[0]["activos"], ["192.0.2.2"])
        solo = correr(regs[:1], [csaf("ICSA-99-8", {"CVE-2099-80001": (9.8, [], [])})], cruces=cruces, assets=assets)
        cap = Capture(Path("x"))
        vf.agregar_hallazgo(cap, solo)
        self.assertEqual(cap.findings, [])

    def test_kev_y_severidad_del_hallazgo(self):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0")]
        aviso = csaf("ICSA-99-9", {"CVE-2099-90001": (7.5, [], [])})
        kev = {"por_cve": {"CVE-2099-90001": {"agregada": "2099-01-01"}}}
        con = correr(regs, [aviso], kev=kev)
        self.assertEqual(con["filas"][0]["celdas"][vf.COLUMNAS.index("kev")], "si")
        sin_cve = correr(regs, [aviso], kev={"por_cve": {}})
        self.assertEqual(sin_cve["filas"][0]["celdas"][vf.COLUMNAS.index("kev")], "no")
        for res, sev in ((con, "Alta"), (sin_cve, "Media"), (correr(regs, [aviso]), "Media"),
                         (correr(regs, [csaf("ICSA-99-9", {"CVE-2099-90001": (9.0, [], [])})]), "Alta")):
            cap = Capture(Path("x"))
            vf.agregar_hallazgo(cap, res)
            self.assertEqual(cap.findings[0]["severidad"], sev)
            self.assertIn("vulnerabilidades conocidas", cap.findings[0]["titulo"])
            self.assertNotIn("cumple", cap.findings[0]["evidencia"].lower())

    def test_sin_firmware_y_no_comparable_no_generan_hallazgo(self):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "")]
        res = correr(regs, [csaf("ICSA-99-10", {"CVE-2099-11001": (9.8, [], [])})])
        self.assertEqual([x["estado"] for x in res["filas"]], ["sin firmware: posible"])
        cap = Capture(Path("x"))
        vf.agregar_hallazgo(cap, res)
        self.assertEqual(cap.findings, [])

    def test_seccion_vacia_y_json(self):
        res = correr([{"macs": [], "ips": ["192.0.2.1"], "entradas": [("ips", "192.0.2.1", "manual", "")]}], [])
        s = vf.seccion(res)
        self.assertIn("Ningun activo tiene fabricante y modelo para cruzar", s["vacio"])
        self.assertEqual(vf.tablas(res), [])
        self.assertEqual(vf.para_json({}), {})
        self.assertEqual(vf.para_json(res)["filas"], [])


class UnaSolaLecturaTest(_Base):
    def carpeta(self):
        d = self.tmp / "avisos"
        d.mkdir()
        (d / "a.json").write_text(json.dumps(csaf("ICSA-99-20", {"CVE-2099-12001": (9.8, [], [])})), encoding="utf-8")
        (d / "b.json").write_text(json.dumps(csaf("ICSA-99-21", {"CVE-2099-12002": (5.0, [], [])},
                                                  vendor="Otro")), encoding="utf-8")
        (d / "no.json").write_text("{}", encoding="utf-8")
        return d

    def test_visitante_no_cambia_el_resultado_de_t6_y_lee_una_vez(self):
        d = self.carpeta()
        cves = {"CVE-2099-12001", "CVE-2099-12002"}
        base = ac.cargar_avisos(d, cves)
        ind = vf.Indice({vf.clave_fabricante("Acme Automation")})
        lecturas = []
        original = Path.read_bytes

        def espia(self):
            lecturas.append(self.name)
            return original(self)
        with mock.patch.object(Path, "read_bytes", espia):
            con = ac.cargar_avisos(d, cves, ind.visitar)
        self.assertEqual(sorted(lecturas), ["a.json", "b.json", "no.json"])
        self.assertEqual(base, con)
        self.assertEqual(ind.avisos_leidos, 2)
        self.assertEqual(ind.avisos_con_fabricante, 1)
        self.assertEqual(con["saltados"], 1)

    def test_sin_entradas_no_corre(self):
        class A:
            avisos_ics = None
            catalogo_vulnerabilidades = None
        self.assertIsNone(vf.de_args(A(), []))


def _leer(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _escribir(path, cab, filas):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return path


def _md(out):
    return "".join(p.read_text(encoding="utf-8") for p in sorted(out.glob("*.md")))


class DiagramaE2ETest(_Base):
    def setUp(self):
        super().setUp()
        self.a, self.e, self.d = self.preparar()

    def preparar(self):
        a = _escribir(self.tmp / "activos.csv", ["Name", "IP", "MAC", "Vendor", "Model", "Firmware", "Type"], [
            ["PLC-1", "192.0.2.10", "02:00:00:00:00:01", "ACME Automation Inc.", "PLC-5000", "V2.3.0", "PLC"],
            ["HMI-1", "192.0.2.11", "02:00:00:00:00:02", "Otro", "", "", "HMI"]])
        e = _escribir(self.tmp / "enlaces.csv", ["Source", "Destination", "Port", "Protocol", "Packets"], [
            ["192.0.2.11", "192.0.2.10", "502", "Modbus", "100"]])
        d = self.tmp / "avisos"
        d.mkdir()
        (d / "a.json").write_text(json.dumps(csaf("ICSA-99-30", {"CVE-2099-13001": (9.8, [], [])})), encoding="utf-8")
        return a, e, d

    def correr(self, nombre, *extra, idioma="es"):
        out = self.tmp / nombre
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_diagrama(["--activos", str(self.a), "--enlaces", str(self.e), "--formato", "generico",
                                "-o", str(out),
                                "--idioma", idioma, *extra])
        self.assertEqual(rc, 0)
        self.consola = buf.getvalue()
        return out

    def test_avisos_generan_csv_seccion_json_y_hallazgo(self):
        out = self.correr("o1", "--avisos-ics", str(self.d))
        filas = _leer(out / "vulnerabilidades_firmware.csv")
        self.assertEqual([(f["activo"], f["cve"], f["estado"]) for f in filas],
                         [("PLC-1", "CVE-2099-13001", "version afectada")])
        self.assertEqual(filas[0]["en_plataforma"], "no")
        self.assertIn("Vulnerabilidades candidatas por fabricante, modelo y firmware", _md(out))
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["vuln_firmware"]["resumen"]["por_estado"]["version afectada"], 1)
        self.assertEqual(res["entorno"]["avisos_ics"]["archivo"], "avisos")
        hall = [h for h in _leer(out / "hallazgos.csv") if "vulnerabilidades conocidas por fabricante" in
                " ".join(h.values())]
        self.assertEqual(len(hall), 1)
        self.assertNotIn("vulnerabilidades.csv", [p.name for p in out.iterdir()])

    def test_cvss_v4_desde_csaf_en_columnas_nuevas(self):
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        aviso = csaf("ICSA-99-31", {"CVE-2099-13005": (9.8, [], [])})
        aviso["vulnerabilities"][0]["references"] = [{"url": "https://www.first.org/cvss/calculator/4.0#" + v4}]
        (self.d / "b.json").write_text(json.dumps(aviso), encoding="utf-8")
        out = self.correr("o4", "--avisos-ics", str(self.d))
        cab = list(_leer(out / "vulnerabilidades_firmware.csv")[0])
        self.assertEqual(cab[cab.index("severidad"):cab.index("severidad") + 3],
                         ["severidad", "cvss_v4", "vector_cvss_v4"])
        por_cve = {f["cve"]: f for f in _leer(out / "vulnerabilidades_firmware.csv")}
        self.assertEqual((por_cve["CVE-2099-13005"]["cvss"], por_cve["CVE-2099-13005"]["cvss_v4"],
                          por_cve["CVE-2099-13005"]["vector_cvss_v4"]), ("9.8", "9.3", v4))
        self.assertEqual((por_cve["CVE-2099-13001"]["cvss_v4"], por_cve["CVE-2099-13001"]["vector_cvss_v4"]),
                         ("", ""))                                  # sin v4: vacias
        self.assertEqual(por_cve["CVE-2099-13001"]["severidad"], "Critica")        # la severidad sigue siendo v3

    def test_catalogo_con_solo_vector_v4_se_puntua(self):
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"       # 7.1
        cat = _escribir(self.tmp / "cat4.csv",
                        ["fabricante", "producto", "version_afectada", "cve", "cvss", "vector_v4", "cvss4"],
                        [["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13006", "5.5", v4, ""],
                         ["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13007", "5.5", v4, "2.0"],
                         ["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13008", "5.5", "", "4.5"],
                         ["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13009", "5.5", "CVSS:4.0/mal", ""]])
        out = self.correr("o5", "--catalogo-vulnerabilidades", str(cat))
        f = {x["cve"]: x for x in _leer(out / "vulnerabilidades_firmware.csv")}
        self.assertEqual((f["CVE-2099-13006"]["cvss_v4"], f["CVE-2099-13006"]["vector_cvss_v4"]), ("7.1", v4))
        self.assertEqual(f["CVE-2099-13007"]["cvss_v4"], "7.1")                 # gana el calculado
        self.assertEqual((f["CVE-2099-13008"]["cvss_v4"], f["CVE-2099-13008"]["vector_cvss_v4"]), ("4.5", ""))
        self.assertEqual((f["CVE-2099-13009"]["cvss_v4"], f["CVE-2099-13009"]["vector_cvss_v4"]), ("", ""))
        self.assertEqual({x["cvss"] for x in f.values()}, {"5.5"})                 # v3 intacto

    def test_catalogo_solo_y_entorno(self):
        cat = _escribir(self.tmp / "cat.csv", ["fabricante", "producto", "version_afectada", "cve", "cvss"],
                        [["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13002", "5.5"]])
        out = self.correr("o2", "--catalogo-vulnerabilidades", str(cat))
        self.assertEqual([f["cve"] for f in _leer(out / "vulnerabilidades_firmware.csv")], ["CVE-2099-13002"])
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["entorno"]["catalogo_vulnerabilidades"]["archivo"], "cat.csv")
        self.assertNotIn(str(self.tmp), json.dumps(res["entorno"]))

    def test_sin_entradas_no_cambia_nada(self):
        out = self.correr("o3")
        self.assertFalse((out / "vulnerabilidades_firmware.csv").exists())
        res = json.loads((out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["vuln_firmware"], {})
        self.assertNotIn("candidatas", _md(out))

    def test_sin_activos_con_modelo_la_seccion_sale_sin_csv(self):
        a = _escribir(self.tmp / "a2.csv", ["Name", "IP", "MAC", "Type"], [["X", "192.0.2.50", "02:00:00:00:00:09", "PLC"]])
        e = _escribir(self.tmp / "e2.csv", ["Source", "Destination", "Port", "Protocol", "Packets"],
                      [["192.0.2.50", "192.0.2.51", "502", "Modbus", "5"]])
        d = self.tmp / "av2"
        d.mkdir()
        (d / "a.json").write_text(json.dumps(csaf("ICSA-99-31", {"CVE-2099-13003": (5.0, [], [])})), encoding="utf-8")
        out = self.tmp / "o4"
        with contextlib.redirect_stdout(io.StringIO()):
            main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico", "-o", str(out),
                           "--avisos-ics", str(d)])
        self.assertFalse((out / "vulnerabilidades_firmware.csv").exists())
        self.assertIn("Ningun activo tiene fabricante y modelo para cruzar", _md(out))

    def test_t6_con_vulnerabilidades_da_el_mismo_avisos_csv(self):
        vul = _escribir(self.tmp / "vul.csv", ["ip", "cve", "severidad", "cvss", "estado"],
                        [["192.0.2.10", "CVE-2099-13001", "Critical", "9.8", "open"]])
        aviso = str(self.d)
        solo_t6 = self.correr("t6", "--vulnerabilidades", str(vul), "--avisos-ics", aviso)
        con = _leer(solo_t6 / "avisos_ics.csv")
        self.assertEqual(len(con), 1)
        fw = _leer(solo_t6 / "vulnerabilidades_firmware.csv")
        self.assertEqual(fw[0]["en_plataforma"], "si")
        hall = [h for h in _leer(solo_t6 / "hallazgos.csv") if "por fabricante, modelo y firmware" in
                " ".join(h.values())]
        self.assertEqual(hall, [])           # ya esta en el hallazgo de E1b
        with mock.patch.object(vf.Indice, "visitar", lambda *a, **k: None):
            base = self.correr("t6b", "--vulnerabilidades", str(vul), "--avisos-ics", aviso)
        self.assertEqual((solo_t6 / "avisos_ics.csv").read_text(encoding="utf-8-sig"),
                         (base / "avisos_ics.csv").read_text(encoding="utf-8-sig"))

    def test_n2_modelo_inferido_del_cpe_cruza_con_csaf(self):
        a = _escribir(self.tmp / "a_n2.csv", ["Name", "IP", "MAC", "Type"], [
            ["SW-1", "192.0.2.20", "02:00:00:00:00:20", "Switch"],
            ["SW-2", "192.0.2.21", "02:00:00:00:00:21", "Switch"]])
        e = _escribir(self.tmp / "e_n2.csv", ["Source", "Destination", "Port", "Protocol", "Packets"],
                      [["192.0.2.20", "192.0.2.21", "80", "HTTP", "5"]])
        d = self.tmp / "av_n2"
        d.mkdir()
        (d / "a.json").write_text(json.dumps(csaf("ICSA-99-40", {"CVE-2099-14001": (7.5, [], [])}, vendor="Siemens",
                                                  producto="SCALANCE XC208", version="vers:intdot/<4.5")),
                                  encoding="utf-8")
        vul = _escribir(self.tmp / "vul_n2.csv", ["node_id", "cve", "cve_score", "matching_cpes"], [
            ["192.0.2.20", "CVE-2099-14001", "7.5",
             "cpe:/h:siemens:scalance_xc208:-, cpe:/o:siemens:scalance_xc208_firmware:04.04.00"]])

        def correr(nombre, *extra):
            out = self.tmp / nombre
            with contextlib.redirect_stdout(io.StringIO()):
                main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico", "-o", str(out),
                               "--avisos-ics", str(d), *extra])
            return out
        out = correr("n2", "--vulnerabilidades", str(vul))
        fw = _leer(out / "vulnerabilidades_firmware.csv")
        self.assertEqual([(f["activo"], f["cve"]) for f in fw], [("SW-1", "CVE-2099-14001")])
        prov = [r for r in _leer(out / "inventario_procedencia.csv") if "scalance xc208" in r.values()]
        self.assertTrue(prov, "sin fila de procedencia")
        self.assertIn("inferido", prov[0].values())
        self.assertIn("inferido:cpe vul_n2.csv", prov[0].values())
        self.assertFalse((correr("n2b") / "vulnerabilidades_firmware.csv").exists())

    def test_ingles_sin_faltantes(self):
        cat = _escribir(self.tmp / "cat.csv", ["fabricante", "producto", "version_afectada", "cve", "cvss"],
                        [["Acme Automation", "PLC-5000", "<3.0", "CVE-2099-13002", "9.5"],
                         ["Acme Automation", "PLC-5000", "sin numeros", "CVE-2099-13004", "5.5"]])
        i18n.FALTANTES.clear()
        out = self.correr("en", "--catalogo-vulnerabilidades", str(cat), "--avisos-ics", str(self.d), idioma="en")
        faltantes = sorted(i18n.FALTANTES)
        i18n.usar("es")
        self.assertEqual(faltantes, [])
        texto = (out / "vulnerabilidades_firmware.csv").read_text(encoding="utf-8-sig")
        self.assertIn("affected version", texto)
        titulos = " ".join(h["titulo"] if "titulo" in h else h.get("title", "") for h in _leer(out / "hallazgos.csv"))
        self.assertIn("Possible known vulnerabilities by vendor, model and firmware (to be confirmed)", titulos)

    def test_catalogo_inexistente_falla_con_mensaje(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            main_diagrama(["--activos", str(self.a), "--enlaces", str(self.e), "--formato", "generico", "-o",
                           str(self.tmp / "x"), "--catalogo-vulnerabilidades", str(self.tmp / "no_existe.csv")])


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CapturasE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gen_pcaps as g
        cls.tmp = Path(tempfile.mkdtemp())
        pcaps = cls.tmp / "pcaps"
        pcaps.mkdir()
        g.guardar(g.punto_a(), pcaps / "a.pcap")
        man = _escribir(cls.tmp / "man.csv", ["IP", "Fabricante", "Modelo", "Firmware"],
                        [["10.10.1.20", "Acme Automation Inc", "PLC-5000", "V2.3.0"]])
        d = cls.tmp / "avisos"
        d.mkdir()
        (d / "a.json").write_text(json.dumps(csaf("ICSA-99-40", {"CVE-2099-14001": (9.8, [], [])})), encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.rc = main([str(pcaps), "-o", str(cls.out), "--cache", str(cls.tmp / "cache"),
                           "--inventario-manual", str(man), "--avisos-ics", str(d)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_csv_seccion_y_hallazgo(self):
        self.assertEqual(self.rc, 0)
        filas = _leer(self.out / "vulnerabilidades_firmware.csv")
        self.assertEqual([(f["ip"], f["cve"], f["estado"]) for f in filas],
                         [("10.10.1.20", "CVE-2099-14001", "version afectada")])
        self.assertIn("manual", filas[0]["procedencia"])
        hall = [h for h in _leer(self.out / "hallazgos.csv") if "por fabricante, modelo y firmware" in
                " ".join(h.values())]
        self.assertEqual(len(hall), 1)
        res = json.loads((self.out / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["vuln_firmware"]["resumen"]["filas"], 1)
        self.assertNotIn(str(self.tmp), json.dumps(res["entorno"]))


class NumeroDePedidoTest(unittest.TestCase):
    def test_numero_de_pedido_completo_del_aviso_es_modelo_exacto(self):
        from ot_assess.vuln_firmware import COINCIDENCIA, nivel_producto
        p = "PX-1500 CPU 1511-1 PN (6XX7511-1AK02-0AB0)"
        self.assertEqual(nivel_producto(p, "6XX7511-1AK02-0AB0"), COINCIDENCIA)
        self.assertEqual(nivel_producto(p, "6XX7 511-1AK02-0AB0"), COINCIDENCIA)      # MLFB de S7 con espacio
        self.assertEqual(nivel_producto("PX-1500 CPU (6XX7511-1AK01-0AB0, 6XX7511-1AK02-0AB0)",
                                        "6XX7 511-1AK02-0AB0"), COINCIDENCIA)
        self.assertEqual(nivel_producto(p, "6XX7511-1AK01-0AB0"), "")                  # otra variante: no casa
        self.assertNotEqual(nivel_producto("PX-1500 (CPU 15)", "CPU 15"), COINCIDENCIA)  # corto: regla de tokens


class ExportacionesClarotyTest(_Base):
    FW_GE = "v8.75 [B5O1] (Boot: v0.00 [], HW: v4.00)"

    def _ge(self, version="< R9.90", fw=FW_GE, fab="GE Automation"):
        regs = [ent("192.0.2.1", fab, "IC695CPE330-ABAF", fw)]
        aviso = csaf("ICSA-99-300-01", {"CVE-2099-30001": (9.8, [], [])},
                     vendor="General Electric (GE) and Emerson", producto="CPE330", version=version)
        return correr(regs, [aviso])

    def test_fabricante_con_parentesis_and_y_modelo_en_el_catalogo(self):
        for fab in ("GE Automation", "General Electric", "GE Fanuc"):
            res = self._ge(fab=fab)
            self.assertEqual(len(res["filas"]), 1, fab)
            x = res["filas"][0]
            self.assertEqual((x["coinc"], x["estado"]), ("modelo exacto", "version afectada"), fab)
        self.assertEqual(self._ge(fw="v9.95 [B5O1] (Boot: v0.00 [], HW: v4.00)")["filas"], [])
        self.assertEqual(self._ge(fab="Emerson")["filas"][0]["estado"], "version afectada")

    def test_claves_de_fabricante(self):
        c = vf.claves_fabricante("General Electric (GE) and Emerson")
        self.assertIn(vf.clave_fabricante("GE"), c)
        self.assertIn(vf.clave_fabricante("Emerson"), c)
        self.assertEqual(vf.claves_fabricante("Acme Automation"), {vf.clave_fabricante("Acme Automation")})
        self.assertEqual(vf.claves_fabricante("B&R Industrial Automation"),
                         {vf.clave_fabricante("B&R Industrial Automation")})       # "&" sin espacios no parte
        self.assertIn(vf.clave_fabricante("Kieback"), vf.claves_fabricante("Kieback & Peter"))

    def test_modelo_dentro_del_numero_de_catalogo(self):
        n = vf.nivel_producto
        self.assertEqual(n("CPE330", "IC695CPE330-ABAF"), vf.COINCIDENCIA)
        self.assertEqual(n("RX3i CPE330", "IC695CPE330-ABAF"), "")
        self.assertEqual(n("S7", "S7-1500"), vf.COINCIDENCIA)           # regla de tokens, no la del catalogo
        self.assertEqual(n("S7", "6ES7511-1AK02"), "")
        self.assertEqual(n("PLC-500", "PLC-5000"), "")                  # no parte una cifra
        self.assertEqual(n("SCALANCE", "IC695SCALANCEX"), "")           # sin digitos: no aplica

    def test_firmware_con_texto_alrededor(self):
        fw = "AXIS M3058-PLVE Fixed Dome Network Camera 10.12.323"
        self.assertEqual(vf.evaluar("< 10.12.400", fw), "si")
        self.assertEqual(vf.evaluar("< 10.12.300", fw), "no")
        self.assertEqual(vf.evaluar("< R9.90", self.FW_GE), "si")
        for fwv, expr, esperado in (("V2.015", "<= 2.15", "si"), ("5.10.08.09", "< 5.10.8.10", "si"),
                                    ("8", "< 9", "si"), ("R9.90", "<= R9.90", "si"), ("R9.90", "< R9.90", "no")):
            self.assertEqual(vf.evaluar(expr, fwv), esperado, (fwv, expr))

    def test_modelo_en_el_campo_de_version(self):
        self.assertEqual(vf.modelo_en_version("SCALANCE", "W744-1"), ("SCALANCE W744-1", ""))
        for v in ("Rev.1", "R16A", "SV3.70", "V2.9", "2.4.1", "vers:intdot/<2.4.1", "< 5", "All versions",
                  "FW-9167-0-11"):
            self.assertEqual(vf.modelo_en_version("SCALANCE", v), ("SCALANCE", v), v)

        def aviso(version):
            return csaf("ICSA-99-301-01", {"CVE-2099-30002": (7.5, [], [])}, vendor="Siemens",
                        producto="SCALANCE", version=version)
        xc = [ent("192.0.2.2", "Siemens", "SCALANCE XC208", "4.0")]
        w7 = [ent("192.0.2.3", "Siemens", "SCALANCE W744-1", "4.0")]
        self.assertEqual(correr(xc, [aviso("W744-1")])["filas"], [])
        res = correr(w7, [aviso("W744-1")])
        self.assertEqual([(x["coinc"], x["estado"]) for x in res["filas"]],
                         [("modelo exacto", "version no comparable: revisar")])


class VersionCvssTest(_Base):
    def _aviso(self):
        a = csaf("ICSA-99-4", {"CVE-2099-90001": (9.8, [], []), "CVE-2099-90002": (7.0, [], []),
                               "CVE-2099-90003": (6.0, [], [])})
        for v, p4 in zip(a["vulnerabilities"], (6.9, 8.7, None)):
            if p4 is not None:
                v["scores"][0]["cvss_v4"] = {"baseScore": p4}
        return a

    def _res(self, ver):
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0")]
        ind = vf.Indice(vf.fabricantes_de(regs))
        ind.visitar(self._aviso(), "a.json")
        return vf.construir(ind, inventario(*regs), None, {}, None, None, ver)

    def test_v4_decide_severidad_orden_y_columna(self):
        res = self._res("4")
        cols = res["columnas"]
        self.assertEqual(cols[cols.index("vector_cvss_v4") + 1], "cvss_decide")
        f = {x["cve"]: dict(zip(cols, x["celdas"])) for x in res["filas"]}
        self.assertEqual([x["cve"] for x in res["filas"]], ["CVE-2099-90002", "CVE-2099-90001", "CVE-2099-90003"])
        self.assertEqual((f["CVE-2099-90001"]["severidad"], f["CVE-2099-90001"]["cvss_decide"]), ("Media", "4.0"))
        self.assertEqual((f["CVE-2099-90002"]["severidad"], f["CVE-2099-90002"]["cvss_decide"]), ("Alta", "4.0"))
        self.assertEqual((f["CVE-2099-90003"]["severidad"], f["CVE-2099-90003"]["cvss_decide"]), ("Media", "3.x"))
        cap = Capture(Path("x"))
        vf.agregar_hallazgo(cap, res)
        self.assertEqual(cap.findings[0]["severidad"], "Media")
        ev = cap.findings[0]["evidencia"]
        self.assertIn("CVSS v4.0 8.7", ev)
        self.assertIn("CVSS v3 6.0", ev)
        sec = vf.seccion(res)
        self.assertIn("CVSS v4.0", sec["nota"])
        self.assertEqual(sec["tabla"][1][0][5], 8.7)      # primera fila, columna cvss: la efectiva
        self.assertEqual(vf.tablas(res)[0][2], cols)
        self.assertIn("cvss_decide", vf.para_json(res)["filas"][0])

    def test_v3_o_sin_clave_identico(self):
        res3, res = self._res("3"), self._res("3")
        self.assertEqual(res3["columnas"], vf.COLUMNAS)
        self.assertNotIn("cvss_decide", res["columnas"])
        self.assertEqual([x["cve"] for x in res["filas"]], ["CVE-2099-90001", "CVE-2099-90002", "CVE-2099-90003"])
        cap = Capture(Path("x"))
        vf.agregar_hallazgo(cap, res)
        self.assertEqual(cap.findings[0]["severidad"], "Alta")
        self.assertNotIn("v4.0", cap.findings[0]["evidencia"])
        self.assertNotIn("CVSS v4", vf.seccion(res)["nota"])

    def test_alta_si_efectiva_v4_llega_a_9(self):
        a = csaf("ICSA-99-5", {"CVE-2099-90009": (5.0, [], [])})
        a["vulnerabilities"][0]["scores"][0]["cvss_v4"] = {"baseScore": 9.3}
        regs = [ent("192.0.2.1", "Acme Automation", "PLC-5000", "1.0")]
        ind = vf.Indice(vf.fabricantes_de(regs))
        ind.visitar(a, "a.json")
        for ver, sev in (("4", "Alta"), ("3", "Media")):
            cap = Capture(Path("x"))
            vf.agregar_hallazgo(cap, vf.construir(ind, inventario(*regs), None, {}, None, None, ver))
            self.assertEqual(cap.findings[0]["severidad"], sev)


if __name__ == "__main__":
    unittest.main()
