"""I1b (D79): reporte de obsolescencia por activo. Datos sinteticos (fabricantes y modelos inventados para el
archivo del analista; la tabla integrada de Microsoft es real). Se corre solo o con unittest discover."""
from __future__ import annotations

import contextlib
import csv
import datetime
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import i18n
from ot_assess import inventario_normalizado as inv
from ot_assess import obsolescencia as ob
from ot_assess.cli_diagrama import main as main_diagrama
from ot_assess.model import Capture

REF = datetime.date(2026, 11, 7)
PF = "plataforma:generico"


def _activo(n, **campos):
    """Registro de inventario sintetico en 192.0.2.<n>. campos: fabricante, modelo, firmware, sistema_operativo,
    criticidad, nivel_purdue, zona."""
    ip = f"192.0.2.{n}"
    e = [("ips", ip, PF, ""), ("nombre", f"EQ-{n}", PF, "")] + [(k, v, PF, "") for k, v in campos.items()]
    return {"macs": [], "ips": [ip], "entradas": e}


def _reporte(*activos, analista=(), ref=REF):
    return ob.construir(inv.construir(list(activos)), list(analista), ref, "fin de la captura")


def _tabla(tmp, filas, cab=("fabricante", "producto", "version", "fecha_fin_soporte", "fuente"), nombre="eos.csv"):
    p = Path(tmp) / nombre
    with open(p, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return str(p)


def _por_ip(rep):
    return {f["ips"][0]: f for f in rep["filas"]}


class _Base(unittest.TestCase):
    def setUp(self):
        i18n.usar("es")
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")


class EstadoTest(_Base):
    def test_windows_7_fuera_de_soporte_con_fecha_y_fuente(self):
        f = _por_ip(_reporte(_activo(1, sistema_operativo="Microsoft Windows 7 Professional SP1")))["192.0.2.1"]
        self.assertEqual((f["estado"], f["fin"], f["fuente"]), (ob.F_VENCIDO, "2020-01-14", "Microsoft Lifecycle"))
        self.assertLess(f["dias"], 0)

    def test_plc_inventado_por_rango_de_firmware(self):
        eos = _tabla(self.tmp, [["Acme Controls Inc", "ZX-100", "<3.1", "2024-01-01", "Aviso Acme 7"]])
        filas, avisos = ob.cargar_analista(eos)
        self.assertEqual(avisos, [])
        rep = _reporte(_activo(1, fabricante="ACME CONTROLS", modelo="ZX-100", firmware="3.0.2"),
                       _activo(2, fabricante="ACME CONTROLS", modelo="ZX-100", firmware="3.2"), analista=filas)
        p = _por_ip(rep)
        self.assertEqual((p["192.0.2.1"]["estado"], p["192.0.2.1"]["fin"]), (ob.F_VENCIDO, "2024-01-01"))
        self.assertEqual(p["192.0.2.1"]["fuente"], "Aviso Acme 7")
        self.assertEqual(p["192.0.2.2"]["estado"], ob.F_SIN_DATO)           # 3.2 no casa con "<3.1"
        self.assertEqual(p["192.0.2.2"]["fin"], "")

    def test_reglas_de_version(self):
        r = ob._regla_version
        self.assertTrue(r("")("cualquiera") and r("")(""))
        self.assertTrue(r(">=2.0,<2.4")("2.3.9") and not r(">=2.0,<2.4")("2.4") and not r(">=2.0,<2.4")("1.9"))
        self.assertTrue(r("2.")("2.4.1") and not r("2.")("3.2") and not r("2.")("12.1"))
        self.assertTrue(r("V1.5")("1.5") and not r("1.5")("1.50"))
        self.assertIsNone(r("<3")(""))
        self.assertIsNone(r("<<3"))

    def test_fecha_a_seis_meses_es_fin_en_12_meses_y_hallazgo_baja(self):
        pronto = (REF + datetime.timedelta(days=182)).isoformat()
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Acme", "ZX-100", "", pronto, ""]]))
        rep = _reporte(_activo(1, fabricante="Acme", modelo="ZX-100", firmware="1.0"), analista=filas)
        f = rep["filas"][0]
        self.assertEqual((f["estado"], f["dias"]), (ob.F_PRONTO, 182))
        extra = ob.agregar_hallazgos([], rep)
        self.assertEqual([(h["titulo"], h["severidad"]) for h in extra.findings], [(ob.TIT_PROXIMO, "Baja")])
        self.assertEqual(extra.findings[0]["activos"], ["192.0.2.1"])
        lejos, _ = ob.cargar_analista(_tabla(self.tmp, [["Acme", "ZX-100", "", "2028-01-01", ""]], nombre="b.csv"))
        self.assertEqual(_reporte(_activo(1, fabricante="Acme", modelo="ZX-100"), analista=lejos)["filas"][0]["estado"],
                         ob.F_VIGENTE)

    def test_sin_datos_de_version_y_sin_dato_de_soporte(self):
        rep = _reporte(_activo(1), _activo(2, fabricante="Acme", modelo="ZX-100", firmware="1.0"),
                       _activo(3, sistema_operativo="Linux 5.4"))
        p = _por_ip(rep)
        self.assertEqual(p["192.0.2.1"]["estado"], ob.F_SIN_VERSION)
        self.assertEqual(p["192.0.2.2"]["estado"], ob.F_SIN_DATO)
        self.assertEqual(p["192.0.2.3"]["estado"], ob.F_SIN_DATO)
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Acme", "ZX-100", "<3.1", "2024-01-01", ""]]))
        sin_fw = _reporte(_activo(1, fabricante="Acme", modelo="ZX-100"), analista=filas)["filas"][0]
        self.assertEqual(sin_fw["estado"], ob.F_SIN_VERSION)               # la regla pide versiones y no hay firmware

    def test_el_archivo_del_analista_manda_sobre_la_tabla_integrada(self):
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Microsoft", "Windows 7", "", "2031-12-31", "Contrato ESU"]]))
        f = _por_ip(_reporte(_activo(1, sistema_operativo="Windows 7"), analista=filas))["192.0.2.1"]
        self.assertEqual((f["estado"], f["fin"], f["fuente"]), (ob.F_VIGENTE, "2031-12-31", "Contrato ESU"))

    def test_windows_10_ltsc_e_iot_sin_dato_salvo_fila_del_analista(self):
        rep = _reporte(_activo(1, sistema_operativo="Windows 10 Enterprise LTSC 2019"),
                       _activo(2, sistema_operativo="Windows 10 IoT Enterprise"),
                       _activo(3, sistema_operativo="Windows 10 Pro 22H2"))
        p = _por_ip(rep)
        self.assertEqual((p["192.0.2.1"]["estado"], p["192.0.2.2"]["estado"]), (ob.F_SIN_DATO, ob.F_SIN_DATO))
        self.assertEqual((p["192.0.2.3"]["estado"], p["192.0.2.3"]["fin"]), (ob.F_VENCIDO, "2025-10-14"))
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Microsoft", r"Windows 10.*LTSC 2019", "", "2029-01-09", ""]]))
        f = _por_ip(_reporte(_activo(1, sistema_operativo="Windows 10 Enterprise LTSC 2019"), analista=filas))
        self.assertEqual(f["192.0.2.1"]["fin"], "2029-01-09")

    def test_windows_ce_y_server_sin_confundirse(self):
        p = _por_ip(_reporte(_activo(1, sistema_operativo="Windows CE 6.0"),
                             _activo(2, sistema_operativo="Windows Server 2008 R2"),
                             _activo(3, sistema_operativo="Windows Embedded Standard 7"),
                             _activo(4, sistema_operativo="Windows Server 2016 Standard")))
        self.assertEqual((p["192.0.2.1"]["estado"], p["192.0.2.1"]["fin"]), (ob.F_SIN_DATO, ""))
        self.assertIn("sin fecha unica", p["192.0.2.1"]["fuente"])
        self.assertEqual(p["192.0.2.2"]["fin"], "2020-01-14")
        self.assertEqual(p["192.0.2.3"]["fin"], "2020-10-13")
        self.assertEqual((p["192.0.2.4"]["fin"], p["192.0.2.4"]["estado"]), ("2027-01-12", ob.F_PRONTO))

    def test_un_renglon_por_producto_que_case(self):
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Acme", "ZX-100", "", "2024-01-01", ""]]))
        rep = _reporte(_activo(1, fabricante="Acme", modelo="ZX-100", sistema_operativo="Windows XP"), analista=filas)
        self.assertEqual(sorted(f["producto"] for f in rep["filas"]), ["Windows XP", "ZX-100"])
        self.assertEqual({f["estado"] for f in rep["filas"]}, {ob.F_VENCIDO})

    def test_fabricante_normalizado(self):
        self.assertTrue(ob._fab_casa("Siemens AG", "SIEMENS"))
        self.assertTrue(ob._fab_casa("Rockwell", "Rockwell Automation, Inc."))
        self.assertFalse(ob._fab_casa("Acme", "Beta Corp"))
        filas, _ = ob.cargar_analista(_tabla(self.tmp, [["Acme Inc", "ZX-100", "", "2024-01-01", ""]]))
        f = _reporte(_activo(1, fabricante="Otro GmbH", modelo="ZX-100", firmware="1"), analista=filas)["filas"][0]
        self.assertEqual(f["estado"], ob.F_SIN_DATO)


class ArchivoTest(_Base):
    def test_fila_invalida_avisa_con_su_numero_y_sigue(self):
        p = _tabla(self.tmp, [["Acme", "ZX-100", "", "2024-01-01", ""], ["Acme", "ZX-200", "", "pronto", ""],
                              ["Acme", "ZX-300", "<<3", "2025-01-01", ""], ["Acme", "", "", "2025-01-01", ""],
                              ["Acme", "ZX-400", "1.", "2026-02-30", ""], ["Acme", "ZX-500", "2.", "2027-01-01", ""]])
        filas, avisos = ob.cargar_analista(p)
        self.assertEqual([f["producto"] for f in filas], ["ZX-100", "ZX-500"])
        self.assertEqual([a.split(":")[0] for a in avisos], [f"--fin-de-soporte fila {n}" for n in (3, 4, 5, 6)])

    def test_alias_en_ingles_y_xlsx_como_csv(self):
        p = _tabla(self.tmp, [["Acme", "ZX-100", "1.", "2024-01-01", "2023-01-01", "ZX-200", "http://x"]],
                   cab=("Vendor", "Model", "Firmware", "EOL", "End of Sale", "Replacement", "Source"))
        filas, avisos = ob.cargar_analista(p)
        self.assertEqual(avisos, [])
        self.assertEqual((filas[0]["reemplazo"], filas[0]["fuente"], filas[0]["venta"]), ("ZX-200", "http://x", "2023-01-01"))
        rep = _reporte(_activo(1, fabricante="Acme", modelo="ZX-100", firmware="1.4"), analista=filas)
        self.assertEqual(rep["filas"][0]["celdas"][ob.COLUMNAS.index("reemplazo_sugerido")], "ZX-200")

    def test_sin_columnas_minimas_falla_claro(self):
        with self.assertRaises(SystemExit) as c:
            ob.cargar_analista(_tabla(self.tmp, [["Acme", "x"]], cab=("fabricante", "notas")))
        self.assertIn("fecha_fin_soporte", str(c.exception))


class HallazgosTest(_Base):
    def _fuera(self, **campos):
        return _reporte(_activo(1, sistema_operativo="Windows XP", **campos))

    def test_hallazgo_nuevo_alta_por_criticidad_o_nivel_si_no_media(self):
        sev = lambda **c: ob.agregar_hallazgos([], self._fuera(**c)).findings[0]["severidad"]   # noqa: E731
        self.assertEqual(sev(criticidad="Alta"), "Alta")
        self.assertEqual(sev(nivel_purdue="Nivel 1"), "Alta")
        self.assertEqual(sev(criticidad="Baja", nivel_purdue="Nivel 4"), "Media")
        self.assertEqual(sev(), "Media")
        h = ob.agregar_hallazgos([], self._fuera(criticidad="Alta")).findings[0]
        self.assertEqual((h["titulo"], h["activos"]), (ob.TIT_FUERA_REP, ["192.0.2.1"]))
        self.assertIn("2014-04-08", h["evidencia"])
        self.assertIn("Microsoft Lifecycle", h["evidencia"])

    def test_el_hallazgo_existente_se_amplia_en_vez_de_duplicarse(self):
        cap = Capture(Path("x.pcap"))
        cap.findings.append({"severidad": "Alta", "titulo": ob.TIT_FUERA, "evidencia": i18n.t("- 192.0.2.9: viejo"),
                             "activos": ["192.0.2.9"]})
        extra = ob.agregar_hallazgos(cap.findings, self._fuera())
        self.assertIsNone(extra)
        h = cap.findings[0]
        self.assertIn("viejo", h["evidencia"])
        self.assertIn("2014-04-08", h["evidencia"])
        self.assertEqual(h["activos"], ["192.0.2.1", "192.0.2.9"])

    def test_sin_vencidos_ni_proximos_no_hay_hallazgo(self):
        self.assertIsNone(ob.agregar_hallazgos([], _reporte(_activo(1), _activo(2, sistema_operativo="Linux"))))

    def test_columnas_de_qa_vacias_y_estado_traducido(self):
        rep = self._fuera()
        (_a, _h, cab, filas), = ob.tablas(rep)
        self.assertEqual(cab, ob.COLUMNAS)
        fila = dict(zip(cab, filas[0]))
        self.assertEqual((fila["validado_por"], fila["fecha_validacion"], fila["comentario"]), ("", "", ""))
        self.assertEqual((fila["id"], fila["fecha_referencia"], fila["dias"]), (rep["filas"][0]["id"], "2026-11-07",
                                                                                (datetime.date(2014, 4, 8) - REF).days))
        i18n.usar("en")
        self.assertEqual(dict(zip(cab, ob.tablas(rep)[0][3][0]))["estado"], "out of support")

    def test_seccion_cuenta_por_estado_y_zona_y_limita_a_diez(self):
        rep = _reporte(*[_activo(n, sistema_operativo="Windows 7", zona="Z1", criticidad="Alta") for n in range(1, 13)],
                       _activo(20, sistema_operativo="Linux"))
        s = ob.seccion(rep)
        filas = s["tabla"][1]
        self.assertIn(["estado", "fuera de soporte", 12], filas)
        self.assertIn(["zona (fuera de soporte)", "Z1", 12], filas)
        self.assertEqual(sum(1 for f in filas if f[0] == "mayor criticidad fuera de soporte"), 10)
        self.assertIn("2026-11-07", s["resumen"])

    def test_referencia_de_captura_exportacion_o_corrida(self):
        cap = Capture(Path("a.pcap"))
        cap.ventana = [1_700_000_000.0, 1_700_086_400.0]
        self.assertEqual(ob.referencia_de([cap]), (datetime.date(2023, 11, 15), "fin de la captura"))
        self.assertEqual(ob.referencia_de((), "2024-03-05 10:00")[0], datetime.date(2024, 3, 5))
        self.assertEqual(ob.referencia_de(())[1], "fecha de la corrida")


class ExtremoAExtremoTest(_Base):
    def correr(self, idioma="es"):
        a = Path(self.tmp) / "activos.csv"
        with open(a, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["Name", "IP", "MAC", "Vendor", "Model", "Firmware", "OS", "Type", "Level"])
            w.writerows([["HMI-1", "10.10.1.10", "aa:bb:cc:00:00:02", "Beta", "", "", "Windows 7", "HMI", "2"],
                         ["PLC-1", "10.10.2.20", "aa:bb:cc:00:00:01", "Acme Controls", "ZX-100", "3.0.2", "", "PLC", "1"],
                         ["PLC-2", "10.10.2.21", "aa:bb:cc:00:00:03", "Acme Controls", "ZX-100", "3.2", "", "PLC", "1"]])
        e = Path(self.tmp) / "enlaces.csv"
        with open(e, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["Source", "Destination", "Port", "Protocol", "Packets"])
            w.writerow(["10.10.1.10", "10.10.2.20", "502", "Modbus", "100"])
        eos = _tabla(self.tmp, [["Acme Controls", "ZX-100", "<3.1", "2024-01-01", "Aviso Acme"]])
        p = Path(self.tmp) / "perfil.json"
        p.write_text(json.dumps({"version": 1, "cliente": "C", "marcos": [{"clave": "iec62443"}], "idioma": idioma}),
                     encoding="utf-8")
        out = Path(self.tmp) / ("salida_" + idioma)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico", "--perfil", str(p),
                                "--fin-de-soporte", eos, "-o", str(out)])
        self.assertEqual(rc, 0)
        return out, buf.getvalue()

    def test_salidas_y_hallazgo(self):
        out, consola = self.correr()
        self.assertIn("obsolescencia (referencia", consola)
        with open(out / "obsolescencia.csv", encoding="utf-8-sig") as fh:
            filas = {f["nombre"]: f for f in csv.DictReader(fh)}
        self.assertEqual(filas["PLC-1"]["estado"], "fuera de soporte")
        self.assertEqual(filas["PLC-1"]["fecha_fin_soporte"], "2024-01-01")
        self.assertEqual(filas["PLC-2"]["estado"], "sin dato de soporte")
        self.assertEqual(filas["HMI-1"]["fecha_fin_soporte"], "2020-01-14")
        self.assertEqual(filas["HMI-1"]["firmware_fuente"], "")
        self.assertEqual(filas["PLC-1"]["modelo_fuente"], "plataforma:generico")
        with open(out / "hallazgos.csv", encoding="utf-8-sig") as fh:
            titulos = [f["titulo"] for f in csv.DictReader(fh)]
        self.assertIn(ob.TIT_FUERA_REP, titulos)
        self.assertIn("Obsolescencia de activos", (out / "reporte_ot.md").read_text(encoding="utf-8"))
        self.assertTrue((out / "reporte_ot.xlsx").exists())

    def test_sin_el_archivo_igual_hay_reporte_con_la_tabla_integrada(self):
        a = Path(self.tmp) / "a.csv"
        a.write_text("Name,IP,OS\nHMI,10.0.0.5,Windows XP\n", encoding="utf-8")
        e = Path(self.tmp) / "e.csv"
        e.write_text("Source,Destination,Port,Protocol,Packets\n10.0.0.5,10.0.0.6,502,Modbus,5\n", encoding="utf-8")
        out = Path(self.tmp) / "sin_archivo"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_diagrama(["--activos", str(a), "--enlaces", str(e), "--formato", "generico",
                                            "-o", str(out)]), 0)
        with open(out / "obsolescencia.csv", encoding="utf-8-sig") as fh:
            self.assertEqual([f["fecha_fin_soporte"] for f in csv.DictReader(fh)], ["2014-04-08"])

    def test_ingles_sin_claves_faltantes(self):
        i18n.FALTANTES.clear()
        out, _ = self.correr("en")
        head = (out / "obsolescencia.csv").read_text(encoding="utf-8-sig").splitlines()[0]
        self.assertIn("end_of_support_date", head)
        self.assertEqual(sorted(i18n.FALTANTES), [])


if __name__ == "__main__":
    unittest.main()
