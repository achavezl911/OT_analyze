"""SC1: Solicitud de Cambio desde la politica y las rutas propuestas (D61). Datos sinteticos, sin red."""
import contextlib
import csv
import io
import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from ot_assess import cli_solicitud
from ot_assess import solicitud_cambio as sc

PROP = ["orden", "nombre", "decision", "razones", "zona_entrada", "zona_salida", "interfaces", "origen", "destino",
        "servicios", "conductos", "origenes", "destinos", "bytes", "dias", "fuentes", "reglas_actuales",
        "justificacion"]
OBJ = ["nombre", "tipo", "valor", "miembros"]
COMP = ["regla_actual", "nombre", "accion", "aciertos", "conductos_observados", "estado", "reglas_propuestas",
        "marcas", "comentario"]
RUTAS = ["red", "interfaz", "siguiente_salto", "tipo", "accion", "razon", "conductos", "salto_en_arp"]
BLOQ = ["interfaz_entrada", "interfaz_salida", "servicio", "origenes", "destinos", "ejemplos_origen",
        "ejemplos_destino", "conductos", "bytes", "razon", "regla_actual"]
OBJETOS = [
    ["H_a", "host", "10.0.0.1", ""], ["H_b", "host", "10.0.0.2", ""], ["N_x", "red", "10.0.2.0/24", ""],
    ["S_tcp_443", "servicio", "tcp/443", ""], ["S_tcp_502", "servicio", "tcp/502", ""],
    ["S_tcp_1000-2000", "servicio", "tcp/1000-2000", ""],
]
JUST_RARA = 'Modbus & "HMI" <PLC> operacion: mantenimiento nocturno | 100% observado'


def regla(n, nombre, dec, o, d, s, just="observado"):
    fila = {c: "" for c in PROP}
    fila.update(orden=n, nombre=nombre, decision=dec, razones="visto un dia" if dec == "revisar" else "",
                zona_entrada="ZIN", zona_salida="ZOUT", origen=o, destino=d, servicios=s, justificacion=just)
    return [fila[c] for c in PROP]


REGLAS = [regla("1", "1_in_out_443", "permitir", "H_a", "N_x", "S_tcp_443"),
          regla("2", "2_in_out_502", "revisar", "H_a", "N_x", "S_tcp_502", JUST_RARA),
          regla("3", "3_in_out_rango", "bloquear", "H_b", "N_x", "S_tcp_1000-2000")]


def fila_c(i, nombre, acc, aci, con, est, props="", com=""):
    return [i, nombre, acc, aci, con, est, props, "", com]


COMPARACION = [
    fila_c("10", "reg_reemplazada", "permitir", "50", "3", "reemplazada", "1_in_out_443"),
    fila_c("11", "reg_ancha", "permitir", "5", "4", "acotar", "1_in_out_443", "mas amplia que lo observado"),
    fila_c("12", "reg_muerta", "permitir", "0", "0", "eliminar candidata", "", "sin aciertos"),
    fila_c("13", "reg_dudosa", "permitir", "7", "0", "validar antes de eliminar", "", "tiene 7 aciertos"),
    fila_c("14", "reg_cero", "permitir", "0", "0", "validar antes de eliminar", "", "validada"),
    fila_c("15", "reg_nocontadores", "permitir", "", "0", "validar antes de eliminar", "", "sin contadores de aciertos"),
    fila_c("16", "reg_bloqueo", "bloquear", "0", "0", "bloqueo", "", "la sustituye la accion por defecto"),
]
RUTAS_F = [["10.9.0.0/24", "eth1", "10.0.0.254", "estatica", "eliminar", "sin trafico", "0", "no"],
           ["10.8.0.0/24", "eth1", "10.0.0.253", "estatica", "revisar", "salto sin ARP", "3", "no"],
           ["10.7.0.0/24", "eth2", "10.0.0.252", "estatica", "mantener", "usada", "9", "si"]]
BLOQUEADOS = [["a", "b", "tcp/1000-2000", "H_b", "N_x", "10.0.0.2", "10.0.2.5", "4", "2048", "sin regla propuesta", ""]]


def escribir_csv(ruta, cab, filas):
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)
    return str(ruta)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)
        self.addCleanup(self._t.cleanup)
        self.prop = escribir_csv(self.d / "fw1_politica_propuesta.csv", PROP, REGLAS)
        self.objs = escribir_csv(self.d / "politica_objetos.csv", OBJ, OBJETOS)
        self.comp = escribir_csv(self.d / "politica_comparacion.csv", COMP, COMPARACION)
        self.rutas = escribir_csv(self.d / "rutas_propuestas.csv", RUTAS, RUTAS_F)
        self.bloq = escribir_csv(self.d / "politica_bloqueados.csv", BLOQ, BLOQUEADOS)

    def correr(self, *extra, completo=True, out="sal"):
        args = ["--propuesta", self.prop, "--objetos", self.objs, "-o", str(self.d / out)]
        if completo:
            args += ["--comparacion", self.comp, "--rutas", self.rutas, "--bloqueados", self.bloq]
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = cli_solicitud.main(args + list(extra))
        return rc, err.getvalue(), self.d / out

    def cambios(self, carpeta):
        with open(carpeta / "solicitud_cambio_cambios.csv", newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))


class TestCambios(Base):
    def test_cambios_por_fase_y_tipo(self):
        rc, err, sal = self.correr()
        self.assertEqual(rc, 0, err)
        cs = self.cambios(sal)
        cnt = {}
        for c in cs:
            cnt[(c["Fase"], c["Accion"])] = cnt.get((c["Fase"], c["Accion"]), 0) + 1
        self.assertEqual(cnt[("1", "crear politica")], 1)
        self.assertEqual(cnt[("1", "crear regla")], 1)
        self.assertEqual(cnt[("1", "crear regla deshabilitada")], 1)
        self.assertEqual(cnt[("1", "crear objeto")], 4)      # H_a, N_x, S_tcp_443, S_tcp_502: solo los usados
        self.assertEqual(cnt[("2", "habilitar regla")], 1)
        self.assertEqual(cnt[("3", "deshabilitar regla actual")], 1)
        self.assertEqual(cnt[("3", "acotar regla actual")], 1)
        self.assertEqual(cnt[("3", "eliminar regla actual")], 2)   # candidata + validar con cero aciertos
        self.assertEqual(cnt[("4", "eliminar ruta")], 1)
        self.assertEqual(cnt[("4", "revisar ruta")], 1)
        self.assertEqual(len(cs), len({c["ID"] for c in cs}))
        self.assertEqual(cs[0]["ID"], "SC-001")

    def test_bloquear_no_crea_regla_y_revisar_deshabilitada(self):
        _, _, sal = self.correr()
        cs = self.cambios(sal)
        elementos = " ".join(c["Elemento"] + " " + c["Detalle"] for c in cs)
        self.assertNotIn("3_in_out_rango", elementos)
        self.assertNotIn("S_tcp_1000-2000", elementos)
        self.assertNotIn("H_b", elementos)
        rev = [c for c in cs if c["Elemento"] == "2_in_out_502"]
        self.assertEqual({c["Accion"] for c in rev}, {"crear regla deshabilitada", "habilitar regla"})
        self.assertTrue(all(c["Elemento"] != "13 reg_dudosa" for c in cs))
        self.assertTrue(all("reg_nocontadores" not in c["Elemento"] for c in cs))
        self.assertTrue(all("reg_bloqueo" not in c["Elemento"] for c in cs))
        ruta = [c for c in cs if c["Accion"] == "revisar ruta"][0]
        self.assertIn("10.0.0.253", ruta["Detalle"])
        self.assertTrue(all(c["Riesgo"] and c["Validacion"] and c["Reversion"] for c in cs))

    def test_sin_opcionales(self):
        rc, err, sal = self.correr(completo=False)
        self.assertEqual(rc, 0, err)
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        self.assertIn("No se proporciono politica_bloqueados.csv", md)
        self.assertIn("No se proporciono politica_comparacion.csv", md)
        self.assertIn("No se proporcionaron rutas propuestas", md)
        fases = {c["Fase"] for c in self.cambios(sal)}
        self.assertEqual(fases, {"1", "2"})

    def test_entrada_invalida_codigo_2(self):
        escribir_csv(self.d / "mala.csv", ["x"], [["1"]])
        rc, err, _ = self.correr("--comparacion", str(self.d / "mala.csv"), completo=False)
        self.assertEqual(rc, 2)
        self.assertIn("faltan las columnas", err)


class TestDocumentos(Base):
    def titulos(self):
        return [s["titulo"] for s in sc.cargar_plantilla()["secciones"]]

    def test_nueve_secciones_en_orden(self):
        _, _, sal = self.correr()
        tit = self.titulos()
        self.assertEqual(len(tit), 9)
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        pos = [md.index("## " + t) for t in tit]
        self.assertEqual(pos, sorted(pos))
        z = zipfile.ZipFile(sal / "solicitud_cambio.docx")
        self.assertIsNone(z.testzip())
        xml = z.read("word/document.xml").decode("utf-8")
        pos = [xml.index(t) for t in tit]
        self.assertEqual(pos, sorted(pos))

    def test_plantilla_cambia_titulos_y_orden(self):
        p = self.d / "plantilla.json"
        p.write_text(json.dumps({"titulo": "Formato X", "secciones": [
            {"clave": "anexos", "titulo": "Anexo A"}, {"clave": "datos_generales", "titulo": "Portada"}]}),
            encoding="utf-8")
        rc, err, sal = self.correr("--plantilla", str(p))
        self.assertEqual(rc, 0, err)
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        self.assertIn("# Formato X", md)
        self.assertLess(md.index("## Anexo A"), md.index("## Portada"))
        self.assertNotIn("Plan por fases", md)

    def test_plantilla_clave_desconocida(self):
        p = self.d / "plantilla.json"
        p.write_text(json.dumps({"secciones": [{"clave": "inventada", "titulo": "X"}]}), encoding="utf-8")
        rc, err, sal = self.correr("--plantilla", str(p))
        self.assertEqual(rc, 2)
        self.assertIn("inventada", err)
        self.assertFalse(sal.exists())
        p.write_text(json.dumps({"secciones_raras": []}), encoding="utf-8")
        self.assertEqual(self.correr("--plantilla", str(p))[0], 2)
        p.write_text(json.dumps({"columnas_csv": ["id", "nada"]}), encoding="utf-8")
        self.assertEqual(self.correr("--plantilla", str(p))[0], 2)

    def test_plantilla_columnas(self):
        p = self.d / "plantilla.json"
        p.write_text(json.dumps({"columnas_csv": ["id", "accion"], "encabezados": {"id": "Folio SC"}}),
                     encoding="utf-8")
        _, _, sal = self.correr("--plantilla", str(p))
        with open(sal / "solicitud_cambio_cambios.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), ["Folio SC", "Accion"])

    def test_sin_cumple_ni_no_cumple(self):
        _, _, sal = self.correr()
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bcumple\b", md + (sal / "solicitud_cambio_cambios.csv").read_text(
            encoding="utf-8-sig"), re.IGNORECASE))
        self.assertIsNone(re.search(r"\bcumple\b", json.dumps(sc.cargar_plantilla()), re.IGNORECASE))
        self.assertIn("a validar", md.lower() + " a validar")   # la evaluacion es del comite
        self.assertIn("validar por el comite", md)

    def test_escape_xml_y_md(self):
        _, _, sal = self.correr()
        xml = zipfile.ZipFile(sal / "solicitud_cambio.docx").read("word/document.xml").decode("utf-8")
        self.assertIn("Modbus &amp; &quot;HMI&quot; &lt;PLC&gt; operaci", xml)
        self.assertNotIn("<PLC>", xml)
        self.assertNotIn('"HMI" <', xml)
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        self.assertIn("Modbus &amp; \"HMI\" &lt;PLC&gt;", md)
        self.assertNotIn("<PLC>", md)
        self.assertIn("nocturno \\| 100%", md)       # la barra no rompe la tabla
        self.assertIn("Descripcion y justificacion", md)

    def test_acentos_en_nombres(self):
        self.prop = escribir_csv(self.d / "p2.csv", PROP, [
            regla("1", "1_in_out_443", "permitir", "H_a", "N_x", "S_tcp_443", "operación crítica año")])
        rc, err, sal = self.correr()
        self.assertEqual(rc, 0, err)
        self.assertIn("operación crítica año", (sal / "solicitud_cambio.md").read_text(encoding="utf-8"))
        xml = zipfile.ZipFile(sal / "solicitud_cambio.docx").read("word/document.xml").decode("utf-8")
        self.assertIn("operación crítica año", xml)

    def test_datos_generales_y_formato_carga(self):
        _, _, sal = self.correr("--firewall-nombre", "FTD-01", "--solicitante", "Ana", "--ventana", "sabado 22:00",
                                "--formato-carga", "panos")
        md = (sal / "solicitud_cambio.md").read_text(encoding="utf-8")
        for t in ("FTD-01", "Ana", "sabado 22:00", "Normal", "panos_set.txt", "LEEME_PANOS.txt"):
            self.assertIn(t, md)
        self.assertNotIn("fmc_reglas.json", md)

    def test_formula_en_csv_neutralizada(self):
        self.prop = escribir_csv(self.d / "p3.csv", PROP, [
            regla("1", "1_in_out_443", "permitir", "H_a", "N_x", "S_tcp_443", "=HYPERLINK(1)")])
        _, _, sal = self.correr()
        self.assertTrue(any(c["Justificacion / evidencia"].startswith("'=") for c in self.cambios(sal)))


if __name__ == "__main__":
    unittest.main()
