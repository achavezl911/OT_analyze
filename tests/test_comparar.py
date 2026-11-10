"""E4: comparar dos corridas (D62). CSV sinteticos y una prueba de punta a punta con capturas sinteticas."""
import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ot_assess import cli_comparar  # noqa: E402
from ot_assess import comparar as cmp  # noqa: E402

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

INV = ["equipo", "ips", "mac", "fabricante", "modelo_descripcion", "firmware", "rol_inferido", "zona_purdue",
       "vlans", "puertos_servidos", "protocolos", "zona_asignada"]
COM = ["origen", "origen_ip", "destino", "destino_ip", "destino_zona", "servicio", "l4", "puerto", "sentido",
       "cruza_zona", "escrituras", "criticidad", "bytes"]
CTL = ["captura", "trama", "protocolo", "operacion", "origen", "destino", "detalle"]
HAL = ["captura", "severidad", "categoria", "titulo", "evidencia"]
FW = ["origen", "origen_ip", "destino", "destino_ip", "servicio", "l4", "puerto", "cruza_zona", "resultado", "regla"]


def activo(**kw):
    f = {c: "" for c in INV}
    f.update(kw)
    return f


def conducto(**kw):
    f = {c: "" for c in COM}
    f.update(sentido="unidireccional", cruza_zona="no", escrituras="0", criticidad="Baja", bytes="1000")
    f.update(kw)
    return f


def fw(o, d, p, res, regla="", l4="tcp"):
    return {"origen": o, "origen_ip": o, "destino": d, "destino_ip": d, "servicio": "x", "l4": l4, "puerto": p,
            "cruza_zona": "si", "resultado": res, "regla": regla}


def escribir_csv(carpeta, nombre, cols, filas):
    carpeta.mkdir(parents=True, exist_ok=True)
    with open(carpeta / nombre, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(filas)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.a, self.d = self.tmp / "antes", self.tmp / "despues"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def poner(self, nombre, cols, antes, despues):
        escribir_csv(self.a, nombre, cols, antes)
        escribir_csv(self.d, nombre, cols, despues)

    def comparar(self, **kw):
        return cmp.comparar(self.a, self.d, **kw)

    def filas(self, r, nom):
        cols, filas = r["tablas"][nom]
        return [dict(zip(cols, f)) for f in cmp._relevantes(nom, filas)]


class ActivosTest(Base):
    def test_nuevo_desaparecido_y_cambiado_por_mac_e_ip(self):
        self.poner("inventario.csv", INV,
                   [activo(equipo="plc1", ips="10.0.0.1", mac="aa:01", rol_inferido="PLC", puertos_servidos="502/tcp"),
                    activo(equipo="hmi", ips="10.0.0.2", mac="aa:02"),
                    activo(equipo="viejo", ips="10.0.0.9", mac="aa:09"),
                    activo(equipo="sinmac", ips="10.0.0.5;10.0.0.6", firmware="1.0")],
                   [activo(equipo="plc1", ips="10.0.0.77", mac="AA:01", rol_inferido="RTU",
                           puertos_servidos="502/tcp;20000/tcp"),
                    activo(equipo="hmi", ips="10.0.0.2", mac="aa:02"),
                    activo(equipo="sinmac", ips="10.0.0.6", firmware="2.0"),
                    activo(equipo="nuevo-plc", ips="10.0.0.50", mac="aa:50", zona_purdue="Nivel 1")])
        f = {x["equipo"]: x for x in self.filas(self.comparar(), "activos")}
        self.assertEqual(f["viejo"]["estado"], "desaparecido")
        self.assertEqual(f["viejo"]["atencion"], "media")
        self.assertEqual(f["nuevo-plc"]["estado"], "nuevo")
        self.assertEqual(f["nuevo-plc"]["atencion"], "alta")
        self.assertIn("rol_inferido: PLC -> RTU", f["plc1"]["cambios"])   # casa por MAC aunque cambie la IP
        self.assertIn("20000/tcp", f["plc1"]["cambios"])
        self.assertIn("firmware: 1.0 -> 2.0", f["sinmac"]["cambios"])     # casa por IP compartida
        self.assertNotIn("hmi", f)

    def test_varias_coincidencias_avisa(self):
        self.poner("inventario.csv", INV, [activo(equipo="a", ips="10.0.0.1;10.0.0.2")],
                   [activo(equipo="b", ips="10.0.0.1"), activo(equipo="c", ips="10.0.0.2")])
        self.assertTrue(any("coincide con 2" in a for a in self.comparar()["avisos"]))


class ConductosTest(Base):
    def test_estados_l4_vacio_y_volumen(self):
        antes = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", l4="", bytes="100"),
                 conducto(origen_ip="1.1.1.1", destino_ip="3.3.3.3", puerto="80", l4="tcp", bytes="100"),
                 conducto(origen_ip="1.1.1.1", destino_ip="4.4.4.4", puerto="22", l4="tcp", bytes="100"),
                 conducto(origen_ip="1.1.1.1", destino_ip="5.5.5.5", puerto="443", l4="tcp", bytes="100")]
        despues = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", l4="tcp", bytes="105"),
                   conducto(origen_ip="1.1.1.1", destino_ip="3.3.3.3", puerto="80", l4="tcp", bytes="5000"),
                   conducto(origen_ip="1.1.1.1", destino_ip="5.5.5.5", puerto="443", l4="tcp", bytes="900",
                            cruza_zona="si", escrituras="2"),
                   conducto(origen_ip="9.9.9.9", destino_ip="8.8.8.8", puerto="1", cruza_zona="si",
                            destino_zona="Nivel 1"),
                   conducto(origen_ip="9.9.9.9", destino_ip="7.7.7.7", puerto="2", cruza_zona="si"),
                   conducto(origen_ip="9.9.9.9", destino_ip="6.6.6.6", puerto="3")]
        self.poner("comunicaciones.csv", COM, antes, despues)
        r = self.comparar()
        por = {(x["destino_ip"], x["estado"]): x for x in self.filas(r, "conductos")}
        self.assertNotIn(("2.2.2.2", "persiste"), por)          # l4 vacio casa con tcp; 1.05x no se marca
        self.assertIn("volumen x50.00", por[("3.3.3.3", "persiste")]["razon"])
        self.assertIn("cruza_zona no -> si", por[("5.5.5.5", "persiste")]["razon"])
        self.assertEqual(por[("4.4.4.4", "ya_no_se_ve")]["estado"], "ya_no_se_ve")
        self.assertEqual(por[("8.8.8.8", "nuevo")]["atencion"], "alta")
        self.assertEqual(por[("7.7.7.7", "nuevo")]["atencion"], "media")
        self.assertEqual(por[("6.6.6.6", "nuevo")]["atencion"], "baja")
        self.assertNotIn("2.2.2.2", {x["destino_ip"] for x in self.filas(r, "conductos")})
        # con un umbral de 100x el volumen de 50x ya no se marca
        r2 = self.comparar(umbral=100)
        self.assertNotIn(("3.3.3.3", "persiste"), {(x["destino_ip"], x["estado"]) for x in self.filas(r2, "conductos")})

    def test_l4_ambiguo_no_casa(self):
        antes = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="53", l4="")]
        despues = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="53", l4="tcp"),
                   conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="53", l4="udp")]
        self.poner("comunicaciones.csv", COM, antes, despues)
        estados = {x["estado"] for x in self.filas(self.comparar(), "conductos")}
        self.assertEqual(estados, {"ya_no_se_ve", "nuevo"})

    def test_escritura_nueva_es_alta(self):
        self.poner("comunicaciones.csv", COM, [],
                   [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", escrituras="3")])
        self.assertEqual(self.filas(self.comparar(), "conductos")[0]["atencion"], "alta")


class EscritoresHallazgosTest(Base):
    def test_escritor_nuevo_y_operaciones_nuevas(self):
        def op(o, d, p, x):
            return {"captura": "c", "trama": "1", "protocolo": p, "operacion": x, "origen": o, "destino": d,
                    "detalle": ""}
        self.poner("control.csv", CTL, [op("h", "p", "Modbus", "Write Single Coil")],
                   [op("h", "p", "Modbus", "Write Single Coil"), op("h", "p", "Modbus", "Diagnostics"),
                    op("x", "p", "DNP3", "Cold Restart")])
        f = {x["estado"]: x for x in self.filas(self.comparar(), "escritores")}
        self.assertEqual(f["operaciones_nuevas"]["operaciones_nuevas"], "Diagnostics")
        self.assertEqual(f["operaciones_nuevas"]["atencion"], "alta")
        self.assertEqual((f["nuevo"]["origen"], f["nuevo"]["atencion"]), ("x", "alta"))

    def test_hallazgos(self):
        def h(t, s):
            return {"captura": "c", "severidad": s, "categoria": "cat", "titulo": t, "evidencia": ""}
        self.poner("hallazgos.csv", HAL, [h("viejo", "Media"), h("igual", "Baja"), h("sube", "Media")],
                   [h("nuevo", "Alta"), h("igual", "Baja"), h("sube", "Alta")])
        f = {x["titulo"]: x for x in self.filas(self.comparar(), "hallazgos")}
        self.assertEqual((f["nuevo"]["estado"], f["nuevo"]["atencion"]), ("nuevo", "media"))
        self.assertEqual(f["viejo"]["estado"], "resuelto")
        self.assertEqual((f["sube"]["severidad_antes"], f["sube"]["severidad_despues"]), ("Media", "Alta"))
        self.assertIn("severidad", f["sube"]["razon"])
        self.assertNotIn("igual", f)   # persiste sin cambios: solo cuenta, no se lista


class FirewallTest(Base):
    def test_cortes_aperturas_y_otra_regla(self):
        com = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", escrituras="5")]
        self.poner("comunicaciones.csv", COM, com, com)
        self.poner("firewall_contraste.csv", FW,
                   [fw("1.1.1.1", "2.2.2.2", "502", "permitido", "r1", l4=""), fw("1.1.1.1", "3.3.3.3", "80", "denegado_observado"),
                    fw("1.1.1.1", "4.4.4.4", "22", "permitido", "r1"), fw("1.1.1.1", "5.5.5.5", "23", "permitido", "r1")],
                   [fw("1.1.1.1", "2.2.2.2", "502", "denegado_observado"), fw("1.1.1.1", "3.3.3.3", "80", "permitido", "r9"),
                    fw("1.1.1.1", "4.4.4.4", "22", "permitido", "r2"), fw("1.1.1.1", "5.5.5.5", "23", "permitido", "r1")])
        f = {x["destino_ip"]: x for x in self.filas(self.comparar(), "firewall")}
        self.assertEqual((f["2.2.2.2"]["cambio"], f["2.2.2.2"]["atencion"]), ("se corto", "alta"))
        self.assertEqual((f["3.3.3.3"]["cambio"], f["3.3.3.3"]["atencion"]), ("se abrio", "media"))
        self.assertEqual(f["4.4.4.4"]["cambio"], "otra regla")
        self.assertNotIn("5.5.5.5", f)


class IdentidadRepetidaTest(Base):
    def datos(self):
        com = [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", servicio="modbus", bytes="100"),
               conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="502", servicio="otro", bytes="9000000"),
               conducto(origen_ip="3.3.3.3", destino_ip="4.4.4.4", puerto="80", l4="", bytes="10"),
               conducto(origen_ip="3.3.3.3", destino_ip="4.4.4.4", puerto="80", l4="tcp", bytes="900000"),
               conducto(origen_ip="5.5.5.5", destino_ip="6.6.6.6", puerto="1", bytes="5", escrituras="1"),
               conducto(origen_ip="5.5.5.5", destino_ip="6.6.6.6", puerto="1", bytes="7", escrituras="2")]
        reglas = [fw("1.1.1.1", "2.2.2.2", "502", "permitido", "r1"),
                  fw("1.1.1.1", "2.2.2.2", "502", "denegado_observado", "r2")]
        return com, reglas

    def test_misma_corrida_cero_cambios(self):
        com, reglas = self.datos()
        self.poner("comunicaciones.csv", COM, com, com)
        self.poner("firewall_contraste.csv", FW, reglas, reglas)
        r = self.comparar()
        for nom in ("conductos", "firewall"):
            self.assertEqual(self.filas(r, nom), [], nom)
        self.assertEqual(sum(v["cambios"] for v in r["resumen"].values()), 0)

    def test_quitar_solo_la_fila_permitida_corta_una_vez(self):
        com, reglas = self.datos()
        self.poner("comunicaciones.csv", COM, com, com)
        self.poner("firewall_contraste.csv", FW, reglas, reglas[1:])
        f = self.filas(self.comparar(), "firewall")
        self.assertEqual([x["cambio"] for x in f], ["se corto"])


class AvisosYSalidasTest(Base):
    def test_csv_ausente_avisa_sin_fallar(self):
        escribir_csv(self.a, "inventario.csv", INV, [])
        escribir_csv(self.d, "inventario.csv", INV, [])
        escribir_csv(self.a, "control.csv", CTL, [])
        r = self.comparar()
        self.assertIn("activos", r["tablas"])
        self.assertNotIn("escritores", r["tablas"])
        self.assertTrue(any("control.csv falta en la posterior" in a for a in r["avisos"]))
        self.assertTrue(any("comunicaciones.csv falta en ninguna" in a for a in r["avisos"]))

    def test_no_comparables_y_metadatos(self):
        self.poner("inventario.csv", INV, [activo(equipo=f"e{i}", ips=f"10.0.0.{i}", mac=f"aa:{i}") for i in range(30)],
                   [activo(equipo=f"e{i}", ips=f"172.16.0.{i}", mac=f"bb:{i}") for i in range(30)])
        for carpeta, ver, cli in ((self.a, "0.19.0", "A"), (self.d, "0.20.0", "B")):
            (carpeta / "resultado.json").write_text(json.dumps(
                {"entorno": {"ot_assess": ver}, "perfil": {"cliente": cli}}), encoding="utf-8")
        (self.d / "hallazgos_importados.csv").write_text("x\n", encoding="utf-8")
        av = " | ".join(self.comparar()["avisos"])
        self.assertIn("menos del 5 %", av)
        self.assertIn("Versiones distintas", av)
        self.assertIn("Perfiles o clientes distintos", av)
        self.assertIn("Tipo de corrida distinto", av)

    def test_misma_corrida_cero_cambios_y_salidas(self):
        self.poner("inventario.csv", INV, [activo(equipo="a", ips="10.0.0.1", mac="aa:01")],
                   [activo(equipo="a", ips="10.0.0.1", mac="aa:01")])
        self.poner("comunicaciones.csv", COM, [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="1")],
                   [conducto(origen_ip="1.1.1.1", destino_ip="2.2.2.2", puerto="1")])
        out = self.tmp / "out"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli_comparar.main(["--antes", str(self.a), "--despues", str(self.a), "-o", str(out)])
        self.assertEqual(rc, 0)
        js = json.loads((out / "comparacion.json").read_text(encoding="utf-8"))
        self.assertEqual(sum(s["cambios"] for s in js["resumen"].values()), 0)
        for n in ("comparacion.md", "comparacion.html", "comparacion_activos.csv", "comparacion_conductos.csv"):
            self.assertTrue((out / n).is_file(), n)

    def test_carpeta_inexistente_sale_con_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli_comparar.main(["--antes", str(self.tmp / "no"), "--despues", str(self.d), "-o", str(self.tmp / "o")])
        self.assertEqual(rc, 2)


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class PuntaAPuntaTest(unittest.TestCase):
    def test_escritor_nuevo_entre_dos_corridas_reales(self):
        import gen_pcaps

        from ot_assess.cli import main
        tmp = Path(tempfile.mkdtemp())
        try:
            for nombre, pkts in (("antes", gen_pcaps.punto_a()),
                                 ("despues", gen_pcaps.punto_a() + gen_pcaps.punto_modbus_diag())):
                (tmp / "pcaps" / nombre).mkdir(parents=True)
                gen_pcaps.guardar(pkts, tmp / "pcaps" / nombre / "c.pcap")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main([str(tmp / "pcaps" / nombre), "-o", str(tmp / nombre)]), 0)
            out = tmp / "cmp"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_comparar.main(
                    ["--antes", str(tmp / "antes"), "--despues", str(tmp / "despues"), "-o", str(out)]), 0)
            with open(out / "comparacion_escritores.csv", newline="", encoding="utf-8-sig") as fh:
                filas = list(csv.DictReader(fh))
            self.assertTrue(any("10.40.1.10" in f["origen"] and "10.40.1.20" in f["destino"] for f in filas), filas)
            self.assertTrue(all(f["atencion"] == "alta" for f in filas))
            # y la misma corrida contra si misma no cambia nada
            out2 = tmp / "cmp2"
            with contextlib.redirect_stdout(io.StringIO()):
                cli_comparar.main(["--antes", str(tmp / "despues"), "--despues", str(tmp / "despues"), "-o", str(out2)])
            js = json.loads((out2 / "comparacion.json").read_text(encoding="utf-8"))
            self.assertEqual(sum(s["cambios"] for s in js["resumen"].values()), 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
