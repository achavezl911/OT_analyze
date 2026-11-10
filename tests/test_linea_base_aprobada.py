"""LB1 (D82): linea base aprobada y desviaciones de una corrida nueva.

Unitarias con carpetas de corrida sinteticas (CSV y JSON escritos a mano, sin tshark) y una prueba de punta a punta
con el CLI `diagrama`. Todo sintetico: IP de documentacion (RFC 5737), MAC y nombres inventados.
"""
from __future__ import annotations

import contextlib
import copy
import csv
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from ot_assess import i18n  # noqa: E402
from ot_assess import linea_base_aprobada as lba  # noqa: E402
from ot_assess import playbooks  # noqa: E402
from ot_assess.cli import main as main_completo  # noqa: E402
from ot_assess.cli_linea_base import main as main_lb  # noqa: E402
from ot_assess.model import Capture  # noqa: E402
from ot_assess.rules.linea_base_aprobada import agregar_hallazgos  # noqa: E402
from ot_assess.standards import referencias  # noqa: E402

INV = ["equipo", "ips", "mac", "fabricante", "firmware", "rol_inferido", "zona_purdue", "puertos_servidos",
       "protocolos", "zona_asignada"]
COM = ["origen", "origen_ip", "destino", "destino_ip", "origen_zona", "destino_zona", "servicio", "l4", "puerto",
       "sentido", "cruza_zona", "escrituras", "bytes"]
CTL = ["captura", "trama", "protocolo", "operacion", "origen", "destino", "detalle"]
HAL = ["captura", "severidad", "categoria", "titulo", "evidencia"]
NOR = ["id", "ips", "mac", "nombre", "modelo", "firmware", "rol", "nivel_purdue", "zona"]

HMI, PLC, PLC2, HIST = "192.0.2.10", "192.0.2.20", "192.0.2.21", "192.0.2.30"


def _escribir(carpeta: Path, nombre: str, cols: list, filas: list) -> None:
    with open(carpeta / nombre, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for f in filas:
            w.writerow({c: f.get(c, "") for c in cols})


def lb_fila(o, d, puerto, p95, per="periodico", serie=True):
    return {"origen": o, "origen_ip": o, "destino": d, "destino_ip": d, "servicio": "Modbus/TCP", "l4": "tcp",
            "puerto": puerto, "bidireccional": True, "bytes_total": 1000, "paquetes_total": 10,
            "bytes_min_p50": p95 // 2 if serie else None, "bytes_min_p95": p95 if serie else None,
            "paquetes_min_p50": 5 if serie else None, "paquetes_min_p95": 9 if serie else None,
            "minutos_ventana": 60 if serie else None, "minutos_activos": 60 if serie else None,
            "periodicidad": per, "primer_visto": "", "ultimo_visto": "", "serie_por_minuto": serie}


def datos_base() -> dict:
    return {
        "inventario": [
            {"equipo": "HMI-1", "ips": HMI, "mac": "02:00:00:00:00:10", "fabricante": "Acme", "firmware": "3.0",
             "rol_inferido": "HMI", "zona_purdue": "Nivel 2", "zona_asignada": "Supervision"},
            {"equipo": "PLC-1", "ips": PLC, "mac": "02:00:00:00:00:20", "fabricante": "Acme", "firmware": "1.0",
             "rol_inferido": "Controlador", "zona_purdue": "Nivel 1", "zona_asignada": "Control"},
            {"equipo": "Historiador", "ips": HIST, "mac": "02:00:00:00:00:30", "fabricante": "Acme",
             "rol_inferido": "Historiador", "zona_purdue": "Nivel 3", "zona_asignada": "Operaciones"}],
        "normalizado": [
            {"id": "a1", "ips": HMI, "mac": "02:00:00:00:00:10", "nombre": "HMI-1", "modelo": "H-100",
             "firmware": "3.0", "rol": "HMI / estacion SCADA", "nivel_purdue": "Nivel 2", "zona": "Supervision"},
            {"id": "a2", "ips": PLC, "mac": "02:00:00:00:00:20", "nombre": "PLC-1", "modelo": "P-200",
             "firmware": "1.0", "rol": "Controlador / dispositivo de campo (PLC, RTU, IED)", "nivel_purdue": "Nivel 1",
             "zona": "Control"},
            {"id": "a3", "ips": HIST, "mac": "02:00:00:00:00:30", "nombre": "Historiador", "modelo": "",
             "firmware": "", "rol": "Historiador", "nivel_purdue": "Nivel 3", "zona": "Operaciones"}],
        "comunicaciones": [
            {"origen": "HMI-1", "origen_ip": HMI, "destino": "PLC-1", "destino_ip": PLC, "origen_zona": "Nivel 2",
             "destino_zona": "Nivel 1", "servicio": "Modbus/TCP", "l4": "tcp", "puerto": "502",
             "sentido": "bidireccional", "cruza_zona": "si", "escrituras": "4", "bytes": "4000"},
            {"origen": "Historiador", "origen_ip": HIST, "destino": "PLC-1", "destino_ip": PLC,
             "origen_zona": "Nivel 3", "destino_zona": "Nivel 1", "servicio": "Modbus/TCP", "l4": "tcp",
             "puerto": "502", "sentido": "bidireccional", "cruza_zona": "si", "escrituras": "0", "bytes": "9000"}],
        "control": [
            {"captura": "a.pcap", "trama": "7", "protocolo": "Modbus/TCP", "operacion": "Write Single Register",
             "origen": HMI, "destino": PLC, "detalle": ""}],
        "hallazgos": [{"titulo": "Texto claro", "severidad": "Media", "categoria": "Cifrado"}],
        "linea_base": {"conductos": [lb_fila(HMI, PLC, 502, 1000), lb_fila(HIST, PLC, 502, 2000)]},
    }


def escribir_corrida(carpeta: Path, d: dict, con_basura: bool = True) -> Path:
    carpeta.mkdir(parents=True, exist_ok=True)
    _escribir(carpeta, "inventario.csv", INV, d["inventario"])
    _escribir(carpeta, "inventario_normalizado.csv", NOR, d["normalizado"])
    _escribir(carpeta, "comunicaciones.csv", COM, d["comunicaciones"])
    _escribir(carpeta, "control.csv", CTL, d["control"])
    _escribir(carpeta, "hallazgos.csv", HAL, [{"captura": "a.pcap", **h} for h in d["hallazgos"]])
    (carpeta / "resultado.json").write_text(json.dumps(
        {"entorno": {"ot_assess": "0.0.1"}, "perfil": {"cliente": "Cliente X", "sitio": "Planta 1"}}), "utf-8")
    (carpeta / "linea_base_trafico.json").write_text(json.dumps(
        {"meta": {"ventana": {"inicio": "2026-01-01T00:00:00Z", "fin": "2026-01-01T01:00:00Z", "minutos": 60},
                  "puntos_de_captura": ["punto1"]}, **d["linea_base"]}), "utf-8")
    if con_basura:
        (carpeta / "captura.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
        (carpeta / "mapa_anonimizacion.csv").write_text("real,anonimo\n", "utf-8")
        (carpeta / "cache_captura.json.gz").write_bytes(b"\x1f\x8b")
    return carpeta


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")
        self.base = datos_base()
        self.corrida = escribir_corrida(self.tmp / "corrida", self.base)

    def aprobar(self, **kw):
        args = dict(sitio="Planta 1", aprobado_por="Ana Perez", revisado_por="Luis Gomez")
        args.update(kw)
        return lba.aprobar(self.corrida, self.tmp / "lb", **args)

    def comparar(self, cambios=None, sitio="Planta 1") -> dict:
        self.aprobar()
        d = copy.deepcopy(self.base)
        if cambios:
            cambios(d)
        return lba.evaluar(self.tmp / "lb", d, sitio)

    def tipos(self, rep) -> dict:
        return {x["tipo"]: x for x in rep["desviaciones"]}

    def hallazgos(self, rep) -> dict:
        cap = Capture(Path("linea base aprobada"))
        agregar_hallazgos(cap, rep)
        return {f["titulo"]: f for f in cap.findings}


class AprobarTest(Base):
    def test_crea_la_carpeta_con_manifiesto_y_sin_pcap_ni_cache_ni_mapa(self):
        r = self.aprobar(nota="ventana de produccion normal")
        lb = self.tmp / "lb"
        nombres = sorted(p.name for p in lb.iterdir())
        self.assertIn("linea_base_aprobada.json", nombres)
        for prohibido in ("captura.pcap", "mapa_anonimizacion.csv", "cache_captura.json.gz"):
            self.assertNotIn(prohibido, nombres)
        datos = json.loads((lb / "linea_base_aprobada.json").read_text("utf-8"))
        self.assertEqual(datos["sitio"], "Planta 1")
        self.assertEqual(datos["aprobado_por"], "Ana Perez")
        self.assertEqual(datos["revisado_por"], "Luis Gomez")
        self.assertEqual(datos["nota"], "ventana de produccion normal")
        self.assertEqual(datos["puntos_de_captura"], ["punto1"])
        self.assertEqual(datos["ventana"]["minutos"], 60)
        self.assertTrue(datos["fecha_aprobacion"])
        self.assertEqual(sorted(datos["manifiesto"]), sorted(r["archivos"]))
        self.assertTrue(all(len(h) == 64 for h in datos["manifiesto"].values()))
        self.assertEqual(lba.verificar(lb), [])

    def test_aprobado_por_igual_a_revisado_por_es_un_error_y_no_crea_nada(self):
        for rev in ("Ana Perez", "  ana perez "):
            with self.assertRaisesRegex(lba.ErrorLineaBase, "personas distintas"):
                self.aprobar(revisado_por=rev)
        self.assertFalse((self.tmp / "lb").exists())

    def test_no_sobrescribe_una_linea_base_existente(self):
        self.aprobar()
        with self.assertRaisesRegex(lba.ErrorLineaBase, "no se sobrescribe"):
            self.aprobar()

    def test_corrida_incompleta_falla(self):
        (self.corrida / "control.csv").unlink()
        with self.assertRaisesRegex(lba.ErrorLineaBase, "control.csv"):
            self.aprobar()

    def test_cli_permisos_y_codigos_de_salida(self):
        lb = self.tmp / "lbcli"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_lb(["aprobar", str(self.corrida), "-o", str(lb), "--sitio", "Planta 1",
                          "--aprobado-por", "Ana Perez", "--revisado-por", "Luis Gomez"])
        self.assertEqual(rc, 0)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(lb.stat().st_mode), 0o700)
            for p in lb.iterdir():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600, p.name)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main_lb(["aprobar", str(self.corrida), "-o", str(self.tmp / "otra"), "--sitio", "P",
                          "--aprobado-por", "Ana", "--revisado-por", "Ana"])
        self.assertEqual(rc, 2)
        self.assertIn("personas distintas", err.getvalue())
        self.assertFalse((self.tmp / "otra").exists())


class VerificarTest(Base):
    def test_pasa_y_tras_editar_un_csv_falla_nombrando_el_archivo(self):
        self.aprobar()
        lb = self.tmp / "lb"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main_lb(["verificar", str(lb)]), 0)
        self.assertIn("OK", out.getvalue())
        with open(lb / "comunicaciones.csv", "a", encoding="utf-8") as fh:
            fh.write("X,198.51.100.1,Y,198.51.100.2,,,,tcp,80,,,,\n")
        errores = lba.verificar(lb)
        self.assertEqual(len(errores), 1)
        self.assertIn("comunicaciones.csv", errores[0])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main_lb(["verificar", str(lb)]), 1)
        self.assertIn("comunicaciones.csv", err.getvalue())

    def test_detecta_metadatos_alterados_archivos_faltantes_y_sobrantes(self):
        self.aprobar()
        lb = self.tmp / "lb"
        datos = json.loads((lb / "linea_base_aprobada.json").read_text("utf-8"))
        datos["aprobado_por"] = "Otra Persona"
        (lb / "linea_base_aprobada.json").write_text(json.dumps(datos), "utf-8")
        self.assertTrue(any("linea_base_aprobada.json" in e for e in lba.verificar(lb)))
        self.aprobar_otra()

    def aprobar_otra(self):
        lb2 = self.tmp / "lb2"
        lba.aprobar(self.corrida, lb2, "Planta 1", "Ana Perez", "Luis Gomez")
        (lb2 / "extra.csv").write_text("a\n", "utf-8")
        self.assertTrue(any("extra.csv" in e for e in lba.verificar(lb2)))
        (lb2 / "extra.csv").unlink()
        (lb2 / "hallazgos.csv").unlink()
        self.assertTrue(any("hallazgos.csv: falta" in e for e in lba.verificar(lb2)))

    def test_carpeta_que_no_es_una_linea_base(self):
        self.assertTrue(lba.verificar(self.corrida))


class DesviacionesTest(Base):
    def test_la_misma_corrida_contra_su_linea_base_no_tiene_desviaciones(self):
        rep = self.comparar()
        self.assertEqual(rep["estado"], "comparada")
        self.assertEqual(rep["desviaciones"], [])
        self.assertEqual(rep["resumen"]["total"], 0)
        self.assertEqual(self.hallazgos(rep), {})
        self.assertEqual(lba.filas_tabla(rep), [])

    def test_escritor_nuevo_es_alta(self):
        def cambio(d):
            d["control"].append({"captura": "b.pcap", "trama": "9", "protocolo": "Modbus/TCP",
                                 "operacion": "Write Single Register", "origen": HIST, "destino": PLC,
                                 "detalle": ""})
        rep = self.comparar(cambio)
        x = self.tipos(rep)[lba.T_ESCRITOR]
        self.assertEqual((x["atencion"], x["origen"], x["destino"]), ("alta", HIST, PLC))
        self.assertEqual(x["zona"], "Control")
        h = self.hallazgos(rep)["Escritor nuevo hacia equipos de control fuera de la linea base aprobada"]
        self.assertEqual(h["severidad"], "Alta")
        self.assertEqual(h["activos"], [PLC, HIST])
        self.assertIn("Planta 1", h["evidencia"])

    def test_conducto_nuevo_hacia_nivel_1_es_alta_y_hacia_nivel_3_media(self):
        def hacia(zona):
            def cambio(d):
                d["comunicaciones"].append({
                    "origen": "HMI-1", "origen_ip": HMI, "destino": "PLC-2", "destino_ip": PLC2,
                    "origen_zona": "Nivel 2", "destino_zona": zona, "servicio": "EtherNet/IP", "l4": "tcp",
                    "puerto": "44818", "sentido": "bidireccional", "cruza_zona": "no", "escrituras": "0",
                    "bytes": "10"})
            return cambio
        rep = self.comparar(hacia("Nivel 1"))
        self.assertEqual(self.tipos(rep)[lba.T_CONDUCTO]["puerto"], "44818")
        tit = "Conducto nuevo fuera de la linea base aprobada"
        self.assertEqual(self.hallazgos(rep)[tit]["severidad"], "Alta")
        shutil.rmtree(self.tmp / "lb")
        rep = self.comparar(hacia("Nivel 3"))
        self.assertEqual(self.hallazgos(rep)[tit]["severidad"], "Media")

    def test_conducto_desde_internet_es_alta(self):
        def cambio(d):
            d["comunicaciones"].append({
                "origen": "x", "origen_ip": "198.51.100.7", "destino": "Historiador", "destino_ip": HIST,
                "origen_zona": "Internet", "destino_zona": "Nivel 3", "servicio": "HTTPS", "l4": "tcp",
                "puerto": "443", "sentido": "unidireccional", "cruza_zona": "si", "escrituras": "0", "bytes": "1"})
        rep = self.comparar(cambio)
        self.assertEqual(self.hallazgos(rep)["Conducto nuevo fuera de la linea base aprobada"]["severidad"], "Alta")

    def test_activo_nuevo_es_media(self):
        def cambio(d):
            d["inventario"].append({"equipo": "Laptop", "ips": "192.0.2.99", "mac": "02:00:00:00:00:99",
                                    "rol_inferido": "Estacion", "zona_purdue": "Nivel 3", "zona_asignada": "Oficina"})
        rep = self.comparar(cambio)
        x = self.tipos(rep)[lba.T_ACTIVO]
        self.assertEqual((x["origen"], x["zona"]), ("Laptop", "Oficina"))
        h = self.hallazgos(rep)["Activo nuevo no aprobado en la red"]
        self.assertEqual(h["severidad"], "Media")
        self.assertEqual(h["activos"], ["192.0.2.99"])

    def test_activo_aprobado_no_visto_es_desviacion_sin_hallazgo(self):
        rep = self.comparar(lambda d: d["inventario"].pop())
        self.assertIn(lba.T_NO_VISTO, self.tipos(rep))
        self.assertEqual(self.hallazgos(rep), {})

    def test_firmware_distinto_en_una_ip_es_media_y_alta_si_es_controlador(self):
        tit = "Cambio de firmware, modelo o MAC respecto de la linea base aprobada"

        def hmi(d):
            d["normalizado"][0]["firmware"] = "3.1"
        rep = self.comparar(hmi)
        x = self.tipos(rep)[lba.T_CAMBIO]
        self.assertEqual((x["atencion"], x["valor_aprobado"], x["valor_actual"]),
                         ("media", "firmware 3.0", "firmware 3.1"))
        self.assertEqual(self.hallazgos(rep)[tit]["severidad"], "Media")
        shutil.rmtree(self.tmp / "lb")

        def plc(d):
            d["normalizado"][1]["firmware"] = "2.0"
        rep = self.comparar(plc)
        self.assertEqual(self.tipos(rep)[lba.T_CAMBIO]["atencion"], "alta")
        self.assertEqual(self.hallazgos(rep)[tit]["severidad"], "Alta")

    def test_modelo_y_mac_distintos_cuentan_y_un_dato_nuevo_no(self):
        def cambio(d):
            d["normalizado"][0]["modelo"] = "H-200"
            d["normalizado"][0]["mac"] = "02:00:00:00:00:77"
            d["normalizado"][2]["firmware"] = "9.9"        # la linea base no tenia firmware: no es un cambio
        rep = self.comparar(cambio)
        cambios = [x for x in rep["desviaciones"] if x["tipo"] == lba.T_CAMBIO]
        self.assertEqual(len(cambios), 1)
        self.assertIn("modelo: H-100 -> H-200", cambios[0]["detalle"])
        self.assertIn("MAC", cambios[0]["detalle"])

    def test_volumen_a_4_veces_su_p95_es_baja_y_a_2_veces_no(self):
        tit = "Trafico fuera de la linea base aprobada"

        def cambio(factor):
            def f(d):
                d["linea_base"]["conductos"][0] = lb_fila(HMI, PLC, 502, 1000 * factor)
            return f
        rep = self.comparar(cambio(4))
        x = self.tipos(rep)[lba.T_VOLUMEN]
        self.assertEqual((x["atencion"], x["origen"], x["destino"]), ("baja", HMI, PLC))
        self.assertIn("x4.0", x["detalle"])
        self.assertEqual(self.hallazgos(rep)[tit]["severidad"], "Baja")
        shutil.rmtree(self.tmp / "lb")
        self.assertEqual(self.comparar(cambio(2))["desviaciones"], [])

    def test_volumen_sin_series_por_minuto_no_se_compara(self):
        def cambio(d):
            d["linea_base"]["conductos"][0] = lb_fila(HMI, PLC, 502, 9999, serie=False)
        self.assertEqual(self.comparar(cambio)["desviaciones"], [])

    def test_periodico_a_irregular_es_baja(self):
        def cambio(d):
            d["linea_base"]["conductos"][0] = lb_fila(HMI, PLC, 502, 1000, per="irregular")
        rep = self.comparar(cambio)
        self.assertEqual(self.tipos(rep)[lba.T_PERIODO]["detalle"].split(": ")[1], "periodico -> irregular")
        self.assertEqual(self.hallazgos(rep)["Trafico fuera de la linea base aprobada"]["severidad"], "Baja")

    def test_conducto_aprobado_ausente_es_baja(self):
        rep = self.comparar(lambda d: d["comunicaciones"].pop())
        x = self.tipos(rep)[lba.T_SIN_TRAFICO]
        self.assertEqual((x["atencion"], x["origen"], x["destino"]), ("baja", HIST, PLC))
        self.assertEqual(self.hallazgos(rep)["Conductos aprobados sin trafico"]["severidad"], "Baja")

    def test_hallazgo_nuevo_es_desviacion_sin_hallazgo_propio(self):
        rep = self.comparar(lambda d: d["hallazgos"].append(
            {"titulo": "Telnet", "severidad": "Alta", "categoria": "Cifrado"}))
        x = self.tipos(rep)[lba.T_HALLAZGO]
        self.assertEqual((x["atencion"], x["detalle"]), ("media", "Telnet"))
        self.assertEqual(self.hallazgos(rep), {})

    def test_sitio_distinto_avisa_y_compara_igual(self):
        rep = self.comparar(sitio="Planta 2")
        self.assertEqual(rep["estado"], "comparada")
        self.assertTrue(any("no coincide" in a and "Planta 2" in a for a in rep["avisos"]))

    def test_orden_por_atencion(self):
        def cambio(d):
            d["inventario"].pop()
            d["control"].append({"captura": "b.pcap", "protocolo": "Modbus/TCP", "operacion": "Write",
                                 "origen": HIST, "destino": PLC})
        atenciones = [x["atencion"] for x in self.comparar(cambio)["desviaciones"]]
        self.assertEqual(atenciones, sorted(atenciones, key={"alta": 0, "media": 1, "baja": 2}.get))


class ManifiestoAlteradoTest(Base):
    def test_manifiesto_alterado_avisa_y_no_compara(self):
        self.aprobar()
        with open(self.tmp / "lb" / "hallazgos.csv", "a", encoding="utf-8") as fh:
            fh.write("a.pcap,Alta,X,Y,z\n")
        d = copy.deepcopy(self.base)
        d["inventario"].append({"equipo": "Laptop", "ips": "192.0.2.99"})
        rep = lba.evaluar(self.tmp / "lb", d, "Planta 1")
        self.assertEqual(rep["estado"], "manifiesto alterado")
        self.assertEqual(rep["desviaciones"], [])
        self.assertIn("hallazgos.csv", rep["avisos"][0])
        self.assertEqual(self.hallazgos(rep), {})
        self.assertEqual(lba.tablas(rep), [])
        self.assertTrue(lba.hay(rep))
        self.assertIn("no se compara", lba.seccion(rep)["resumen"])
        self.assertEqual(lba.para_json(rep)["estado"], "manifiesto alterado")


class SalidasTest(Base):
    def test_columnas_de_revision_vacias_y_cabecera_fija(self):
        rep = self.comparar(lambda d: d["inventario"].pop())
        (archivo, hoja, cab, filas), = lba.tablas(rep)
        self.assertEqual(archivo, "desviaciones_linea_base.csv")
        self.assertLessEqual(len(hoja), 31)
        self.assertEqual(cab, ["tipo", "atencion", "zona", "origen", "destino", "puerto", "detalle",
                               "valor_aprobado", "valor_actual", "estado_revision", "revisado_por", "fecha",
                               "comentario"])
        self.assertTrue(filas)
        for f in filas:
            self.assertEqual(len(f), len(cab))
            self.assertEqual(f[9:], ["", "", "", ""])

    def test_seccion_y_json(self):
        def cambio(d):
            d["inventario"].append({"equipo": "Laptop", "ips": "192.0.2.99"})
            d["inventario"].pop(0)
        rep = self.comparar(cambio)
        s = lba.seccion(rep)
        self.assertIn("Planta 1", s["resumen"])
        self.assertIn("Ana Perez", s["resumen"])
        self.assertIn("Luis Gomez", s["resumen"])
        self.assertEqual(len(s["tablas"]), 2)
        self.assertLessEqual(len(s["tablas"][1][2]), 10)
        j = lba.para_json(rep)
        self.assertEqual((j["sitio"], j["desviaciones"]), ("Planta 1", rep["resumen"]["total"]))
        json.dumps(j)

    def test_los_textos_nunca_dicen_cumple(self):
        rep = self.comparar(lambda d: d["inventario"].append({"equipo": "L", "ips": "192.0.2.99"}))
        textos = [lba.NOTA, lba.seccion(rep)["resumen"]]
        for f in self.hallazgos(rep).values():
            textos += [f["evidencia"], f["por_que_importa"], f["recomendacion"]]
        for x in textos:
            self.assertNotIn("cumple", x.lower())


class InglesTest(Base):
    def test_todo_el_texto_de_la_linea_base_esta_en_el_catalogo(self):
        def todo(d):
            d["inventario"].pop()                                                       # no visto
            d["inventario"].append({"equipo": "Laptop", "ips": "192.0.2.99", "mac": "02:00:00:00:00:99",
                                    "zona_purdue": "Nivel 3", "zona_asignada": "Oficina"})
            d["comunicaciones"].pop()                                                   # sin trafico
            d["comunicaciones"].append({
                "origen": "HMI-1", "origen_ip": HMI, "destino": "PLC-2", "destino_ip": PLC2,
                "origen_zona": "Internet", "destino_zona": "Nivel 1", "servicio": "EtherNet/IP", "l4": "tcp",
                "puerto": "44818", "sentido": "bidireccional", "cruza_zona": "si", "escrituras": "2", "bytes": "9"})
            d["control"].append({"captura": "b", "protocolo": "Modbus/TCP", "operacion": "Write", "origen": HIST,
                                 "destino": PLC})
            d["hallazgos"].append({"titulo": "Tormenta de difusion o multidifusion", "severidad": "Alta",
                                   "categoria": "Anomalia"})
            d["normalizado"][1].update(firmware="2.0", modelo="P-300", mac="02:00:00:00:00:88")
            d["linea_base"]["conductos"][0] = lb_fila(HMI, PLC, 502, 9000, per="irregular")
        i18n.usar("en")
        i18n.FALTANTES.clear()
        rep = self.comparar(todo)
        self.assertEqual({x["tipo"] for x in rep["desviaciones"]}, set(lba.TIPOS))
        hall = self.hallazgos(rep)
        self.assertEqual(len(hall), 6)
        for f in hall.values():
            for campo in ("titulo", "evidencia", "por_que_importa", "recomendacion"):
                i18n.t(f[campo])
        lba.seccion(rep)
        lba.filas_tabla(rep)
        lba.imprimir(rep)
        self.assertEqual(sorted(i18n.FALTANTES), [])


class PlaybooksYMapeosTest(unittest.TestCase):
    TITULOS = ("Escritor nuevo hacia equipos de control fuera de la linea base aprobada",
               "Conducto nuevo fuera de la linea base aprobada", "Activo nuevo no aprobado en la red",
               "Cambio de firmware, modelo o MAC respecto de la linea base aprobada",
               "Trafico fuera de la linea base aprobada", "Conductos aprobados sin trafico")

    def test_cada_titulo_tiene_playbook_y_mapeo_sin_revisar(self):
        ids = {playbooks.para_titulo(t) for t in self.TITULOS}
        self.assertEqual(len(ids), 6)
        self.assertNotIn("", ids)
        for t in self.TITULOS:
            refs = referencias(t)
            self.assertTrue(refs, t)
        for archivo in ("iec62443", "nist-800-82", "nist-csf", "mitre-ics", "nerc-cip"):
            marco = json.loads((RAIZ / "ot_assess" / "marcos" / f"{archivo}.json").read_text("utf-8"))
            self.assertEqual(marco["validacion"]["estado"], "sin revisar", archivo)

    def test_los_titulos_de_la_regla_son_los_de_la_prueba(self):
        src = (RAIZ / "ot_assess" / "rules" / "linea_base_aprobada.py").read_text("utf-8")
        for t in self.TITULOS:
            self.assertIn(f'"{t}"', src)


class IngresoTest(unittest.TestCase):
    """De punta a punta con el CLI `diagrama` (exportaciones CSV): aprobar, repetir y desviar."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(i18n.usar, "es")

    def exportar(self, nombre, firmware_hmi="3.0", extra=False):
        d = self.tmp / nombre
        d.mkdir()
        activos = [["PLC-1", PLC, "02:00:00:00:00:20", "Acme", "1.0", "PLC", "1"],
                   ["HMI-1", HMI, "02:00:00:00:00:10", "Acme", firmware_hmi, "HMI", "2"],
                   ["Historiador", HIST, "02:00:00:00:00:30", "Acme", "", "Server", "3"]]
        enlaces = [[HMI, PLC, "502", "Modbus", "100"], [HIST, PLC, "502", "Modbus", "40"]]
        if extra:
            activos.append(["PLC-2", PLC2, "02:00:00:00:00:21", "Acme", "1.0", "PLC", "1"])
            enlaces.append([HMI, PLC2, "44818", "EtherNet/IP", "12"])
        for n, cols, filas in (("activos.csv", ["Name", "IP", "MAC", "Vendor", "Firmware", "Type", "Level"], activos),
                               ("enlaces.csv", ["Source", "Destination", "Port", "Protocol", "Packets"], enlaces)):
            with open(d / n, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                w.writerows(filas)
        return d

    def correr(self, nombre, expo, *extra):
        out = self.tmp / nombre
        perfil = self.tmp / (nombre + ".json")
        perfil.write_text(json.dumps({"version": 1, "cliente": "C", "sitio": "Planta 1",
                                      "marcos": [{"clave": "iec62443"}]}), "utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = main_completo(["diagrama", "--activos", str(expo / "activos.csv"), "--enlaces",
                                str(expo / "enlaces.csv"), "--formato", "generico", "--perfil", str(perfil),
                                "-o", str(out), *extra])
        self.assertEqual(rc, 0, buf.getvalue())
        return out, buf.getvalue()

    def csv(self, ruta):
        with open(ruta, encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def test_aprobar_repetir_y_desviar(self):
        base, _ = self.correr("base", self.exportar("e1"))
        lb = self.tmp / "lb"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_completo(["linea-base", "aprobar", str(base), "-o", str(lb), "--sitio", "Planta 1",
                                "--aprobado-por", "Ana Perez", "--revisado-por", "Luis Gomez"])
        self.assertEqual(rc, 0)
        self.assertFalse(any(p.suffix in (".pcap", ".pcapng") for p in lb.iterdir()))

        # la misma corrida: sin desviaciones ni hallazgos de linea base
        igual, consola = self.correr("igual", self.exportar("e2"), "--linea-base", str(lb))
        self.assertIn("0 desviaciones", consola)
        self.assertEqual(self.csv(igual / "desviaciones_linea_base.csv"), [])
        j = json.loads((igual / "resultado.json").read_text("utf-8"))["linea_base_aprobada"]
        self.assertEqual((j["estado"], j["desviaciones"], j["sitio"]), ("comparada", 0, "Planta 1"))
        self.assertNotIn("linea base aprobada", (igual / "hallazgos.csv").read_text("utf-8-sig"))

        # activo nuevo, conducto nuevo hacia nivel 1 y firmware distinto
        nueva, consola = self.correr("nueva", self.exportar("e3", firmware_hmi="3.1", extra=True),
                                     "--linea-base", str(lb))
        tipos = {f["tipo"] for f in self.csv(nueva / "desviaciones_linea_base.csv")}
        self.assertEqual(tipos, {"activo nuevo no aprobado", "conducto nuevo", "cambio de firmware, modelo o MAC"})
        hall = {f["titulo"]: f for f in self.csv(nueva / "hallazgos.csv")}
        self.assertEqual(hall["Activo nuevo no aprobado en la red"]["severidad"], "Media")
        self.assertEqual(hall["Conducto nuevo fuera de la linea base aprobada"]["severidad"], "Alta")
        self.assertEqual(hall["Cambio de firmware, modelo o MAC respecto de la linea base aprobada"]["severidad"],
                         "Media")
        self.assertTrue(hall["Activo nuevo no aprobado en la red"]["iec62443"])
        plan = (nueva / "plan_remediacion.csv").read_text("utf-8-sig")
        self.assertIn("pb-activo-nuevo-linea-base", plan)
        md = (nueva / "reporte_ot.md").read_text("utf-8")
        self.assertIn("Desviaciones respecto de la linea base aprobada", md)
        self.assertIn("Ana Perez", md)
        self.assertTrue((nueva / "reporte_ot.xlsx").is_file())

        # linea base alterada: aviso y sin comparacion
        with open(lb / "inventario.csv", "a", encoding="utf-8") as fh:
            fh.write("X\n")
        rota, consola = self.correr("rota", self.exportar("e4", extra=True), "--linea-base", str(lb))
        self.assertIn("no pasa la verificacion", consola)
        self.assertFalse((rota / "desviaciones_linea_base.csv").exists())
        self.assertEqual(json.loads((rota / "resultado.json").read_text("utf-8"))["linea_base_aprobada"]["estado"],
                         "manifiesto alterado")

    def test_en_ingles_y_sin_la_opcion(self):
        base, _ = self.correr("base", self.exportar("e1"))
        lb = self.tmp / "lb"
        lba.aprobar(base, lb, "Planta 1", "Ana Perez", "Luis Gomez")
        sin, _ = self.correr("sin", self.exportar("e0"))
        self.assertFalse((sin / "desviaciones_linea_base.csv").exists())
        self.assertEqual(json.loads((sin / "resultado.json").read_text("utf-8"))["linea_base_aprobada"], {})
        out = self.tmp / "en"
        perfil = self.tmp / "en.json"
        perfil.write_text(json.dumps({"version": 1, "cliente": "C", "sitio": "Planta 1", "idioma": "en",
                                      "marcos": [{"clave": "iec62443"}]}), "utf-8")
        e = self.exportar("e5", extra=True)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main_completo(["diagrama", "--activos", str(e / "activos.csv"), "--enlaces", str(e / "enlaces.csv"),
                                "--formato", "generico", "--perfil", str(perfil), "-o", str(out),
                                "--linea-base", str(lb)])
        self.assertEqual(rc, 0)
        md = (out / "reporte_ot.md").read_text("utf-8")
        self.assertIn("Deviations from the approved baseline", md)
        self.assertTrue((out / "desviaciones_linea_base.csv").is_file())

    def test_carpeta_inexistente_es_un_error_de_uso(self):
        e = self.exportar("e1")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main_completo(["diagrama", "--activos", str(e / "activos.csv"), "--enlaces", str(e / "enlaces.csv"),
                           "--formato", "generico", "-o", str(self.tmp / "o"),
                           "--linea-base", str(self.tmp / "no_existe")])


if __name__ == "__main__":
    unittest.main()
