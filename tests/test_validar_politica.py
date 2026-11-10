"""M5: validar la politica propuesta contra el trafico de otra ventana (D67). Datos sinteticos."""
from __future__ import annotations

import contextlib
import csv
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))

import gen_exports
from test_firewalls_cruces import ACL, RUTAS_EXP
from test_firewalls_integracion import _sesion

from ot_assess import cli_validar
from ot_assess.cli import main
from ot_assess.firewalls import fmc
from ot_assess.firewalls import validar_politica as vp

PERMITE_TODO = ACL + "permit ip any any rule-id 1\n"

OBJETOS = [
    ("H_A", "host", "10.1.1.10", ""), ("H_C", "host", "10.1.1.99", ""), ("H_B", "host", "10.2.2.20", ""),
    ("G_IN", "grupo", "", "H_A"), ("G_O", "grupo", "", "G_IN"), ("G_OC", "grupo", "", "G_IN;H_C"),
    ("N_INT", "red", "10.1.0.0/16", ""), ("ANY_INTERNET", "red", "0.0.0.0/0", ""),
    ("S_502", "servicio", "tcp/502", ""), ("S_80", "servicio", "tcp/80", ""), ("S_443", "servicio", "tcp/443", ""),
    ("S_ANY", "servicio", "ip", ""), ("SG_R", "grupo_servicio", "", "S_502;S_80"),
]


def regla(orden, nombre, dec, ifs, o, d, s):
    a, b = ifs.split(" -> ")
    return {"orden": orden, "nombre": nombre, "decision": dec, "razones": "", "zona_entrada": "SZ_" + a,
            "zona_salida": "SZ_" + b, "interfaces": ifs, "origen": o, "destino": d, "servicios": s,
            "justificacion": "x"}


REGLAS = [
    regla(1, "r_bloq", "bloquear", "inside -> dmz", "H_C", "H_B", "S_502"),
    regla(2, "r1", "permitir", "inside -> dmz", "G_OC", "H_B", "SG_R"),
    regla(3, "r2", "permitir", "inside -> outside", "N_INT", "ANY_INTERNET", "S_443"),
    regla(4, "r_sinuso", "permitir", "dmz -> inside", "H_B", "H_A", "S_80"),
    regla(5, "r_rev", "revisar", "dmz -> outside", "H_B", "ANY_INTERNET", "S_443"),
]


def cruce(ifo, ifd, o, d, l4, puerto, res="permitido", con=1, by=100, **kw):
    f = {"interfaz_origen": ifo, "interfaz_destino": ifd, "ip_origen": o, "ip_destino": d, "nombre_origen": "",
         "nombre_destino": "", "ambito_destino": "interna", "protocolo_l4": l4, "puerto": puerto,
         "protocolo_aplicacion": "", "conductos": con, "bytes": by, "regla_actual": "1", "resultado": res,
         "l4_inferido": "no", "etiquetas": "", "fuentes": ""}
    f.update(kw)
    return f


CRUCES = [
    cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 502),                       # cubierto
    cruce("inside", "dmz", "10.1.1.55", "10.2.2.20", "tcp", 502, by=900),               # origen nuevo
    cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 9999, by=800),              # puerto nuevo
    cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 23, "denegado_observado"),  # sigue bloqueado
    cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 80, "denegado_observado"),  # se abriria
    cruce("inside", "dmz", "10.1.1.99", "10.2.2.20", "tcp", 502),                       # fila bloquear
    cruce("inside", "outside", "10.1.5.5", "8.8.4.4", "tcp", 443, ambito_destino="Internet"),
    cruce("inside", "outside", "10.1.5.5", "10.9.9.9", "tcp", 443, by=700),             # privado: no es Internet
    cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "", 80, l4_inferido="si"),         # l4 vacio
    cruce("dmz", "outside", "10.2.2.20", "8.8.4.4", "tcp", 443, by=600),                # solo la revisar
]


def escribir_csv(ruta, cab, filas):
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cab, extrasaction="ignore")
        w.writeheader()
        for f in filas:
            w.writerow(f)


def leer(ruta):
    with open(ruta, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def preparar(self, reglas=None, objetos=None, cruces=None, carpeta="v1"):
        prop, obj = self.dir / "p.csv", self.dir / "o.csv"
        escribir_csv(prop, fmc.COL_PROPUESTA + ("interfaces",), reglas if reglas is not None else REGLAS)
        escribir_csv(obj, fmc.COL_OBJETOS, [dict(zip(fmc.COL_OBJETOS, o)) for o in (objetos or OBJETOS)])
        d = self.dir / carpeta
        d.mkdir(exist_ok=True)
        escribir_csv(d / vp.ARCHIVO_CRUCES, vp.COL_ENTRADA + ["l4_inferido", "etiquetas", "fuentes"],
                     cruces if cruces is not None else CRUCES)
        return prop, obj, d

    def correr(self, *extra, carpetas=("v1",), out="out"):
        o, e = io.StringIO(), io.StringIO()
        args = ["--propuesta", str(self.dir / "p.csv"), "--objetos", str(self.dir / "o.csv"),
                "-o", str(self.dir / out)]
        for c in carpetas:
            args += ["--cruces", str(self.dir / c)]
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            rc = cli_validar.main(args + list(extra))
        return rc, o.getvalue(), e.getvalue()

    def filas(self, out="out"):
        return {(f["ip_origen"], f["ip_destino"], f["puerto"], f["interfaz_origen"]): f
                for f in leer(self.dir / out / "validacion_cruces.csv")}


class CategoriasTest(Base):
    def test_ventana_nueva(self):
        self.preparar()
        rc, salida, _ = self.correr()
        self.assertEqual(rc, 0)       # se_romperia no es un error de la herramienta
        f = self.filas()
        cub = f[("10.1.1.10", "10.2.2.20", "502", "inside")]
        self.assertEqual((cub["categoria"], cub["regla_propuesta"]), ("sigue_permitido", "r1"))
        org = f[("10.1.1.55", "10.2.2.20", "502", "inside")]
        self.assertEqual((org["categoria"], org["casi_regla"]), ("se_romperia", "r1"))
        self.assertEqual(org["sugerencia"], "agregar 10.1.1.55 al grupo G_OC de la regla r1")
        pto = f[("10.1.1.10", "10.2.2.20", "9999", "inside")]
        self.assertEqual(pto["categoria"], "se_romperia")
        self.assertEqual(pto["sugerencia"], "agregar TCP/9999 al grupo SG_R de la regla r1")
        self.assertEqual(f[("10.1.1.10", "10.2.2.20", "23", "inside")]["categoria"], "sigue_bloqueado")
        blo = f[("10.1.1.99", "10.2.2.20", "502", "inside")]
        self.assertEqual((blo["categoria"], blo["regla_propuesta"], blo["decision"]),
                         ("bloqueo_decidido", "r_bloq", "bloquear"))
        self.assertEqual(f[("10.1.5.5", "8.8.4.4", "443", "inside")]["categoria"], "sigue_permitido")
        priv = f[("10.1.5.5", "10.9.9.9", "443", "inside")]
        self.assertEqual((priv["categoria"], priv["casi_regla"]), ("se_romperia", "r2"))
        self.assertIn("agregar 10.9.9.9 al objeto ANY_INTERNET", priv["sugerencia"])
        self.assertIn("se_romperia: 4 cruces", salida)

    def test_denegado_hoy_que_la_propuesta_permite_se_abre_y_l4_vacio_casa(self):
        self.preparar()
        self.correr()
        filas = leer(self.dir / "out" / "validacion_cruces.csv")
        p80 = [x for x in filas if x["puerto"] == "80" and x["interfaz_origen"] == "inside"]
        self.assertEqual(sorted(x["categoria"] for x in p80), ["se_abriria", "sigue_permitido"])
        vacio = [x for x in p80 if x["protocolo_l4"] == ""][0]
        self.assertEqual((vacio["categoria"], vacio["regla_propuesta"]), ("sigue_permitido", "r1"))

    def test_revisar_solo_con_la_opcion(self):
        self.preparar()
        self.correr()
        sin = self.filas()[("10.2.2.20", "8.8.4.4", "443", "dmz")]
        self.assertEqual((sin["categoria"], sin["casi_regla"]), ("se_romperia", "r_rev"))
        self.assertIn("--incluir-revisar", sin["sugerencia"])
        self.correr("--incluir-revisar", out="out2")
        con = self.filas("out2")[("10.2.2.20", "8.8.4.4", "443", "dmz")]
        self.assertEqual((con["categoria"], con["decision"], con["regla_propuesta"]),
                         ("sigue_permitido", "revisar", "r_rev"))

    def test_resultado_en_ingles_y_bloqueo_de_la_herramienta(self):
        # la etiqueta en ingles sale del catalogo, no de un texto escrito a mano
        from ot_assess import i18n
        i18n.usar("en")
        try:
            et = i18n.t("desde Internet")
        finally:
            i18n.usar("es")
        cr = [cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 502, "allowed"),
              cruce("outside", "inside", "45.33.32.156", "10.1.1.10", "tcp", 3389, "allowed", etiquetas=et)]
        self.preparar(cruces=cr)
        self.correr()
        f = self.filas()
        self.assertEqual(f[("10.1.1.10", "10.2.2.20", "502", "inside")]["resultado_hoy"], "permitido")
        t = f[("45.33.32.156", "10.1.1.10", "3389", "outside")]
        self.assertEqual(t["categoria"], "bloqueo_decidido")
        self.assertIn("politica_bloqueados.csv", t["sugerencia"])


class OrdenYGruposTest(Base):
    def test_la_primera_que_coincide_gana(self):
        c = [cruce("inside", "dmz", "10.1.1.99", "10.2.2.20", "tcp", 502)]
        self.preparar(cruces=c)
        self.correr()
        self.assertEqual(self.filas()[("10.1.1.99", "10.2.2.20", "502", "inside")]["categoria"], "bloqueo_decidido")
        # misma propuesta con la permitir antes: gana la permitir
        r = [dict(x) for x in REGLAS]
        r[0]["orden"], r[1]["orden"] = 2, 1
        self.preparar(reglas=r, cruces=c)
        self.correr(out="o2")
        f = self.filas("o2")[("10.1.1.99", "10.2.2.20", "502", "inside")]
        self.assertEqual((f["categoria"], f["regla_propuesta"]), ("sigue_permitido", "r1"))

    def test_grupos_anidados(self):
        # H_A llega a G_OC por G_IN (un nivel anidado)
        self.preparar(cruces=[cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 80)])
        self.correr()
        self.assertEqual(next(iter(self.filas().values()))["categoria"], "sigue_permitido")

    def test_grupo_circular_es_error(self):
        obj = OBJETOS + [("G_X", "grupo", "", "G_Y"), ("G_Y", "grupo", "", "G_X")]
        self.preparar(objetos=obj)
        rc, _, err = self.correr()
        self.assertEqual(rc, 2)
        self.assertIn("circular", err)


class EntradaInvalidaTest(Base):
    def _error(self, reglas=None, objetos=None):
        self.preparar(reglas=reglas, objetos=objetos)
        rc, _, err = self.correr()
        self.assertEqual(rc, 2)
        self.assertNotIn(str(self.dir), err)
        self.assertFalse((self.dir / "out").exists())
        return err

    def test_objeto_inexistente_con_numero_de_fila(self):
        r = [dict(x) for x in REGLAS]
        r[1]["origen"] = "H_NO_EXISTE"
        err = self._error(reglas=r)
        self.assertIn("propuesta fila 3", err)
        self.assertIn("H_NO_EXISTE", err)

    def test_ip_invalida_con_numero_de_fila(self):
        obj = [("H_A", "host", "10.1.1.999", "")] + OBJETOS[1:]
        err = self._error(objetos=obj)
        self.assertIn("objetos fila 2", err)
        self.assertIn("10.1.1.999", err)

    def test_puerto_invalido(self):
        obj = OBJETOS[:8] + [("S_502", "servicio", "tcp/70000", "")] + OBJETOS[9:]
        self.assertIn("objetos fila 10", self._error(objetos=obj))

    def test_orden_repetido(self):
        r = [dict(x) for x in REGLAS]
        r[2]["orden"] = 1
        self.assertIn("orden repetido", self._error(reglas=r))

    def test_falta_columna_sin_ruta_absoluta(self):
        self.preparar()
        (self.dir / "p.csv").write_text("orden,nombre\n1,a\n", encoding="utf-8")
        rc, _, err = self.correr()
        self.assertEqual(rc, 2)
        self.assertIn("faltan las columnas", err)
        self.assertNotIn(str(self.dir), err)

    def test_cruces_inexistentes(self):
        self.preparar()
        rc, _, err = self.correr(carpetas=("no_hay",))
        self.assertEqual(rc, 2)
        self.assertNotIn(str(self.dir), err)


class AgregarYSalidasTest(Base):
    def test_dos_cruces_con_el_mismo_cruce_se_suman(self):
        a = cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 502, con=2, by=100, fuentes="a.pcap")
        b = cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "tcp", 502, con=3, by=50, fuentes="b.pcap")
        self.preparar(cruces=[a], carpeta="v1")
        self.preparar(cruces=[b], carpeta="v2")
        rc, _, _ = self.correr(carpetas=("v1", "v2"))
        self.assertEqual(rc, 0)
        filas = leer(self.dir / "out" / "validacion_cruces.csv")
        self.assertEqual(len(filas), 1)
        self.assertEqual((filas[0]["conductos"], filas[0]["bytes"], filas[0]["fuentes"]), ("5", "150", "a.pcap; b.pcap"))

    def test_reglas_sin_uso_md_columnas_y_permisos(self):
        self.preparar()
        self.correr()
        reglas = {r["nombre"]: r for r in leer(self.dir / "out" / "validacion_reglas.csv")}
        self.assertEqual(list(next(iter(reglas.values()))), vp.COL_REGLAS)
        self.assertEqual(reglas["r_sinuso"]["sin_uso"], "si")
        self.assertEqual(reglas["r1"]["sin_uso"], "")
        self.assertGreater(int(reglas["r1"]["conductos"]), 0)
        self.assertTrue(reglas["r_rev"]["sin_uso"].startswith("no evaluada"))
        with open(self.dir / "out" / "validacion_cruces.csv", newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), vp.COL_CRUCES)
        md = (self.dir / "out" / "validacion.md").read_text(encoding="utf-8")
        for txt in ("sigue_permitido:", "se_romperia: 4", "r_sinuso", "tambien es parcial",
                    "agregar TCP/9999 al grupo SG_R"):
            self.assertIn(txt, md)
        # los se_romperia salen ordenados por bytes: el de 900 antes que el de 700
        self.assertLess(md.index("10.1.1.55"), md.index("10.9.9.9"))
        if os.name == "posix":
            for n in ("validacion_cruces.csv", "validacion_reglas.csv", "validacion.md"):
                self.assertEqual(stat.S_IMODE((self.dir / "out" / n).stat().st_mode), 0o600, n)

    def test_salida_determinista(self):
        self.preparar()
        self.correr(out="a")
        self.correr(out="b")
        for n in ("validacion_cruces.csv", "validacion_reglas.csv", "validacion.md"):
            self.assertEqual((self.dir / "a" / n).read_bytes(), (self.dir / "b" / n).read_bytes(), n)

    def test_main_registrado_y_en_la_ayuda(self):
        self.preparar()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["politica-validar", "--propuesta", str(self.dir / "p.csv"), "--objetos",
                       str(self.dir / "o.csv"), "--cruces", str(self.dir / "v1"), "-o", str(self.dir / "o3")])
        self.assertEqual(rc, 0)
        from ot_assess import cli
        self.assertIn("politica-validar", cli.DOC)


class ProbableRespuestaTest(Base):
    IDA = cruce("inside", "dmz", "10.1.1.10", "10.2.2.20", "udp", 3391)

    def cat(self, cruces, carpetas=None, **kw):
        if carpetas:
            for nombre, cs in carpetas.items():
                self.preparar(reglas=[], cruces=cs, carpeta=nombre)
        else:
            self.preparar(reglas=[], cruces=cruces)
        rc, _, _ = self.correr(carpetas=tuple(carpetas) if carpetas else ("v1",))
        self.assertEqual(rc, 0)
        return {(k[0], k[2]): f for k, f in self.filas().items()}

    def test_par_udp_la_vuelta_es_probable_respuesta(self):
        vuelta = cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "udp", 56645)
        f = self.cat([self.IDA, vuelta])
        self.assertEqual(f[("10.1.1.10", "3391")]["categoria"], "se_romperia")
        r = f[("10.2.2.20", "56645")]
        self.assertEqual(r["categoria"], "probable_respuesta")
        self.assertEqual(r["sugerencia"], "respuesta probable de 10.1.1.10:3391 (el firewall la deja pasar por "
                         "estado; verificar si es otra conexion)")
        md = (self.dir / "out" / "validacion.md").read_text(encoding="utf-8")
        self.assertIn("probable_respuesta: 1 cruces", md)
        self.assertNotIn("56645", md.split("## Reglas de la propuesta")[0].split("## Lo que se romperia")[1])

    def test_sin_cruce_inverso_sigue_se_romperia(self):
        f = self.cat([cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "udp", 56645)])
        self.assertEqual(f[("10.2.2.20", "56645")]["categoria"], "se_romperia")

    def test_limite_49151_no_aplica(self):
        vuelta = cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "udp", 49151)
        f = self.cat([self.IDA, vuelta])
        self.assertEqual(f[("10.2.2.20", "49151")]["categoria"], "se_romperia")
        vuelta = cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "udp", 49152)
        f = self.cat([self.IDA, vuelta])
        self.assertEqual(f[("10.2.2.20", "49152")]["categoria"], "probable_respuesta")

    def test_el_inverso_puede_venir_de_otra_cruces(self):
        vuelta = cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "udp", 56645)
        f = self.cat(None, carpetas={"v1": [vuelta], "v2": [self.IDA]})
        self.assertEqual(f[("10.2.2.20", "56645")]["categoria"], "probable_respuesta")

    def test_otro_protocolo_no_casa(self):
        vuelta = cruce("dmz", "inside", "10.2.2.20", "10.1.1.10", "tcp", 56645)
        f = self.cat([self.IDA, vuelta])
        self.assertEqual(f[("10.2.2.20", "56645")]["categoria"], "se_romperia")


class InvarianteTest(unittest.TestCase):
    """Validar contra los MISMOS cruces de la corrida que genero la propuesta: nada se rompe ni se abre."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        est = gen_exports.escribir(cls.tmp / "ex")["b"]
        (cls.tmp / "fw.txt").write_text(_sesion(RUTAS_EXP, PERMITE_TODO), encoding="utf-8")
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["diagrama", "--activos", str(est["activos"]), "--enlaces", str(est["enlaces"]),
                       "-o", str(cls.out), "--firewall", str(cls.tmp / "fw.txt")])
        assert rc == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def validar(self, *extra, nombre="v", propuesta="politica_propuesta.csv"):
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli_validar.main(["--propuesta", str(self.out / propuesta), "--objetos",
                                   str(self.out / "politica_objetos.csv"), "--cruces", str(self.out),
                                   "-o", str(self.tmp / nombre), *extra])
        self.assertEqual(rc, 0)
        return [f["categoria"] for f in leer(self.tmp / nombre / "validacion_cruces.csv")]

    def test_con_incluir_revisar_no_se_rompe_ni_se_abre(self):
        cats = self.validar("--incluir-revisar", nombre="v1")
        self.assertTrue(cats)
        self.assertEqual(cats.count("se_romperia"), 0)
        self.assertEqual(cats.count("se_abriria"), 0)
        self.assertGreater(cats.count("sigue_permitido"), 0)

    def test_sin_incluir_revisar_las_revisar_se_romperian(self):
        # el analista marca la primera regla como revisar (cambio a mano)
        filas = leer(self.out / "politica_propuesta.csv")
        filas[0]["decision"] = "revisar"
        escribir_csv(self.out / "editada.csv", list(filas[0]), filas)
        cats = self.validar(nombre="v2", propuesta="editada.csv")
        self.assertGreater(cats.count("se_romperia"), 0)
        self.assertEqual(cats.count("se_abriria"), 0)
        cats = self.validar("--incluir-revisar", nombre="v3", propuesta="editada.csv")
        self.assertEqual(cats.count("se_romperia"), 0)


if __name__ == "__main__":
    unittest.main()
