"""M3b: exportacion de la politica propuesta a Cisco FMC (D48). Sin red: el script generado recibe una peticion falsa."""
import contextlib
import csv
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from ot_assess import cli_politica

CLAVE = "S3cr3t-Pass-XYZ"
PROP = ["orden", "nombre", "decision", "razones", "zona_entrada", "zona_salida", "origen", "destino", "servicios",
        "justificacion"]
OBJ = ["nombre", "tipo", "valor", "miembros"]
OBJETOS = [
    ["H_a", "host", "10.0.0.1", ""], ["H_b", "host", "10.0.0.2", ""], ["N_x", "red", "10.0.2.0/24", ""],
    ["G_1", "grupo", "", "H_a;H_b"], ["ANY_INTERNET", "red", "0.0.0.0/0", "excepto las redes internas"],
    ["S_tcp_443", "servicio", "tcp/443", ""], ["S_udp_53", "servicio", "udp/53", ""],
    ["S_tcp_1000-2000", "servicio", "tcp/1000-2000", ""], ["SG_1_x", "grupo_servicio", "", "S_tcp_443;S_udp_53"],
    ["H_sin_usar", "host", "no-es-ip", ""],
]
REGLAS = [
    ["1", "1_in_a_out_S_tcp_443", "permitir", "", "ZIN", "ZOUT", "G_1", "N_x", "SG_1_x", "observado: 3 conductos"],
    ["2", "2_in_a_out_S_tcp_443", "revisar", "visto un solo dia; RDP", "ZIN", "ZOUT", "H_a", "ANY_INTERNET",
     "S_tcp_443", "x" * 400],
    ["3", "3_in_a_out_S_tcp_443", "bloquear", "", "ZIN", "ZOUT", "H_b", "N_x", "S_tcp_1000-2000", ""],
]


def _csv(ruta, cab, filas):
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cab)
        w.writerows(filas)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.dir = Path(self._t.name)
        self.out = self.dir / "salida"

    def exportar(self, reglas=None, objetos=None, extra=(), nombre="FW1_politica_propuesta.csv"):
        _csv(self.dir / nombre, PROP, REGLAS if reglas is None else reglas)
        _csv(self.dir / "o.csv", OBJ, OBJETOS if objetos is None else objetos)
        err, o = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(o):
            rc = cli_politica.main(["--propuesta", str(self.dir / nombre), "--objetos", str(self.dir / "o.csv"),
                                    "-o", str(self.out), *extra])
        return rc, o.getvalue(), err.getvalue()

    def json(self, nombre):
        return json.loads((self.out / nombre).read_text(encoding="utf-8"))


class ExportacionTest(Base):
    def test_por_defecto_solo_permitir_y_bloquear_nunca(self):
        rc, _o, _e = self.exportar()
        self.assertEqual(rc, 0)
        self.assertEqual([r["name"] for r in self.json("fmc_reglas.json")], ["1_in_a_out_S_tcp_443"])
        rc, _o, _e = self.exportar(extra=["--incluir-revisar"])
        nombres = [r["name"] for r in self.json("fmc_reglas.json")]
        self.assertEqual(nombres, ["1_in_a_out_S_tcp_443", "2_in_a_out_S_tcp_443"])
        self.assertNotIn("3_in_a_out_S_tcp_443", nombres)

    def test_revisar_va_deshabilitada_con_comentario(self):
        self.exportar(extra=["--incluir-revisar"])
        r1, r2 = self.json("fmc_reglas.json")
        self.assertTrue(r1["enabled"])
        self.assertFalse(r2["enabled"])
        self.assertTrue(r2["newComments"][0].startswith("revisar: visto un solo dia; RDP"))
        self.assertLessEqual(len(r2["newComments"][0]), 250)

    def test_forma_de_las_reglas(self):
        self.exportar()
        r = self.json("fmc_reglas.json")[0]
        self.assertEqual(r, {
            "name": "1_in_a_out_S_tcp_443", "action": "ALLOW", "enabled": True, "sourceZones": ["ZIN"],
            "destinationZones": ["ZOUT"], "sourceNetworks": ["G_1"], "destinationNetworks": ["N_x"],
            "destinationPorts": ["SG_1_x"], "logBegin": False, "logEnd": True, "sendEventsToFMC": True,
            "newComments": ["observado: 3 conductos"]})

    def test_forma_de_los_objetos_y_solo_los_usados(self):
        self.exportar(extra=["--incluir-revisar"])
        o = self.json("fmc_objetos.json")
        self.assertEqual(sorted(x["name"] for x in o["hosts"]), ["H_a", "H_b"])
        self.assertEqual(o["hosts"][0], {"name": "H_a", "type": "Host", "value": "10.0.0.1", "description": ""}
                         if o["hosts"][0]["name"] == "H_a" else o["hosts"][0])
        self.assertEqual({x["name"]: x["value"] for x in o["redes"]},
                         {"N_x": "10.0.2.0/24", "ANY_INTERNET": "0.0.0.0/0"})
        self.assertEqual(o["grupos_red"], [{"name": "G_1", "type": "NetworkGroup", "objects": [
            {"name": "H_a", "type": "Host"}, {"name": "H_b", "type": "Host"}]}])
        self.assertEqual(sorted((x["name"], x["protocol"], x["port"]) for x in o["servicios"]),
                         [("S_tcp_443", "TCP", "443"), ("S_udp_53", "UDP", "53")])
        self.assertEqual(o["servicios"][0]["type"], "ProtocolPortObject")
        self.assertEqual(o["grupos_servicio"][0]["type"], "PortObjectGroup")
        self.assertNotIn("H_sin_usar", json.dumps(o))          # valor invalido pero sin uso: no estorba
        self.assertNotIn("S_tcp_1000-2000", json.dumps(o))     # solo lo usaba la regla bloquear

    def test_rango_de_puertos(self):
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_a", "H_b", "S_tcp_1000-2000", ""]]
        self.exportar(reglas=reglas)
        self.assertEqual(self.json("fmc_objetos.json")["servicios"][0]["port"], "1000-2000")

    def test_nombre_de_politica_por_defecto_y_propio(self):
        _rc, o, _e = self.exportar()
        self.assertRegex(o, r"PROPUESTA_FW1_\d{8}")
        self.assertRegex((self.out / "aplicar_fmc.py").read_text(), r'POLITICA = "PROPUESTA_FW1_\d{8}"')
        self.exportar(extra=["--politica", "MI_POLITICA"])
        self.assertIn('POLITICA = "MI_POLITICA"', (self.out / "aplicar_fmc.py").read_text())

    def test_avisos_de_reglas_any_y_de_muchos_objetos(self):
        _rc, o, _e = self.exportar(extra=["--incluir-revisar"])
        self.assertIn("0.0.0.0/0", o)
        muchos = [[f"H{i}", "host", f"10.1.{i // 250}.{i % 250 + 1}", ""] for i in range(51)]
        reglas = [["1", "r1", "permitir", "", "A", "B", ";".join(m[0] for m in muchos), "H_a", "S_tcp_443", ""]]
        _rc, o, _e = self.exportar(reglas=reglas, objetos=OBJETOS + muchos)
        self.assertIn("51 objetos en origen", o)

    def test_archivos_y_leeme(self):
        self.exportar()
        for a in ("fmc_objetos.json", "fmc_reglas.json", "aplicar_fmc.py", "LEEME_FMC.txt"):
            self.assertTrue((self.out / a).exists(), a)
        leeme = (self.out / "LEEME_FMC.txt").read_text()
        self.assertIn("solo cubre lo observado", leeme)
        self.assertIn("ventana de cambio", leeme)


class ValidacionTest(Base):
    def _falla(self, texto, **kw):
        rc, _o, e = self.exportar(**kw)
        self.assertEqual(rc, 2)
        self.assertIn(texto, e)
        self.assertFalse((self.out / "fmc_reglas.json").exists())      # nada se escribe

    def test_objeto_inexistente(self):
        reglas = [["1", "r1", "permitir", "", "A", "B", "H_borrado", "H_b", "S_tcp_443", ""]]
        self._falla("'H_borrado' no esta en el archivo de objetos", reglas=reglas)

    def test_nombre_invalido(self):
        reglas = [["1", "regla con espacios", "permitir", "", "A", "B", "H_a", "H_b", "S_tcp_443", ""]]
        self._falla("nombre de regla no valido", reglas=reglas)
        obj = [["H a", "host", "10.0.0.1", ""]] + OBJETOS[1:]
        reglas = [["1", "r1", "permitir", "", "A", "B", "H a", "H_b", "S_tcp_443", ""]]
        self._falla("nombre de objeto no valido", reglas=reglas, objetos=obj)

    def test_nombre_largo_y_repetido(self):
        reglas = [["1", "r" * 65, "permitir", "", "A", "B", "H_a", "H_b", "S_tcp_443", ""]]
        self._falla("nombre de regla no valido", reglas=reglas)
        dup = [["1", "r1", "permitir", "", "A", "B", "H_a", "H_b", "S_tcp_443", ""]] * 2
        self._falla("regla repetida", reglas=dup)
        self._falla("objeto repetido", objetos=OBJETOS + [OBJETOS[0]])

    def test_valores_mal_formados(self):
        for obj, texto in ((["H_a", "host", "10.0.0.999", ""], "valor de host no valido"),
                           (["N_x", "red", "10.0.2.5/24", ""], "valor de red no valido"),
                           (["S_tcp_443", "servicio", "tcp/70000", ""], "servicio no exportable"),
                           (["S_tcp_443", "servicio", "icmp", ""], "servicio no exportable")):
            objetos = [o for o in OBJETOS if o[0] != obj[0]] + [obj]
            self._falla(texto, objetos=objetos)

    def test_zona_vacia(self):
        reglas = [["1", "r1", "permitir", "", "", "B", "H_a", "H_b", "S_tcp_443", ""]]
        self._falla("zona de seguridad vacia", reglas=reglas)

    def test_lado_de_clase_equivocada(self):
        reglas = [["1", "r1", "permitir", "", "A", "B", "S_tcp_443", "H_b", "H_a", ""]]
        self._falla("no sirve en", reglas=reglas)

    def test_columna_faltante(self):
        _csv(self.dir / "p.csv", ["orden", "nombre"], [])
        _csv(self.dir / "o.csv", OBJ, OBJETOS)
        with contextlib.redirect_stderr(io.StringIO()):
            rc = cli_politica.main(["--propuesta", str(self.dir / "p.csv"), "--objetos", str(self.dir / "o.csv"),
                                    "-o", str(self.out)])
        self.assertEqual(rc, 2)


class FalsoFmc:
    """Peticion falsa de FMC: registra las llamadas y responde lo minimo."""

    def __init__(self, zonas=("ZIN", "ZOUT"), objetos=None, politicas=(), limitar=0):
        self.zonas = list(zonas)
        self.objetos = objetos or {}
        self.politicas = list(politicas)
        self.limitar = limitar
        self.llamadas = []
        self.cuerpos = []
        self.cabeceras = []
        self.n = 0

    def __call__(self, metodo, url, cab, cuerpo):
        ruta = url.split("fmc.test", 1)[1]
        self.llamadas.append((metodo, ruta))
        self.cabeceras.append(cab)
        datos = json.loads(cuerpo.decode()) if cuerpo else None
        self.cuerpos.append((ruta, datos))
        if self.limitar and metodo == "GET":
            self.limitar -= 1
            return 429, {"Retry-After": "7"}, b""
        if ruta.endswith("generatetoken"):
            return 204, {"X-auth-access-token": "TOKEN-123", "DOMAIN_UUID": "DOM"}, b""
        assert cab.get("X-auth-access-token") == "TOKEN-123"
        ruta = ruta.split("?")[0]
        if metodo == "GET":
            if ruta.endswith("/securityzones"):
                items = [{"id": "z-" + z, "name": z} for z in self.zonas]
            elif ruta.endswith("/accesspolicies"):
                items = [{"id": "p-" + p, "name": p} for p in self.politicas]
            else:
                items = self.objetos.get(ruta.rsplit("/", 1)[1], [])
            return 200, {}, json.dumps({"items": items}).encode()
        if ruta.endswith("/accesspolicies"):
            return 201, {}, json.dumps({"id": "POL1", "name": datos["name"]}).encode()
        items = []
        for o in datos:
            self.n += 1
            items.append({"id": f"id{self.n}", "name": o["name"], "type": o.get("type")})
        return 201, {}, json.dumps({"items": items}).encode()

    def posts(self, sin_token=True):
        return [c for c in self.llamadas if c[0] == "POST" and not (sin_token and c[1].endswith("generatetoken"))]


def _cargar_script(ruta):
    spec = importlib.util.spec_from_file_location("aplicar_fmc_generado", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ScriptTest(Base):
    def setUp(self):
        super().setUp()
        self.exportar(extra=["--incluir-revisar"])
        self.mod = _cargar_script(self.out / "aplicar_fmc.py")
        self.mod.SECRETOS.clear()

    def correr(self, falso, *args, conf="SI"):
        sal, preguntas = io.StringIO(), []
        respuestas = {"URL": "https://fmc.test", "Usuario": "admin"}

        def entrada(p):
            preguntas.append(p)
            return conf if p.startswith("Escriba") else respuestas[p.split()[0].rstrip(":")]
        with contextlib.redirect_stdout(sal):
            rc = self.mod.main(["--carpeta", str(self.out), *args], peticion=falso, entrada=entrada,
                               clave=lambda p: CLAVE, dormir=falso.dormidas.append if hasattr(falso, "dormidas")
                               else (lambda s: None))
        return rc, sal.getvalue(), preguntas

    def test_simular_no_hace_post_salvo_el_token(self):
        f = FalsoFmc()
        rc, o, _p = self.correr(f)
        self.assertEqual(rc, 0)
        self.assertEqual(f.posts(), [])
        self.assertEqual([c for c in f.llamadas if c[0] != "GET"], [("POST", "/api/fmc_platform/v1/auth/generatetoken")])
        self.assertIn("SIMULACION", o)
        self.assertRegex(o, r"hosts\s+existentes 0, a crear 2")

    def test_aplicar_sin_confirmar_no_hace_post(self):
        f = FalsoFmc()
        rc, o, _p = self.correr(f, "--aplicar", conf="no")
        self.assertEqual(rc, 0)
        self.assertEqual(f.posts(), [])
        self.assertIn("Cancelado", o)

    def test_aplicar_con_confirmacion_crea_objetos_politica_y_reglas(self):
        f = FalsoFmc()
        rc, o, _p = self.correr(f, "--aplicar")
        self.assertEqual(rc, 0, o)
        rutas = [r for _m, r in f.posts()]
        self.assertTrue(all("bulk=true" in r or r.endswith("/accesspolicies") for r in rutas), rutas)
        # objetos antes que la politica y esta antes que las reglas; grupos despues de sus miembros
        i_pol = next(i for i, r in enumerate(rutas) if r.endswith("/accesspolicies"))
        self.assertTrue(all("/object/" in r for r in rutas[:i_pol]))
        self.assertIn("/policy/accesspolicies/POL1/accessrules?bulk=true", rutas[-1])
        self.assertLess([r.split("/")[-1].split("?")[0] for r in rutas].index("hosts"),
                        [r.split("/")[-1].split("?")[0] for r in rutas].index("networkgroups"))
        pol = dict(f.cuerpos)["/api/fmc_config/v1/domain/DOM/policy/accesspolicies"]
        self.assertEqual(pol["defaultAction"]["action"], "BLOCK")
        self.assertTrue(pol["defaultAction"]["logBegin"])
        self.assertRegex(pol["name"], r"^PROPUESTA_FW1_\d{8}$")
        reglas = f.cuerpos[-1][1]
        self.assertEqual(len(reglas), 2)
        self.assertEqual(reglas[0]["sourceNetworks"]["objects"][0]["id"].startswith("id"), True)
        self.assertEqual(reglas[0]["sourceZones"]["objects"][0], {"id": "z-ZIN", "type": "SecurityZone", "name": "ZIN"})
        self.assertEqual(reglas[0]["destinationPorts"]["objects"][0]["type"], "PortObjectGroup")
        self.assertIs(reglas[1]["enabled"], False)
        grupo = next(d for r, d in f.cuerpos if r.endswith("networkgroups?bulk=true"))
        self.assertTrue(all(m["id"].startswith("id") for m in grupo[0]["objects"]))

    def test_solo_crea_lo_que_falta(self):
        f = FalsoFmc(objetos={"hosts": [{"id": "h1", "name": "H_a", "value": "10.0.0.1"}]})
        self.correr(f, "--aplicar")
        hosts = next(d for r, d in f.cuerpos if r.endswith("/hosts?bulk=true"))
        self.assertEqual([h["name"] for h in hosts], ["H_b"])
        grupo = next(d for r, d in f.cuerpos if r.endswith("networkgroups?bulk=true"))
        self.assertEqual(grupo[0]["objects"][0]["id"], "h1")

    def test_mismo_nombre_con_otro_valor_detiene(self):
        f = FalsoFmc(objetos={"hosts": [{"id": "h1", "name": "H_a", "value": "9.9.9.9"}]})
        rc, o, _p = self.correr(f, "--aplicar")
        self.assertEqual(rc, 1)
        self.assertIn("H_a", o)
        self.assertEqual(f.posts(), [])

    def test_falta_una_zona_detiene_y_las_lista(self):
        f = FalsoFmc(zonas=["ZIN"])
        rc, o, _p = self.correr(f, "--aplicar")
        self.assertEqual(rc, 1)
        self.assertIn("ZOUT", o)
        self.assertEqual(f.posts(), [])

    def test_politica_existente_detiene(self):
        f = FalsoFmc(politicas=["MIPOL"])
        rc, o, _p = self.correr(f, "--aplicar", "--politica", "MIPOL")
        self.assertEqual(rc, 1)
        self.assertIn("MIPOL", o)
        self.assertEqual(f.posts(), [])

    def test_reglas_en_lotes_de_mil(self):
        reglas = json.loads((self.out / "fmc_reglas.json").read_text())
        grande = [dict(reglas[0], name=f"r{i}") for i in range(1001)]
        (self.out / "fmc_reglas.json").write_text(json.dumps(grande))
        f = FalsoFmc()
        self.correr(f, "--aplicar")
        lotes = [d for r, d in f.cuerpos if "accessrules" in r]
        self.assertEqual([len(x) for x in lotes], [1000, 1])

    def test_nunca_delete_ni_put(self):
        f = FalsoFmc()
        self.correr(f, "--aplicar")
        self.assertEqual({m for m, _r in f.llamadas}, {"GET", "POST"})
        with self.assertRaises(self.mod.ErrorApi):
            self.mod.Cliente("https://x", f, self.out / "l.log").llamar("PUT", "/x")
        with self.assertRaises(self.mod.ErrorApi):
            self.mod.Cliente("https://x", f, self.out / "l.log").llamar("DELETE", "/x")

    def test_la_contrasena_no_aparece_en_salida_ni_log(self):
        f = FalsoFmc(zonas=[])
        _rc, o, _p = self.correr(f, "--aplicar")
        f2 = FalsoFmc()
        _rc, o2, _p = self.correr(f2, "--aplicar")
        log = (self.out / "aplicar_fmc.log").read_text()
        for texto in (o, o2, log):
            self.assertNotIn(CLAVE, texto)
            self.assertNotIn("TOKEN-123", texto)
        self.assertIn("generatetoken 204", log)
        self.assertNotIn("Authorization", log)
        # la contrasena solo viaja en la cabecera Basic del token
        con_clave = [c for c in f2.cabeceras if any(CLAVE in str(v) for v in c.values())]
        self.assertEqual(len(con_clave), 0)       # va codificada en base64, no en claro
        self.assertTrue(f2.cabeceras[0]["Authorization"].startswith("Basic "))

    def test_un_error_de_api_no_filtra_la_contrasena(self):
        def malo(metodo, url, cab, cuerpo):
            if url.endswith("generatetoken"):
                return 204, {"X-auth-access-token": "T", "DOMAIN_UUID": "D"}, b""
            return 500, {}, json.dumps({"error": "fallo con " + CLAVE}).encode()
        malo.dormidas = []
        rc, o, _p = self.correr(malo)
        self.assertEqual(rc, 1)
        self.assertNotIn(CLAVE, o)
        self.assertNotIn(CLAVE, (self.out / "aplicar_fmc.log").read_text())

    def test_429_con_retry_after_reintenta(self):
        f = FalsoFmc(limitar=1)
        f.dormidas = []
        rc, _o, _p = self.correr(f)
        self.assertEqual(rc, 0)
        self.assertEqual(f.dormidas, [7.0])
        gets = [r for m, r in f.llamadas if m == "GET"]
        self.assertEqual(gets[0], gets[1])        # la misma peticion se repite

    def test_limite_de_120_llamadas_por_minuto(self):
        dormidas, t = [], [0.0]
        cli = self.mod.Cliente("https://fmc.test", lambda *a: (200, {}, b"{}"), self.out / "l.log",
                               dormir=dormidas.append, reloj=lambda: t[0])
        for _ in range(121):
            cli.llamar("GET", "/x")
        self.assertEqual(len(dormidas), 1)
        self.assertGreater(dormidas[0], 0)

    def test_url_sin_https_y_modo_inseguro(self):
        f = FalsoFmc()
        sal = io.StringIO()
        with contextlib.redirect_stdout(sal):
            rc = self.mod.main(["--carpeta", str(self.out), "--url", "http://fmc.test"], peticion=f,
                               entrada=lambda p: "admin", clave=lambda p: CLAVE)
        self.assertEqual(rc, 2)
        self.assertEqual(f.llamadas, [])
        _rc, o, _p = self.correr(FalsoFmc(), "--inseguro")
        self.assertIn("ADVERTENCIA", o)

    def test_el_script_no_acepta_credenciales_por_argumento(self):
        src = (self.out / "aplicar_fmc.py").read_text()
        self.assertNotRegex(src, r"add_argument\(\"--(usuario|user|clave|password|contrasena)")
        self.assertIsNone(re.search(r"\bDELETE\b|\"PUT\"", src.replace("DELETE ni PUT", "")))
        compile(src, "aplicar_fmc.py", "exec")


if __name__ == "__main__":
    unittest.main()


class ServicioCualquieraTest(unittest.TestCase):
    """M3a produce S_IP (valor 'ip') para conductos sin puerto: en FMC es una regla sin destinationPorts."""

    def test_regla_con_servicio_ip_sale_sin_puertos(self):
        import tempfile

        from ot_assess.firewalls import fmc
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            prop = d / "p.csv"
            obj = d / "o.csv"
            prop.write_text("orden,nombre,decision,razones,zona_entrada,zona_salida,interfaces,origen,destino,servicios,"
                            "conductos,origenes,destinos,bytes,dias,fuentes,reglas_actuales,justificacion\n"
                            "1,r1,permitir,,A,B,,H_a,H_b,S_IP,1,1,1,0,2,,,x\n", encoding="utf-8")
            obj.write_text("nombre,tipo,valor,miembros\nH_a,host,10.0.0.1,\nH_b,host,10.0.0.2,\nS_IP,servicio,ip,\n",
                           encoding="utf-8")
            res = fmc.exportar(prop, obj, d / "out") if hasattr(fmc, "exportar") else None
            out = d / "out"
            if res is None:
                from ot_assess import cli_politica
                cli_politica.main(["--propuesta", str(prop), "--objetos", str(obj), "-o", str(out)])
            reglas = json.loads((out / "fmc_reglas.json").read_text())
            reglas = reglas.get("reglas", reglas) if isinstance(reglas, dict) else reglas
            self.assertEqual(reglas[0]["destinationPorts"], [])
            objetos = json.loads((out / "fmc_objetos.json").read_text())
            self.assertNotIn("S_IP", json.dumps(objetos))
