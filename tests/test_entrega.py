"""B6: paquete de entrega con manifiesto y verificacion (D64)."""
import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ot_assess import (
    anonimizar,
    cli_entrega,
)
from ot_assess import entrega as ent

try:
    import scapy  # noqa: F401
    HAY_SCAPY = True
except ImportError:
    HAY_SCAPY = False

FECHA = "2026-11-05T12:00:00Z"


def correr(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli_entrega.main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def salida(self, nombre="corrida", extra=True):
        d = self.tmp / "origen" / nombre
        d.mkdir(parents=True)
        res = {"entorno": {"ot_assess": "9.9.9", "capturas": [{"archivo": "a.pcap", "sha256": "ab" * 32}],
                           "perfil": {"archivo": "perfil.json", "sha256": "cd" * 32}},
               "perfil": {"cliente": "ACME", "sitio": "Planta 1"}}
        (d / "resultado.json").write_text(json.dumps(res), encoding="utf-8")
        (d / "inventario.csv").write_text("equipo,ips\nplc,10.0.0.1\n", encoding="utf-8")
        if extra:
            (d / "reporte.md").write_text(f"Origen: {d}\n", encoding="utf-8")
        return d


class ManifiestoTest(Base):
    def test_manifiesto_y_sumas(self):
        d = self.salida()
        out = self.tmp / "ent"
        rc, so, _ = correr(str(d), "-o", str(out), "--titulo", "Prueba")
        self.assertEqual(rc, 0, so)
        man = json.loads((out / "manifiesto.json").read_text(encoding="utf-8"))
        self.assertEqual(man["formato"], "ot_assess.entrega/1")
        self.assertTrue(man["herramienta"]["version"])
        self.assertEqual((man["titulo"], man["cliente"], man["sitio"]), ("Prueba", "ACME", "Planta 1"))
        c = man["carpetas"][0]
        self.assertEqual((c["carpeta"], c["tipo"], c["version_herramienta"]), ("corrida", "capturas", "9.9.9"))
        self.assertIn({"rol": "captura", "archivo": "a.pcap", "sha256": "ab" * 32}, c["entradas"])
        self.assertTrue(man["empaquetado_utc"].endswith("Z"))
        rutas = {s["ruta"] for s in c["salidas"]}
        self.assertEqual(rutas, {"corrida/resultado.json", "corrida/inventario.csv", "corrida/reporte.md"})
        for s in c["salidas"]:
            self.assertEqual(s["sha256"], sha(out / s["ruta"]))
            self.assertEqual(s["tamano"], (out / s["ruta"]).stat().st_size)
        # manifiesto.sha256 en formato sha256sum, incluye el manifiesto
        lineas = (out / "manifiesto.sha256").read_text(encoding="utf-8").splitlines()
        tabla = {}
        for ln in lineas:
            h, r = ln.split("  ", 1)
            tabla[r] = h
        self.assertIn("manifiesto.json", tabla)
        self.assertNotIn("manifiesto.sha256", tabla)
        for r, h in tabla.items():
            self.assertEqual(sha(out / r), h, r)
        if shutil.which("sha256sum"):
            p = subprocess.run(["sha256sum", "-c", "manifiesto.sha256"], cwd=str(out),
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("sha256sum -c manifiesto.sha256", (out / "LEEME_ENTREGA.txt").read_text(encoding="utf-8"))

    def test_permisos(self):
        d = self.salida()
        out = self.tmp / "ent"
        os.umask(0o022)
        try:
            self.assertEqual(correr(str(d), "-o", str(out))[0], 0)
        finally:
            os.umask(0o022)
        self.assertEqual(stat.S_IMODE((out / "manifiesto.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((out / "corrida").stat().st_mode), 0o700)

    def test_sin_ruta_absoluta(self):
        d = self.salida()
        (d / "comparacion.json").write_text(json.dumps(
            {"antes": str(d / "x"), "despues": str(d / "y"), "umbral_volumen": 10, "avisos": [], "resumen": {},
             "meta": {}}), encoding="utf-8")
        out = self.tmp / "ent"
        rc, so, _ = correr(str(d), "-o", str(out))
        self.assertEqual(rc, 0)
        for r in (out).rglob("*"):
            if r.is_file():
                t = r.read_text(encoding="utf-8")
                self.assertNotIn(str(self.tmp), t, r.name)
        for ln in so.splitlines():      # el destino lo escribio el analista; los avisos no deben traer rutas
            if ln.startswith("[!]"):
                self.assertNotIn(str(self.tmp), ln)
        cj = json.loads((out / "corrida" / "comparacion.json").read_text(encoding="utf-8"))
        self.assertEqual((cj["antes"], cj["despues"]), ("x", "y"))

    def test_mismo_nombre_no_choca(self):
        a = self.salida("salida")
        b = self.tmp / "otro" / "salida"
        b.mkdir(parents=True)
        (b / "x.csv").write_text("a\n", encoding="utf-8")
        out = self.tmp / "ent"
        self.assertEqual(correr(str(a), str(b), "-o", str(out))[0], 0)
        self.assertTrue((out / "salida" / "inventario.csv").is_file())
        self.assertTrue((out / "salida_2" / "x.csv").is_file())
        self.assertEqual(correr("--verificar", str(out))[0], 0)

    def test_no_pisa_entrega_existente(self):
        d = self.salida()
        out = self.tmp / "ent"
        out.mkdir()
        (out / "algo").write_text("x", encoding="utf-8")
        self.assertEqual(correr(str(d), "-o", str(out))[0], 2)


class ExcluidosTest(Base):
    def test_exclusiones_obligatorias(self):
        d = self.salida()
        (d / "aplicar_fmc.log").write_text("log\n", encoding="utf-8")
        (d / "crudo").mkdir()
        (d / "crudo" / "api.json").write_text("{}", encoding="utf-8")
        (d / ".oculto").write_text("x", encoding="utf-8")
        (self.tmp / "secreto.txt").write_text("secreto", encoding="utf-8")
        os.symlink(self.tmp / "secreto.txt", d / "enlace.txt")
        # cache de E6 (cabecera de cache_capturas) en una carpeta cualquiera y fuera de ella
        cache = d / "mi_cache"
        cache.mkdir()
        with gzip.open(cache / ("0" * 64 + ".json.gz"), "wb") as fh:
            fh.write(json.dumps({"formato": 1, "clave": "{}", "captura": {}}).encode())
        with gzip.open(d / ("1" * 64 + ".json.gz"), "wb") as fh:
            fh.write(json.dumps({"formato": 1, "clave": "{}", "captura": {}}).encode())
        # un .json.gz que no es cache se queda
        with gzip.open(d / "datos.json.gz", "wb") as fh:
            fh.write(b'{"otra": 1}')
        # anonimizacion real: mapa y lista de terminos (con otro nombre)
        mapa = anonimizar.Mapa(d / "m.json")
        mapa.agregar_termino("ACME")
        mapa.ip("10.1.2.3")
        mapa.guardar()
        (d / "lista.txt").write_text("# terminos\nACME\n", encoding="utf-8")
        (d / "notas.txt").write_text("texto de entrega\n", encoding="utf-8")
        out = self.tmp / "ent"
        rc, so, _ = correr(str(d), "-o", str(out), "--cache", str(cache), "--excluir", "*.tmp")
        self.assertEqual(rc, 0, so)
        presentes = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
        self.assertEqual(presentes - {"manifiesto.json", "manifiesto.sha256", "LEEME_ENTREGA.txt"},
                         {"corrida/resultado.json", "corrida/inventario.csv", "corrida/reporte.md",
                          "corrida/datos.json.gz", "corrida/notas.txt"})
        for motivo in ("enlace simbolico", "registro", "crudos", "oculto", "cache de lectura", "carpeta de cache",
                       "mapa de anonimizacion", "terminos de anonimizacion"):
            self.assertIn(motivo, so)
        self.assertNotIn("ACME\n", (out / "manifiesto.json").read_text(encoding="utf-8").replace("ACME\"", ""))

    def test_excluir_patron(self):
        d = self.salida()
        (d / "borrador.csv").write_text("x\n", encoding="utf-8")
        out = self.tmp / "ent"
        self.assertEqual(correr(str(d), "-o", str(out), "--excluir", "borrador*")[0], 0)
        self.assertFalse((out / "corrida" / "borrador.csv").exists())


class VerificarTest(Base):
    def paquete(self):
        d = self.salida()
        out = self.tmp / "ent"
        self.assertEqual(correr(str(d), "-o", str(out))[0], 0)
        return out

    def test_ok(self):
        out = self.paquete()
        rc, so, _ = correr("--verificar", str(out))
        self.assertEqual(rc, 0, so)

    def test_modificado_faltante_sobrante(self):
        out = self.paquete()
        (out / "corrida" / "inventario.csv").write_text("cambiado\n", encoding="utf-8")
        rc, so, _ = correr("--verificar", str(out))
        self.assertEqual(rc, 1)
        self.assertIn("MODIFICADO: corrida/inventario.csv", so)
        (out / "corrida" / "reporte.md").unlink()
        (out / "extra.txt").write_text("x", encoding="utf-8")
        rc, so, _ = correr("--verificar", str(out))
        self.assertEqual(rc, 1)
        self.assertIn("FALTANTE: corrida/reporte.md", so)
        self.assertIn("SOBRANTE: extra.txt", so)

    def test_manifiesto_editado_no_pasa(self):
        out = self.paquete()
        mj = out / "manifiesto.json"
        mj.write_text(mj.read_text(encoding="utf-8").replace("Planta 1", "Planta 2"), encoding="utf-8")
        rc, so, _ = correr("--verificar", str(out))
        self.assertEqual(rc, 1)
        self.assertIn("MODIFICADO: manifiesto.json", so)

    def test_no_es_paquete(self):
        rc, _, err = correr("--verificar", str(self.tmp))
        self.assertEqual(rc, 2)
        rc, _, err = correr("--verificar", str(self.tmp / "no_existe"))
        self.assertEqual(rc, 2)


class ZipTest(Base):
    def test_zip_determinista_y_verificable(self):
        d = self.salida()
        a, b = self.tmp / "a", self.tmp / "b"
        with mock.patch.object(ent, "ahora_utc", return_value=FECHA):
            self.assertEqual(correr(str(d), "-o", str(a), "--zip")[0], 0)
            self.assertEqual(correr(str(d), "-o", str(b), "--zip")[0], 0)
        za, zb = self.tmp / "a.zip", self.tmp / "b.zip"
        self.assertEqual(za.read_bytes(), zb.read_bytes())
        with zipfile.ZipFile(za) as z:
            nombres = [i.filename for i in z.infolist()]
            self.assertEqual(nombres, sorted(nombres))
            self.assertTrue(all(i.date_time[:3] == (2026, 11, 5) for i in z.infolist()))
            self.assertTrue(all(not n.startswith("/") and ".." not in n for n in nombres))
            self.assertNotIn(str(self.tmp), z.read("corrida/reporte.md").decode())
        rc, so, _ = correr("--verificar", str(za))
        self.assertEqual(rc, 0, so)

    def test_zip_modificado(self):
        d = self.salida()
        with mock.patch.object(ent, "ahora_utc", return_value=FECHA):
            correr(str(d), "-o", str(self.tmp / "a"), "--zip")
        z = self.tmp / "a.zip"
        mal = self.tmp / "mal.zip"
        with zipfile.ZipFile(z) as zi, zipfile.ZipFile(mal, "w") as zo:
            for i in zi.infolist():
                datos = zi.read(i.filename)
                if i.filename == "corrida/inventario.csv":
                    datos = b"cambiado\n"
                zo.writestr(i.filename, datos)
        rc, so, _ = correr("--verificar", str(mal))
        self.assertEqual(rc, 1)
        self.assertIn("MODIFICADO: corrida/inventario.csv", so)

    def test_zip_con_ruta_peligrosa(self):
        for nombre in ("../x", "/abs/x", "a/../../x"):
            z = self.tmp / "peligro.zip"
            with zipfile.ZipFile(z, "w") as zo:
                zo.writestr("manifiesto.json", "{}")
                zo.writestr("manifiesto.sha256", "")
                zo.writestr(nombre, "x")
            rc, _, err = correr("--verificar", str(z))
            self.assertEqual(rc, 2, nombre)
            self.assertIn("ruta no permitida", err)
            z.unlink()


@unittest.skipUnless(shutil.which("tshark") and HAY_SCAPY, "requiere tshark y scapy")
class CorridaRealTest(Base):
    def test_corrida_real_empaquetada(self):
        import gen_pcaps

        from ot_assess.cli import main
        pc = self.tmp / "pcaps"
        pc.mkdir()
        gen_pcaps.guardar(gen_pcaps.punto_a(), pc / "c.pcap")
        corrida = self.tmp / "corrida_real"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(pc), "-o", str(corrida)]), 0)
        out = self.tmp / "ent"
        rc, so, _ = correr(str(corrida), "-o", str(out))
        self.assertEqual(rc, 0, so)
        man = json.loads((out / "manifiesto.json").read_text(encoding="utf-8"))
        c = man["carpetas"][0]
        self.assertEqual(c["tipo"], "capturas")
        self.assertEqual(c["version_herramienta"], man["herramienta"]["version"])
        self.assertEqual([e["archivo"] for e in c["entradas"] if e["rol"] == "captura"], ["c.pcap"])
        self.assertEqual(c["entradas"][0]["sha256"], sha(pc / "c.pcap"))
        self.assertGreater(len(c["salidas"]), 3)
        for s in c["salidas"]:
            self.assertEqual(s["sha256"], sha(out / s["ruta"]))
        self.assertFalse(list(out.rglob("*.pcap")))
        for p in out.rglob("*"):
            if p.is_file():
                self.assertNotIn(str(self.tmp), p.read_text(encoding="utf-8", errors="replace"), p.name)
        self.assertEqual(correr("--verificar", str(out))[0], 0)


if __name__ == "__main__":
    unittest.main()
