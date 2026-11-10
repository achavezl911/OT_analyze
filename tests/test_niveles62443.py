"""Catalogo de niveles de seguridad de ISA/IEC 62443 (D75). No lee normas/: solo el JSON versionado."""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess import niveles62443 as nv
from ot_assess import standards as st

D = nv.cargar()
MAX_TITULO = 12


def clave(i):
    return [int(x) for x in re.findall(r"\d+", i)]


def cuenta(s):
    return len(s.split())


class TestSR(unittest.TestCase):
    def test_7_fr_y_51_sr(self):
        self.assertEqual(sorted(D["fr"]), ["FR%d" % i for i in range(1, 8)])
        self.assertEqual(len(D["sr"]), 51)
        for ident, sr in D["sr"].items():
            self.assertIn(sr["fr"], D["fr"], ident)
            self.assertEqual(sr["fr"], "FR" + ident.split()[1].split(".")[0], ident)

    def test_listas_por_nivel(self):
        """Cada SR tiene SL 1-4; toda lista no vacia lleva la SR base; son acumulativas."""
        for ident, sr in D["sr"].items():
            self.assertEqual(sorted(sr["sl"]), ["1", "2", "3", "4"], ident)
            previo = set()
            for n in nv.NIVELES:
                lista = sr["sl"][n]
                if lista:
                    self.assertIn(ident, lista, "%s SL %s sin la SR base" % (ident, n))
                self.assertTrue(previo <= set(lista), "%s SL %s no acumula el nivel anterior" % (ident, n))
                self.assertEqual(len(lista), len(set(lista)), ident)
                previo = set(lista)
            # Los niveles 'Not selected' forman un prefijo (SL 1..k): sl_minimo lo refleja.
            self.assertEqual(sr["sl_minimo"], min(int(n) for n in nv.NIVELES if sr["sl"][n]), ident)
            self.assertTrue(sr["sl"]["4"], ident)

    def test_sr_con_sl_minimo_mayor_a_1(self):
        """Excepcion del texto (D75): estas SR no se exigen en SL 1."""
        sin_sl1 = sorted((i for i, s in D["sr"].items() if s["sl_minimo"] > 1), key=clave)
        self.assertEqual(sin_sl1, ["SR 1.2", "SR 1.8", "SR 1.9", "SR 2.6", "SR 2.7", "SR 2.11", "SR 2.12",
                                   "SR 3.4", "SR 3.7", "SR 3.8", "SR 3.9", "SR 4.2", "SR 6.2", "SR 7.8"])
        self.assertEqual(D["sr"]["SR 2.7"]["sl_minimo"], 3)
        self.assertEqual(D["sr"]["SR 2.12"]["sl_minimo"], 3)

    def test_valores_conocidos(self):
        self.assertEqual(nv.requisitos_sl("SR 1.1", 1), ["SR 1.1"])
        self.assertEqual(nv.requisitos_sl("SR 1.1", 4),
                         ["SR 1.1", "SR 1.1 RE 1", "SR 1.1 RE 2", "SR 1.1 RE 3"])
        self.assertEqual(nv.requisitos_sl("SR 5.2", 2), ["SR 5.2", "SR 5.2 RE 1"])
        self.assertEqual(nv.requisitos_sl("SR 5.2", 3), ["SR 5.2", "SR 5.2 RE 1", "SR 5.2 RE 2", "SR 5.2 RE 3"])
        self.assertEqual(nv.requisitos_sl("SR 1.2", 1), [])


class TestRE(unittest.TestCase):
    def _comprobar(self, requisitos, res):
        citados = set()
        for ident, r in requisitos.items():
            for n in nv.NIVELES:
                for x in r.get("sl", {}).get(n, []):
                    if " RE " in x:
                        citados.add(x)
                        self.assertIn(x, res, "%s cita un RE que no esta en el catalogo" % ident)
                        self.assertEqual(res[x]["requisito"], ident, "RE %s citado en %s" % (x, ident))
                        self.assertTrue(x.startswith(ident + " RE "), x)
            propios = {x for x in res if res[x]["requisito"] == ident}
            self.assertEqual(sorted(propios, key=clave), r.get("re", []), ident)
        self.assertEqual(citados, set(res))
        for x, r in res.items():
            self.assertEqual(r["sl_minimo"], min(
                int(n) for n in nv.NIVELES if x in requisitos[r["requisito"]]["sl"][n]), x)

    def test_re_de_la_33(self):
        self._comprobar(D["sr"], D["re_sr"])
        self.assertEqual(len(D["re_sr"]), 49)

    def test_re_de_la_42(self):
        self._comprobar({k: v for k, v in D["componente"].items() if v["clase"] == "propio"},
                        D["re_componente"])
        self.assertEqual(len(D["re_componente"]), 49)


class TestComponentes(unittest.TestCase):
    def test_estructura_4_2(self):
        c = D["componente"]
        self.assertEqual(len(c), 87)
        tipos = {}
        for r in c.values():
            tipos[r["tipo"]] = tipos.get(r["tipo"], 0) + 1
        self.assertEqual(tipos, {"CR": 57, "SAR": 2, "EDR": 8, "HDR": 8, "NDR": 12})
        for ident, r in c.items():
            self.assertTrue(ident.startswith(r["tipo"] + " "), ident)
            if r["clase"] == "propio":
                previo = set()
                for n in nv.NIVELES:
                    lista = r["sl"][n]
                    if lista:
                        self.assertIn(ident, lista, ident)
                    self.assertTrue(previo <= set(lista), "%s SL %s" % (ident, n))
                    previo = set(lista)
            else:
                self.assertNotIn("sl", r, ident)
        self.assertEqual(sorted(i for i, r in c.items() if r["clase"] == "sin_requisito_de_componente"),
                         ["CR 2.3", "CR 5.4"])
        self.assertEqual(c["CR 5.2"]["tipos"], ["NDR"])
        self.assertEqual(D["componente"]["NDR 5.2"]["sl"]["3"][-1], "NDR 5.2 RE 3")

    def test_errata_sl4_rotulado_como_sl3(self):
        """El texto de la 4-2 rotula dos veces 'SL 3' en seis requisitos; se tratan como SL 4 (D75)."""
        self.assertEqual(len(D["anomalias_del_texto"]), 6)
        for ident in ("EDR 2.13", "EDR 3.12", "HDR 2.13", "HDR 3.12", "NDR 2.13", "NDR 3.12"):
            self.assertTrue(D["componente"][ident]["sl"]["4"], ident)

    def test_contraste_con_tabla_b1(self):
        for doc, c in D["contraste_tabla_b1"].items():
            if isinstance(c, dict):
                self.assertEqual(c["diferencias"], [], doc)
                self.assertGreater(c["filas"], 90, doc)


class TestZCRyMadurez(unittest.TestCase):
    def test_zcr(self):
        for i in range(1, 8):
            self.assertIn("ZCR %d" % i, D["zcr"])
        self.assertEqual(len(D["zcr"]), 39)
        self.assertEqual(D["zcr"]["ZCR 5.6"]["padre"], "ZCR 5")
        self.assertIsNone(D["zcr"]["ZCR 5"]["padre"])
        self.assertEqual(D["zcr"]["ZCR 5.9"]["seccion"], "3-2 4.6.10")

    def test_madurez_y_spr(self):
        self.assertEqual(sorted(D["madurez"]), ["ML 1", "ML 2", "ML 3", "ML 4"])
        self.assertEqual(D["umbral_repetible"]["entre"], ["ML 2", "ML 3"])
        # El TR 2-2 define SPR-T, SPR-I y SPR-O; SPR-A del brief es SPR-O (logrado).
        self.assertEqual(sorted(D["spr"]), ["SPR-I", "SPR-O", "SPR-T"])
        self.assertEqual(D["spr"]["SPR-O"]["alias_del_brief"], "SPR-A")
        self.assertEqual(D["agregacion"]["regla"], "minimo")
        self.assertEqual(sorted(D["tipos_sl"]), ["SL-A", "SL-C", "SL-T"])
        self.assertEqual(sorted(D["niveles_sl"]), ["1", "2", "3", "4"])

    def test_documentos(self):
        docs = D["documentos"]
        self.assertEqual(sorted(docs), ["3-2", "3-3", "4-2", "tr2-2"])
        self.assertTrue(docs["3-3"]["vigente_anterior_2020"])
        self.assertTrue(docs["4-2"]["vigente_anterior_2020"])
        self.assertNotIn("vigente_anterior_2020", docs["3-2"])
        self.assertEqual(docs["3-2"]["anio"], 2020)
        self.assertEqual(docs["tr2-2"]["anio"], 2025)
        self.assertIn("ISA/IEC 62443-2-1:2024", [x["documento"] for x in D["documentos_no_usados"]])


def _titulos(obj, ruta=""):
    """Todos los dict {'es','en'} del catalogo con su ruta."""
    if isinstance(obj, dict):
        if set(obj) == {"es", "en"}:
            yield ruta, obj
        else:
            for k, v in obj.items():
                yield from _titulos(v, ruta + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _titulos(v, ruta + "/%d" % i)


class TestTitulos(unittest.TestCase):
    def test_titulos_cortos_y_bilingues(self):
        n = 0
        for ruta, t in _titulos(D):
            n += 1
            for idioma in ("es", "en"):
                self.assertTrue(t[idioma].strip(), ruta)
                tope = MAX_TITULO if "/descripcion" not in ruta and "/motivo" not in ruta \
                    and "/aviso" not in ruta and "/pendiente" not in ruta and "/tema" not in ruta else 25
                self.assertLessEqual(cuenta(t[idioma]), tope, "%s (%s): %r" % (ruta, idioma, t[idioma]))
        self.assertGreater(n, 250)

    def test_toda_entrada_tiene_titulo(self):
        for seccion in ("sr", "re_sr", "componente", "re_componente", "zcr", "madurez"):
            for ident, r in D[seccion].items():
                self.assertEqual(sorted(r["titulo"]), ["en", "es"], ident)
        for ident in D["fr"]:
            self.assertEqual(sorted(D["fr"][ident]["titulo"]), ["en", "es"])
        self.assertEqual(nv.titulo("SR 1.3"), "Gestion de cuentas")
        self.assertEqual(nv.titulo("SR 1.3", "en"), "Account management")
        self.assertEqual(nv.titulo("ZCR 3", "en"), "Partition the system into zones and conduits")

    def test_sin_veredicto_de_cumplimiento(self):
        texto = json.dumps(D, ensure_ascii=False).lower()
        for prohibido in ("shall", "no cumple", "cumple con", "complies", "compliant"):
            self.assertNotIn(prohibido, texto, prohibido)


class TestMarcos(unittest.TestCase):
    def test_sr_de_cobertura_son_las_del_catalogo(self):
        cob = json.loads((st.DIR_MARCOS / "cobertura" / "iec62443.json").read_text(encoding="utf-8"))
        ids = [r["id"] for r in cob["requisitos"]]
        self.assertEqual(sorted(ids, key=clave), sorted(D["sr"], key=clave))
        for r in cob["requisitos"]:
            self.assertEqual(r["texto"], D["sr"][r["id"]]["titulo"]["es"], r["id"])
            self.assertEqual(r["grupo"], D["sr"][r["id"]]["fr"], r["id"])

    def test_sr_citadas_en_el_marco_usan_el_nombre_del_catalogo(self):
        marco = st.ESTANDARES["iec62443"]
        vistas = set()
        for texto in marco.refs.values():
            for m in re.finditer(r"\bSR (\d+\.\d+) ([^;]+)", texto):
                ident = "SR " + m.group(1)
                self.assertIn(ident, D["sr"], texto)
                self.assertEqual(m.group(2).strip(), D["sr"][ident]["titulo"]["es"], texto)
                vistas.add(ident)
        self.assertGreaterEqual(len(vistas), 15)


if __name__ == "__main__":
    unittest.main()
