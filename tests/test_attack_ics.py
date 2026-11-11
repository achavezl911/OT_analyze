"""AT1 (D112): catalogo compacto de ATT&CK for ICS y generador desde el STIX oficial."""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

from ot_assess import attack_ics as ai

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
import actualizar_attack_ics as gen

ID = re.compile(r"T\d{4}(?:\.\d{3})?")
CITA = re.compile(r"(T\d{4}(?:\.\d{3})?)(?: ([A-Z][^;\"]*))?")
CENTINELA = "TEXTO_ATTACK_NO_SALE"


def _obj(tipo, oid, **kw):
    o = {"type": tipo, "id": oid, "description": CENTINELA}
    o.update(kw)
    return o


def _tec(oid, tid, nombre, **kw):
    return _obj("attack-pattern", oid, name=nombre, external_references=(
        [{"source_name": "mitre-attack", "external_id": tid}] if tid else []), **kw)


def _bundle():
    kc = [{"kill_chain_name": "mitre-ics-attack", "phase_name": "evasion"},
          {"kill_chain_name": "otra", "phase_name": "x"}]
    return {"type": "bundle", "objects": [
        _obj("x-mitre-collection", "c", name="ICS ATT&CK", x_mitre_version="9.9",
             modified="2030-01-02T03:04:05.000Z"),
        _obj("marking-definition", "m", definition_type="statement",
             definition={"statement": "Copyright 2015-2030, The MITRE Corporation."}),
        _obj("x-mitre-matrix", "mx", name="ATT&CK for ICS", tactic_refs=["t2", "t1"]),
        _obj("x-mitre-tactic", "t1", name="Evasion", x_mitre_shortname="evasion"),
        _obj("x-mitre-tactic", "t2", name="Initial Access", x_mitre_shortname="initial-access"),
        _tec("p1", "T1001", "Padre", kill_chain_phases=kc),
        _tec("p2", "T1001.001", "Hija", x_mitre_is_subtechnique=True, kill_chain_phases=kc),
        _tec("p3", "T0001", "Vieja", revoked=True),
        _obj("relationship", "r", relationship_type="revoked-by", source_ref="p3", target_ref="p1"),
        _tec("p4", "T0002", "Obsoleta", x_mitre_deprecated=True),
        _tec("p5", "", "Sin id", x_mitre_deprecated=True),
    ]}


class TestCatalogo(unittest.TestCase):
    def test_contenido(self):
        self.assertEqual(ai.version(), "20.1")
        cat = ai.cargar()
        self.assertEqual(len(cat["tacticas"]), 12)
        self.assertEqual(len(cat["tecnicas"]), 104)
        self.assertEqual(ai.reemplazo("T0855"), "T1692.001")
        self.assertFalse(ai.vigente("T0855"))
        self.assertTrue(ai.vigente("T1692.001"))
        self.assertEqual(ai.nombre("T1693.001"), "Modify Firmware: System Firmware")
        self.assertIn("Inhibit Response Function", ai.tacticas("T1693.001"))
        self.assertIn("Copyright", cat["aviso"])

    def _revisar(self, texto, origen):
        for m in CITA.finditer(texto):
            tid, nom = m.group(1), m.group(2)
            self.assertTrue(ai.vigente(tid),
                            f"{origen} cita {tid}, que no esta vigente (reemplazo: {ai.reemplazo(tid) or 'ninguno'})")
            if nom:
                self.assertEqual(nom.strip(), ai.nombre(tid), origen)

    def test_citas_vigentes(self):
        d = json.loads((RAIZ / "ot_assess" / "marcos" / "mitre-ics.json").read_text(encoding="utf-8"))
        for k, v in d["referencias"].items():
            self._revisar(v, "mitre-ics.json: " + k)
        self.assertIn(ai.version(), d["version_fuente"])
        n = 0
        for p in sorted((RAIZ / "ot_assess" / "playbooks").glob("*.json")):
            for r in json.loads(p.read_text(encoding="utf-8")).get("referencias", []):
                if r.startswith("MITRE ICS"):
                    n += 1
                    self.assertRegex(r, r"^MITRE ICS T\d{4}(\.\d{3})?$", p.name)
                    self._revisar(r, p.name)
        self.assertGreater(n, 20)
        src = (RAIZ / "ot_assess" / "ingenieria.py").read_text(encoding="utf-8")
        self.assertTrue(ID.search(src))
        self._revisar(src, "ingenieria.py")


class TestGenerador(unittest.TestCase):
    def test_bundle_sintetico(self):
        cat = gen.construir(_bundle(), "x.json")
        self.assertEqual(cat["version"], "9.9")
        self.assertEqual(cat["publicada"], "2030-01-02")
        self.assertEqual(cat["fuente"], "mitre-attack/attack-stix-data x.json")
        self.assertEqual(cat["tacticas"], [{"id": "initial-access", "nombre": "Initial Access"},
                                            {"id": "evasion", "nombre": "Evasion"}])
        self.assertEqual(cat["tecnicas"], {"T1001": {"nombre": "Padre", "tacticas": ["evasion"]},
                                           "T1001.001": {"nombre": "Padre: Hija", "tacticas": ["evasion"]}})
        self.assertEqual(cat["revocadas"], {"T0001": {"nombre": "Vieja", "por": "T1001"}})
        self.assertEqual(cat["obsoletas"], {"T0002": "Obsoleta"})
        self.assertTrue(cat["aviso"].startswith("Copyright 2015-2030, The MITRE Corporation."))
        self.assertIn("non-exclusive, royalty-free license", cat["aviso"])
        self.assertNotIn(CENTINELA, gen.serializar(cat))

    def test_check_y_errores(self):
        with tempfile.TemporaryDirectory() as td:
            ent, sal, mal = (os.path.join(td, n) for n in ("in.json", "out.json", "mal.json"))
            Path(ent).write_text(json.dumps(_bundle()), encoding="utf-8")
            Path(mal).write_text(json.dumps({"type": "bundle", "objects": [{"type": "x"}]}), encoding="utf-8")
            self.assertEqual(gen.main([ent, "--salida", sal, "--check"]), 1)
            self.assertEqual(gen.main([ent, "--salida", sal]), 0)
            self.assertEqual(gen.main([ent, "--salida", sal, "--check"]), 0)
            Path(sal).write_text("{}\n", encoding="utf-8")
            self.assertEqual(gen.main([ent, "--salida", sal, "--check"]), 1)
            with self.assertRaises(SystemExit) as cm:
                gen.main([mal, "--salida", sal])
            self.assertIn("ATT&CK for ICS", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
