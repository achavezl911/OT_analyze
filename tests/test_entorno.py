"""Lector de commit sin git (COR-03): ref suelta, packed-refs, HEAD desacoplado y sin .git."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ot_assess.entorno import commit_corto  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"


class CommitCortoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.git = self.tmp / ".git"

    def _git(self, head, suelta=None, packed=None):
        (self.git / "refs/heads").mkdir(parents=True)
        (self.git / "HEAD").write_text(head)
        if suelta:
            (self.git / "refs/heads/x").write_text(suelta)
        if packed:
            (self.git / "packed-refs").write_text(packed)

    def test_ref_suelta(self):
        self._git("ref: refs/heads/x\n", suelta=SHA + "\n")
        self.assertEqual(commit_corto(self.tmp), SHA[:12])

    def test_packed_refs(self):
        self._git("ref: refs/heads/x\n", packed=f"# pack-refs\n{SHA} refs/heads/x\n")
        self.assertEqual(commit_corto(self.tmp), SHA[:12])

    def test_head_desacoplado(self):
        self._git(SHA + "\n")
        self.assertEqual(commit_corto(self.tmp), SHA[:12])

    def test_sin_git_o_ref_inexistente(self):
        self.assertEqual(commit_corto(self.tmp), "no disponible")
        self._git("ref: refs/heads/x\n")
        self.assertEqual(commit_corto(self.tmp), "no disponible")


class LineasTest(unittest.TestCase):
    def test_sin_campos_ignorados_dice_ninguno(self):
        from ot_assess.entorno import lineas
        e = {"ot_assess": "x", "commit": "c", "tshark": "TShark 1", "estandares": "iec62443",
             "max_packets": 0, "campos_ignorados": [], "capturas": []}
        self.assertIn(("Campos ignorados por este tshark", "ninguno"), lineas(e))


if __name__ == "__main__":
    unittest.main()
