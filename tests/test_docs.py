"""La documentacion no puede desactualizarse en silencio. Solo biblioteca estandar."""
from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DOCS = [RAIZ / "README.md", RAIZ / "CLAUDE.md", RAIZ / "AGENTS.md", RAIZ / "SECURITY.md",
        *sorted((RAIZ / "docs").glob("*.md"))]


class DocsTest(unittest.TestCase):
    def test_catalogo_generado_esta_al_dia(self):
        r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "generar_catalogo.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_enlaces_relativos_existen(self):
        malos = []
        for doc in DOCS:
            for destino in re.findall(r"\]\(([^)\s]+)\)", doc.read_text(encoding="utf-8")):
                if destino.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                if not (doc.parent / destino.split("#")[0]).exists():
                    malos.append(f"{doc.relative_to(RAIZ)} -> {destino}")
        self.assertEqual(malos, [], "enlaces rotos")

    def test_rutas_citadas_existen(self):
        """Toda ruta `ot_assess/...`, `scripts/...`, `tests/...` o `docs/...` citada entre comillas invertidas existe."""
        malas = []
        for doc in DOCS:
            for ruta in re.findall(r"`((?:ot_assess|scripts|tests|docs)/[\w./-]*[\w/])(?:::[\w.]+)?`",
                                   doc.read_text(encoding="utf-8")):
                if not (RAIZ / ruta).exists():
                    malas.append(f"{doc.relative_to(RAIZ)}: {ruta}")
        self.assertEqual(malas, [], "rutas citadas que no existen")

    def test_decisiones_y_hallazgos_citados_existen(self):
        """Cada Dn citada esta definida en DECISIONES.md y cada ID del registro de auditoria esta definido."""
        decisiones = (RAIZ / "docs" / "DECISIONES.md").read_text(encoding="utf-8")
        definidas = set(re.findall(r"\*\*(D\d+) ", decisiones))
        registro = (RAIZ / "docs" / "AUDITORIA.md").read_text(encoding="utf-8")
        ids = set(re.findall(r"^\| ((?:SEG|COR|PRU|DIS|PRO)-\d+) \|", registro, re.M))
        faltan = []
        for doc in DOCS:
            texto = doc.read_text(encoding="utf-8")
            faltan += [f"{doc.name}: {d}" for d in sorted(set(re.findall(r"\bD\d{1,2}\b", texto))) if d not in definidas]
            faltan += [f"{doc.name}: {i}" for i in sorted(set(re.findall(r"\b(?:SEG|COR|PRU|DIS|PRO)-\d+\b", texto)))
                       if i not in ids]
        self.assertEqual(faltan, [], "referencias a decisiones o hallazgos sin definir")

    def test_version_unica(self):
        from ot_assess import __version__
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
