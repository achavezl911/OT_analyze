#!/usr/bin/env bash
# Reune la evidencia de una auditoria en una carpeta: version, inventario, pruebas, cobertura,
# dependencias y la revision estatica reproducible. Un solo comando; no modifica el codigo.
#   scripts/evidencia.sh [carpeta_destino]     (por defecto: evidencia/<fecha>_<commit>/)
cd "$(dirname "$0")/.." || exit 2
commit=$(git rev-parse --short HEAD 2>/dev/null || echo sin-git)
sucio=$(git status --porcelain 2>/dev/null | grep -q . && echo " (con cambios sin confirmar)")
dest="${1:-evidencia/$(date +%Y%m%d)_$commit}"
mkdir -p "$dest" || exit 2

{ echo "version        : $(python3 -c 'from ot_assess import __version__ as v; print(v)')"
  echo "commit         : $(git rev-parse HEAD 2>/dev/null)$sucio"
  echo "rama           : $(git branch --show-current 2>/dev/null)"
  echo "fecha (UTC)    : $(date -u +%FT%TZ)"
  echo "python         : $(python3 --version 2>&1)"
  echo "tshark         : $(tshark --version 2>/dev/null | head -1 || echo 'no instalado')"
  echo "sistema        : $(uname -srm)"; } > "$dest/01_version.txt"

{ echo "archivos versionados: $(git ls-files | wc -l)"
  echo "--- lineas de Python por area"
  for d in ot_assess ot_assess/detail ot_assess/diagram ot_assess/importers ot_assess/report ot_assess/rules tests scripts; do
    prof=3; [ "$d" = "ot_assess" ] && prof=1
    printf '%-22s %6s\n' "$d" "$(find "$d" -maxdepth $prof -name '*.py' | xargs cat | wc -l)"; done; } > "$dest/02_inventario_codigo.txt"

scripts/verificar.sh > "$dest/03_verificacion.txt" 2>&1; echo "codigo de salida: $?" >> "$dest/03_verificacion.txt"

if python3 -m coverage --version >/dev/null 2>&1; then
  python3 -m coverage erase
  python3 -m coverage run --branch --source=ot_assess -m unittest discover -s tests >/dev/null 2>&1
  python3 -m coverage report --skip-empty > "$dest/04_cobertura.txt" 2>&1; python3 -m coverage erase
else echo "coverage no instalado (scripts/setup.sh)" > "$dest/04_cobertura.txt"; fi

python3 - > "$dest/05_dependencias.txt" <<'PY'
import ast, glob, sys
std = getattr(sys, "stdlib_module_names", None)
mods = set()
for f in glob.glob("ot_assess/**/*.py", recursive=True) + ["ot_pcap_assess.py"]:
    for n in ast.walk(ast.parse(open(f, encoding="utf-8").read())):
        if isinstance(n, ast.Import): mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module: mods.add(n.module.split(".")[0])
mods -= {"ot_assess"}
if std is None: print("Python < 3.10: no se puede separar stdlib de terceros; revisar a mano:", sorted(mods))
else:
    print("stdlib  :", ", ".join(sorted(m for m in mods if m in std)))
    print("terceros:", ", ".join(sorted(m for m in mods if m not in std)) or "ninguno")
print("binarios externos invocados: tshark, capinfos, editcap (Wireshark)")
PY

# Revision estatica reproducible: cada patron con su resultado (vacio = no aparece).
{ for patron in 'shell *= *True' 'os\.system|os\.popen' '\beval\(|\bexec\(' 'pickle|marshal|yaml\.load' \
                '^\s*(import|from) (socket|urllib|requests|http\.client|ftplib|smtplib)' 'subprocess\.' \
                'tempfile|mkdtemp|/tmp'; do
    echo "### $patron"; grep -rnE "$patron" ot_assess ot_pcap_assess.py | sed 's/^/    /'; echo; done
  echo "### secretos en todo el historial"
  git grep -nEI '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY)' $(git rev-list --all) 2>/dev/null | sed 's/^/    /'
  echo "### extensiones de datos de cliente en el historial (fuera de tests/ y docs/)"
  git log --all --name-only --format= | sort -u | grep -Ei '\.(pcap|pcapng|cap|zip|7z|rar|xlsx|log|env|pem|key)$' | grep -v '^tests/\|^docs/' | sed 's/^/    /'
} > "$dest/06_revision_estatica.txt"

python3 scripts/generar_catalogo.py --check > "$dest/07_catalogo.txt" 2>&1
echo "[ok] evidencia en $dest"
ls "$dest"
