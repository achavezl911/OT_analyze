#!/usr/bin/env bash
# Lint + pruebas con salida corta. Código de salida != 0 si algo falla.
# La salida completa de unittest incluye el log del CLI (cientos de líneas); aquí solo el resumen.
cd "$(dirname "$0")/.." || exit 2

rc=0
if python3 -m pyflakes --version >/dev/null 2>&1; then
  # Se ignoran los avisos conocidos y sin riesgo: imports de registro y un f-string en report/md.py.
  lint=$(python3 -m pyflakes ot_assess ot_pcap_assess.py tests 2>&1 \
         | grep -v "imported but unused\|f-string is missing placeholders")
  if [ -n "$lint" ]; then echo "[lint]"; echo "$lint"; rc=1; else echo "[lint] ok"; fi
else
  echo "[lint] omitido: falta pyflakes (scripts/setup.sh)"
  [ -z "${PERMITIR_OMITIDAS:-}" ] && rc=1
fi

python3 scripts/generar_catalogo.py --check || rc=1       # el catalogo de docs sale del codigo

out=$(python3 -m unittest discover -s tests 2>&1); t=$?
echo "$out" | grep -E '^(Ran |OK|FAILED)'
if [ $t -ne 0 ]; then
  echo "$out" | grep -E -A14 '^(FAIL|ERROR):' | head -80
  rc=1
fi
if echo "$out" | grep -q "skipped"; then
  echo "[!] pruebas omitidas: falta tshark o scapy (scripts/setup.sh)"
  if [ -z "${PERMITIR_OMITIDAS:-}" ]; then
    echo "[!] No se admiten pruebas omitidas (PRU-03). Sin tshark a proposito: PERMITIR_OMITIDAS=1 scripts/verificar.sh"
    rc=1
  fi
fi
exit $rc
