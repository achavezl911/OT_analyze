#!/usr/bin/env bash
# Prepara el entorno para la prueba de extremo a extremo (solo desarrollo). Idempotente.
set -e
if ! command -v tshark >/dev/null; then
  if command -v apt-get >/dev/null; then
    S=""; [ "$(id -u)" -ne 0 ] && S="sudo"
    # sin update, el paquete no se encuentra en un entorno limpio. Una fuente externa del runner caida (p. ej. un
    # PPA de Launchpad) hace que update salga con 100 aunque el archivo de Ubuntu este al dia: se avisa y se
    # intenta instalar igual; si tshark no se instala, el script falla como antes.
    $S apt-get update -qq -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
      || echo "[!] apt-get update con errores (alguna fuente no responde); se intenta instalar tshark igual"
    DEBIAN_FRONTEND=noninteractive $S apt-get install -y -qq tshark
  else
    echo "[!] Instala Wireshark (tshark) manualmente: brew install --cask wireshark / dnf install wireshark-cli"; exit 1
  fi
fi
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
# versiones fijas en requirements-dev.txt (SEG-07)
python3 -c "import scapy, pyflakes, coverage" 2>/dev/null || python3 -m pip install -q -r "$RAIZ/requirements-dev.txt"
echo "[ok] tshark $(tshark --version | head -1 | awk '{print $3}'), scapy, pyflakes y coverage listos"
