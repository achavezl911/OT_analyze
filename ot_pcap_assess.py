#!/usr/bin/env python3
"""Punto de entrada de compatibilidad. La logica vive en el paquete ot_assess.

    python ot_pcap_assess.py capturas/ -o reporte/
    python -m ot_assess capturas/ -o reporte/
"""
import sys

from ot_assess.cli import main

if __name__ == "__main__":
    sys.exit(main())
