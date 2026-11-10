"""Lectura de JSON que viene del usuario (SEG-08).

json lanza RecursionError, no ValueError, con anidamiento muy profundo. Aqui se convierte en ValueError
para que cada llamador conserve su manejo de JSON invalido. Todo JSON de entrada pasa por cargar();
tests/test_json_entrada.py falla si aparece json.load(s) fuera de este modulo y de los datos internos.
"""
import json

MENSAJE_ANIDADO = "JSON demasiado anidado"


def cargar(texto):
    """Igual que json.loads (str, bytes o bytearray); un anidamiento excesivo da ValueError."""
    try:
        return json.loads(texto)
    except RecursionError:
        raise ValueError(MENSAJE_ANIDADO) from None
