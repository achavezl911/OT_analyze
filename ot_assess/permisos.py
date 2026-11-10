"""Permisos de las salidas (SEG-04).

Las salidas contienen topologia y activos del cliente. Durante main el umask
es 0o077: las carpetas nuevas quedan 0700 y los archivos nuevos 0600 en POSIX.
Una carpeta que ya existia conserva sus permisos. En Windows os.umask no
restringe el acceso (los permisos se heredan de la carpeta padre).
"""
from __future__ import annotations

import functools
import os


def salida_privada(func):
    @functools.wraps(func)
    def envoltura(*args, **kwargs):
        anterior = os.umask(0o077)
        try:
            return func(*args, **kwargs)
        finally:
            os.umask(anterior)
    return envoltura
