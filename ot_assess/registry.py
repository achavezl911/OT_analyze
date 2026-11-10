"""Registro minimo: una lista que se llena con un decorador.

    COLECTORES = Registry()

    @COLECTORES
    def mi_colector(rc): ...

El orden de registro es el orden de ejecucion.
"""
from __future__ import annotations


class Registry(list):
    def __call__(self, fn):
        self.append(fn)
        return fn
