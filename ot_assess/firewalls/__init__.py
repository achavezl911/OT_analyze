"""Firewalls: modelo comun y adaptadores por fabricante (F1a: Cisco FTD/ASA)."""
from .modelo import Firewall, Interfaz, Nat, Objeto, Regla, Ruta

__all__ = ["Firewall", "Interfaz", "Nat", "Objeto", "Regla", "Ruta"]
