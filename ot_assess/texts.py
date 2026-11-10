"""Textos fijos del reporte: brecha de visibilidad y preguntas al cliente."""
from __future__ import annotations

from .i18n import t

# Causas por las que dos plataformas pasivas difieren. (etiqueta, titulo del hallazgo)
VIS_CHECKS = [
    ("Captura truncada (snaplen corto)",
     "Captura truncada (snaplen por debajo del MTU)"),
    ("SPAN o TAP en un solo sentido",
     "La mayoria de las conversaciones aparece en un solo sentido"),
    ("Sin paquetes de identidad en la ventana",
     "La captura no contiene ningun paquete que revele identidad de equipos"),
    ("Pocos paquetes de identidad",
     "Muy pocos paquetes de identidad en la captura"),
    ("Trafico dominado por I/O ciclico",
     "El trafico es casi todo I/O ciclico, que no revela identidad"),
    ("Ventana de captura corta", "Ventana de captura corta"),
    ("Etiqueta VLAN ausente en el punto de captura",
     "Sin segmentacion por VLAN visible en el punto de captura"),
    ("Paquetes duplicados por SPAN", "Paquetes duplicados en la captura"),
    ("El punto de captura solo ve difusion y multicast",
     "El punto de captura casi no ve trafico unicast"),
]

VERIFY_WITH_CLIENT = [
    "<strong>Punto de captura distinto.</strong> Si la otra herramienta se "
    "conecto a otro SPAN, ve otro trafico. Hay que comparar el inventario de "
    "cada una, no el conteo de hallazgos.",
    "<strong>Sondeo activo habilitado o no.</strong> Las plataformas OT "
    "identifican firmware de dos formas: pasiva y por sondeo activo controlado. "
    "Si una lo tiene encendido y la otra no, la primera enumera CVEs y la "
    "segunda no, sobre exactamente la misma red.",
    "<strong>Taxonomia distinta.</strong> Lo que una herramienta llama "
    "'vulnerabilidad' otra lo reporta como alerta de higiene, riesgo de "
    "configuracion o un atributo del activo. Hay que comparar hallazgo por "
    "hallazgo, no los totales.",
    "<strong>Modo aprendizaje.</strong> Un sensor en fase de linea base no "
    "alerta, por diseno.",
    "<strong>Activos sin modelo ni firmware resuelto.</strong> Si el sensor no "
    "determino modelo y version, no puede asociar CVEs aunque el activo este "
    "en su inventario. Conviene revisar cuantos nodos tiene con esos campos "
    "vacios: ese numero es el diagnostico.",
]

CLIENT_QUESTIONS = [
    "En que punto exacto se tomaron estas capturas y donde esta conectado cada "
    "sensor. Si no es el mismo punto, la comparacion no es valida.",
    "La otra herramienta, hace sondeo activo? Estaba habilitado durante el analisis?",
    "Puede compartir el reporte de la otra herramienta con el detalle de cada "
    "hallazgo, para distinguir CVEs sobre firmware de hallazgos de higiene?",
    "Cuantos activos tiene cada plataforma en inventario, y cuantos de ellos "
    "con fabricante, modelo y firmware resueltos?",
    "Que ventana de tiempo cubrio cada analisis?",
    "El SPAN esta configurado en ambos sentidos y preserva las etiquetas VLAN?",
    "Hubo actividad de ingenieria o mantenimiento durante la ventana de captura?",
    "El sensor sigue en modo aprendizaje o ya paso a produccion?",
]


def vis_checks() -> list:
    """VIS_CHECKS con la etiqueta traducida; el titulo del hallazgo no (es la clave de cruce)."""
    return [(t(label), titulo) for label, titulo in VIS_CHECKS]


def verify_with_client() -> list:
    return [t(q) for q in VERIFY_WITH_CLIENT]


def client_questions() -> list:
    return [t(q) for q in CLIENT_QUESTIONS]
