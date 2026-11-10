"""Reglas LB1 (D82): hallazgos de las desviaciones respecto de la linea base aprobada.

No se registran con @RULES: no leen una captura, leen el resultado de `linea_base_aprobada.evaluar`. Un hallazgo por
tipo de desviacion, con las 10 de mayor atencion como evidencia.
"""
from __future__ import annotations

from ..i18n import t, unir
from .base import finding

MAX_TOP = 10     # igual que linea_base_aprobada.MAX_TOP (ese modulo no se importa aqui: ciclo con report)


def _evidencia(lista: list) -> str:
    lineas = []
    for x in lista[:MAX_TOP]:
        ext = " -> ".join(p for p in (x["origen"], x["destino"]) if p)
        lineas.append(t("{linea}", linea=" | ".join(p for p in (ext, x["detalle"], x["zona"]) if p)))
    if len(lista) > MAX_TOP:
        lineas.append(t(" y {n} mas", n=len(lista) - MAX_TOP))
    return unir("\n", lineas)


def _ips(lista: list) -> list:
    return [ip for x in lista for ip in x["activos"]]


def agregar_hallazgos(cap, rep: dict) -> None:
    """Agrega a `cap` un hallazgo por tipo de desviacion. Sin comparacion (manifiesto alterado) no hay hallazgos."""
    if not rep or rep.get("estado") != "comparada":
        return
    from ..linea_base_aprobada import (  # importacion tardia: linea_base_aprobada importa report, y este, las reglas
        T_ACTIVO,
        T_CAMBIO,
        T_CONDUCTO,
        T_ESCRITOR,
        T_PERIODO,
        T_SIN_TRAFICO,
        T_VOLUMEN,
    )
    por = {}
    for x in rep["desviaciones"]:
        por.setdefault(x["tipo"], []).append(x)
    cab = t("Linea base aprobada del sitio {s}, aprobada el {f}.", s=rep["sitio"] or "-",
            f=rep["fecha_aprobacion"] or "-")

    def ev(tipo):
        return unir("\n", [cab, t("{n} desviaciones de este tipo", n=len(por[tipo])), _evidencia(por[tipo])])

    if T_ESCRITOR in por:
        finding(
            cap, "Alta", "Escritor nuevo hacia equipos de control fuera de la linea base aprobada", ev(T_ESCRITOR),
            "Un origen que antes no enviaba operaciones de control a ese equipo ahora lo hace. Puede ser un cambio "
            "autorizado (una HMI nueva, un mantenimiento) o un uso no autorizado del protocolo de control.",
            "Confirmar con operacion si el origen y la operacion estaban autorizados; si lo estaban, aprobar una "
            "linea base nueva; si no, limitar el origen con el firewall y revisar el equipo destino.",
            categoria="Control", activos=_ips(por[T_ESCRITOR]))
    if T_CONDUCTO in por:
        finding(
            cap, "Media", "Conducto nuevo fuera de la linea base aprobada", ev(T_CONDUCTO),
            "Existe una comunicacion (par de equipos, puerto o protocolo) que la linea base aprobada no tenia. Un "
            "conducto nuevo hacia el nivel 0-2 o desde Internet amplia la superficie de ataque del proceso.",
            "Confirmar el motivo del conducto con el dueno del proceso; si no esta justificado, bloquearlo; si lo "
            "esta, documentarlo y aprobar una linea base nueva.",
            categoria="Segmentacion", activos=_ips(por[T_CONDUCTO]))
        if any(x["alta_regla"] for x in por[T_CONDUCTO]):
            cap.findings[-1]["severidad"] = "Alta"
    if T_ACTIVO in por:
        finding(
            cap, "Media", "Activo nuevo no aprobado en la red", ev(T_ACTIVO),
            "Hay equipos que la linea base aprobada no tenia. Un equipo desconocido puede ser un cambio autorizado, "
            "un equipo personal o de un tercero, o un dispositivo conectado sin control.",
            "Identificar al dueno de cada equipo, confirmar que el alta fue autorizada y, si no, desconectarlo o "
            "aislarlo; si es legitimo, agregarlo al inventario y aprobar una linea base nueva.",
            categoria="Inventario", activos=_ips(por[T_ACTIVO]))
    if T_CAMBIO in por:
        finding(
            cap, "Media", "Cambio de firmware, modelo o MAC respecto de la linea base aprobada", ev(T_CAMBIO),
            "Una misma direccion IP muestra otro firmware, modelo o MAC que en la linea base. Puede ser una "
            "actualizacion o un reemplazo de equipo (cambio autorizado) o un equipo distinto que tomo la direccion.",
            "Cotejar con la bitacora de cambios; si el cambio no esta registrado, verificar fisicamente el equipo y "
            "su configuracion. Si fue autorizado, aprobar una linea base nueva.",
            categoria="Inventario", activos=_ips(por[T_CAMBIO]))
        if any(x["controlador"] for x in por[T_CAMBIO]):
            cap.findings[-1]["severidad"] = "Alta"
    if T_VOLUMEN in por or T_PERIODO in por:
        lista = [*por.get(T_VOLUMEN, []), *por.get(T_PERIODO, [])]
        finding(
            cap, "Baja", "Trafico fuera de la linea base aprobada",
            unir("\n", [cab, t("{n} desviaciones de volumen o periodicidad", n=len(lista)), _evidencia(lista)]),
            "El volumen por minuto de un conducto supera 3 veces su p95 aprobado, o un conducto periodico dejo de "
            "serlo. Puede ser un cambio de proceso, una falla de un equipo o trafico que no debia estar.",
            "Comparar con la operacion del periodo (arranques, paros, cambios de proceso); si no hay explicacion, "
            "revisar los equipos del conducto. Los umbrales no estan calibrados: confirmar con la linea base del sitio.",
            categoria="Anomalia", activos=_ips(lista))
    if T_SIN_TRAFICO in por:
        finding(
            cap, "Baja", "Conductos aprobados sin trafico", ev(T_SIN_TRAFICO),
            "Conductos de la linea base aprobada no se vieron en esta corrida. Puede ser un cambio de proceso, un "
            "equipo apagado o una falla de comunicacion; tambien puede ser que la captura no incluya ese punto.",
            "Confirmar con operacion si el conducto debia estar activo y si el punto de captura lo ve (validacion de "
            "la captura); si falla, tratarlo como una falla de comunicacion.",
            categoria="Anomalia", activos=_ips(por[T_SIN_TRAFICO]))
