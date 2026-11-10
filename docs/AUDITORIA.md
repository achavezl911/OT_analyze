# Guía de auditoría

Punto de entrada para quien audite este código. Está pensada para que una auditoría se prepare con un
solo comando y se reparta en áreas independientes. Estado verificado el **2026-11-02**, versión del código
`0.1.0`.

## 1. Qué se audita y qué no

| Dentro del alcance | Fuera del alcance |
|---|---|
| El paquete `ot_assess/` y el punto de entrada `ot_pcap_assess.py` (Python: ≈5 100 líneas; más ≈1 300 en `tests/` y `scripts/`) | Wireshark/`tshark`, que es un binario externo (ver SEG-03) |
| `scripts/` y `tests/` | El intérprete de Python y su biblioteca estándar |
| La documentación y su coherencia con el código | La exactitud normativa de cada marco (IEC 62443, NERC CIP, NIST): el mapeo es orientativo (DIS-01) |

La herramienta **no abre conexiones de red, no ejecuta código dinámico y no usa shell**; esto se comprueba
con la revisión estática reproducible del paquete de evidencia (apartado 2).

## 2. Preparar la auditoría en cinco minutos

```bash
git clone <repositorio> && cd OT_analisis
scripts/setup.sh          # tshark, scapy, pyflakes y coverage (solo desarrollo)
scripts/evidencia.sh      # reúne todo en evidencia/<fecha>_<commit>/
```

`scripts/evidencia.sh` no modifica el código y produce:

| Archivo | Contenido |
|---|---|
| `01_version.txt` | Versión, commit exacto, rama, fecha, versiones de Python y de `tshark` |
| `02_inventario_codigo.txt` | Archivos versionados y líneas de Python por área |
| `03_verificacion.txt` | Lint + todas las pruebas + catálogo al día, con código de salida |
| `04_cobertura.txt` | Cobertura de líneas y ramas por módulo |
| `05_dependencias.txt` | Módulos importados (biblioteca estándar frente a terceros) y binarios externos invocados |
| `06_revision_estatica.txt` | Búsqueda de `shell=True`, `eval`/`exec`, `pickle`, uso de red, archivos temporales, secretos y datos de cliente en **todo el historial** |
| `07_catalogo.txt` | Si `docs/CATALOGO.md` coincide con el código |

## 3. Orden de lectura sugerido

| Paso | Documento | Para qué |
|---|---|---|
| 1 | Este archivo | Alcance, registro de hallazgos conocidos, lista de verificación |
| 2 | [ARQUITECTURA.md](ARQUITECTURA.md) | Flujo de datos, contratos entre módulos, invariantes, modos de fallo |
| 3 | [SEGURIDAD.md](SEGURIDAD.md) | Modelo de amenazas y controles, con la evidencia de cada uno |
| 4 | [PRUEBAS.md](PRUEBAS.md) | Qué está probado, qué no y cómo se mide |
| 5 | [CATALOGO.md](CATALOGO.md) | Reglas, marcos, protocolos, puertos, opciones y columnas de salida (generado del código) |
| 6 | [DECISIONES.md](DECISIONES.md) | Por qué el diseño es como es |

## 4. Registro de hallazgos conocidos

Autoevaluación previa a una auditoría externa, hecha el 2026-11-02 con pruebas reproducibles. **Es la lista
de partida, no una lista cerrada.** Severidad: **Alta** = puede producir una conclusión falsa en un entregable
o comprometer el equipo del analista; **Media** = debilita una garantía o deja un riesgo sin control;
**Baja** = mejora de robustez o de proceso. Estados: Abierto · Mitigado · Aceptado · Cerrado.

| ID | Sev. | Hallazgo | Estado | Evidencia reproducible | Recomendación |
|---|---|---|---|---|---|
| COR-01 | Alta | Una captura corrupta, truncada o vacía producía un reporte "exitoso" (código de salida 0) con conclusiones falsas, por ejemplo "No se observaron escrituras ni comandos de control". `fields_pass` descartaba `stderr` y no revisaba el código de salida de `tshark`. | **Cerrado** en 0.2.0 | Pruebas `CapturaIlegibleTest` y `TsharkConErrorTest` (`tests/test_pipeline.py`). Reproducción original: `head -c 3000 /dev/urandom > x.pcap; python3 ot_pcap_assess.py <carpeta con x.pcap> -o out` | `capinfos` valida cada captura antes de analizar (código de salida y número de paquetes); `fields_pass` y `phs` abortan si `tshark` falla. La captura ilegible no se analiza, recibe el hallazgo "Captura ilegible o sin paquetes" (Alta) y ninguno de ausencia; el código de salida es 2 (1 si ninguna es legible, sin reporte). Ver D18 |
| COR-02 | Media | La regla "Paquetes duplicados en la captura" es inalcanzable: lee `Number of duplicate packets` y `capinfos` 4.2.2 no lo reporta. | **Cerrado** | `capinfos -M <captura> \| grep -i duplic` (sin salida); `DuplicadosTest` en `tests/test_pipeline.py` | Los duplicados se calculan con `editcap -d` (`Tshark.duplicados`, ventana de 5 paquetes); la regla dispara con un entero > 0. La prueba falla si se anula la llamada |
| COR-03 | Media | Degradación silenciosa: los campos que el `tshark` local no soporta se ignoran y solo se avisa por consola. El reporte no registra la versión de `tshark` ni los campos ignorados. | **Cerrado** en 0.4.0 | Pruebas `test_entorno_en_reportes_y_json` y `test_campo_ignorado_aparece_en_el_reporte` (`tests/test_pipeline.py`), `tests/test_entorno.py` | Sección "Entorno de análisis" en HTML y Markdown y clave `entorno` en `resultado.json`: versión de ot_assess y commit, versión de `tshark`, marcos, `--max-packets`, campos ignorados y SHA-256 de cada captura (`ot_assess/entorno.py`). `resultado.json` pasó de lista a objeto `{entorno, capturas}` |
| COR-04 | Baja | Enrutador de diagramas: `_choca` evalúa la curva directa, no la ruta ya desviada; un trazo puede rozar una tarjeta de una fila posterior. En redes densas el diagrama por activo queda con cruces. | Aceptado | `ot_assess/diagram/svg.py`, función `_ruta`; ver D8 | Retocar solo con datos reales y un ejemplo concreto |
| COR-05 | Media | La regla "RIP activo en la red de control" no se disparaba con tráfico real: buscaba el protocolo `rip` y Wireshark 4.2.2 lo rotula `RIPv1`, `RIPv2` o `RIPng`. Apareció al escribir el escenario de PRU-01. | **Cerrado** en 0.3.0 | `DeteccionesTest.test_punto_c` (RIPv2 sintético); `tshark -r <captura RIP> -T fields -e _ws.col.protocol` | La regla suma los protocolos que empiezan por `rip`. Cualquier otra regla que compare nombres de protocolo por igualdad merece la misma revisión |
| SEG-01 | Media | El lector XLSX no limita el tamaño al descomprimir (bomba zip): `z.read()` sin tope. | **Cerrado** | `tests/test_importers.py::BombaZipTest` | Medida: `lector._Lectura` lee con `f.read(MAX_PARTE + 1)` sin confiar en la cabecera; topes 64 MiB por parte, 256 MiB en total y 10000 entradas; rechaza con SystemExit |
| SEG-02 | Media | Los CSV de salida no neutralizan celdas que empiezan con `=`, `+`, `-` o `@`: al abrirlos en una hoja de cálculo se interpretan como fórmulas. El dato lo controla un tercero (nombre de equipo en la red o en una exportación). | **Cerrado** | Un activo llamado `=HYPERLINK("http://x","click")` sale tal cual en `inventario_importado.csv` | `report/common.escritor_csv` antepone `'` en todos los CSV; prueba `test_formula_en_nombre_se_neutraliza_en_inventario` y `test_celda_csv` |
| SEG-03 | Media | Las capturas no confiables las interpreta Wireshark con sus disectores: la superficie de ataque es heredada del binario externo. | Aceptado, mitigación operativa | Ver SEGURIDAD.md, amenaza A1 | Analizar en un equipo aislado y con Wireshark al día |
| SEG-04 | Baja | Los archivos de salida (topología y activos del cliente) se crean con los permisos por defecto del sistema. | **Cerrado** | `ls -l` de la carpeta de salida | `ot_assess/permisos.py` (`salida_privada`) fija `umask 0o077` en ambos `main` y lo restaura al salir (incluso con error); carpeta nueva 0700, archivos 0600 en POSIX, una carpeta existente no cambia. En Windows `umask` no tiene efecto. Pruebas `test_permisos_de_la_salida`, `test_permisos_de_la_salida_diagrama`, `test_umask_se_restaura_si_main_falla` |
| SEG-05 | Baja | Se ejecuta el binario que indique `--tshark` o el primero del `PATH`, sin verificar su integridad. | Aceptado | `ot_assess/tools.py`, función `find_tool` | Documentar; opcionalmente imprimir la ruta y la versión (ya se imprime la ruta) |
| SEG-06 | Baja | El reporte Markdown solo escapa `\|` y saltos de línea: un nombre con HTML crudo podría renderizarse según el visor. HTML, SVG y Mermaid sí se escapan. | **Cerrado** | `ot_assess/report/common.py`, función `md_escape` | `md_escape` escapa `&`, `<` y `>` (primero `&`); prueba `test_md_escape_html` |
| SEG-07 | Baja | Las dependencias de desarrollo (`scapy`, `pyflakes`, `coverage`) se instalan sin versión fija. No afecta a la ejecución, que no tiene dependencias. | **Cerrado** (2026-11-09) | `requirements-dev.txt` y `scripts/setup.sh` | Versiones fijas en `requirements-dev.txt` (`scapy==2.8.0`; `pyflakes` y `coverage` con marcadores de entorno para Python 3.9 y >= 3.10); `setup.sh` instala desde ese archivo |
| SEG-08 | Baja | Un JSON profundamente anidado en una exportación termina con `RecursionError` sin mensaje controlado (código 1 y traza). No expone datos. | **Cerrado** (2026-11-09) | `python3 -c "print('['*200000 + ']'*200000)" > p.json` y pasarlo como `--activos`: ahora `[!]` sin traza; `tests/test_json_entrada.py` | Todo JSON de entrada pasa por `json_entrada.cargar()`, que convierte `RecursionError` en `ValueError`; cada llamador conserva su manejo de archivo inválido. La prueba de guarda falla si aparece `json.load(s)` fuera de esa función y de los datos internos listados. De paso, `--madurez` con una línea mayor que el límite de campo de `csv` ya no da traza |
| PRU-01 | Alta | 13 de las 29 detecciones no tenían ninguna prueba que las disparara (la cobertura de líneas, 93 %, lo ocultaba). | **Cerrado** en 0.3.0 (12 de 13; la restante, "Paquetes duplicados", se cerró con COR-02) | `DeteccionesTest` en `tests/test_pipeline.py`; `python3 scripts/generar_catalogo.py` y leer la columna "Detección probada de extremo a extremo": 30 de 30 | Escenarios sintéticos `punto_c` y `punto_d` en `tests/gen_pcaps.py`. Cada regla se desactivó a propósito y la prueba falló |
| PRU-02 | Media | Nada se ha probado con datos reales: ni capturas de planta ni exportaciones reales de Nozomi, Claroty o Dragos. Los nombres de columna son alias no validados (D4). | Abierto, bloqueado por datos de cliente | `tests/gen_exports.py` y `tests/gen_pcaps.py` son sintéticos | Probar con muestras reales anonimizadas |
| PRU-03 | Baja | Sin `tshark` o `scapy` se omiten las 19 pruebas de extremo a extremo y el resultado sigue siendo "OK". `scripts/verificar.sh` lo avisa; una ejecución directa de `unittest` no. | **Cerrado** (2026-11-02) | Sin scapy en el `PATH`, `scripts/verificar.sh` termina con código 1 | `scripts/verificar.sh` falla con cualquier prueba omitida o sin lint, también fuera de la integración continua; `PERMITIR_OMITIDAS=1` lo tolera a propósito. Reabierto al lanzar un agente por SSH sin el entorno virtual: daba OK con 19 omitidas |
| DIS-01 | Baja | Los mapeos a IEC 62443, NERC CIP y NIST son orientativos y no los ha revisado un especialista de cada marco. | Abierto | `ot_assess/marcos/*.json` (campo `validacion`) | Revisión por un especialista antes de presentarlos como referencia normativa |
| PRO-01 | Media | No había integración continua: la verificación dependía de ejecutarla a mano. | **Cerrado** en 0.3.0 | `.github/workflows/verificar.yml`; pestaña Actions del repositorio | Flujo que ejecuta `scripts/setup.sh` y `scripts/verificar.sh` en cada push con Python 3.9 y 3.13. `verificar.sh` falla si se omite alguna prueba (PRU-03). Ver D21 |
| PRO-02 | Media | No hay `LICENSE` ni titularidad declarada del código. Hasta el 2026-11-02 el repositorio era público (verificado). | **Cerrado** (2026-11-02) | `LICENSE` | Todos los derechos reservados; el titular es el propietario y nadie usa, copia ni accede al código sin su autorización previa |
| PRO-03 | Baja | El trabajo estaba en una rama sin fusionar a `main` y sin etiquetas de versión. | Mitigado: fusionado a `main` (d5826c0); **falta la etiqueta `v0.3.0`**, que el entorno de sesiones no puede crear (el push de etiquetas es rechazado) | `git log --oneline origin/main..HEAD`; `git ls-remote --tags origin` | El propietario crea `v0.3.0` sobre d5826c0 (`git tag v0.3.0 d5826c0 && git push origin v0.3.0`, o Releases en GitHub). Desde ahora: fusionar a `main` con la verificación en verde y etiquetar `vX.Y.Z` igual a `__version__` (apartado 6) |

Las filas de este registro las lee `tests/test_docs.py`: cualquier ID citado en otro documento debe existir aquí.

## 5. Lista de verificación por área

Cada punto indica dónde mirar o qué comando ejecutar. Marca cada uno como OK, hallazgo o no aplica.

| Área | Qué comprobar | Cómo |
|---|---|---|
| Entradas | Qué archivos se leen y cómo se validan (capturas, CSV/JSON/XLSX, marcos y mapeos JSON) | `ot_assess/importers/lector.py`, `ot_assess/standards.py` (`cargar_archivo`), `ot_assess/importers/plataformas.py` (`cargar_mapeo`); SEGURIDAD.md |
| Ejecución externa | Que `tshark` se invoque sin shell y con argumentos en lista | `ot_assess/tools.py`; `06_revision_estatica.txt` |
| Salidas | Escape de datos externos en HTML, SVG, Mermaid, CSV y Markdown | `ot_assess/report/`, `ot_assess/diagram/`; prueba `test_nombres_hostiles_se_escapan`; SEG-02, SEG-06 |
| Datos de cliente | Que no haya datos reales en el repositorio ni en su historial | `06_revision_estatica.txt`; `.gitignore` |
| Dependencias | Ninguna en ejecución; binarios externos y de desarrollo | `05_dependencias.txt`; SEG-07 |
| Corrección | Que las conclusiones del reporte se sostengan; modos de fallo | ARQUITECTURA.md "Modos de fallo"; COR-01, COR-02, COR-03 |
| Pruebas | Qué se prueba, cobertura de ramas, brechas | PRUEBAS.md; `04_cobertura.txt`; PRU-01 |
| Determinismo | Dos corridas sobre las mismas entradas dan las mismas salidas | prueba `test_salida_determinista` |
| Documentación | Que no esté desactualizada | `scripts/generar_catalogo.py --check`; `tests/test_docs.py` |
| Proceso | Integración continua, licencia, versionado | PRO-01, PRO-02, PRO-03 |

## 6. Versionado y trazabilidad

- La versión está en `ot_assess/__init__.py` (`__version__`), se imprime con `--version` y aparece en el pie de
  todos los reportes. Un entregable se puede relacionar con la versión que lo produjo.
- Regla de subida: **menor** cuando cambia una detección, un mapeo a un marco o el formato de una salida;
  **parche** para correcciones que no alteran resultados. Cada versión fusionada a `main` lleva la etiqueta
  `vX.Y.Z` (PRO-03, D21); la referencia exacta sigue siendo el commit, que `scripts/evidencia.sh` registra.
- El reporte incluye el commit, la versión de `tshark` y el SHA-256 de cada captura (COR-03).

## 7. Cómo se gestiona un hallazgo de auditoría

1. Se agrega una fila al registro (apartado 4) con un ID nuevo: `SEG` seguridad, `COR` corrección, `PRU`
   pruebas, `DIS` diseño, `PRO` proceso. Nunca se reutiliza un ID.
2. La corrección entra en un commit que incluye **la prueba que la demuestra** y actualiza el registro
   (estado y, si procede, la columna de evidencia).
3. Si el hallazgo es una decisión de diseño que se acepta, se registra en [DECISIONES.md](DECISIONES.md) y el
   estado pasa a "Aceptado".
4. Si cambia el catálogo (reglas, opciones, columnas), se regenera con `python3 scripts/generar_catalogo.py`.

## 8. Limitaciones declaradas

- Las conclusiones del reporte dependen de lo que contiene la captura. La ausencia de un hallazgo no prueba la
  ausencia del riesgo (README, "Notas de interpretación").
- Los roles, zonas y criticidades se **infieren** del tráfico; no son declarados por los equipos.
- Los formatos de exportación de Nozomi, Claroty y Dragos no son públicos: la importación reconoce columnas por
  alias y muestra qué interpretó (D4).
- Las exportaciones importadas no distinguen lectura de escritura (D5).
- La herramienta no emite identificadores de CVE (D1).
