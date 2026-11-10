# Arnés de trabajo: arquitecto e implementador

Lo lee el **arquitecto**. El implementador no necesita este archivo: le basta `CLAUDE.md` y su brief. Decisión: D22.

## Roles

| Rol | Quién | Hace | No hace |
|---|---|---|---|
| Propietario | Alejandro | Decide alcance, prioridad, marco por cliente, cuenta (MAX o API) y qué se fusiona a `main` | — |
| Arquitecto | Claude Opus, sesión fuera del contenedor | Diseña, investiga (una búsqueda por tema), redacta un brief por tarea, lanza al implementador, refuta con `ot-revisar` y leyendo el diff, actualiza el arnés | Escribir el código del producto |
| Implementador | Claude Code en el contenedor, una sesión por tarea | Ejecuta el brief en su rama: código, prueba que falla sin el cambio, catálogo, commit | Elegir otra tarea, buscar en la web, subir a GitHub, fusionar, tocar el arnés del contenedor |

## Contenedor

- Contenedor LXC `ot-analisis`, Debian 13, 2 vCPU, 4 GB. Acceso solo por llave SSH, usuario `analista`
  (sin sudo); root solo por llave. Consola de emergencia: `pct enter 105` en el nodo.
- Repositorio en `~/OT_analisis`; entorno de desarrollo en `~/.venv-ot` (scapy, pyflakes, coverage, ruff, bandit,
  pip-audit). Sin esa venv `scripts/verificar.sh` falla (PRU-03): nunca da OK con pruebas omitidas.
- Herramientas del arnés, propiedad de root (el implementador no las puede editar):

| Herramienta | Uso |
|---|---|
| `ot-claude max\|api [args]` | Lanza Claude Code en el repo con la venv. Antes comprueba la cuenta y **aborta si no es la pedida** (un MAX caducado no cae en silencio al API). `--cuenta` solo la muestra |
| `ot-tarea max\|api brief.md` | Una tarea = una sesión nueva en modo `-p`, con los permisos del implementador. Modelo por defecto `claude-sonnet-5-5`, esfuerzo `medium` (`OT_MODELO`, `OT_ESFUERZO`); en API, tope `OT_PRESUPUESTO` (5 USD). Guarda todo en `~/tareas` e imprime un resumen de tokens, turnos, permisos denegados y resultado |
| `ot-publicar <rama> [--solo-subir]` | Solo root (`ssh ot-analisis-root ot-publicar ...`; el token de GitHub está en `/root/.config/ot-publicar/token`, fuera del alcance del implementador). Sube la rama, espera la CI `verificar` de ese commit y, si termina en verde, avanza `main` sin forzar y crea la etiqueta `v<__version__>`. Con la CI en rojo no toca `main` (D29) |
| `ot-revisar rama [base]` | Compuerta: datos de cliente, secretos, verificación tocada o pruebas borradas, `verificar.sh`, bandit **nuevo** frente a la base, ruff y shellcheck en lo cambiado |
| `/usr/local/share/ot-arnes/implementador.json` | Permisos del implementador: edita y verifica; sin `git push`, `merge`, `reset`, `config`, red, `sudo`, subagentes ni lectura de credenciales |

Copias de referencia versionadas en `scripts/arnes/`. Las que corren son las de `/usr/local`, de root: si se cambia una, se reinstala a mano y se versiona la copia en el mismo commit. `ot-revisar` avisa si una rama toca esa carpeta.

## Arranque del arquitecto (chat nuevo)

1. `ssh ot-analisis` (usuario `analista`) o `ssh ot-analisis-root`: alias del equipo del propietario, solo por llave.
2. Leer este archivo y, de `docs/ESTADO.md`, solo la tabla "Pendiente" y las preguntas abiertas.
3. Partir la siguiente fila en tareas, redactar el brief y lanzar `ot-tarea max`. No releer código para orientarse: `git log --oneline -10` y `grep`.

## Cuentas

- **MAX es la cuenta por defecto.** API solo cuando el propietario lo indique para esa tarea.
- MAX vive en la configuración por defecto de Claude Code; API, en el perfil de Console (`~/.claude-api`). El perfil
  de Console no se separa por directorio de configuración: por eso la guardia de `ot-claude` es obligatoria.
- En API, `--max-budget-usd` corta la sesión; en MAX el costo que reporta la salida es nominal: lo que cuenta es la cuota.

## Flujo de una tarea

1. El arquitecto toma la fila que el propietario priorizó en `docs/ESTADO.md` y la parte en tareas pequeñas
   (una sesión cada una, esfuerzo S).
2. Redacta el brief y lo deja en `~/tareas/<id>.md`; lanza `ot-tarea max ~/tareas/<id>.md`.
3. Lee solo el resumen de `ot-tarea`. Si hubo permisos denegados o error, corrige el brief, no la sesión.
4. `ot-revisar <rama>`: con NO APROBADO, la refutación vuelve como brief nuevo (o `--resume <sesion>` si es un
   ajuste de una línea). Con APROBADO, el arquitecto lee el diff y decide.
5. El arquitecto actualiza `docs/ESTADO.md` y, si hubo decisión, `docs/DECISIONES.md`. La fusión a `main` la decide el
   propietario, con la CI en verde (D21).

## Plantilla de brief

```
Tarea: <ID> <título>
Rama: <nombre>, creada desde main actualizado
Objetivo: <una a tres líneas>
Archivos: <los que debes leer o tocar; no leas otros salvo que un grep lo exija>
Hechos: <datos ya investigados que necesitas; no busques en la web>
Aceptación: <pruebas nuevas que fallan sin el cambio>; scripts/verificar.sh en OK; catálogo regenerado si aplica
Fuera de alcance: <...>
Al terminar: commit en la rama y responde en diez líneas como máximo: qué cambió, cómo se verificó, qué queda.
```

## Reglas de tokens

- El implementador no lee `docs/ESTADO.md` ni el README completo: el brief trae lo que necesita.
- Una tarea por sesión: el contexto empieza limpio y no se arrastra historial.
- El arquitecto no relee código ni reportes: lee el resumen de `ot-tarea`, la salida de `ot-revisar` y el diff.
- Lo que se decide o se investiga se escribe una vez (ESTADO o DECISIONES) para que nadie lo vuelva a buscar.
- Opus solo para diseño y refutación; Sonnet implementa; si una tarea falla dos veces con Sonnet, se parte más o se
  escala a Opus con esfuerzo bajo.

## Pendientes del arnés

- Token de GitHub: de grano fino, solo este repositorio (Contents lectura y escritura, Actions y Metadata lectura),
  cargado por el propietario como root el 2026-11-03. Caduca: renovarlo en `/root/.config/ot-publicar/token`.
- Proteger `main` en GitHub exigiendo la verificación `verificar` en verde.
