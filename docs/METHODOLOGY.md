# Metodología del laboratorio — `METHODOLOGY.md`

Define **cómo se producen los datos**: quién ejecuta cada medición (qué usuario), con qué
comando, qué se espera observar y qué significa el resultado. Las fórmulas y unidades viven
en [`docs/METRICS.md`](METRICS.md); las cifras registradas, en [`docs/RESULTS.md`](RESULTS.md);
los comandos exactos para replicar, en [`docs/REPRODUCIBILITY.md`](REPRODUCIBILITY.md).
Principio rector: cada dato del paper debe ser reproducible con un comando documentado.

---

## 1. Verificación de precondiciones desde el foothold

**Pregunta.** ¿Qué parte del diagnóstico de CVE-2025-32463 puede confirmarse desde el
propio foothold (usuario `webuser`), sin ser root?

**Respuesta (diseño):** la parte *binario y sistema de archivos* sí; la parte
*configuración de sudoers* no.

| Señal de CVE-2025-32463 | ¿Verificable como `webuser`? | Por qué |
|---|---|---|
| Versión de sudo (rango 1.9.14–1.9.17) | **Sí** | `sudo --version` consulta al binario setuid; no requiere privilegios ni reglas de sudoers. |
| `/tmp` ejecutable (para el `.so` staged) | **Sí** | `findmnt -no OPTIONS /tmp` lee `/proc/self/mountinfo`, accesible a cualquier usuario. |
| Reglas de sudoers (señales de configuración) | **No** | `/etc/sudoers` y `/etc/sudoers.d/*` son `0440 root:root`, ilegibles para un usuario raso. Además, `sudo -l` de `webuser` solo informa su propia situación (ninguna), nunca las reglas de `operador`, `auditor` o `editor`. |

**Consecuencia práctica (diseño del lab):**

- `foothold.sh` (②) deja evidencia **parcial** de CVE-2025-32463: versión + `/tmp`
  ejecutable. Es suficiente para el punto pedagógico central: la CVE aplica aunque el
  usuario no tenga ninguna regla de sudo. La guardia anti-root del script aborta (exit 1)
  si se lo ejecuta como root: la demo nunca se contamina con privilegios.
- El diagnóstico **completo** (`scan.sh`, ①) corre como **root** dentro del contenedor,
  porque las señales de sudoers (propias y de otros usuarios) exigen leer los archivos
  de configuración, operación reservada a root. El scan es, entonces, la vista del
  auditor — no del atacante (limitación L-9 de `docs/LIMITATIONS.md`).

---

## 2. Protocolo de medición de las CVEs foco

Protocolo implementado por `scripts/benchmark.sh` con PoC externos en `LAB_POC_DIR`
(política en `SECURITY.md` §3) y **validado experimentalmente** con la corrida del
31-10-2026 ([`docs/RESULTS.md`](RESULTS.md)). Esta sección fija **cómo** se producen los
datos que las fórmulas de [`docs/METRICS.md`](METRICS.md) consumen.

### 2.1 Insumos y diseño del experimento

- **PoC externos** en `LAB_POC_DIR` (default `/opt/lab/poc`): descubrimiento de cualquier
  `*.sh` del primer nivel, en orden alfabético estable; los nombres viajan al TSV sin
  renombrar (contrato en [`docs/POC.md`](POC.md) §3).
- **Diseño pre/post (M5):** cada experimento consta de **dos corridas completas** del
  benchmark: pre-mitigación (estado vulnerable restaurado) y post-mitigación (tras aplicar ③).
  En la corrida del 31-10-2026: 2 corridas × 2 PoC × N=5 = 20 iteraciones.
- **Salida:** TSV con líneas `B` (una por iteración: iteración, éxito 0|1, ms, estado, poc) y
  `BAGG` (una por PoC: éxitos, total, media, mín, máx); extensión v2 con el nombre del PoC
  como último campo (`docs/METRICS.md` §5).

### 2.2 Usuario de ejecución (convención `.user`)

- El arnés corre como **root** —es el instrumento de medición— y degrada privilegios por
  iteración con `su - <usuario> -c "timeout -k 5 ${LAB_POC_TIMEOUT} bash <poc>"`. El PoC
  nunca corre como root salvo que la propia escalada lo logre.
- **Identidad por PoC:** sidecar `<poc>.user` junto al PoC con el nombre del usuario de
  ejecución en una línea (convención en `docs/POC.md` §3). **Sin sidecar ⇒ `webuser`**,
  que es el default del contrato (`docs/METRICS.md` §3/§6). En la corrida registrada:
  `poc_32462.sh.user` → `auditor` (`uid=1002`); `poc_32463.sh` sin sidecar → `webuser`
  (`uid=1000`).
- **Justificación:** la regla vulnerable de CVE-2025-32462 pertenece a `auditor`
  (`auditor clinica-legacy=(ALL) NOPASSWD: /usr/bin/less`), mientras que CVE-2025-32463 no
  requiere regla alguna y conserva el foothold del usuario raso. Cada identidad queda
  evidenciada en el log por iteración (`id` del pre-vuelo del PoC).

### 2.3 Definición de éxito por iteración (criterio dual, M3)

1. la **salida** del PoC contiene `uid=0(root)`, **o**
2. aparece una **entrada nueva en `/root/`** (comparación de listados antes/después de cada
   iteración; en este contenedor nada más escribe en `/root/`).

- **Por qué dual:** los PoC adaptados emiten `id` al terminar (criterio 1), pero el criterio 2
  hace el arnés independiente del formato de salida de un PoC de terceros: si la carga
  escalada solo deja un artefacto, la iteración igualmente cuenta como éxito.
- **Clasificación de cada iteración** (orden de evaluación: primero éxito, luego timeout,
  luego error de arnés): `EXPLOTABLE` (criterio dual satisfecho), `MITIGADO` (corrió y no
  consiguió root), `TIMEOUT` (exit 124/137 de `timeout(1)`), `ERROR` (exit 125/126/127: el
  arnés no pudo ejecutar el PoC; cuenta como no éxito, nunca infla la tasa).

### 2.4 N (repeticiones) y condición de parada

- **`N = 5` iteraciones por PoC** (`LAB_POC_ITERATIONS`, default 5, acotado a [1, 50]; un
  valor inválido se corrige con advertencia en stderr). Con 2 PoC son 10 iteraciones por
  corrida.
- **Justificación de N=5:** punto de equilibrio, para un arnés interactivo de panel, entre
  evidencia estadística mínima (media, mín y máx descriptivos) y duración total del
  experimento. El protocolo no pretende un estudio de varianza: reporta los agregados tal
  como los emite la línea `BAGG` (media en décimas de ms con aritmética entera, sin
  flotantes).
- **Condición de parada dura:** `timeout -k 5 ${LAB_POC_TIMEOUT}` con
  **`LAB_POC_TIMEOUT = 30` s por iteración** (default, acotado a [1, 300]). El `timeout` corre
  *dentro* de la sesión degradada (es el padre directo del `bash` del PoC): al cortar, mata al
  PoC y no deja procesos huérfanos; la gracia de `‑k 5` cubre PoC que ignoren SIGTERM. Un PoC
  colgado nunca puede bloquear el benchmark ni el panel. En la corrida registrada el timeout
  no llegó a dispararse (máximo observado: 5754 ms).

### 2.5 Medición de tiempo (M4)

- **Reloj del host (root):** `t0`/`t1` con `date +%s%N` alrededor de la invocación completa
  `su - <usuario> -c "timeout ... bash <poc>"`. El tiempo incluye el arranque de
  `su` + `timeout` + `bash`: es el **tiempo de escalada observable desde fuera del PoC**, no
  un tiempo interno instrumentado (evita modificar los PoC de terceros con cronómetros).
- **Agregados por PoC:** media (décimas de ms), mín y máx sobre las N iteraciones (línea
  `BAGG`).
- **Lectura condicionada:** el tiempo es métrica de interés cuando hay éxito; en la corrida
  post-mitigación mide la duración del *intento* fallido (p. ej., el 32462 post-agota su
  secuencia pty completa) y **no** constituye un overhead del control (`RESULTS.md` §6).

### 2.6 Registro de resultados y traslado al informe

- Cada tabla de [`docs/RESULTS.md`](RESULTS.md) declara fecha de corrida, entorno, PoC
  utilizados (con identidad de ejecución) y parámetros; las cifras derivan directamente de
  `B`/`BAGG` sin recálculos manuales.
- La distribución de estados del diagnóstico (M2) se reporta junto al benchmark (pre vs
  post), como se hace en `RESULTS.md` §2.
- **Reproducibilidad:** cada cifra debe poder regenerarse siguiendo
  `docs/REPRODUCIBILITY.md` sin pasos manuales implícitos; el respaldo de sudoers
  generado por `mitigate.sh` (`/opt/lab/backups/...`) permite restaurar el estado vulnerable y
  repetir la corrida pre.
