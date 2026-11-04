# Contrato de métricas — `METRICS.md`

**Fuente única de las definiciones, fórmulas y unidades.** Define qué se mide, con qué
fórmula, en qué unidad y con qué protocolo. Cómo se producen los datos: `docs/METHODOLOGY.md`
§2. Dónde se registran: `docs/RESULTS.md`.

---

## 1. Propósito y convenciones

Este contrato obliga a todo el proyecto (scripts, dashboard y paper): una métrica que no aparezca aquí **no se reporta**.

- **Unidades:** los tiempos se expresan en milisegundos (ms); las tasas, en porcentaje (%); las iteraciones, en enteros.
- **Estados:** se usa el glosario único de `docs/SCOPE.md` §7 (`EXPLOTABLE`, `MITIGADO`, `NO_AFECTADO`, `POC_NO_DISPONIBLE`).
- **Regla de reporte:** toda cifra publicada en `docs/RESULTS.md` debe ser reproducible siguiendo `docs/REPRODUCIBILITY.md`. Lo que no se pueda medir se reporta **`N/A` documentado**, nunca como cero ni como ausencia silenciosa.

---

## 2. Métricas de diagnóstico (siempre disponibles)

### M1 — Cobertura de precondiciones

| Campo | Definición |
|---|---|
| Qué mide | Proporción de precondiciones **definidas** para las CVEs foco que `scan.sh` **evalúa en vivo** sobre el sistema (frente a las que solo se infieren del rango de versión). |
| Fórmula | `cobertura = precondiciones_evaluadas_en_vivo / precondiciones_definidas × 100`, por CVE y global. |
| Fuente | Campo `pre` de las líneas `F` del TSV: cada par `check=si|no` cuenta como una precondición evaluada. |
| Unidad | % |

Precondiciones definidas para las CVEs foco: CVE-2025-32463 → `tmp_exec` + `chroot` (2); CVE-2025-32462 → `regla_host_remoto` (1). Total: **3**.

### M2 — Distribución de estados

| Campo | Definición |
|---|---|
| Qué mide | Cantidad de hallazgos por estado tras cada corrida, separando CVEs foco de históricas (columna `scope` del TSV v2). |
| Fuente | Línea `S` del TSV (`S <explotable> <mitigado> <no_afectado>`) + agregado por `scope` en el dashboard. |
| Uso en el paper | Línea de base (pre-mitigación) y post-mitigación, control por control. |

Estados esperados del baseline: 32463 `EXPLOTABLE`, 32462 `EXPLOTABLE`, y las tres históricas `NO_AFECTADO` (aserciones del CI).

---

## 3. Métricas de explotación (Opción B — solo si hay PoC externo)

Estas métricas requieren que el operador haya provisto los PoCs de las CVEs foco (`poc_32463.sh`, `poc_32462.sh`) en `LAB_POC_DIR`. Si no, todas se reportan `N/A` documentado y `benchmark.sh` emite `POC_NO_DISPONIBLE`.

### M3 — Tasa de éxito

| Campo | Definición |
|---|---|
| Qué mide | Fracción de iteraciones del PoC que lograron escalada a root. |
| Fórmula | `tasa = iteraciones_exitosas / N × 100` |
| Definición de éxito | La salida del PoC contiene `uid=0(root)` **o** queda escrito un marcador en `/root/`. |
| Parámetros | `N = LAB_POC_ITERATIONS` (por defecto **5**); identidad de ejecución por sidecar `.user` (default `webuser`; convención en `POC.md` §3 y `METHODOLOGY.md` §2.2); timeout por iteración de 30 s. |
| Unidad | % |

### M4 — Tiempo de escalada

| Campo | Definición |
|---|---|
| Qué mide | Duración de cada iteración del PoC, desde su inicio hasta su finalización (éxito, fracaso o timeout). |
| Fórmula | Por iteración: `t = (t1 − t0) / 1e6` ms con `date +%s%N`. Se reporta **media, mín y máx** sobre las N iteraciones. |
| Fuente | Líneas `B` y `BAGG` del TSV del benchmark; el dashboard calcula/agrega los estadísticos. |
| Unidad | ms |

### M5 — Comparación antes / después

| Campo | Definición |
|---|---|
| Qué mide | Efecto de `mitigate.sh` sobre M3 y M4: el dashboard guarda el benchmark pre-mitigación y lo confronta con el post-mitigación. |
| Resultado esperado | Tasa de éxito post-mitigación = **0 %** cuando el control aplica (p. ej. `/tmp noexec` para 32463). Si el control no aplica a un PoC, se documenta por qué. |
| Uso en el paper | Evidencia central de la Opción B: permite reportar eficacia de mitigaciones **sin distribuir exploits**. |

---

## 4. Métricas operativas

### M6 — Tiempo de diagnóstico

| Campo | Definición |
|---|---|
| Qué mide | Tiempo entre la invocación de `POST /api/scan` y la disponibilidad del resultado parseado en el dashboard (incluye `docker exec` + `scan.sh` + `parseScan`). |
| Fórmula | Diferencia de `performance.now()` en `lib/lab.ts` alrededor de `runInLab`. |
| Unidad | ms (cota superior actual del runner: timeout de 60 s) |

### M7 — Tiempo de mitigación

| Campo | Definición |
|---|---|
| Qué mide | Tiempo entre la invocación de `mitigate.sh` y la **verificación completa**: `visudo -c` global OK + re-scan finalizado. |
| Fórmula | Igual que M6, sobre la secuencia completa de mitigación + re-scan. |
| Unidad | ms |

Se recomienda registrar ambas como media de ≥ 3 corridas en `docs/RESULTS.md`.

---

## 5. Contrato de datos (formato TSV)

Formato estable intercambiado entre scripts y dashboard. **Fuente única del formato**, para
el diagnóstico (`scan.sh`) y para el benchmark (`benchmark.sh`). La **v2** agrega el campo
final en cada línea (en `F`: `scope`; en `B`/`BAGG`: el nombre del PoC):

```
V <version>
F <cve> <nombre> <severidad> <version_vuln 0|1> <estado> <precondiciones k=v;...> <nota> <scope foco|historica>
S <explotable> <mitigado> <no_afectado>
POCDIR <directorio>                                     # benchmark, siempre primera línea
POC <nombre>                                            # benchmark, solo modo --check
B <iter> <exito 0|1> <ms> <estado_final> <poc>          # benchmark, una por iteración
BAGG <exito> <total> <media_ms> <min_ms> <max_ms> <poc> # benchmark, una por PoC
```

- `parseScan` (en `lib/lab.ts`) consume `V`/`F`/`S`; el campo 8 (`scope`) toma el valor por defecto `historica` si falta.
- El benchmark escribe `POCDIR`/`B`/`BAGG`; los estadísticos de M4 derivan de `BAGG` (o los calcula el dashboard si la línea viene abreviada). Un parser escrito contra el formato v1 sigue leyendo sin cambios los primeros campos.

---

## 6. Protocolo de medición (resumen)

El diseño completo del experimento está en `docs/METHODOLOGY.md` §2; en una línea:

1. **Iteraciones:** `N = 5` por defecto (`LAB_POC_ITERATIONS`), con identidad por sidecar `.user` (default `webuser`; `su - <usuario> -c ...`).
2. **Éxito:** `uid=0(root)` en la salida o marcador en `/root/` (idéntico criterio en M3 y M4).
3. **Timeout:** 30 s por iteración; un PoC colgado no puede bloquear el benchmark.
4. **Trazabilidad:** cada tabla de `docs/RESULTS.md` registra fecha, `sudo --version`, digest de la imagen base y —si aplica— commit/fecha del PoC utilizado (sección “PoC utilizado”).
5. **Reproducibilidad:** cada cifra debe poder regenerarse siguiendo `docs/REPRODUCIBILITY.md` sin pasos manuales implícitos.

---

## 7. Qué NO mide este contrato

- **No mide la robustez de los exploits:** no es un fuzzing ni una comparativa de PoCs; el PoC es un insumo de terceros usado para validar mitigaciones.
- **No mide rendimiento de `sudo`** ni overhead de los controles más allá de los tiempos definidos.
- **No mide el eslabón [1] (acceso inicial):** el vector web es simulado (ver `docs/SCOPE.md` §6); no existen métricas de RCE web.
