# Reproducibilidad — `REPRODUCIBILITY.md`

**Fuente única de las instrucciones de ejecución paso a paso.** Propósito: que cualquier
persona, en una máquina limpia, regenere **cada tabla** de `docs/RESULTS.md` con comandos
documentados y cero pasos manuales implícitos (principio de `docs/METHODOLOGY.md` §1 y
§2.6). `lab/Dockerfile` remite a este documento para el sincronizado del digest pinneado.

---

## 1. Alcance

Este documento cubre la replicación de las **cuatro piezas de evidencia** de
`docs/RESULTS.md`:

| Pieza | Sección de RESULTS.md | Qué se regenera |
|---|---|---|
| Diagnóstico pre/post (M2) | §2 | Estados `EXPLOTABLE`/`MITIGADO` por CVE (resumen `S`) |
| Benchmark pre-mitigación (M3/M4) | §3 | TSV `B`/`BAGG`: 5/5 y 5/5, tiempos por iteración |
| Mitigación aplicada | §4 | `MITIGATE_OK`, reglas 6 → 4, `/tmp noexec` |
| Benchmark post-mitigación + comparación (M5) | §5–§6 | TSV `B`/`BAGG`: 0/5 y 0/5, `MITIGADO` ×5 |

No cubre: la adaptación de PoC nuevos (eso es `docs/POC.md` §5) ni la instalación de Docker
(`README.md` §Requisitos).

---

## 2. Artefactos fijados (lo que NO debe variar)

La corrida de referencia es válida solo si estos artefactos son idénticos. Si alguno
cambia, la corrida es una **réplica nueva** y debe registrarse como tal (§7).

| Artefacto | Valor fijado | Dónde se verifica |
|---|---|---|
| Imagen base | `debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3` | `lab/Dockerfile` línea `FROM` |
| Tarball de sudo | `sudo-1.9.15.tar.gz`, hash `fd0e254870e92e873b508ba16382f5ac3af81a5a38d1ea9cf973606db4262589` | Build: `awk` + `sha256sum -c` contra el `SHA256` oficial de sudo.ws |
| sudo en el target | `1.9.15` (`ARG SUDO_VERSION`) | `docker exec sudo-lab-target sudo --version` |
| Escenario de sudoers | `lab/sudoers.lab` (copia prístina en `/opt/lab/sudoers.lab.orig`, 0644) | `docker logs sudo-lab-target` al arranque; `visudo -c` |
| Capabilities del target | Las 7 de `SECURITY.md` §2.2 (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `SYS_ADMIN`, `SYS_CHROOT`) | `docker inspect` (paso C) |
| Montajes | `./scripts:/opt/lab/scripts:ro` y `./poc:/opt/lab/poc:ro` | `docker inspect` (paso C) |
| Variables del arnés | `LAB_POC_DIR=/opt/lab/poc`; defaults `LAB_POC_ITERATIONS=5`, `LAB_POC_TIMEOUT=30` | `docker-compose.yml` |
| Node del dashboard | `22` (`dashboard/.nvmrc`) | Solo afecta al panel, no a la medición |

> **Nota sobre el digest.** Si Debian publica una reconstrucción y se decide actualizar el
> digest, hacerlo **a conciencia y a la vez** en dos lugares: `lab/Dockerfile` y la tabla de
> esta sección. La medición de tasas no debería cambiar; los tiempos sí pueden variar
> levemente entre reconstrucciones de la base.

---

## 3. Entorno de la corrida validada (referencia)

| Campo | Valor |
|---|---|
| Fecha | 31 de octubre de 2026 |
| Contenedor | `sudo-lab-target` (imagen `sudo-lab-target:1.9.15`, hostname `srv-web`) |
| Backup de sudoers de esa corrida | `/opt/lab/backups/20261031-171738` |
| Volumen experimental | 2 corridas (pre/post) × 2 PoC × N=5 = **20 iteraciones** |
| Identidades | `webuser` (uid=1000) para `poc_32463.sh`; `auditor` (uid=1002) para `poc_32462.sh` (sidecar `.user`, `POC.md` §3) |
| Criterio de éxito | Dual: `uid=0(root)` en stdout **o** entrada nueva en `/root/` (`METHODOLOGY.md` §2.3) |

### 3.1 Equivalencias Windows (Docker Desktop)

Windows no trae `make`: todos los comandos `make X` de este documento tienen equivalencia
directa con `docker compose` / `docker exec` (el contenedor y los scripts son idénticos):

| `make …` (Linux/macOS) | Equivalente Windows (PowerShell, desde la raíz del repo) |
|---|---|
| `make preflight` | `bash scripts/preflight.sh` (Git Bash/WSL) o verificar a mano: Docker Desktop corriendo + Compose v2 |
| `make up` | `docker compose up -d --build --wait --wait-timeout 180` |
| `make scan` | `docker exec sudo-lab-target bash /opt/lab/scripts/scan.sh` |
| `make foothold` | `docker exec -u webuser sudo-lab-target bash /opt/lab/scripts/foothold.sh` |
| `make mitigate` | `docker exec sudo-lab-target bash /opt/lab/scripts/mitigate.sh` |
| `make reset` | `docker exec sudo-lab-target bash /opt/lab/scripts/mitigate.sh --reset` |
| `make benchmark` | `docker exec sudo-lab-target bash /opt/lab/scripts/benchmark.sh` |
| `make down` | `docker compose down` |
| `make clean` | `docker compose down -v --remove-orphans` + `docker rmi sudo-lab-target:1.9.15` |
| `make test` | `cd dashboard; npm install; npx tsx --test lib/lab.test.ts` |

Notas: (a) `--wait` reemplaza al bucle manual: el comando no regresa hasta que el
HEALTHCHECK declara `healthy`; (b) Windows no necesita `make` para nada del protocolo —
es la razón por la que el README no lo exige; (c) los archivos del repo usan `LF`
(`.gitattributes`), conservar ese ajuste en el editor.

---

## 4. Pasos exactos de replicación

### Paso A — Precondiciones del host

```bash
make preflight          # o: bash scripts/preflight.sh
# Esperado: "Preflight OK". Docker 24+, Compose v2; Node >= 22 (aviso, no bloquea el lab).
```

### Paso B — Obtener y colocar los PoC externos

El repo versionado **no distribuye** exploits (`SECURITY.md` §3): los PoC se obtienen de
sus fuentes originales (`docs/POC.md` §4) o del comprimido de entrega del equipo, y se
colocan en `./poc/` **antes** de `make up`:

```bash
mkdir -p poc
# Fuentes (POC.md §4/§6):
#   CVE-2025-32463 -> sudo-chwoot.sh de Rich Mirch (Stratascale CRU);
#                     mirror público pr0v3rbs/CVE-2025-32463_chwoot  -> guardar como poc_32463.sh
#   CVE-2025-32462 -> PoC de 0p5cur (repo CVE-2025-32462-POC)       -> guardar como poc_32462.sh
chmod 644 poc/*.sh                     # el arnés saltea PoC ilegibles para el usuario raso
printf 'auditor' > poc/poc_32462.sh.user   # sidecar de identidad (PASO OBLIGATORIO, L-13)
```

Verificación de disponibilidad (no ejecuta nada):

```bash
docker exec sudo-lab-target bash /opt/lab/scripts/benchmark.sh --check
# Esperado: POC poc_32462.sh / POC      poc_32463.sh  (dos líneas POC, una por script)
```

Aplicar el checklist de adaptación de `docs/POC.md` §5 (rutas, glibc, dependencias
`less`/`util-linux`, flags `-shared -fPIC`). Ese checklist ya está **completado** para los
PoC de la corrida de referencia; es obligatorio solo si se usan PoC distintos.

### Paso C — Levantar el target y verificar el instrumento

```bash
make up    # o en Windows: docker compose up -d --build --wait (tabla §3.1)
```

Verificaciones de integridad (las tres deben dar OK **antes** de medir):

```bash
# 1) Salud del sudoers (HEALTHCHECK):
docker inspect --format '{{.State.Health.Status}}' sudo-lab-target   # -> healthy
# 2) Capabilities exactas (lección SYS_CHROOT: una capability faltante invalida el pre-test
#    SILENCIOSAMENTE; ver LIMITATIONS.md L-15):
docker inspect --format '{{.HostConfig.CapAdd}}' sudo-lab-target
#    Esperado: [CHOWN DAC_OVERRIDE FOWNER SETGID SETUID SYS_ADMIN SYS_CHROOT]
# 3) Montajes :ro y variables:
docker inspect --format '{{json .Mounts}}' sudo-lab-target
```

### Paso D — Corrida PRE-mitigación (tablas §2 y §3 de RESULTS.md)

```bash
make scan > evidencia/scan-pre.tsv
# Esperado (resumen): S<TAB>2<TAB>0<TAB>3
#   2 EXPLOTABLE (CVE-2025-32463, CVE-2025-32462) · 0 MITIGADO · 3 NO_AFECTADO (históricas)
# Y en las líneas F: EXPLOTABLE para ambas CVEs foco.

make benchmark > evidencia/benchmark-pre.tsv
# Esperado (agregados BAGG): BAGG<TAB>5<TAB>5<TAB><media><TAB><min><TAB><max><TAB>poc_32463.sh
#                            BAGG<TAB>5<TAB>5<TAB><media><TAB><min><TAB><max><TAB>poc_32462.sh
```

Contrato de la corrida pre (lo determinista vs. lo referencial):

| Dato | Esperado | Naturaleza |
|---|---|---|
| Tasa 32463 y 32462 | **5/5 = 100 %** cada uno | **Determinista** (estado vulnerable restaurado) |
| Estados por iteración | `EXPLOTABLE` ×5 en cada PoC | Determinista |
| Media 32463 | ≈ 66 ms (referencia: 66.0, rango 64–70) | Referencial: varía por máquina, estable intra-corrida |
| Media 32462 | ≈ 2.7 s (referencia: 2740.8, rango 2739–2745) | Referencial; domina la secuencia pty |
| Identidad por iteración | `uid=1000(webuser)` / `uid=1002(auditor)` en el log (stderr) | Determinista |

### Paso E — Aplicar la mitigación (tabla §4 de RESULTS.md)

```bash
make mitigate > evidencia/mitigate.out
# Esperado: "MITIGATE_OK" al final; reglas activas 6 -> 4; backup en /opt/lab/backups/<ts>;
#   "/tmp ahora es noexec"; aviso si /dev/shm sigue ejecutable (límite L-5);
#   recordatorio: la mitigación completa es sudo 1.9.17p1+.

make scan > evidencia/scan-post.tsv
# Esperado: S<TAB>1<TAB>1<TAB>3   (32462 -> MITIGADO; 32463 sigue EXPLOTABLE: no tiene
#   mitigacion de configuracion real, ver SCOPE.md §8 y LIMITATIONS.md L-5)
```

### Paso F — Corrida POST-mitigación (tablas §5 y §6 de RESULTS.md)

```bash
make benchmark > evidencia/benchmark-post.tsv
```

Contrato de la corrida post:

| Dato | Esperado | Naturaleza |
|---|---|---|
| Tasa 32463 y 32462 | **0/5 = 0 %** cada uno | Determinista (con los controles aplicados) |
| Estado de diagnóstico por iteración | 32462: `MITIGADO` ×5. 32463: `EXPLOTABLE` ×5 (el PoC puntual falla por `/tmp noexec`, pero la CVE no se cierra; `SCOPE.md` §8) | Determinista |
| Media 32463 | ≈ 60–70 ms | Referencial: el PoC corre completo pero no escala |
| Media 32462 | mayor que la pre (ref.: 4835.8 ms) | Referencial: la pty agota su secuencia ante la denegación; **no es overhead del control** (lectura condicionada de M4, `RESULTS.md` §6) |

### Paso G — Reversibilidad e idempotencia (cierre del protocolo)

```bash
make reset > evidencia/reset.out
# Esperado: "RESET_OK"; visudo -c global OK; /tmp remontado exec.

make scan
# Esperado: S<TAB>2<TAB>0<TAB>3  (el estado vulnerable vuelve a ser el default, L-8)

# Comprobación del contrato sin PoC (idéntica a la que automatiza el CI):
mkdir -p poc_vacio   # p. ej. tras mover ./poc fuera del árbol
# (con ./poc sin *.sh) docker exec sudo-lab-target bash /opt/lab/scripts/benchmark.sh --check
# Esperado: POC_NO_DISPONIBLE
```

---

## 5. Cotejo contra RESULTS.md

1. Copiar los agregados de las líneas `BAGG` **tal cual** a las tablas (la fuente de toda
   cifra es el TSV; sin recálculos manuales — `RESULTS.md` §7).
2. Calcular la tasa como `éxitos/N` (M3) y el Δ de la comparación pre/post (M5).
3. Comparar las tablas obtenidas con `RESULTS.md`: **las tasas deben ser idénticas**
   (100 %/100 % pre, 0 %/0 % post); **los tiempos solo comparables en orden de magnitud y
   estabilidad intra-corrida** (L-11: reloj del host, incluye `su`+`timeout`+`bash`).
4. Registrar la réplica con su propia fecha y entorno (§7 de este documento) — la corrida
   del 31-10-2026 no se "reemplaza", se acompaña.

Si la tasa pre no es 100 %: NO reportar 0 % como mitigación (sería el falso "0 % del
instrumento", lección SYS_CHROOT). Ir a §6.

---

## 6. Diagnóstico de desviaciones

| Síntoma | Causa más probable | Acción |
|---|---|---|
| Pre-test 32463 = 0/5 **sin errores** | Falta `SYS_CHROOT` (o `SYS_ADMIN`) en el compose (L-15) | Verificar CapAdd (paso C-2); restaurar las 7 capabilities de `SECURITY.md` §2.2 y repetir |
| Pre-test 32462 = 0/5 sin errores | Falta el sidecar `poc_32462.sh.user` → corrió como `webuser` (L-13), o falta la regla `auditor clinica-legacy=...` (sudoers no vulnerable) | Crear sidecar (paso B); `make reset`; re-scan debe dar `S 2 0 3` |
| Estados `ERROR` en el TSV | PoC ilegible para el usuario raso (chmod), o falta `su`/`timeout` | `chmod 644 poc/*.sh` (paso B); verificación de paquetes del Dockerfile |
| Estados `TIMEOUT` | PoC colgado | Ajustar `LAB_POC_TIMEOUT` (default 30 s, tope 300); documentar el caso |
| `MITIGATE_FAIL` | Sudoers inválido tras el hardening, o la regla de oro detectó una ampliación | El script hace rollback automáticamente; revisar `/opt/lab/backups/<ts>` y el log |
| `make benchmark` → `POC_NO_DISPONIBLE` | `./poc` vacío o montado después del `up` | Colocar PoC y recrear: `make down && make up` |
| Contenedor `unhealthy` / scan "0 hallazgos" | Target caído o sudoers inválido | `docker compose ps`, `docker logs` |
| El dashboard no arranca por versión de Node | Node < 22 o ausente | `nvm use` (versión fijada en `dashboard/.nvmrc`); el lab bash funciona igual sin Node |
| Puerto 3000 ocupado | Otro proceso escucha en el puerto | Liberar el puerto o correr con otro puerto (`npm run dev -- -p 3001`); el dashboard es local, nunca exponerlo |
| Build falla por red o digest | Sin acceso a sudo.ws/Docker Hub, o digest reconstruido | Reintentar (el build usa `curl --retry 3`); verificar conectividad; actualizar digest a conciencia (§2) |

---

## 7. Registro de réplicas (plantilla)

Cada réplica completa del protocolo (pasos A–G) se registra con esta plantilla:

```text
Réplica de la corrida de RESULTS.md
Fecha/hora:                <YYYY-MM-DD HH:MM TZ>
Operador / máquina:        <nombre, SO, Docker Desktop/Engine versión>
Digest de base confirmado: <sí/no>
PoC utilizados (nombre + fuente + fecha de descarga): <...>
Sidecar .user presente:    <sí/no — poc_32462.sh.user = auditor>
scan pre  (S):             <S 2 0 3 | otro>
benchmark pre  (BAGG):     <5/5 media min max | ...> × <PoC>
mitigate:                  <MITIGATE_OK | FAIL>  backup: /opt/lab/backups/<ts>
scan post (S):             <S 0 2 3 | otro>
benchmark post (BAGG):     <0/5 ...> × <PoC>
reset:                     <RESET_OK>  re-scan: <S 2 0 3>
Desviaciones y notas:      <...>
```

---

## 8. Replicación automatizada (CI)

El workflow `.github/workflows/ci.yml` (job `laboratorio`) ejecuta en cada push la versión
mecanizada de los pasos A/C/D/E/G **sin PoC** (crea `./poc` vacío):

- build + `--wait` + `healthy` (paso C) →
- pre-test con aserciones `S 2 0 3` y `EXPLOTABLE` en ambas foco (paso D) →
- `MITIGATE_OK` (paso E) → post-test `S 0 2 3` sin `EXPLOTABLE` (paso F-E) →
- `RESET_OK` + re-scan `S 2 0 3` (paso G) →
- arnés sin PoC responde `POC_NO_DISPONIBLE` (contrato).

Un pipeline verde demuestra que el **estado vulnerable y el mitigado del baseline** siguen
reproducibles; el benchmark con PoC real (tasas y tiempos) sigue siendo un paso manual del
operador por la política del PoC (`SECURITY.md` §3).
