# Catálogo y adaptación de PoC externos — `POC.md`

**Fuente única** de: qué es un PoC para este laboratorio (§3), la convención de identidad
`.user` (§3) y las fuentes/ajustes de adaptación de cada PoC (§4–§6). La política de manejo
vive en `SECURITY.md` §3; los resultados empíricos, en `docs/RESULTS.md`; el protocolo de
medición, en `docs/METHODOLOGY.md` §2; los comandos para reproducir, en
`docs/REPRODUCIBILITY.md`.

---

## 1. Propósito y política

Este laboratorio **no contiene ningún exploit versionado**. Lo que sí contiene es todo lo necesario para *consumir* un PoC de manera controlada y medible: el arnés `scripts/benchmark.sh`, la sonda de disponibilidad `GET /api/poc` y el botón **④ Lanzar Ataque** del panel, condicionado a que el operador haya colocado el PoC explícitamente en `LAB_POC_DIR`.

El PoC es, entonces, un **insumo externo de terceros**: se descarga por fuera del repo, se adapta siguiendo el checklist de este documento y corre exclusivamente dentro del contenedor aislado (`sudo-lab-target`, Debian 12, sudo 1.9.15 compilado a mano). Su ejecución es responsabilidad exclusiva del operador (reglas de `SECURITY.md` §3).

---

## 2. Dónde se colocan: `LAB_POC_DIR`

El arnés busca los PoC en `LAB_POC_DIR`, que por defecto es **`/opt/lab/poc`** dentro del contenedor. `docker-compose.yml` ya declara el montaje de solo lectura:

```yaml
    volumes:
      - ./scripts:/opt/lab/scripts:ro
      - ./poc:/opt/lab/poc:ro        # PoC externos; NUNCA se versionan
```

El operador solo tiene que crear `./poc/` y colocar ahí los scripts **antes** de levantar el
contenedor (si se hace después, recrear: `docker compose up -d --force-recreate`). Los pasos
exactos están en `docs/REPRODUCIBILITY.md` §4 paso B; el directorio `poc/` está en
`.gitignore`.

Variables de entorno reconocidas por el arnés (opcionales, vía `environment:` del servicio):

| Variable | Default | Tope | Significado |
|---|---|---|---|
| `LAB_POC_DIR` | `/opt/lab/poc` | — | Directorio de PoC dentro del contenedor |
| `LAB_POC_ITERATIONS` | `5` | `50` | N iteraciones por PoC (métrica M3) |
| `LAB_POC_TIMEOUT` | `30` (s) | `300` (s) | Límite por iteración; un PoC colgado no bloquea el benchmark |

---

## 3. Qué considera el laboratorio un "PoC"

- **Cualquier archivo `*.sh` en el primer nivel de `LAB_POC_DIR`** (orden alfabético). Los
  nombres del comprimido externo (`poc_32463.sh`, `poc_32462.sh`) se usan tal cual: no hace
  falta renombrarlos — el arnés reporta cada nombre en el TSV y el panel lo muestra
  en la tabla de resultados.
- Basta **permiso de lectura** para la identidad de ejecución correspondiente (el montaje es
  `:ro`; si un archivo quedara `0600`, el arnés lo saltea con advertencia en el log y el
  panel lo explica).
- La sonda `GET /api/poc` corre `benchmark.sh --check`, que **solo lista** lo descubierto,
  sin ejecutar nada: preguntar si hay PoC nunca lanza un exploit.
- El botón **④ Lanzar Ataque** (`POST /api/benchmark`) ejecuta cada PoC con la **identidad
  que le corresponde** (convención `.user`, abajo), N veces, con `timeout` por iteración.
  El arnés corre como root (es el instrumento de medición: degrada privilegios y lee
  `/root/`), pero el PoC nunca corre como root salvo que la propia escalada lo logre.
- El criterio de éxito por iteración, los estados del TSV y el formato de salida están
  definidos en `docs/METHODOLOGY.md` §2.3 y `docs/METRICS.md` §5; no se duplican aquí.

**Identidad de ejecución por PoC (convención `.user`).** Cada PoC declara el usuario con el
que debe correr mediante un **archivo sidecar** ubicado junto a él en `LAB_POC_DIR`,
nombrado `<poc>.user` y cuyo contenido (una línea) es el nombre del usuario:

| Archivo en `LAB_POC_DIR` | Contenido | Identidad de ejecución |
|---|---|---|
| `poc_32462.sh.user` | `auditor` | `uid=1002(auditor)` |
| *(sin sidecar para `poc_32463.sh`)* | — | default `webuser`: `uid=1000(webuser)` |

- **Regla general:** sin sidecar ⇒ `webuser` (default del contrato `docs/METRICS.md` §3/§6;
  el sidecar es la excepción declarada y documentada).
- **Justificación:** la regla vulnerable de CVE-2025-32462 pertenece a otro usuario del
  escenario (`auditor clinica-legacy=(ALL) NOPASSWD: /usr/bin/less`); sin la convención, ese
  PoC no podría ejercer la regla. CVE-2025-32463, en cambio, no requiere ninguna regla y
  conserva el foothold `webuser`.
- El cambio de identidad lo realiza el arnés (root) con `su - <usuario> -c ...`; el PoC no
  hace escaladas de identidad previas por su cuenta.

---

## 4. PoC públicos de referencia por CVE

Para la evaluación de este proyecto se utilizan únicamente PoC de las **2 CVEs foco**. El
operador solo necesita proporcionar los scripts de estas dos (incluidos en el comprimido
externo `PoC - Externos.rar` del equipo).

El entorno del laboratorio (sudo 1.9.15) **NO es vulnerable** a las 3 CVEs históricas
(2023-22809, 2021-3156, 2019-14287), por lo que no tiene sentido técnico ejecutar PoC contra
ellas; su diagnóstico queda cubierto por `scan.sh`.

| CVE (Foco) | PoC de referencia | Archivo a descargar | Notas de ejecución |
|---|---|---|---|
| CVE-2025-32463 | pr0v3rbs/CVE-2025-32463_chwoot | `poc_32463.sh` | Extraer solo el script de exploit del repo original; ignorar su Dockerfile. |
| CVE-2025-32462 | 0p5cur/CVE-2025-32462-POC | `poc_32462.sh` | Script directo. Requiere la identidad `auditor` (sidecar `.user`). |

*(Nota: los nombres de los repositorios son ejemplos de referencia. Si algún enlace no está
disponible al momento de la ejecución, se deben buscar alternativas en GitHub para la misma
CVE.)*

---

## 5. Checklist de adaptación Ubuntu → Debian

Los PoC públicos suelen estar escritos para Ubuntu 24.04 con sudo 1.9.16p2. El target del lab
usa Debian 12 con sudo 1.9.15 compilado a mano. Verificación realizada con los PoC de la
corrida de referencia — **cada casilla registra el resultado**:

- [x] **Ruta de sudo**: el script asume `/usr/bin/sudo`. En el lab es correcto
      (compilado con `--prefix=/usr`). **Confirmado**: los logs del benchmark reportan
      `/usr/bin/sudo` para ambas identidades; no hizo falta ajustar rutas.
- [x] **Versión de glibc**: comparar `ldd --version` en Debian vs Ubuntu.
      **Confirmado sin ajustes**: glibc 2.36 (Debian 12) construye el nombre del módulo NSS
      igual que en Ubuntu (`libnss_<servicio>.so.2`, incluso cuando el servicio contiene
      barras — verificado contra `nss/nss_module.c`); no hubo diferencias que exigieran
      cambiar offsets ni mecanismos.
- [x] **Dependencias**: verificar que el contenedor tenga `python3`, `gcc`,
      `perl` o lo que el PoC requiera. El Dockerfile actual instala
      `build-essential`, `curl`, `zlib1g-dev`, `procps`.
      **Ajuste aplicado**: se agregaron al Dockerfile **`less`** (objetivo del escape
      `!sh` del PoC 32462) y **`util-linux`** (`script(1)`, la pty con la que se automatiza
      ese escape). `gcc` ya estaba vía `build-essential`.
- [x] **Flags de compilación del `.so`**: si el PoC compila una librería,
      verificar que las flags (`-shared -fPIC`) funcionen en Debian 12.
      **Confirmado sin cambios**: `-shared -fPIC -Wl,-init,woot` compila y el `DT_INIT` del
      constructor queda expuesto (`readelf -d`).
- [x] **Rutas de NSS**: el PoC puede asumir rutas específicas de Ubuntu
      (`/lib/x86_64-linux-gnu/`). Debian 12 usa la misma ruta, pero verificar.
      **Confirmado sin ajustes**: el mecanismo del 32463 no depende de rutas absolutas — la
      carga es **relativa al CWD** (`libnss_/woot1337.so.2` se resuelve contra el directorio
      de escenario que el PoC hereda a sudo). La única disciplina necesaria es no cambiar de
      CWD entre el staging y el disparo.
- [x] **Usuario del PoC**: ejecutar como usuario raso, nunca como root.
      **Ajuste aplicado (extensión)**: identidad **por PoC** mediante la convención
      `.user` (§3): `poc_32462.sh.user` = `auditor` (la regla vulnerable es suya);
      `poc_32463.sh` sin sidecar ⇒ `webuser`. El PoC nunca corre como root salvo que la
      propia escalada lo logre.
- [x] **Timeout**: si el PoC se cuelga, el benchmark lo corta
      (`timeout -k 5 ${LAB_POC_TIMEOUT}` por iteración).
      **Confirmado**: con 30 s por iteración ningún PoC se colgó; el timeout actuó como red
      de seguridad sin dispararse.
- [x] *(ítem surgido de la adaptación)* **Autenticación de la regla atacada**: para que
      la automatización pty del 32462 no dependa de tipear una contraseña, la regla del
      escenario se definió **`NOPASSWD`** en `sudoers.lab`
      (`auditor clinica-legacy=(ALL) NOPASSWD: /usr/bin/less`). El PoC conserva, como
      alternativa, la variable `POC_SUDO_PASS` para reglas con contraseña.

*(Los ajustes y sus motivos quedan registrados en §6; su efecto se cuantifica en
`docs/RESULTS.md`: demuestra que la metodología es robusta y no depende de una
configuración exacta.)*

---

## 6. Registro de adaptación por PoC

Cada fila consigna el origen exacto y los ajustes del checklist que hicieron falta; el
benchmark reporta el nombre de archivo tal cual, y ese nombre es el que viaja al TSV y al
informe. Los resultados cuantitativos de cada PoC están en `docs/RESULTS.md` (§3 y §5).

| PoC | CVE objetivo | Origen (repo / commit / fecha) | Licencia | Estado de adaptación | Ajustes realizados (ref. §5) |
|---|---|---|---|---|---|
| `poc_32463.sh` | CVE-2025-32463 | `sudo-chwoot.sh` de Rich Mirch (Stratascale CRU); comprimido externo `PoC - Externos.rar`, descarga 2026-10; mirror público `pr0v3rbs/CVE-2025-32463_chwoot` | *sin licencia declarada en el comprimido (PoC público de referencia)* | **Adaptado y validado** (resultados en `RESULTS.md`) | Sin cambios de gcc ni glibc (§5, ítems 1–4). Se añadieron, con fines de instrumentación y robustez: marcador de diagnóstico del constructor NSS (`.woot_ctor_ran`), escape condicional de chroot por doble chroot, pre-vuelo de versión/PATH de sudo y modo arnés sin TTY (payload `id` → `uid=0(root)` en stdout, criterio M3). El escenario NSS original se conserva íntegro. |
| `poc_32462.sh` | CVE-2025-32462 | PoC de 0p5cur (opscur); comprimido externo `PoC - Externos.rar`, descarga 2026-10 | *sin licencia declarada en el comprimido (PoC público de referencia)* | **Adaptado y validado** (resultados en `RESULTS.md`) | Host suplantado fijado a la regla del escenario (`LAB_POC_HOST=clinica-legacy`, con validación de patrón); guardia de identidad `auditor` (aborta con código 2 si no); automatización del escape `!sh` de `less` vía pty con `script(1)`, con **pausa inicial** (less inicializa la tty con TCSAFLUSH y descarta teclas en cola) y marcador `/tmp/pwn_32462.txt`; dependencias nuevas en el Dockerfile (`less`, `util-linux`) y regla `NOPASSWD` en `sudoers.lab` (§5). |

Ambos PoC corren no interactivos bajo el arnés (stdin sin TTY ⇒ no bloquean) y dejan la
evidencia del criterio M3 directamente en stdout.

---

## 7. Consideraciones éticas y de publicación

- **Dónde corre:** únicamente dentro del contenedor aislado del laboratorio, en la máquina del
  operador. Nunca contra sistemas de producción, de la facultad ni de terceros (política
  completa en `SECURITY.md` §3, que es su fuente única).
- **Si la adaptación no funciona:** no es un fracaso del proyecto, es parte de la
  investigación. Si un PoC no se adapta en un tiempo razonable, se documenta en
  `docs/LIMITATIONS.md` (L-12) y las métricas de explotación se reportan **N/A documentado**
  (nunca cero ni ausencia silenciosa — `docs/METRICS.md` §1).
