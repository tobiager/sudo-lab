#!/usr/bin/env bash
# =============================================================================
#  benchmark.sh — Arnés de MEDICIÓN DE EXPLOTACIÓN (Opción B)
# -----------------------------------------------------------------------------
#  Propósito: ejecutar el PoC externo que el operador haya colocado en
#  LAB_POC_DIR (montado por compose en /opt/lab/poc:ro), N veces, cada uno con
#  la identidad de usuario que le corresponde (sidecar <poc>.user; default
#  webuser), y medir tasa de éxito y tiempos de escalada (métricas M3/M4 del
#  contrato docs/METRICS.md). El repo versionado NO contiene ningún PoC: este
#  script sólo sabe CONSUMIRlos.
#
#  Contrato del PoC externo:
#    - Cualquier archivo *.sh en el primer nivel de LAB_POC_DIR se considera un
#      PoC (por ejemplo poc_32463.sh y poc_32462.sh del comprimido externo, tal
#      como vienen, sin renombrar). Se ejecutan en orden alfabético.
#    - El PoC corre con `bash <ruta>` (basta permiso de LECTURA; el volumen es
#      :ro) bajo la identidad declarada en el sidecar <poc>.user (default
#      webuser; convención en docs/POC.md §3): `su - <usuario> -c ...`.
#    - Éxito (METRICS M3): la salida del PoC contiene
#      uid=0(root) O aparece una entrada NUEVA en /root/ (marcador). El
#      criterio es dual y no exige que el PoC imprima nada especial.
#
#  Salida (STDOUT — TSV, lo consume /api/benchmark; contrato completo en
#  docs/METRICS.md §5):
#    POCDIR\t<directorio>                              (siempre, primera línea)
#    POC\t<nombre>                                     (sólo modo --check, una por PoC)
#    POC_NO_DISPONIBLE                                 (ambos modos, si no hay *.sh)
#    B\t<iter> <exito 0|1> <ms> <estado_final> <poc>   (una por iteración)
#    BAGG\t<exito> <total> <media_ms> <min_ms> <max_ms> <poc>   (una por PoC)
#
#  Extensión v2 del contrato METRICS.md §5: el nombre del PoC se agrega como
#  ÚLTIMO campo de B y BAGG (misma técnica que `scope` como campo final de las
#  líneas F del scan). Un parser escrito contra el
#  contrato v1 sigue leyendo sin cambios los primeros campos; con varios PoCs
#  el panel puede atribuir cada iteración a su CVE.
#
#  Estados por iteración:
#    EXPLOTABLE  escalada observada (uid=0(root) o marcador nuevo en /root/)
#    MITIGADO    el PoC corrió y terminó sin conseguir root
#    TIMEOUT     el PoC excedió LAB_POC_TIMEOUT (exit 124/137 de timeout(1))
#    ERROR       el arnés no pudo ejecutar el PoC (exit 125/126/127: archivo
#                ilegible, timeout/su ausentes). Cuenta como NO éxito (nunca
#                infla la tasa) y queda visible en la tabla del panel.
#
#  STDERR: log legible (progreso por iteración), mismo convenio que scan.sh.
#
#  Uso manual (host):    docker exec sudo-lab-target bash /opt/lab/scripts/benchmark.sh
#  Sonda de disponibilidad:  ... benchmark.sh --check   (la usa GET /api/poc)
#  Uso desde el panel:   botón "④ Lanzar Ataque" → POST /api/benchmark
#
#  Por qué este script requiere root (guardia espejo de foothold.sh): es el
#  ARNÉS de medición, no la vista del atacante. Necesita (a) degradar
#  privilegios con `su - <usuario>` en cada iteración y (b) leer /root/ para el
#  criterio de éxito por marcador. El PoC, en cambio, NUNCA corre como root.
# =============================================================================
set -uo pipefail
# `set -uo pipefail` SIN -e, igual que scan.sh: el benchmark debe llegar
# SIEMPRE a sus líneas B/BAGG aunque una iteración falle; los fallos se
# capturan explícitamente con '|| var=$?' y se clasifican como estado.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# ---- Guardia 1: el arnés corre como root (ver justificación en el encabezado)
if [ "$(id -u)" -ne 0 ]; then
  echo "[benchmark] ERROR: este script es el arnés de medición y requiere root." >&2
  echo "[benchmark]   Cada PoC corre como usuario raso vía 'su'; /root/ sólo es legible" >&2
  echo "[benchmark]   por root (criterio de éxito por marcador, METRICS M3)." >&2
  echo "[benchmark]   Uso correcto: docker exec sudo-lab-target \\" >&2
  echo "[benchmark]     bash /opt/lab/scripts/benchmark.sh" >&2
  exit 1
fi

# ---- Guardia 2: el usuario default del PoC debe existir ----------------------
# webuser lo crea lab/entrypoint.sh. Si no existe, todas las
# iteraciones serían ERROR sistemático: es un fallo de INFRAESTRUCTURA y como
# tal se reporta (exit != 0 → la API responde 502 con mensaje accionable).
if ! id -u webuser >/dev/null 2>&1; then
  bad "El usuario 'webuser' no existe en este contenedor (¿corrió el entrypoint?)."
  exit 1
fi

# ---- Configuración -----------------------------------------------------------
# LAB_POC_DIR: se resuelve DENTRO del contenedor.
# LAB_POC_ITERATIONS: N por defecto 5 (METRICS M3). LAB_POC_TIMEOUT: límite por
# iteración en segundos (METRICS §6: "un PoC colgado no puede
# bloquear el benchmark"). Ambos se acotan para que una mala configuración no
# cuelgue el panel (la ruta API impone además su propio timeout de request).
POC_DIR="${LAB_POC_DIR:-/opt/lab/poc}"

N="${LAB_POC_ITERATIONS:-5}"
case "$N" in ''|*[!0-9]*) warn "LAB_POC_ITERATIONS=\"$N\" no es un entero: uso 5."; N=5 ;; esac
if [ "$N" -lt 1 ]; then warn "LAB_POC_ITERATIONS=$N < 1: uso 5."; N=5; fi
if [ "$N" -gt 50 ]; then warn "LAB_POC_ITERATIONS=$N > 50: se acota a 50."; N=50; fi

T="${LAB_POC_TIMEOUT:-30}"
case "$T" in ''|*[!0-9]*) warn "LAB_POC_TIMEOUT=\"$T\" no es un entero: uso 30."; T=30 ;; esac
if [ "$T" -lt 1 ]; then warn "LAB_POC_TIMEOUT=$T < 1: uso 30."; T=30; fi
if [ "$T" -gt 300 ]; then warn "LAB_POC_TIMEOUT=$T > 300 s: se acota a 300."; T=300; fi

# ---- Descubrimiento de PoCs (cualquier archivo .sh) -------------------------
# Primer nivel del directorio, orden alfabético estable (LC_ALL=C). Se usan
# glob + array de bash: inmune a espacios en los nombres de archivo.
shopt -s nullglob
pocs=("$POC_DIR"/*.sh)
if [ "${#pocs[@]}" -gt 1 ]; then
  mapfile -t pocs < <(printf '%s\n' "${pocs[@]}" | LC_ALL=C sort)
fi

# shquote: envuelve una ruta para incrustarla con seguridad dentro del string
# de `su -c` (que vuelve a pasar por shell). Con esto, un PoC llamado
# "poc con espacio.sh" llega íntegro al comando interno.
shquote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Listado de /root/ para el criterio de éxito por marcador.
# Heurística documentada (METRICS M3): se considera éxito si aparece una
# ENTRADA NUEVA en /root/ entre el antes y el después de la iteración. En este
# contenedor nada más escribe en /root/, así que la comparación de nombres es
# suficiente y no exige que el PoC imprima nada.
root_listing() { ls -A /root 2>/dev/null | LC_ALL=C sort; }

# ---- Modo --check: sonda de disponibilidad para GET /api/poc ----------------
# NO ejecuta nada: sólo reporta qué descubrió. Una única implementación del
# descubrimiento sirve tanto al botón (habilitado/deshabilitado) como al
# benchmark real, evitando que la ruta API duplique la lógica de filtro *.sh.
if [ "${1:-}" = "--check" ]; then
  printf 'POCDIR\t%s\n' "$POC_DIR"
  if [ "${#pocs[@]}" -eq 0 ]; then
    printf 'POC_NO_DISPONIBLE\n'
  else
    for p in "${pocs[@]}"; do printf 'POC\t%s\n' "$(basename "$p")"; done
  fi
  exit 0
fi

# ---- Modo run ---------------------------------------------------------------
printf 'POCDIR\t%s\n' "$POC_DIR"

if [ "${#pocs[@]}" -eq 0 ]; then
  # Sin PoC el benchmark NO es un error — imprime el
  # marcador del glosario (METRICS §1) y termina limpio (exit 0).
  printf 'POC_NO_DISPONIBLE\n'
  warn "Sin PoCs (*.sh) en ${POC_DIR}: nada que medir (POC_NO_DISPONIBLE)."
  warn "Colocá los PoC en ese directorio (ver docs/POC.md) y volvé a intentar."
  exit 0
fi

step "Benchmark de explotación — ${#pocs[@]} PoC(s), N=$N iteración(es), timeout ${T}s"
step "Los PoC corren como usuario raso (sidecar .user); el arnés corre como root y mide cada iteración."

for poc in "${pocs[@]}"; do
  pname="$(basename "$poc")"
  exitos=0
  total_ms=0
  min_ms=-1
  max_ms=0

  step "PoC: $pname"

  # Determinar el usuario del PoC: sidecar <poc>.user (convención POC.md §3);
  # default webuser.
  POC_USER="webuser"
  if [ -f "${poc}.user" ]; then
    POC_USER="$(tr -d '[:space:]' < "${poc}.user")"
  fi

  # Pre-chequeo de LEGIBILIDAD como el usuario correspondiente
  if ! su - "$POC_USER" -c "test -r $(shquote "$poc")" 2>/dev/null; then
    warn "$pname: $POC_USER no puede leerlo (¿permisos del montaje? chmod 644). Se saltea."
    continue
  fi

  for i in $(seq 1 "$N"); do
    # Limpieza de marcadores de PoCs anteriores para evitar falsos positivos
    rm -f /tmp/pwn_32462.txt

    # t0/t1 en nanosegundos (GNU date, disponible en Debian). El tiempo de
    # reloj incluye el arranque de su+timeout+bash: es el "tiempo de escalada"
    t0="$(date +%s%N)"

    before="$(root_listing)" || before=""
    # El timeout corre DENTRO de la sesión de webuser (es el padre directo del
    # bash del PoC): al cortar, mata al PoC y no deja procesos huérfanos.
    # -k 5: gracia de 5 s con SIGKILL si el PoC ignora SIGTERM.
    # '|| su_rc=$?' captura el fallo esperado sin que pipefail aborte el bucle.
    out="$(su - "$POC_USER" -c "timeout -k 5 ${T} bash $(shquote "$poc")" 2>&1)" && su_rc=0 || su_rc=$?
    after="$(root_listing)" || after=""

    t1="$(date +%s%N)"
    ms=$(( (t1 - t0) / 1000000 ))
    total_ms=$(( total_ms + ms ))
    if [ "$min_ms" -lt 0 ]; then min_ms=$ms; fi
    if [ "$ms" -lt "$min_ms" ]; then min_ms=$ms; fi
    if [ "$ms" -gt "$max_ms" ]; then max_ms=$ms; fi

    # Clasificación (orden IMPORTA: primero éxito, luego timeout, luego arnés):
    #   1. uid=0(root) en la salida O entrada nueva en /root/  → EXPLOTABLE.
    #      El éxito por salida prevalece aunque el exit code sea raro: un PoC
    #      puede conseguir root y salir con código distinto de 0.
    #   2. exit 124 (SIGTERM de timeout) / 137 (SIGKILL de -k)  → TIMEOUT.
    #   3. exit 125/126/127 (timeout/su/bash no pudieron ejecutar) → ERROR.
    #   4. resto: el PoC corrió y no consiguió root              → MITIGADO.
    if [[ "$out" == *'uid=0(root)'* ]] || [ "$after" != "$before" ]; then
      estado=EXPLOTABLE
      exitos=$((exitos + 1))
      printf 'B\t%d\t1\t%d\t%s\t%s\n' "$i" "$ms" "$estado" "$pname"
      bad "  iter $i/$N: EXPLOTABLE (${ms} ms) — escalada a root observada"
      # Evidencia para el registro del panel: primeras líneas de la salida
      # (recién ahora se recortan: primero se capturó la salida COMPLETA, mismo
      # criterio anti-SIGPIPE+pipefail que fijó foothold.sh).
      if [ -n "$out" ]; then
        printf '%s\n' "$out" | head -n 3 | cut -c1-120 | sed 's/^/[benchmark]     | /' >&2
      fi
    else
      case "$su_rc" in
        124|137)
          estado=TIMEOUT
          printf 'B\t%d\t0\t%d\t%s\t%s\n' "$i" "$ms" "$estado" "$pname"
          warn "  iter $i/$N: TIMEOUT (${ms} ms) — el PoC excedió ${T}s"
          ;;
        125|126|127)
          estado=ERROR
          printf 'B\t%d\t0\t%d\t%s\t%s\n' "$i" "$ms" "$estado" "$pname"
          warn "  iter $i/$N: ERROR (${ms} ms) — el arnés no pudo ejecutar el PoC (exit $su_rc)"
          ;;
        *)
          estado=MITIGADO
          printf 'B\t%d\t0\t%d\t%s\t%s\n' "$i" "$ms" "$estado" "$pname"
          ok "  iter $i/$N: MITIGADO (${ms} ms) — sin escalada"
          ;;
      esac
    fi
  done

  # Línea agregada. La media se emite con una décima: se calcula
  # en décimas de ms con aritmética entera de bash (sin awk ni flotantes):
  #   media_décimas = total_ms * 10 / N ; se imprime como X.Y
  media_t=$(( total_ms * 10 / N ))
  printf 'BAGG\t%d\t%d\t%d.%d\t%d\t%d\t%s\n' \
    "$exitos" "$N" "$(( media_t / 10 ))" "$(( media_t % 10 ))" "$min_ms" "$max_ms" "$pname"
  step "Resumen $pname: $exitos/$N exitosos · media $(( media_t / 10 )).$(( media_t % 10 )) ms · min $min_ms · max $max_ms ms"
done

step "Benchmark terminado. Aplicá mitigaciones (③) y repetí para comparar antes/después (M5)."
