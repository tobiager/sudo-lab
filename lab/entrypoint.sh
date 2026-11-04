#!/bin/bash
# =============================================================================
#  lab/entrypoint.sh — preparación del contenedor target
# -----------------------------------------------------------------------------
#  Flujo de arranque:
#    0. VALIDACIÓN GLOBAL de sudoers con `visudo -c` en DOS puntos:
#      (a) al INICIO del script, antes de tocar nada: valida el estado heredado
#          de la imagen (/etc/sudoers + los includes que ya existan). Si está
#          roto, el arranque aborta con exit 1 — el fallo es INMEDIATO y visible
#          en `docker logs`, no un comportamiento raro a mitad de la demo;
#      (b) tras instalar /etc/sudoers.d/lab: se vuelve a validar la CADENA
#          COMPLETA con el escenario ya montado (un conflicto del escenario con
#          el sudoers global, p. ej. alias duplicados, no puede pasar inadvertido).
#    1. crea los usuarios del escenario (idempotente),
#    2. instala la copia prístina `sudoers.lab.orig` como /etc/sudoers.d/lab
#       (0440, root:root) — así el contenedor vuelve al estado VULNERABLE en
#       cada arranque y `mitigate.sh --reset` tiene siempre una fuente limpia,
#    3. queda vivo con `sleep infinity` (hijo de docker-init, porque compose
#       usa `init: true`).
#  El HEALTHCHECK del Dockerfile cubre la vida del contenedor con la MISMA
#  verificación (`visudo -c -q` cada 30 s).
# =============================================================================
set -euo pipefail

log() { echo "[entrypoint] $*"; }

# ---------------------------------------------------------------------------
# (a) Validación global ANTES de cualquier modificación
#     `visudo -c` sin -f examina /etc/sudoers y TODOS los archivos del
#     includedir /etc/sudoers.d: la cadena completa. Corre como root: el
#     entrypoint no cambia de usuario en ningún punto.
# ---------------------------------------------------------------------------
if ! visudo -c; then
  echo "[entrypoint] FATAL: la configuración global de sudoers es inválida." >&2
  echo "[entrypoint]   El contenedor se detiene en lugar de arrancar con una" >&2
  echo "[entrypoint]   base rota. Revisá /etc/sudoers y /etc/sudoers.d/* en la" >&2
  echo "[entrypoint]   imagen (o el bind-mount que la haya sobrescrito)." >&2
  exit 1
fi
log "sudoers global preexistente: OK (visudo -c)"

# ---------------------------------------------------------------------------
# 1. Usuarios del escenario (idempotente: reiniciar el contenedor no duplica)
# ---------------------------------------------------------------------------
# Orden de creación => UIDs estables (los observados en la corrida registrada,
# docs/RESULTS.md §3 y §5):
#   webuser  = 1000  foothold simulado; SIN reglas de sudo a propósito
#   operador = 1001  señal de CVE-2019-14287 (regla vi con Runas (ALL, !root))
#   auditor  = 1002  señal de CVE-2025-32462 (regla clinica-legacy sobre less)
#   editor   = 1003  señal de CVE-2023-22809 (regla sudoedit sobre /etc/motd)
# Cuentas SIN contraseña (useradd las deja bloqueadas): el único acceso es
# `docker exec` / `su` desde root. Los PoC corren COMO estos usuarios, nunca
# al revés (docs/THREAT-MODEL.md, Ad1/Ad2).
ensure_user() {
  local u="$1"
  if id -u "$u" >/dev/null 2>&1; then
    log "usuario ${u} ya existe (uid $(id -u "$u"))"
  else
    useradd -m "$u"
    log "usuario ${u} creado (uid $(id -u "$u"))"
  fi
}

ensure_user webuser
ensure_user operador
ensure_user auditor
ensure_user editor

# ---------------------------------------------------------------------------
# 2. Sudoers del laboratorio (siempre desde la copia prístina de la imagen)
# ---------------------------------------------------------------------------
LAB_SUDOERS_SRC="/opt/lab/sudoers.lab.orig"
LAB_SUDOERS_DST="/etc/sudoers.d/lab"

if [ ! -r "$LAB_SUDOERS_SRC" ]; then
  echo "[entrypoint] FATAL: falta ${LAB_SUDOERS_SRC} (¿imagen mal construida?)." >&2
  exit 1
fi

install -o root -g root -m 0440 "$LAB_SUDOERS_SRC" "$LAB_SUDOERS_DST"
log "sudoers del lab instalado en ${LAB_SUDOERS_DST} (0440 root:root)"

# Validación del archivo del lab (comportamiento preexistente; se conserva
# porque el mensaje de error apunta con precisión al archivo específico).
if ! visudo -c -q -f "$LAB_SUDOERS_DST"; then
  echo "[entrypoint] FATAL: ${LAB_SUDOERS_DST} no parsea como sudoers." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# (b) Validación GLOBAL con el escenario ya montado
#     La cadena completa (/etc/sudoers + /etc/sudoers.d/*) se verifica una vez
#     más tras la instalación: es el mismo criterio que aplica mitigate.sh
#     después de su hardening, ahora también en el arranque.
# ---------------------------------------------------------------------------
if ! visudo -c; then
  echo "[entrypoint] FATAL: la cadena completa de sudoers es inválida tras" >&2
  echo "[entrypoint]   instalar ${LAB_SUDOERS_DST}." >&2
  exit 1
fi
log "cadena completa de sudoers: OK (visudo -c)"

# ---------------------------------------------------------------------------
# 3. Mantener el contenedor vivo
# ---------------------------------------------------------------------------
# Con `init: true` (compose) este sleep es HIJO de docker-init
# (tini, PID 1): las señales de `docker compose stop` llegan limpias y los
# procesos huérfanos que dejen los PoC los recolecta tini, no este sleep.
exec sleep infinity
