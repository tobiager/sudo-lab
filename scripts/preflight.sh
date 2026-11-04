#!/usr/bin/env bash
# =============================================================================
#  preflight.sh — Verificación de PRERREQUISITOS del host
# -----------------------------------------------------------------------------
#  Propósito: que "que cualquiera ejecute el lab desde cero sin adivinar nada"
#  empiece por un chequeo honesto de la máquina. Se corre con `make preflight`
#  (o `bash scripts/preflight.sh`) ANTES de `make up`.
#
#  Qué verifica:
#    1. docker instalado (CLI)                       → FALLO si falta
#    2. daemon de Docker accesible (docker info)     → FALLO si no responde
#    3. docker compose v2 (plugin, no docker-compose v1) → FALLO si falta
#    4. docker-compose.yml presente en la raíz       → FALLO si falta
#    5. node >= 22 LTS (sólo afecta al dashboard)    → AVISO si falta o es viejo
#
#  Semántica de severidad:
#    - Docker/Compose son la BASE del laboratorio: si faltan, se termina con
#      error (exit 1) y mensaje accionable.
#    - Node es necesario sólo para el dashboard: si falta o es < 22, el labora-
#      torio bash sigue funcionando, así que se AVISA (no se aborta). Con
#      `--strict` los avisos se tratan como fallos (útil en CI o demo final).
#
#  Salida: log legible con OK / AVISO / FALLO por ítem + resumen.
#  Exit codes: 0 = prerequisitos duros cumplidos · 1 = algún FALLO.
# =============================================================================
set -uo pipefail

STRICT=0
if [ "${1:-}" = "--strict" ]; then STRICT=1; fi
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Uso: scripts/preflight.sh [--strict]"
  echo "  --strict  trata los AVISOS (p. ej. Node < 22) como fallos (exit 1)."
  exit 0
fi

FALLOS=0
AVISOS=0

ok()    { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
aviso() { printf '  \033[33mAVISO\033[0m %s\n' "$1"; AVISOS=$((AVISOS+1)); }
fallo() { printf '  \033[31mFALLO\033[0m %s\n' "$1"; FALLOS=$((FALLOS+1)); }

# fail_or_warn: aplica la semántica --strict a los chequeos "blandos".
fail_or_warn() { # <mensaje>
  if [ "$STRICT" -eq 1 ]; then fallo "$1"; else aviso "$1"; fi
}

echo "== Preflight del laboratorio sudo-lab =="
echo "   (--strict: $([ "$STRICT" -eq 1 ] && echo 'activado' || echo 'desactivado'))"

# ---- 1) Docker CLI ----------------------------------------------------------
echo "[1/5] Docker CLI"
if command -v docker >/dev/null 2>&1; then
  ok "docker presente: $(docker --version 2>/dev/null || echo 'versión no informada')"
else
  fallo "docker no está instalado. Instalá Docker Engine/Desktop (https://docs.docker.com/get-docker/) y volvé a correr."
fi

# ---- 2) Daemon corriendo ----------------------------------------------------
# Sólo tiene sentido si el CLI existe: sin binario el diagnostico ya falló.
echo "[2/5] Daemon de Docker"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "daemon accesible (Docker corriendo)"
  else
    fallo "el daemon de Docker no responde. ¿Arrancaste Docker Desktop / el servicio docker? (systemctl start docker)"
  fi
else
  aviso "no se puede chequear el daemon: falta el CLI de docker."
fi

# ---- 3) Docker Compose v2 ---------------------------------------------------
# El lab usa `docker compose` (plugin v2): `make up` depende de --wait, que la
# v1 (binario docker-compose, ya EOL) no tiene.
echo "[3/5] Docker Compose"
if docker compose version >/dev/null 2>&1; then
  ok "compose v2 presente: $(docker compose version --short 2>/dev/null || echo 'v2')"
else
  if command -v docker-compose >/dev/null 2>&1; then
    fallo "sólo se detectó docker-compose v1 (EOL). Instalá el plugin v2: apt-get install docker-compose-plugin."
  else
    fallo "docker compose v2 no está disponible. Instalá el plugin: apt-get install docker-compose-plugin."
  fi
fi

# ---- 4) Archivos del repo ---------------------------------------------------
# El preflight se corre desde la raíz del repo (make lo garantiza); si alguien
# lo invoca desde otro lado, el error debe ser claro y no un build roto.
echo "[4/5] Archivos del laboratorio"
if [ -f docker-compose.yml ]; then
  ok "docker-compose.yml encontrado en la raíz"
else
  fallo "no se encontró docker-compose.yml: corré el preflight desde la raíz del repositorio."
fi

# ---- 5) Node >= 22 ----------------------------------------------------------
# Node 22 LTS (soportada hasta 2027-04). Sin Node el lab bash funciona igual:
# por eso es AVISO y no FALLO (con --strict se eleva).
echo "[5/5] Node.js >= 22 (dashboard)"
if command -v node >/dev/null 2>&1; then
  NODE_MAJOR="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
  if [ -n "$NODE_MAJOR" ] && [ "$NODE_MAJOR" -ge 22 ] 2>/dev/null; then
    ok "node $(node -v) cumple el requisito (>= 22)"
  else
    fail_or_warn "node $(node -v 2>/dev/null || echo '?') es anterior a 22 LTS: el dashboard puede fallar. Cambiá con 'nvm use' (versión fijada en dashboard/.nvmrc)."
  fi
else
  fail_or_warn "node no está instalado: el dashboard no podrá ejecutarse (el lab bash sigue funcionando). Instalá Node 22 LTS (recomendado: nvm; versión fijada en dashboard/.nvmrc)."
fi

# ---- Resumen ----------------------------------------------------------------
echo "------------------------------------------------------------"
if [ "$FALLOS" -gt 0 ]; then
  echo "Preflight FALLIDO: $FALLOS fallo(s), $AVISOS aviso(s). Corregí los FALLO y volvé a correr."
  exit 1
fi
if [ "$AVISOS" -gt 0 ]; then
  echo "Preflight con avisos: 0 fallos, $AVISOS aviso(s). El lab bash está listo; el dashboard puede no estarlo."
  [ "$STRICT" -eq 1 ] && exit 1
  exit 0
fi
echo "Preflight OK: la máquina cumple todos los prerequisitos. Seguí con 'make up'."
exit 0
