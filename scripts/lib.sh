#!/usr/bin/env bash
# =============================================================================
#  lib.sh — utilidades compartidas por scan.sh y mitigate.sh
#  - Logging con color hacia STDERR (los logs van a stderr; STDOUT es la salida
#    máquina que consume el dashboard).
#  - Comparador de versiones de sudo que entiende el sufijo de patch 'pN'.
# =============================================================================

# ---- Logging (STDERR) -------------------------------------------------------
if [ -t 2 ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
  C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'
else
  C_RESET=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""
fi

log()   { echo "${C_DIM}[*]${C_RESET} $*" >&2; }
ok()    { echo "${C_GRN}[+]${C_RESET} $*" >&2; }
warn()  { echo "${C_YEL}[!]${C_RESET} $*" >&2; }
bad()   { echo "${C_RED}[x]${C_RESET} $*" >&2; }
step()  { echo "${C_BLU}==>${C_RESET} $*" >&2; }

# ---- Versión de sudo --------------------------------------------------------
# Devuelve la versión instalada, p.ej. "1.9.15" o "1.9.17p1".
sudo_version() {
  sudo --version 2>/dev/null | head -1 \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1
}

# Normaliza una versión a una clave numérica comparable.
# 1.9.17    -> 001009017000
# 1.9.17p1  -> 001009017001
# 1.8.31p2  -> 001008031002
ver_key() {
  local v="$1" maj min rest pat p
  v="$(echo "$v" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)"
  [ -z "$v" ] && { echo "000000000000"; return; }
  maj="${v%%.*}"; rest="${v#*.}"
  min="${rest%%.*}"; rest="${rest#*.}"      # rest = "17" | "17p1" | "31p2"
  pat="${rest%%p*}"
  if [[ "$rest" == *p* ]]; then p="${rest#*p}"; else p=0; fi
  printf "%03d%03d%03d%03d" "$maj" "$min" "${pat:-0}" "${p:-0}"
}

ver_lt() { [ "$(ver_key "$1")" -lt "$(ver_key "$2")" ]; }   # $1 <  $2
ver_ge() { [ "$(ver_key "$1")" -ge "$(ver_key "$2")" ]; }   # $1 >= $2
ver_le() { [ "$(ver_key "$1")" -le "$(ver_key "$2")" ]; }   # $1 <= $2

# ¿$1 está dentro de [$2, $3] inclusive?
ver_in_range() { ver_ge "$1" "$2" && ver_le "$1" "$3"; }

# ---- Inspección de sudoers --------------------------------------------------
# Imprime (stdout) todas las líneas de reglas activas, sin comentarios.
sudoers_rules() {
  grep -hvE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true
}
