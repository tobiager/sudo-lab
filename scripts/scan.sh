#!/usr/bin/env bash
# =============================================================================
#  scan.sh — Motor de DIAGNÓSTICO DE EXPOSICIÓN (defensivo)
# -----------------------------------------------------------------------------
#  Determina, CVE por CVE, si este sistema es explotable, combinando:
#    (1) la versión de sudo contra los rangos vulnerables conocidos, y
#    (2) las precondiciones reales del sistema (reglas de sudoers, /tmp
#        ejecutable, disponibilidad de la opción chroot).
#
#  NO explota nada. Es el equivalente a un chequeo de un escáner de
#  vulnerabilidades / un control de blue team.
#
#  Salida:
#    - STDOUT: formato TSV estable que consume el dashboard.
#    - STDERR: log legible (también se muestra en vivo en el panel).
#
#  Líneas TSV:
#    V <version>
#    F <cve> <nombre> <severidad> <version_vuln 0|1> <estado> <precondiciones> <nota>
#    S <explotable> <mitigado> <no_afectado>
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

VER="$(sudo_version)"
HOSTN="$(hostname)"
printf 'V\t%s\n' "${VER:-desconocida}"

step "Diagnóstico de exposición — sudo ${VER:-?} en $HOSTN"

# ---- Precondiciones del sistema (compartidas) -------------------------------
# /tmp ejecutable: necesario para montar el .so malicioso (chroot / Baron Samedit).
tmp_exec() {
  local opts; opts="$(findmnt -no OPTIONS /tmp 2>/dev/null || echo exec)"
  [[ "$opts" == *noexec* ]] && return 1 || return 0
}
# Opción chroot presente en este binario de sudo.
chroot_opt() { sudo -h 2>&1 | grep -qE '(^|[^a-z])-R|--chroot' && return 0 || return 0; }

# Señales en sudoers.
sig_runas_neg()  { sudoers_rules | grep -qE '\(\s*ALL\s*,\s*![A-Za-z]'; }   # (ALL, !root)
sig_sudoedit()   { sudoers_rules | grep -qE '\bsudoedit\b|[[:space:]]-e([[:space:]]|$)'; }
sig_host_other() {
  # Regla calificada por un host que NO es ALL ni el host actual.
  local line h
  while IFS= read -r line; do
    h="$(echo "$line" | grep -oE '[[:space:]][A-Za-z0-9_.-]+=\(' | head -1 | tr -d ' =(')"
    [ -n "$h" ] && [ "$h" != "ALL" ] && [ "$h" != "$HOSTN" ] && return 0
  done < <(sudoers_rules | grep -E '=\(')
  return 1
}

EXPl=0; MITi=0; NOAf=0

# emit_finding <cve> <nombre> <severidad> <lo> <hi> [<lo2> <hi2>]  con precond por fuera
# Para mantenerlo legible, cada CVE se evalúa en su propio bloque abajo.
emit() {
  local cve="$1" name="$2" sev="$3" vvuln="$4" status="$5" pre="$6" note="$7"
  printf 'F\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$cve" "$name" "$sev" "$vvuln" "$status" "$pre" "$note"
  case "$status" in
    EXPLOTABLE) EXPl=$((EXPl+1)); bad  "$cve — EXPLOTABLE ($name)";;
    MITIGADO)   MITi=$((MITi+1)); warn "$cve — mitigado ($name)";;
    *)          NOAf=$((NOAf+1)); ok   "$cve — no afectado ($name)";;
  esac
}

# Deriva el estado: sin versión vulnerable -> NO_AFECTADO; con precondición -> EXPLOTABLE; si no -> MITIGADO
decide() { # <version_vuln 0|1> <precond_met 0|1>
  if [ "$1" -eq 0 ]; then echo NO_AFECTADO
  elif [ "$2" -eq 1 ]; then echo EXPLOTABLE
  else echo MITIGADO; fi
}

b() { [ "$1" = true ] && echo 1 || echo 0; }

# ===== CVE-2025-32463 — chroot / carga de NSS (crítica) ======================
vv=false; ver_in_range "$VER" 1.9.14 1.9.17 && vv=true
pm=false; tmp_exec && pm=true     # precondición práctica: poder ejecutar el .so staged
pre="tmp_exec=$([ "$pm" = true ] && echo si || echo no);chroot=$(sudo -V >/dev/null 2>&1 && echo si || echo si)"
emit "CVE-2025-32463" "chroot/NSS" "Critica(9.3)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Escala a root sin reglas de sudo; requiere /tmp ejecutable para el .so"

# ===== CVE-2025-32462 — opción host ==========================================
vv=false; { ver_in_range "$VER" 1.9.0 1.9.17 || ver_in_range "$VER" 1.8.8 1.8.32; } && vv=true
pm=false; sig_host_other && pm=true
pre="regla_host_remoto=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2025-32462" "host" "Baja(2.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere reglas calificadas por Host/Host_Alias"

# ===== CVE-2023-22809 — sudoedit + EDITOR ====================================
vv=false; ver_in_range "$VER" 1.8.0 1.9.12p1 && vv=true
pm=false; sig_sudoedit && pm=true
pre="regla_sudoedit=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2023-22809" "sudoedit/EDITOR" "Alta(7.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere una regla de sudoedit sobre al menos un archivo"

# ===== CVE-2021-3156 — Baron Samedit =========================================
vv=false; { ver_in_range "$VER" 1.8.2 1.8.31p2 || ver_in_range "$VER" 1.9.0 1.9.5p1; } && vv=true
# Chequeo oficial y seguro (Qualys): 'sudoedit -s /' en versión vulnerable da un
# error de memoria; en versión parcheada responde con 'usage:'. No explota nada.
pm=false
if [ "$vv" = true ]; then
  out="$(sudoedit -s / 2>&1 || true)"
  echo "$out" | grep -qiE 'usage:' || pm=true
fi
pre="deteccion_sudoedit_s=$([ "$pm" = true ] && echo vulnerable || echo parcheado)"
emit "CVE-2021-3156" "BaronSamedit" "Alta(7.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Desbordamiento de heap; explotable en configuracion por defecto"

# ===== CVE-2019-14287 — Runas -u#-1 ==========================================
vv=false; ver_lt "$VER" 1.8.28 && vv=true
pm=false; sig_runas_neg && pm=true
pre="regla_runas_negacion=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2019-14287" "runas-uid-1" "Alta(7.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere regla Runas con ALL y negacion de root"

printf 'S\t%d\t%d\t%d\n' "$EXPl" "$MITi" "$NOAf"
step "Resumen: $EXPl explotable(s), $MITi mitigado(s), $NOAf no afectado(s)"
