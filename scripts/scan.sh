#!/usr/bin/env bash
# =============================================================================
#  scan.sh — Motor de DIAGNÓSTICO DE EXPOSICIÓN (defensivo) — salida TSV v2
# -----------------------------------------------------------------------------
#  Determina, CVE por CVE, si este sistema es explotable, combinando:
#    (1) la versión de sudo contra los rangos vulnerables conocidos, y
#    (2) las precondiciones reales del sistema (reglas de sudoers, /tmp
#        ejecutable, disponibilidad de la opción chroot).
#
#  NO explota nada. Es el equivalente a un chequeo de un escáner de
#  vulnerabilidades / un control de blue team.
#
#  Decisiones de diseño (por qué cada chequeo es como es):
#    - chroot_opt() REAL: detecta -R/--chroot en la ayuda de sudo (devuelve 0
#      sólo si la capacidad existe de verdad).
#    - La precondición de CVE-2025-32463 es opcion_chroot (capacidad real del
#      binario, no depende de sudoers ni de /tmp); tmp_exec se reporta solo
#      como dato informativo, nunca decide el estado de esta CVE.
#    - decide_sudoedit(): para CVE-2021-3156 el test en vivo
#      ('sudoedit -s /', método Qualys) es AUTORIDAD sobre el rango de
#      versión: vv=1 + 'usage:' => backport de distro => NO_AFECTADO (reportar
#      MITIGADO sería incorrecto: no existe control compensatorio alguno, el
#      binario ya no es vulnerable).
#    - TSV v2: la línea F agrega el campo final scope=foco|historica
#      (consumido por parseScan, campo 8, default 'historica').
#    - sig_host_other() itera TODAS las coincidencias de cada línea: una regla
#      con varios hosts ya no puede ocultar el host remoto relevante.
#    - sig_sudoedit() matchea la palabra 'sudoedit' como COMANDO de la
#      especificación (no el flag genérico -e, que producía falsos positivos).
#    - LÍMITES de sudoers_rules() documentados junto a su uso.
#
#  Salida (STDOUT — TSV v2, formato estable que consume el dashboard;
#  contrato completo en docs/METRICS.md §5):
#    V <version>
#    F <cve> <nombre> <severidad> <version_vuln 0|1> <estado> <precondiciones> <nota> <scope>
#       scope ∈ {foco, historica}  (glosario en docs/SCOPE.md §7)
#    S <explotable> <mitigado> <no_afectado>
#  STDERR: log legible (también se muestra en vivo en el panel).
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
# /tmp ejecutable. Dato INFORMATIVO: el directorio chroot puede estar en cualquier
# ruta escribible por el usuario, asi que NO condiciona la explotabilidad.
tmp_exec() {
  local opts; opts="$(findmnt -no OPTIONS /tmp 2>/dev/null || echo exec)"
  [[ "$opts" == *noexec* ]] && return 1 || return 0
}
# [chroot_opt] Detecta la opción -R / --chroot en la ayuda de sudo: está
# presente en TODO el rango afectado por CVE-2025-32463 y desaparece si el
# binario se compiló con --disable-chroot. Devuelve 0 sólo si la capacidad
# existe de verdad.
chroot_opt() {
  sudo -h 2>&1 | grep -qE -- '(^|[[:space:]])(-R([[:space:]]|,)|--chroot=)' && return 0
  return 1
}

# ---- Señales en sudoers -----------------------------------------------------
# LÍMITES de sudoers_rules() (definida en lib.sh) — documentación:
#   - NO sigue includes anidados: sólo lee /etc/sudoers y los archivos de
#     /etc/sudoers.d/ de primer nivel; un `@includedir` dentro de sudoers.d no
#     se expande.
#   - NO expande alias (User_Alias, Host_Alias, Cmnd_Alias): una regla escrita
#     vía alias NO matchea las señales de abajo (el alias en sí puede sí).
#   Si en el futuro se agrega soporte para includes anidados o expansión de
#   alias, actualizar ESTAS señales y las equivalentes de mitigate.sh.
sig_runas_neg()  { sudoers_rules | grep -qE '\(\s*ALL\s*,\s*![A-Za-z]'; }   # (ALL, !root)

# 'sudoedit' como comando de la especificación. Un match genérico del flag -e
# producía FALSOS POSITIVOS (cualquier regla con el flag -e en los argumentos
# de un comando, p.ej. `visudo -e` o `crontab -e`, no es superficie de
# CVE-2023-22809). La superficie real es el comando pseudo sudoedit, que activa
# el camino de edición controlada por sudo.
sig_sudoedit()   { sudoers_rules | grep -qE '(^|[[:space:]])sudoedit([[:space:]]|$)'; }

# Regla calificada por un host que NO es ALL ni el host actual. Se iteran TODAS
# las coincidencias de host de cada línea (evaluar sólo la primera permitiría
# que una regla como `u hostA, srv-web=(root) cmd` ocultara el host remoto
# cuando hostA aparece primero).
sig_host_other() {
  local line h
  while IFS= read -r line; do
    while IFS= read -r h; do
      [ -n "$h" ] && [ "$h" != "ALL" ] && [ "$h" != "$HOSTN" ] && return 0
    done < <(printf '%s\n' "$line" | grep -oE '[[:space:]][A-Za-z0-9_.-]+=\(' | tr -d ' =(')
  done < <(sudoers_rules | grep -E '=\(')
  return 1
}

EXPl=0; MITi=0; NOAf=0

# emit <cve> <nombre> <severidad> <version_vuln> <estado> <precondiciones> <nota> <scope>
# TSV v2: octavo campo <scope> que clasifica el hallazgo según el
# glosario: 'foco' (CVE-2025-32463, CVE-2025-32462) o 'historica'
# (2023-22809, 2021-3156, 2019-14287).
emit() {
  local cve="$1" name="$2" sev="$3" vvuln="$4" status="$5" pre="$6" note="$7" scope="$8"
  printf 'F\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$cve" "$name" "$sev" "$vvuln" "$status" "$pre" "$note" "$scope"
  case "$status" in
    EXPLOTABLE) EXPl=$((EXPl+1)); bad  "$cve — EXPLOTABLE ($name)";;
    MITIGADO)   MITi=$((MITi+1)); warn "$cve — mitigado ($name)";;
    *)          NOAf=$((NOAf+1)); ok   "$cve — no afectado ($name)";;
  esac
}

# Deriva el estado (regla general): sin versión vulnerable -> NO_AFECTADO;
# con precondición presente -> EXPLOTABLE; si no -> MITIGADO.
decide() { # <version_vuln 0|1> <precond_met 0|1>
  if [ "$1" -eq 0 ]; then echo NO_AFECTADO
  elif [ "$2" -eq 1 ]; then echo EXPLOTABLE
  else echo MITIGADO; fi
}

# Decisión específica para CVE-2021-3156 (Baron Samedit).
# El test en vivo es autoridad sobre el rango de versión, porque las distros
# aplican backport del parche SIN cambiar el número de versión declarado:
#   vv=0                      -> NO_AFECTADO (fuera de rango)
#   vv=1 + responde 'usage:'  -> backport de distro -> NO_AFECTADO
#                                (no hay control compensatorio: el binario ya
#                                no es vulnerable)
#   vv=1 + error 'not a regular file' -> EXPLOTABLE (no requiere precondición
#                                de sudoers: la configuración por defecto alcanza)
decide_sudoedit() { # <version_vuln 0|1> <responde_usage 0|1>
  if [ "$1" -eq 0 ]; then echo NO_AFECTADO
  elif [ "$2" -eq 0 ]; then echo EXPLOTABLE
  else echo NO_AFECTADO; fi
}

b() { [ "$1" = true ] && echo 1 || echo 0; }

# ===== CVE-2025-32463 — chroot / carga de NSS (crítica) — CVE FOCO ===========
# Precondición real: versión en rango + opción --chroot disponible. NO depende de
# sudoers ni de /tmp: el directorio chroot puede ser cualquier ruta que el propio
# usuario controle (p.ej. su $HOME), así que ningún control compensatorio la
# cierra, solo el parche (ver docs/ATTACK-CHAIN.md y SECURITY.md).
vv=false; ver_in_range "$VER" 1.9.14 1.9.17 && vv=true
pm=false; chroot_opt && pm=true
pre="opcion_chroot=$([ "$pm" = true ] && echo si || echo no);tmp_exec_informativo=$(tmp_exec && echo si || echo no)"
emit "CVE-2025-32463" "chroot/NSS" "Critica(9.3)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Escala a root sin reglas de sudo; solo se corrige actualizando a 1.9.17p1+" "foco"

# ===== CVE-2025-32462 — opción host — CVE FOCO ===============================
vv=false; { ver_in_range "$VER" 1.9.0 1.9.17 || ver_in_range "$VER" 1.8.8 1.8.32; } && vv=true
pm=false; sig_host_other && pm=true
pre="regla_host_remoto=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2025-32462" "host" "Baja(2.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere reglas calificadas por Host/Host_Alias" "foco"

# ===== CVE-2023-22809 — sudoedit + EDITOR — CVE HISTÓRICA ====================
vv=false; ver_in_range "$VER" 1.8.0 1.9.12p1 && vv=true
pm=false; sig_sudoedit && pm=true
pre="regla_sudoedit=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2023-22809" "sudoedit/EDITOR" "Alta(7.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere una regla de sudoedit sobre al menos un archivo" "historica"

# ===== CVE-2021-3156 — Baron Samedit — CVE HISTÓRICA =========================
vv=false; { ver_in_range "$VER" 1.8.2 1.8.31p2 || ver_in_range "$VER" 1.9.0 1.9.5p1; } && vv=true
# Chequeo oficial y seguro (Qualys): 'sudoedit -s /' en una versión vulnerable
# responde con un error del tipo 'not a regular file'; en una versión parcheada
# (o con backport) responde con 'usage:'. No explota nada. Sólo se ejecuta si la
# versión está en rango.
responde_usage=0
if [ "$(b $vv)" -eq 1 ]; then
  out="$(su -s /bin/bash webuser -c 'sudoedit -s /' 2>&1 || true)"
  printf '%s\n' "$out" | grep -qiE 'usage:' && responde_usage=1
fi
# Etiqueta de precondición informativa para la columna <precondiciones>.
if [ "$(b $vv)" -eq 0 ]; then
  det="fuera_de_rango"
elif [ "$responde_usage" -eq 1 ]; then
  det="parcheado_backport"
else
  det="vulnerable_test_en_vivo"
fi
pre="deteccion_sudoedit_s=$det"
# El estado lo decide el TEST EN VIVO (decide_sudoedit), no sólo el
# rango de versión: así se evita el MITIGADO falso en distros con backport.
emit "CVE-2021-3156" "BaronSamedit" "Alta(7.8)" "$(b $vv)" \
     "$(decide_sudoedit "$(b $vv)" "$responde_usage")" "$pre" \
     "Desbordamiento de heap; explotable en configuracion por defecto" "historica"

# ===== CVE-2019-14287 — Runas -u#-1 — CVE HISTÓRICA ==========================
vv=false; ver_lt "$VER" 1.8.28 && vv=true
pm=false; sig_runas_neg && pm=true
pre="regla_runas_negacion=$([ "$pm" = true ] && echo si || echo no)"
emit "CVE-2019-14287" "runas-uid-1" "Alta(8.8)" "$(b $vv)" "$(decide "$(b $vv)" "$(b $pm)")" "$pre" \
     "Requiere regla Runas con ALL y negacion de root" "historica"

printf 'S\t%d\t%d\t%d\n' "$EXPl" "$MITi" "$NOAf"
step "Resumen: $EXPl explotable(s), $MITi mitigado(s), $NOAf no afectado(s)"
