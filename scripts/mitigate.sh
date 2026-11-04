#!/usr/bin/env bash
# =============================================================================
#  mitigate.sh — Motor de MITIGACIÓN (controles compensatorios)
# -----------------------------------------------------------------------------
#  Aplica, SIN actualizar sudo, las contramedidas que cierran las precondiciones
#  de explotación detectadas por scan.sh.
#
#  REGLA DE ORO: el hardening NUNCA agrega reglas de sudoers, sólo elimina o
#  restringe (especificación en SECURITY.md §2.5). Este script lo verifica
#  mecánicamente: difunde el conjunto de reglas antes/después y, si el
#  resultado introdujera algún permiso nuevo, revierte con los backups y
#  aborta.
#
#  Controles y decisiones de diseño:
#    1) El sudoers endurecido ELIMINA la regla de 32462 sin redeclararla:
#       redeclararla (menos aún con (ALL)) reconstruiría una escalada, porque
#       `less` permite escape de shell (!cmd).
#    2) CVE-2025-32463 NO tiene mitigación de configuración real: cualquier
#       cuenta local puede disparar `sudo --chroot` sin que exista ninguna
#       regla de sudoers que lo permita. Por las dudas, igual se barre
#       /etc/sudoers y /etc/sudoers.d/* COMENTANDO (no borrando) las líneas
#       con firma de chroot (CHROOT=, --chroot, -R) que alguien hubiera
#       configurado explícitamente, con backup previo en
#       /opt/lab/backups/<ts>/ y validación con `visudo -cf` antes de
#       instalar — pero esto es defensa en profundidad, no cierra la CVE.
#       PROHIBIDO añadir `Defaults !use_chroot`: esa opción no existe en
#       sudoers y rompería la validación. El `chmod u-s /usr/bin/sudo` queda
#       documentado como opción extrema, NO aplicada por defecto (rompería
#       el propio lab).
#    3) Mitigación canónica de CVE-2025-32462: eliminar las reglas calificadas
#       por host remoto; NUNCA reemplazarlas por ALL (eso ampliaría la regla a
#       todos los hosts).
#    4) Límites del control /tmp noexec, documentados abajo: sólo cubre
#       /tmp; /dev/shm, /var/tmp y los homes siguen ejecutables, y ninguno de
#       ellos cierra CVE-2025-32463 (el directorio chroot puede ser cualquiera).
#    5) Chequeo post-mitigación de /dev/shm: advierte si queda ejecutable.
#    6) `visudo -c` GLOBAL (conjunto completo /etc/sudoers + sudoers.d/*)
#       al final del hardening y también en --reset.
#    7) Idempotencia: segunda corrida => exit 0 sin cambios de reglas ni
#       degradación; difunde reglas antes/después y aborta si agregara
#       alguna línea de permisos (con excepción explícita: la línea que
#       RESTRINGE un permiso que el mismo usuario ya tenía, p.ej.
#       `operador ALL=(operador) /usr/bin/vi` restringe
#       `operador ALL=(ALL, !root) /usr/bin/vi`).
#
#  Flags:
#    --reset   restaura el sudoers de laboratorio original (vuelve a vulnerable).
# ==============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

HARDENED=/etc/sudoers.d/lab
ORIG=/opt/lab/sudoers.lab.orig
BACKUP_ROOT=/opt/lab/backups
TS="$(date +%Y%m%d-%H%M%S)"

# ---- utilidades -------------------------------------------------------------

# Snapshot ordenado y deduplicado del conjunto de reglas activas (sin
# comentarios). Mismo alcance que las señales de scan.sh: no sigue includes
# anidados ni expande alias.
rules_snapshot() { sudoers_rules | LC_ALL=C sort | uniq; }

# ¿La línea tiene firma de uso de chroot (CVE-2025-32463)?
# Firmas buscadas: 'CHROOT=' (Defaults/alias), '--chroot' y '-R' usada como flag
# de sudo. El patrón de -R va acotado por separadores para no marcar, p.ej.,
# '-Rv' de otro comando. Ante la duda, se marca: es un control conservador.
chroot_sig_line() {
  printf '%s\n' "$1" | grep -qE 'CHROOT=|--chroot|(^|[[:space:]",=])-R([[:space:]",=]|$)'
}

# ¿La línea "agregada" es en realidad una RESTRICCIÓN de un permiso que
# el MISMO usuario ya tenía? Es el único caso en que una línea nueva no viola
# la regla de oro. Se exige que TODAS las cláusulas (host, runas) de la línea
# agregada queden cubiertas por ALGUNA línea previa del mismo usuario con el
# MISMO comando:
#   - host agregado ⊆ host previo (un host concreto está cubierto por ALL;
#     al revés NO: redeclarar 'host_remoto' como 'ALL' amplía y viola — es
#     exactamente la regresión que esto detecta), y
#   - cada usuario de runas agregado ⊆ runas previo ('ALL' previo cubre a
#     cualquier usuario salvo que lo niegue explícitamente, p.ej. '!root':
#     conceder (root) cuando antes había (ALL, !root) es una AMPLIACIÓN).
# Un `Defaults` nuevo nunca es restricción. Limitaciones: comparación literal
# de la especificación de comando; no expande alias (mismo alcance que
# sudoers_rules).
runas_token_covered() { # <token> <lista_runas_previa>
  local tok="$1" list="$2"
  printf '%s\n' "$list" | grep -qE "(^|[[:space:],])${tok}([[:space:],]|$)" && return 0
  if printf '%s\n' "$list" | grep -qE '(^|[[:space:],])ALL([[:space:],]|$)'; then
    printf '%s\n' "$list" | grep -qE "(^|[[:space:],])!${tok}([[:space:],]|$)" && return 1
    return 0
  fi
  return 1
}

is_restriction() { # <linea_agregada>   (usa $BEFORE global)
  local line="$1" u hosts runas cmd
  case "$line" in Defaults*) return 1;; esac
  local re='^([^[:space:]]+)[[:space:]]+([^=[:space:]]+)=\(([^)]*)\)[[:space:]]+(.+)$'
  [[ "$line" =~ $re ]] || return 1   # sin especificación (host,runas): conservador => no es restricción
  u="${BASH_REMATCH[1]}"; hosts="${BASH_REMATCH[2]}"; runas="${BASH_REMATCH[3]}"; cmd="${BASH_REMATCH[4]}"

  local h tok bline bh br found ok all=1
  local hlist rlist
  IFS=',' read -ra hlist <<< "$hosts"
  for h in "${hlist[@]}"; do
    h="$(printf '%s' "$h" | tr -d '[:space:]')"
    [ -n "$h" ] || continue
    found=0
    while IFS= read -r bline; do
      [ -z "$bline" ] && continue
      [[ "$bline" =~ $re ]] || continue
      [ "${BASH_REMATCH[1]}" = "$u" ] || continue
      [ "${BASH_REMATCH[4]}" = "$cmd" ] || continue
      bh="${BASH_REMATCH[2]}"; br="${BASH_REMATCH[3]}"
      [ "$bh" = "ALL" ] || [ "$bh" = "$h" ] || continue
      ok=1
      IFS=',' read -ra rlist <<< "$runas"
      for tok in "${rlist[@]}"; do
        tok="$(printf '%s' "$tok" | tr -d '[:space:]')"
        [ -n "$tok" ] || continue
        if ! runas_token_covered "$tok" "$br"; then ok=0; break; fi
      done
      if [ "$ok" -eq 1 ]; then found=1; break; fi
    done <<< "$BEFORE"
    [ "$found" -eq 1 ] || { all=0; break; }
  done
  [ "$all" -eq 1 ] && return 0
  return 1
}

# Copia el archivo que se va a modificar al backup de esta corrida.
# Estructura: $BACKUP_ROOT/<ts>/<ruta-absoluta-del-archivo>.
backup_file() { # <archivo>
  local f="$1" dest
  dest="${BACKUP_ROOT}/${TS}$(dirname "$f")"
  mkdir -p "$dest"
  install -m 0600 "$f" "${dest}/$(basename "$f")"
  ok "backup: $f -> ${dest}/$(basename "$f")"
}

# Rollback: restaura, desde los backups de ESTA corrida, todo lo que se
# haya modificado. Se usa si el hardening agregara permisos o si `visudo -c`
# global fallara al cierre.
rollback() {
  local bdir="${BACKUP_ROOT}/${TS}" b rel
  [ -d "$bdir" ] || return 0
  while IFS= read -r b; do
    rel="${b#"$bdir"}"
    install -m 0440 "$b" "$rel" 2>/dev/null || cp -p "$b" "$rel"
    ok "restaurado: $rel"
  done < <(find "$bdir" -type f)
  if visudo -c >/dev/null 2>&1; then
    ok "visudo -c global tras rollback: OK"
  else
    bad "visudo -c global tras rollback: FALLO — revisar ${bdir}"
  fi
}

# ---- modo --reset -----------------------------------------------------------
if [ "${1:-}" = "--reset" ]; then
  step "Restaurando estado vulnerable del laboratorio"
  if [ -f "$ORIG" ]; then
    install -m 0440 "$ORIG" "$HARDENED"
    ok "sudoers de laboratorio restaurado"
  fi
  mount -o remount,exec /tmp 2>/dev/null && ok "/tmp remontado exec" || warn "no se pudo remontar /tmp"
  # visudo -c GLOBAL también en --reset: el estado restaurado debe
  # ser válido para TODO el conjunto, no sólo para el archivo de lab.
  if visudo -c >/dev/null 2>&1; then
    ok "visudo -c global: OK"
  else
    bad "visudo -c global: FALLO tras restaurar"
    visudo -c 2>&1 | sed 's/^/    /' >&2
    echo "RESET_FAIL"
    exit 1
  fi
  echo "RESET_OK"
  exit 0
fi

step "Aplicando mitigaciones (controles compensatorios, sin actualizar sudo)"

# Snapshot ANTES de tocar nada: base de la verificación de idempotencia
# y de la regla de oro. Se difunde por STDERR (el STDOUT es para el dashboard).
BEFORE="$(rules_snapshot)"
log "Reglas activas ANTES: $(printf '%s\n' "$BEFORE" | grep -c .) línea(s)"
printf '%s\n' "$BEFORE" | sed 's/^/    antes   | /' >&2

# ---- 1) Barrido anti-chroot canónico ----------------------------------------
# Comenta (no borra) las líneas con firma de chroot en /etc/sudoers y
# /etc/sudoers.d/*, con backup y validación previa de cada archivo.
# Nota: NO se añade ningún `Defaults !use_chroot` (no existe en sudoers).
log "Barrido de firmas de chroot en /etc/sudoers y /etc/sudoers.d/* (CVE-2025-32463)"
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  # Prefiltro con chroot_sig_line (fuente única de la firma).
  tiene_firma=0
  while IFS= read -r l; do
    if chroot_sig_line "$l"; then tiene_firma=1; break; fi
  done < "$f"
  [ "$tiene_firma" -eq 1 ] || continue
  log "Líneas con firma de chroot en $f: comentando (mitigación canónica 32463)"
  cand="$(mktemp)"
  # Comenta sólo las líneas NO comentadas que matcheen la firma.
  # (Mismo patrón que chroot_sig_line: mantener ambos sincronizados.)
  awk '($0 !~ /^[[:space:]]*#/) && ($0 ~ /CHROOT=|--chroot|(^|[[:space:]",=])-R([[:space:]",=]|$)/) \
        { print "# [mitigate 32463] " $0; next } { print }' "$f" > "$cand"
  if cmp -s "$f" "$cand"; then
    rm -f "$cand"                 # ya estaba todo comentado (re-corrida)
    continue
  fi
  if visudo -cf "$cand" >/dev/null 2>&1; then
    backup_file "$f"
    install -m 0440 "$cand" "$f"
    ok "$f: líneas de chroot comentadas; visudo -cf OK"
  else
    # Validación previa falló: NO se instala nada para ese archivo.
    bad "$f: el resultado de comentar no validó; archivo SIN cambios"
    warn "Editá manualmente con visudo usando el backup ${BACKUP_ROOT}/${TS} si corresponde."
  fi
  rm -f "$cand"
done

# ---- 2) Reescritura del sudoers de laboratorio -------------------------------
# Bloque endurecido objetivo. Puntos clave:
#   - la regla de 32462 NO se redeclara (menos aún con (ALL));
#   - la regla calificada por host remoto se elimina; no se reemplaza;
#   - `Defaults !requiretty` ya existía en el sudoers de lab: no es una regla
#     nueva (regla de oro).
log "Reescribiendo $HARDENED con el bloque endurecido del laboratorio"
TMPF="$(mktemp)"
cat > "$TMPF" <<'EOF'
# sudoers de laboratorio — ENDURECIDO por mitigate.sh
Defaults !requiretty

# 2019: se elimina la negacion; 'operador' corre vi solo como su propio usuario.
operador ALL=(operador) /usr/bin/vi

# 2025-32462: la regla calificada por host remoto se ELIMINA.
#   No se reemplaza por ALL=(ALL): 'less' permite escape de shell (!cmd) y
#   reconstruiria una escalada a root peor que la original.

# 2023-22809: la regla de sudoedit se elimina (sin superficie EDITOR).
EOF

if visudo -cf "$TMPF" >/dev/null 2>&1; then
  if cmp -s "$HARDENED" "$TMPF"; then
    ok "$HARDENED ya estaba endurecido (sin cambios)"
  else
    backup_file "$HARDENED"
    install -m 0440 "$TMPF" "$HARDENED"
    ok "sudoers endurecido e instalado"
  fi
else
  bad "el sudoers endurecido no validó; no se aplicaron cambios de sudoers"
fi
rm -f "$TMPF"

# ---- 3) /tmp noexec ---------------------------------------------------------
# LÍMITES de este control (especificación en docs/LIMITATIONS.md L-5):
#   - Sólo cubre /tmp: /dev/shm, /var/tmp y los homes de los usuarios siguen
#     EJECUTABLES, y el directorio de chroot de CVE-2025-32463 puede ser
#     cualquiera de ellos. Por eso este control NO cierra esa CVE.
#   - Es un control compensatorio, no un parche: CVE-2025-32463 se cierra de
#     raíz actualizando a sudo 1.9.17p1+ o recompilando con --disable-chroot.
log "Remontando /tmp como noexec,nosuid,nodev (defensa en profundidad; no cierra CVE-2025-32463)"
if mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null; then
  ok "/tmp ahora es noexec (no cierra CVE-2025-32463)"
else
  warn "no se pudo remontar /tmp (¿falta CAP_SYS_ADMIN?). Control no aplicado."
fi

# ---- 4) Chequeo post-mitigación de /dev/shm ---------------------------------
# /dev/shm es el primer lugar al que migraría el staging si /tmp
# queda noexec. Si sigue ejecutable, se advierte: el control de /tmp es parcial
# (límite L-5 de docs/LIMITATIONS.md).
if findmnt -no OPTIONS /dev/shm >/dev/null 2>&1; then
  if findmnt -no OPTIONS /dev/shm | grep -qw noexec; then
    ok "/dev/shm ya es noexec"
  else
    warn "/dev/shm sigue EJECUTABLE: el staging del .so puede migrar allí (límite del control /tmp noexec, L-5)."
  fi
fi

# ---- 5) Validación global -----------------------------------------------------
# `visudo -c` valida el CONJUNTO completo (/etc/sudoers + /etc/sudoers.d/*), no
# sólo los archivos editados. Si falla, se revierte todo con los backups.
if visudo -c >/dev/null 2>&1; then
  ok "visudo -c global: OK"
else
  bad "visudo -c global: FALLO — revirtiendo al estado previo"
  visudo -c 2>&1 | sed 's/^/    /' >&2
  rollback
  echo "MITIGATE_FAIL"
  exit 1
fi

# ---- 6) Idempotencia y regla de oro ------------------------------------------
AFTER="$(rules_snapshot)"
log "Reglas activas DESPUÉS: $(printf '%s\n' "$AFTER" | grep -c .) línea(s)"
printf '%s\n' "$AFTER" | sed 's/^/    despues | /' >&2

ADDED="$(comm -13 <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER"))"
REMOVED="$(comm -23 <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER"))"

VIOLATIONS=""
if [ -n "$ADDED" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if is_restriction "$line"; then
      warn "línea RESTRINGIDA de un permiso preexistente (permitida): $line"
    else
      VIOLATIONS+="$line"$'\n'
    fi
  done <<< "$ADDED"
fi

if [ -n "$VIOLATIONS" ]; then
  bad "VIOLACIÓN DE LA REGLA DE ORO: el hardening agregó permisos nuevos:"
  printf '%s\n' "$VIOLATIONS" | sed 's/^/    + /' >&2
  bad "Revirtiendo al estado previo (backups en ${BACKUP_ROOT}/${TS})"
  rollback
  echo "MITIGATE_FAIL"
  exit 1
fi

if [ -z "$ADDED" ] && [ -z "$REMOVED" ]; then
  ok "Idempotencia: sin cambios en el conjunto de reglas (re-corrida sin efecto)"
else
  if [ -n "$REMOVED" ]; then
    log "Reglas eliminadas por el hardening:"
    printf '%s\n' "$REMOVED" | sed 's/^/    - /' >&2
  fi
fi

# ---- Recordatorio de la mitigación completa ---------------------------------
warn "CVE-2025-32463 sigue EXPLOTABLE: ningun control compensatorio la cierra (ni este sudoers ni /tmp noexec)."
warn "Recordá: la mitigación COMPLETA de 2025-32462/32463 es actualizar a sudo 1.9.17p1+."
warn "Estos son controles compensatorios para entornos legacy que no pueden parchear."
warn "Opción extrema NO aplicada por defecto: chmod u-s /usr/bin/sudo (rompería el propio lab)."

echo "MITIGATE_OK"
step "Mitigaciones aplicadas. Volvé a diagnosticar para verificar."
exit 0
