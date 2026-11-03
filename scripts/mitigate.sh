#!/usr/bin/env bash
# =============================================================================
#  mitigate.sh — Motor de MITIGACIÓN (controles compensatorios)
# -----------------------------------------------------------------------------
#  Aplica, SIN actualizar sudo, las contramedidas que cierran las precondiciones
#  de explotación detectadas por scan.sh:
#
#    1) Endurece sudoers: elimina la negación en Runas (2019), las reglas de
#       sudoedit amplias (2023) y la regla calificada por host remoto (2462).
#       Con eso CVE-2025-32462 pasa a MITIGADO.
#    2) Remonta /tmp como noexec,nosuid,nodev: defensa en profundidad. NO cierra
#       CVE-2025-32463: el directorio chroot puede estar en cualquier ruta
#       escribible, asi que sigue EXPLOTABLE hasta actualizar sudo a 1.9.17p1+.
#
#  Es puramente defensivo. Tras aplicarlo, volvé a correr scan.sh para comparar.
#
#  Flags:
#    --reset   restaura el sudoers de laboratorio original (vuelve a vulnerable).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

HARDENED=/etc/sudoers.d/lab

if [ "${1:-}" = "--reset" ]; then
  step "Restaurando estado vulnerable del laboratorio"
  if [ -f /opt/lab/sudoers.lab.orig ]; then
    install -m 0440 /opt/lab/sudoers.lab.orig "$HARDENED"
    ok "sudoers de laboratorio restaurado"
  fi
  mount -o remount,exec /tmp 2>/dev/null && ok "/tmp remontado exec" || warn "no se pudo remontar /tmp"
  echo "RESET_OK"
  exit 0
fi

step "Aplicando mitigaciones (controles compensatorios, sin actualizar sudo)"

# ---- 1) Hardening de sudoers ------------------------------------------------
log "Reescribiendo $HARDENED con reglas de mínimo privilegio"
TMPF="$(mktemp)"
cat > "$TMPF" <<'EOF'
# sudoers de laboratorio — ENDURECIDO por mitigate.sh
Defaults !requiretty

# 2019: se elimina la negacion. 'operador' corre vi solo como su propio usuario.
operador ALL=(operador) /usr/bin/vi

# 2025-32462: se elimina la regla calificada por un host remoto. No se la reemplaza
# por ALL: eso daria mas privilegio (less permite abrir una shell).

# 2023-22809: se elimina la regla de sudoedit (ya no hay superficie EDITOR).
EOF

if visudo -cf "$TMPF" >/dev/null 2>&1; then
  install -m 0440 "$TMPF" "$HARDENED"
  ok "sudoers endurecido e instalado"
else
  bad "el sudoers endurecido no validó; no se aplicaron cambios de sudoers"
fi
rm -f "$TMPF"

# ---- 2) /tmp noexec ---------------------------------------------------------
log "Remontando /tmp como noexec,nosuid,nodev (defensa en profundidad)"
if mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null; then
  ok "/tmp ahora es noexec (no cierra CVE-2025-32463)"
else
  warn "no se pudo remontar /tmp (¿falta CAP SYS_ADMIN?). Control no aplicado."
fi

# ---- Recordatorio de la mitigación completa ---------------------------------
warn "CVE-2025-32463 sigue EXPLOTABLE: ningun control compensatorio la cierra."
warn "La correccion real de 2025-32462/32463 es actualizar a sudo 1.9.17p1+."

echo "MITIGATE_OK"
step "Mitigaciones aplicadas. Volvé a diagnosticar para verificar."
