#!/usr/bin/env bash
# =============================================================================
#  mitigate.sh — Motor de MITIGACIÓN (controles compensatorios)
# -----------------------------------------------------------------------------
#  Aplica, SIN actualizar sudo, las contramedidas que cierran las precondiciones
#  de explotación detectadas por scan.sh:
#
#    1) Endurece sudoers: elimina la negación en Runas (2019), las reglas de
#       sudoedit amplias (2023) y las reglas calificadas por host remoto (2462).
#    2) Remonta /tmp como noexec,nosuid,nodev: impide ejecutar el .so que las
#       técnicas de chroot (2025-32463) y Baron Samedit necesitan preparar.
#
#  Es puramente defensivo. Tras aplicarlo, volvé a correr scan.sh para ver cómo
#  los hallazgos pasan de EXPLOTABLE a MITIGADO.
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

# 2025-32462: la regla deja de estar calificada por un host remoto (ahora ALL).
auditor ALL=(ALL) /usr/bin/less

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
log "Remontando /tmp como noexec,nosuid,nodev (bloquea staging de .so)"
if mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null; then
  ok "/tmp ahora es noexec"
else
  warn "no se pudo remontar /tmp (¿falta CAP SYS_ADMIN?). Control no aplicado."
fi

# ---- Recordatorio de la mitigación completa ---------------------------------
warn "Recordá: la mitigación COMPLETA de 2025-32462/32463 es actualizar a sudo 1.9.17p1+."
warn "Estos son controles compensatorios para entornos legacy que no pueden parchear."

echo "MITIGATE_OK"
step "Mitigaciones aplicadas. Volvé a diagnosticar para verificar."
