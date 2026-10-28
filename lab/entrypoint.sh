#!/usr/bin/env bash
# =============================================================================
#  Arranque del contenedor de laboratorio.
#  Crea los usuarios del escenario e instala el sudoers de laboratorio.
#  Al reiniciar el contenedor, el entorno vuelve al estado vulnerable inicial.
# =============================================================================
set -euo pipefail

echo "[lab] Inicializando target de laboratorio (hostname=$(hostname))..."

# --- Usuarios del escenario --------------------------------------------------
# webuser: foothold de bajos privilegios (sin reglas de sudo, a propósito).
# operador / auditor / editor: portan las señales de configuración de cada CVE.
for u in webuser operador auditor editor; do
  if ! id "$u" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$u"
    echo "[lab]  + usuario creado: $u"
  fi
done

# --- sudoers de laboratorio --------------------------------------------------
install -m 0440 /opt/lab/sudoers.lab /etc/sudoers.d/lab
if visudo -cf /etc/sudoers.d/lab >/dev/null 2>&1; then
  echo "[lab]  sudoers.d/lab instalado y validado"
else
  echo "[lab]  ADVERTENCIA: sudoers.d/lab no validó; revisá la sintaxis" >&2
fi

# Guardar una copia prístina para poder 'resetear' sin reiniciar el contenedor.
install -m 0440 /opt/lab/sudoers.lab /opt/lab/sudoers.lab.orig

echo "[lab] Listo. sudo $(sudo --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?')"
echo "[lab] Contenedor en espera. Usá el dashboard o 'docker exec' para operar."

exec sleep infinity
