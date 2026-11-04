#!/usr/bin/env bash
# =============================================================================
#  foothold.sh — Simulación del ACCESO INICIAL (paso [1] de la cadena, ver
#  docs/ATTACK-CHAIN.md)
# -----------------------------------------------------------------------------
#  Qué representa: el estado del atacante justo después del vector web — una
#  shell SIN privilegios con el usuario del "servicio web". No hay Apache ni
#  payload: el lab NARRA el vector web y lo representa con el usuario
#  'webuser' (decisión de alcance en docs/SCOPE.md §6; equivalencia
#  webuser ≈ www-data).
#
#  Qué hace: deja evidencia del punto de partida del atacante:
#    1. id              → identidad (usuario raso, sin privilegios).
#    2. sudo -l         → NINGUNA regla de sudo (a propósito, ver abajo).
#    3. sudo --version  → el binario vulnerable es alcanzable igualmente.
#    4. /tmp ejecutable → precondición de CVE-2025-32463 visible sin root.
#  Qué NO hace: no explota nada (sin PoC, sin escalada, sin payload). El repo
#  versionado no contiene exploits.
#
#  Uso manual (host):
#    docker exec -u webuser sudo-lab-target bash /opt/lab/scripts/foothold.sh
#  Uso desde el panel: botón "② Simular foothold" → POST /api/foothold
#  ejecuta exactamente ese comando.
#
#  Salida: STDOUT es el log legible que el panel muestra con tipo 'foot'.
#  A diferencia de scan.sh, NO hay salida máquina (TSV): este script no
#  alimenta a un parser, sólo a la consola del panel.
# =============================================================================
set -euo pipefail

# --- [Guardia] Debe correr como usuario SIN privilegios -----------------------
# El sentido pedagógico exige correr como usuario raso: si se ejecutara como
# root, `id` y `sudo -l` mostrarían un estado equivocado y la demo quedaría
# vacía de contenido. Abortamos con mensaje claro (la API lo devuelve como
# 502 y el panel lo muestra en el registro de errores).
if [ "$(id -u)" -eq 0 ]; then
  echo "[foothold] ERROR: este script simula un usuario SIN privilegios." >&2
  echo "[foothold]   Ejecutalo como webuser:" >&2
  echo "[foothold]   docker exec -u webuser sudo-lab-target bash /opt/lab/scripts/foothold.sh" >&2
  exit 1
fi

echo "[foothold] == Simulación del acceso inicial (foothold, sin explotación) =="

# --- Evidencia 1: identidad del foothold --------------------------------------
# Debian trae 'www-data' como usuario de servicio por defecto;
# el lab usa 'webuser' (creado en lab/entrypoint.sh sin contraseña y SIN
# reglas de sudo, a propósito) para no confundirlo con el usuario de un
# Apache real, que en este laboratorio no existe.
echo "[foothold] usuario del servicio (simulado): $(id)"

# --- Evidencia 2: reglas de sudo del usuario ----------------------------------
# `sudo -n -l`: el flag -n (non-interactive) garantiza que sudo NUNCA pida
# contraseña ni se cuelgue — requisito duro para una llamada desde la API del
# panel (docker exec sin TTY). webuser no figura en /etc/sudoers ni en
# sudoers.d/lab (ver lab/sudoers.lab): la respuesta esperada es del tipo
#   "Sorry, user webuser may not run sudo on srv-web."
# Con `set -e` activo, el fallo esperado se captura con '|| sudo_rc=$?' para
# poder interpretarlo en lugar de abortar el script.
sudo_rc=0
sudo_out="$(sudo -n -l 2>&1)" || sudo_rc=$?

if [ "$sudo_rc" -eq 0 ]; then
  # Ramo INESPERADO en el lab: si el sudoers fue editado a mano y webuser
  # ganó reglas, el escenario cambió — avisarlo en voz alta.
  echo "[foothold] reglas sudo del usuario:"
  printf '%s\n' "$sudo_out" | sed 's/^/[foothold]   /'
  echo "[foothold] ADVERTENCIA: webuser TIENE reglas de sudo — el escenario de"
  echo "[foothold]   laboratorio cambió (¿se restauró mal el sudoers?)."
elif printf '%s\n' "$sudo_out" | grep -qiE 'may not run sudo|not allowed to run sudo|a password is required|no tty present'; then
  # Ramo ESPERADO: sin reglas. La evidencia cruda se muestra igual: el panel
  # (y el paper) deben poder citar la respuesta real de sudo.
  echo "[foothold] reglas sudo del usuario: NINGUNA"
  printf '%s\n' "$sudo_out" | sed 's/^/[foothold]   (sudo) /'
else
  # Salida ambigua: mostrarla sin interpretar de más.
  echo "[foothold] reglas sudo del usuario: sin respuesta clasificable:"
  printf '%s\n' "$sudo_out" | sed 's/^/[foothold]   /'
fi

# --- Evidencia 3: el binario vulnerable es alcanzable igualmente --------------
# Punto pedagógico central de CVE-2025-32463: sudo es setuid-root, así que su
# versión no depende de las reglas del usuario. Cualquier cuenta local —con o
# sin reglas— invoca el MISMO binario vulnerable.
# Higiene con `set -o pipefail`: se captura la salida COMPLETA y recién después
# se recorta la primera línea; un `sudo --version | head -1` directo puede
# recibir SIGPIPE y, con pipefail, abortar el script. Además el fallo se captura
# con '||': la misión de este script es llegar SIEMPRE a la conclusión final,
# aunque la consulta de versión falle (degradaría a "desconocida").
sudo_ver_line=""
sudo_ver_line="$(sudo --version 2>/dev/null)" || sudo_ver_line=""
sudo_ver_line="${sudo_ver_line%%$'\n'*}"
# '|| sudo_ver=""': si no hay versión que extraer (sudo_ver_line vacío), grep
# sale 1 y con pipefail abortaría el script antes de la conclusión final.
sudo_ver=""
sudo_ver="$(printf '%s\n' "$sudo_ver_line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -n 1)" || sudo_ver=""
echo "[foothold] binario sudo alcanzable desde el foothold: ${sudo_ver_line:-?}"

# --- Evidencia 4: precondición de 32463 verificable SIN root ------------------
# Las señales de sudoers exigen root (por eso el
# diagnóstico completo corre como root en scan.sh); pero la parte de
# CVE-2025-32463 que depende del sistema de archivos — /tmp ejecutable para
# el .so staged — sí es verificable desde el propio foothold.
tmp_opts="$(findmnt -no OPTIONS /tmp 2>/dev/null || echo exec)"
if [[ "$tmp_opts" == *noexec* ]]; then
  echo "[foothold] /tmp montado con noexec (${tmp_opts}): precondición de"
  echo "[foothold]   CVE-2025-32463 ausente (¿ya se aplicó la mitigación?)."
else
  echo "[foothold] /tmp es ejecutable (${tmp_opts}): precondición de"
  echo "[foothold]   CVE-2025-32463 presente, visible sin ser root."
fi

# --- Conclusión pedagógica (cierre del foothold) ------------------------------
echo "[foothold] Conclusión: sin reglas de sudo, CVE-2025-32463 sigue aplicando:"
echo "[foothold]   sudo ${sudo_ver:-desconocida} + /tmp ejecutable bastan."
echo "[foothold] Paso siguiente: diagnosticar (①) y mitigar (③) desde el panel."
