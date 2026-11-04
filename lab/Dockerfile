# =============================================================================
#  lab/Dockerfile — imagen del contenedor target del laboratorio sudo-lab
# -----------------------------------------------------------------------------
#  Debian 12 slim + sudo compilado desde fuente. Este contenedor es
#  INTENCIONALMENTE VULNERABLE (ver docs/THREAT-MODEL.md): su misión es
#  reproducir con fidelidad el fenómeno que el laboratorio mide. Los controles
#  de seguridad del lab viven en docker-compose.yml (cap_drop ALL + 7
#  capabilities, red interna, montajes :ro) y en SECURITY.md; este Dockerfile
#  aporta los controles de INTEGRIDAD de la cadena de suministro:
#
#    - Pin de la imagen base por DIGEST (no por tag): debian:12-slim se
#      reconstruye upstream con regularidad; el digest fija los bytes.
#      Digest del manifest multi-arch v2 (válido en amd64 y arm64):
#        sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
#      (documentado además en docs/REPRODUCIBILITY.md §2 — actualizar ambos a
#      la vez, a conciencia.)
#
#    - Verificación del tarball de sudo contra el archivo `SHA256` OFICIAL
#      de sudo.ws (https://www.sudo.ws/dist/SHA256) ANTES de compilar.
#      Si el hash no coincide, el build ABORTA y no queda ningún binario.
#      El mecanismo se adapta solo a SUDO_VERSION: no hay hashes clavados
#      en el Dockerfile (el archivo oficial es la fuente de verdad).
#
#  Controles preservados del endurecimiento validado:
#    - HEALTHCHECK con `visudo -c -q` (mide salud del SUDOERS, no del
#      binario: `sudo --version` sería siempre verde).
#    - SIN `VOLUME`: los montajes los declara solo docker-compose.yml
#      (correr la imagen suelta no genera volúmenes anónimos).
#    - Layout: entrypoint en /opt/lab/entrypoint.sh y copia prístina del sudoers
#      en /opt/lab/sudoers.lab.orig (0644 root:root).
# =============================================================================

# --- Imagen base pinneada por digest -----------------------------------------
# NOTA: se pinnea el digest del MANIFEST LIST (multi-arch), no el de una sola
# plataforma: el mismo Dockerfile construye en x86_64 y en Apple Silicon.
FROM debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

LABEL org.opencontainers.image.title="sudo-lab target" \
      org.opencontainers.image.description="Debian 12 + sudo vulnerable para medir mitigaciones de CVE-2025-32463/32462" \
      org.opencontainers.image.source="https://www.sudo.ws/"

# --- Versión de sudo a compilar (parametrizable) ------------------------------
# Default 1.9.15: la versión validada del laboratorio, en el rango vulnerable
# a CVE-2025-32463 (1.9.14–1.9.17, ver scan.sh). Al cambiarla, mantener
# sincronizada la etiqueta `image:` de docker-compose.yml.
# Referencia (hashes oficiales de sudo.ws/dist/SHA256):
#   sudo-1.9.15.tar.gz    fd0e254870e92e873b508ba16382f5ac3af81a5a38d1ea9cf973606db4262589
#   sudo-1.9.15p5.tar.gz  558d10b9a1991fb3b9fa7fa7b07ec4405b7aefb5b3cb0b0871dbc81e3a88e558
ARG SUDO_VERSION=1.9.15

# --- Dependencias de build y de escenario ------------------------------------
#   build-essential  : gcc/make para compilar sudo Y para que el PoC de
#                      CVE-2025-32463 compile su librería NSS en /tmp (el lab
#                      DEBE poder explotarse en su estado vulnerable)
#   curl + ca-certificates : descarga verificada del tarball
#   zlib1g-dev       : sudo la enlaza si está disponible
#   procps           : ps/kill, usados por los scripts del arnés
#   less             : objetivo del escape `!sh` del PoC de CVE-2025-32462
#   util-linux       : script(1) — pty no interactiva para ese escape;
#                      también findmnt/su (scan.sh, benchmark.sh)
# --no-install-recommends + limpieza en el MISMO RUN: capas pequeñas.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      zlib1g-dev \
      procps \
      less \
      util-linux \
 && rm -rf /var/lib/apt/lists/*

# --- Descarga VERIFICADA y compilación de sudo --------------------------------
# Bloque atómico: si `sha256sum -c` falla, el && encadena el aborto del build
# y no se instala nada. Detalles de rigor:
#   - `curl --retry 3`: tolera fallos transitorios de red.
#   - El match del checksum se hace por CAMPO EXACTO con awk (último campo ==
#     nombre del tarball) para que no coincidan vecinos del índice oficial
#     como `sudo-X.patch.gz` o futuros `.sig` con el mismo prefijo.
RUN cd /tmp \
 && curl -fsSL --retry 3 -o "sudo-${SUDO_VERSION}.tar.gz" \
      "https://www.sudo.ws/dist/sudo-${SUDO_VERSION}.tar.gz" \
 && curl -fsSL --retry 3 -o SHA256 "https://www.sudo.ws/dist/SHA256" \
 && awk -v f="sudo-${SUDO_VERSION}.tar.gz" '$NF == f' SHA256 | sha256sum -c - \
 && tar xzf "sudo-${SUDO_VERSION}.tar.gz" \
 && cd "sudo-${SUDO_VERSION}" \
 && ./configure --prefix=/usr --libexecdir=/usr/libexec --with-secure-path \
 && make -j"$(nproc)" \
 && make install \
 && cd /tmp \
 && rm -rf "sudo-${SUDO_VERSION}" "sudo-${SUDO_VERSION}.tar.gz" SHA256 \
 && sudo --version | head -n 1

# --- Artefactos del laboratorio -----------------------------------------------
# sudoers.lab.orig : copia PRÍSTINA sellada en la imagen. El entrypoint la
#   instala en /etc/sudoers.d/lab (0440, root:root) en cada arranque — por eso
#   el contenedor "vuelve al estado vulnerable al reiniciarse" — y
#   `mitigate.sh --reset` la restaura. Ningún usuario raso del escenario puede
#   alterarla. Los SCRIPTS no se copian: los monta compose
#   (./scripts:/opt/lab/scripts:ro) para editar sin rebuild.
COPY sudoers.lab /opt/lab/sudoers.lab.orig
COPY entrypoint.sh /opt/lab/entrypoint.sh
RUN chmod 0644 /opt/lab/sudoers.lab.orig \
 && chmod 0755 /opt/lab/entrypoint.sh

# --- HEALTHCHECK representativo -----------------------------------------------
# `visudo -c -q` valida en silencio /etc/sudoers y todos los archivos del
# includedir /etc/sudoers.d (la cadena completa). Un sudoers roto => exit != 0
# => `docker inspect` reporta unhealthy: el fallo se ve ANTES de la demo, no a
# mitad. Corre como root (usuario por defecto del contenedor), condición
# necesaria para leer /etc/sudoers.d con permisos 0440.
# --start-period cubre la ventana del primer arranque (el entrypoint crea
# usuarios e instala el sudoers antes de estabilizar).
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD /usr/sbin/visudo -c -q || exit 1

# --- SIN `VOLUME` -------------------------------------------------------------
# El montaje ./scripts:/opt/lab/scripts:ro lo declara compose. La instrucción
# VOLUME no aporta nada dentro de compose (ya monta el volumen) y creaba
# volúmenes anónimos al correr la imagen suelta.

ENTRYPOINT ["/opt/lab/entrypoint.sh"]
# El entrypoint termina en `exec sleep infinity`: con `init: true` (compose),
# docker-init es PID 1 y ese sleep es su hijo (zombis de los PoC recolectados
# por tini, señales de `docker compose stop` limpias). No se declara CMD.
