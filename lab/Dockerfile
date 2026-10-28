# =============================================================================
#  sudo-lab · Target vulnerable (uso educativo, entorno aislado)
# -----------------------------------------------------------------------------
#  Compila una versión concreta de sudo para poder ejercer el diagnóstico y las
#  mitigaciones contra una base REAL. No contiene exploits: es únicamente el
#  "blanco" sobre el que corren scan.sh y mitigate.sh.
#
#  Versiones vulnerables de referencia (para CVE-2025-32463): 1.9.14 – 1.9.17.
#  Cambiá SUDO_VERSION para estudiar otros rangos.
# =============================================================================
FROM debian:12-slim

ARG SUDO_VERSION=1.9.15
ENV DEBIAN_FRONTEND=noninteractive

# Dependencias de compilación de sudo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl libpam0g-dev zlib1g-dev procps \
 && rm -rf /var/lib/apt/lists/*

# Compilar e instalar la versión solicitada de sudo sobre /usr.
# (Descarga el tarball oficial del proyecto sudo en tiempo de build, en la
#  máquina del alumno, no en ningún servidor remoto de terceros.)
RUN cd /tmp \
 && curl -fsSL "https://www.sudo.ws/dist/sudo-${SUDO_VERSION}.tar.gz" -o sudo.tar.gz \
 && tar xzf sudo.tar.gz \
 && cd "sudo-${SUDO_VERSION}" \
 && ./configure --prefix=/usr --libexecdir=/usr/libexec --with-secure-path \
 && make -j"$(nproc)" \
 && make install \
 && cd / \
 && rm -rf /tmp/sudo* \
 && sudo --version | head -1

# Copiar la configuración de laboratorio y el arranque.
COPY sudoers.lab /opt/lab/sudoers.lab
COPY entrypoint.sh /opt/lab/entrypoint.sh
RUN chmod +x /opt/lab/entrypoint.sh

# Los scripts de diagnóstico/mitigación se montan como volumen en runtime
# (ver docker-compose.yml) para poder editarlos sin reconstruir la imagen.
VOLUME ["/opt/lab/scripts"]

ENTRYPOINT ["/opt/lab/entrypoint.sh"]
