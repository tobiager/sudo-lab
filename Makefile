# =============================================================================
#  Makefile — sudo-lab
# -----------------------------------------------------------------------------
#  Interfaz única del laboratorio: cualquier operación se hace desde la raíz
#  del repo con `make <objetivo>`, sin recordar comandos de docker ni rutas
#  internas. Cada objetivo llama a los scripts reales del laboratorio tal como
#  los consume el dashboard (misma superficie de comandos = menos deriva entre
#  lo que documenta el paper y lo que se ejecuta de verdad). En Windows hay
#  equivalencias directas con docker compose/exec: docs/REPRODUCIBILITY.md §3.1.
#
#  Convenciones:
#    - El contenedor target se llama sudo-lab-target (service `target` en
#      docker-compose.yml). Se puede sobreescribir: make scan CONTAINER=otro.
#    - Los objetivos que hablan con el target verifican ANTES que el contenedor
#      esté corriendo (macro GUARD): el error típico "0 hallazgos" por un
#      contenedor caído se convierte en un mensaje accionable.
#    - `make up` usa --wait: el build termina y el comando no regresa hasta que
#      el HEALTHCHECK (visudo -c -q) declara `healthy` al contenedor.
# =============================================================================

# --- Configuración (sobreescribible por línea de comandos) -------------------
SHELL      := /bin/bash
COMPOSE    ?= docker compose
CONTAINER  ?= sudo-lab-target
SERVICE    ?= target
DASHBOARD  := dashboard

.DEFAULT_GOAL := help
.PHONY: help up down scan mitigate reset foothold benchmark preflight test clean

# --- Guardia: el target debe estar corriendo ---------------------------------
# Se expande como receta en cada objetivo que ejecuta `docker exec`. Con el
# flag -f el estado "exited" también falla: sólo "running" da acceso al lab.
define GUARD
    @docker inspect --format '{{.State.Running}}' $(CONTAINER) 2>/dev/null | grep -qx 'true' \
      || { echo "ERROR: el contenedor '$(CONTAINER)' no está corriendo."; \
           echo "       Ejecutá 'make up' y esperá a que el HEALTHCHECK quede healthy."; \
           exit 1; }
endef

# --- Ayuda: lista automática a partir de los comentarios ## -----------------
help: ## muestra este listado de objetivos
	@awk 'BEGIN { FS = ":.*##"; printf "sudo-lab — objetivos disponibles:\n\n" } \
        /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# --- Ciclo de vida del laboratorio -------------------------------------------
up: ## construye y levanta el target (espera a healthy)
	$(COMPOSE) up -d --build --wait --wait-timeout 180
	@echo "Target healthy. Diagnosticá con 'make scan' o abrí el dashboard (cd $(DASHBOARD) && npm run dev)."

down: ## detiene y elimina el target (conserva la imagen)
	$(COMPOSE) down --remove-orphans

clean: ## down + borra imagen y volúmenes (vuelve a "máquina limpia")
	$(COMPOSE) down -v --remove-orphans
	- $(COMPOSE) rmi --force $(SERVICE) 2>/dev/null || true
	@echo "Entorno limpio: el próximo 'make up' reconstruye todo (1–2 min)."

# --- Motor del laboratorio (los mismos comandos que usa el panel) ------------
scan: ## diagnóstico de exposición (scan.sh, TSV V/F/S)
	$(GUARD)
	docker exec $(CONTAINER) bash /opt/lab/scripts/scan.sh

mitigate: ## aplica los controles compensatorios (mitigate.sh)
	$(GUARD)
	docker exec $(CONTAINER) bash /opt/lab/scripts/mitigate.sh

reset: ## restaura el estado vulnerable original (mitigate.sh --reset)
	$(GUARD)
	docker exec $(CONTAINER) bash /opt/lab/scripts/mitigate.sh --reset

foothold: ## simula el acceso inicial como webuser (foothold.sh)
	$(GUARD)
	docker exec -u webuser $(CONTAINER) bash /opt/lab/scripts/foothold.sh

benchmark: ## mide el PoC externo (requiere LAB_POC_DIR con *.sh)
	$(GUARD)
	docker exec $(CONTAINER) bash /opt/lab/scripts/benchmark.sh

# --- Calidad y reproducibilidad ----------------------------------------------
preflight: ## verifica prerequisitos del host (Docker, Compose, Node >= 22)
	bash scripts/preflight.sh

test: ## tests de TypeScript del parser (parseScan) en dashboard/
	cd $(DASHBOARD) && npm install --no-audit --no-fund --loglevel=error
	cd $(DASHBOARD) && npm run typecheck --if-present
	cd $(DASHBOARD) && npx --yes tsx --test lib/lab.test.ts
