# ============================================================================
# ONYX CTI PLATFORM — Makefile
# Build, run, and manage the ONYX stack.
# ============================================================================

.PHONY: help build up down restart logs status clean init test lint

# Default target
help: ## Show this help
	@echo ""
	@echo "  ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗"
	@echo "  ██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝"
	@echo "  ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ "
	@echo "  ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ "
	@echo "  ╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗"
	@echo "   ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝"
	@echo ""
	@echo "  ONYX CTI Platform v3.0 — GENESIS"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# --- Environment ---
init: ## Initialize environment (copy .env, create dirs)
	@python3 scripts/gen_env.py
	@echo "[ONYX] Environment file ready"

# --- Docker ---
build: ## Build all Docker images
	docker compose build --parallel

up: init ## Start all services (detached)
	docker compose up -d

down: ## Stop all services
	docker compose down

restart: down up ## Restart all services

logs: ## Tail logs from all services
	docker compose logs -f --tail=100

logs-api: ## Tail API server logs
	docker compose logs -f --tail=100 onyx-api

logs-es: ## Tail Elasticsearch logs
	docker compose logs -f --tail=100 elasticsearch

# --- Status ---
status: ## Show service status
	@echo "\n[ONYX] Service Status:"
	@docker compose ps
	@echo "\n[ONYX] Health Checks:"
	@curl -sf http://localhost:8000/api/v1/health 2>/dev/null | python -m json.tool || echo "  API: not running"
	@echo ""

# --- Development ---
dev-api: ## Run API server locally (no Docker)
	cd onyx-api && uvicorn onyx_api.main:app --reload --host 0.0.0.0 --port 8000

dev-dash: ## Run dashboard locally (no Docker)
	cd onyx-dashboard && npm run dev

# --- Testing ---
test: ## Run all tests
	cd onyx-core && python -m pytest tests/ -v
	cd onyx-api && python -m pytest tests/ -v

lab: ## Serve the live Signal Lab on http://127.0.0.1:8765
	python3 demo/lab_server.py

lint: ## Run linting (ruff + mypy)
	cd onyx-core && ruff check . && mypy .
	cd onyx-api && ruff check . && mypy .

# --- Cleanup ---
clean: ## Remove all containers, volumes, and build artifacts
	docker compose down -v --remove-orphans
	docker system prune -f
	@echo "[ONYX] Cleaned up"

reset: clean ## Full reset: remove all data and rebuild
	docker volume rm onyx-es-data onyx-mongo-data onyx-redis-data 2>/dev/null || true
	$(MAKE) build
	$(MAKE) up
	@echo "[ONYX] Full reset complete — fresh start"

# --- Database ---
es-status: ## Check Elasticsearch cluster health
	@curl -sf -u elastic:$${ELASTICSEARCH_PASSWORD} http://localhost:9200/_cluster/health?pretty

mongo-shell: ## Open MongoDB shell
	docker compose exec mongodb mongosh -u $${MONGODB_USER:-onyx_admin} -p $${MONGODB_PASSWORD} --authenticationDatabase admin onyx_cti

redis-cli: ## Open Redis CLI
	docker compose exec redis redis-cli -a $${REDIS_PASSWORD}
