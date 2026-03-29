# MiragePot Makefile
# Common commands for development and running the honeypot

.PHONY: help install install-dev run server dashboard test lint format clean demo

# Default target
help:
	@echo "MiragePot - AI-Driven Adaptive SSH Honeypot"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install      Install dependencies"
	@echo "  install-dev  Install with development dependencies"
	@echo "  run          Start honeypot and dashboard together"
	@echo "  server       Start only the SSH honeypot server"
	@echo "  dashboard    Start only the Streamlit dashboard"
	@echo "  demo         Start full Docker stack for demos (with cold start verification)"
	@echo "  test         Run tests"
	@echo "  lint         Run linters (ruff, mypy)"
	@echo "  format       Format code with black"
	@echo "  clean        Remove build artifacts and caches"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Python 3.10+"
	@echo "  - Ollama running with phi3 model"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pre-commit install || true

# Running
run:
	python run.py

server:
	python -m miragepot --port 2222

dashboard:
	streamlit run dashboard/app.py

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=miragepot --cov-report=html --cov-report=term

# Code quality
lint:
	ruff check miragepot/ tests/
	mypy miragepot/

format:
	black miragepot/ tests/
	ruff check --fix miragepot/ tests/

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Ollama helpers
ollama-start:
	ollama serve &

ollama-pull:
	ollama pull phi3

ollama-status:
	@ollama list 2>/dev/null || echo "Ollama not running. Start with: ollama serve"

# Docker demo deployment
demo:
	@echo "🚀 Starting MiragePot demo environment..."
	@echo ""
	cd docker && docker compose down -v
	cd docker && docker compose up --build -d
	@echo ""
	@bash scripts/wait-for-healthy.sh
	@echo ""
	@echo "✅ MiragePot is ready!"
	@echo ""
	@echo "📍 Access points:"
	@echo "   SSH Honeypot:  ssh root@localhost -p 2222 (any password works)"
	@echo "   Streamlit:     http://localhost:8501"
	@echo "   Grafana:       http://localhost:3000 (admin/admin)"
	@echo "   Prometheus:    http://localhost:9091"
	@echo ""
	@echo "💡 Run demo session: python scripts/demo_session.py"
	@echo ""
