.PHONY: install install-gui dev lint fmt test run-api run-gui docker-build docker-up docker-down clean

PYTHON ?= python3
COMPOSE = docker compose -f docker/docker-compose.yml

# Headless core only -- what the Docker image / CI needs.
install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

# Adds the Tkinter desktop client's extra deps (ttkbootstrap, non-headless
# opencv, ...). Run this on the operator's desktop machine, not in Docker.
install-gui:
	$(PYTHON) -m pip install -e ".[gui]"

# Full local dev environment: runtime + gui + lint/test tooling.
dev:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PYTHON) -m pip install -e ".[gui,dev]"

lint:
	ruff check .
	mypy src

fmt:
	ruff check --fix .
	ruff format .

test:
	pytest

run-api:
	uvicorn lpr.api.main:app --reload --host 0.0.0.0 --port 8000

run-gui:
	$(PYTHON) -m lpr.ui.app

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up -d

docker-down:
	$(COMPOSE) down

clean:
	find . -type d -name '__pycache__' -not -path './.git/*' -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
