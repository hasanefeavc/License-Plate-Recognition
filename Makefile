.PHONY: install install-gui dev lint fmt test test-fast secrets dataset-scaffold \
        dataset-check evaluate train export-onnx run-api run-gui docker-build \
        docker-up docker-down clean

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

# The subset that needs no ML wheels. Same set the CI "lint-and-unit" job runs,
# so a failure here is a failure there.
test-fast:
	pytest tests/test_dataset.py tests/test_evaluation.py tests/test_normalize.py \
	       tests/test_voting.py tests/test_config.py -q

# Credential scan over the working tree AND git history. Run it before any push.
secrets:
	pytest tests/test_secrets.py -q

# --- Detection model pipeline ------------------------------------------------
# DATASET points at the YOLO dataset; override it for a set living elsewhere:
#   make dataset-check DATASET=/srv/plates
DATASET ?= datasets/plates
EVAL_IMAGES ?= $(DATASET)/images/test

dataset-scaffold:
	$(PYTHON) scripts/fetch_dataset.py --scaffold $(DATASET)

# Always run this before booking GPU time. It catches an empty val split, a
# train/val leak and pixel-coordinate labels -- each of which produces a
# training run that completes and a model that detects nothing.
dataset-check:
	$(PYTHON) scripts/fetch_dataset.py --check $(DATASET)/data.yaml

# --min-map refuses to install weights that did not clear the bar, so a bad run
# cannot quietly replace a good model.
train:
	$(PYTHON) scripts/train_plate_detector.py --data $(DATASET)/data.yaml --min-map 0.85

export-onnx:
	$(PYTHON) scripts/export_onnx.py

# End-to-end accuracy and latency. Needs a labelled evaluation set including
# negatives -- images with no plate -- or the false-positive rate cannot be
# measured and its gate fails rather than passing vacuously.
evaluate:
	$(PYTHON) scripts/evaluate.py --images $(EVAL_IMAGES) --device both \
	       --json accuracy-report.json

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
