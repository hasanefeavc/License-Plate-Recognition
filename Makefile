.PHONY: run launch start stop restart init setup status doctor css css-check install install-gui dev lint fmt \
        test test-fast secrets dataset-scaffold dataset-check evaluate train \
        export-onnx run-api run-gui docker-build docker-up docker-down clean

# Sanal ortam yolları (sisteme değil venv'e bakar)
VENV ?= venv
PYTHON = $(VENV)/bin/python
UVICORN = $(VENV)/bin/uvicorn
PYTEST = $(VENV)/bin/pytest
RUFF = $(VENV)/bin/ruff
MYPY = $(VENV)/bin/mypy

COMPOSE = docker compose -f docker/docker-compose.yml

# --- Kolay Yönetim (Tek Komutlar) --------------------------------------------

# Tek komutla başlat (venv yoksa kurar, sunucuyu reload modunda açar, CTRL+C ile durur)
run:
	@test -d $(VENV) || $(MAKE) setup
	$(UVICORN) lpr.api.main:app --reload --host 0.0.0.0 --port 8000

# Aynı işin tek tıklık hâli: ./run.sh (Windows'ta run.bat). `run` hedefinden
# kasıtlı olarak ayrı tutuldu, çünkü ikisi farklı iki kullanıcıya hizmet ediyor:
# `make run` geliştirici içindir ve --reload ile 0.0.0.0'a bağlanır; run.sh ise
# sahadaki kurulum içindir, sanal ortamı ve bağımlılıkları kendisi hazırlar,
# reload açmaz ve host/port'u config.yaml'dan okur. `run` hedefini run.sh'a
# devretmek geliştiricinin reload'unu sessizce kapatırdı.
launch:
	./run.sh

# Tek komutla arka planda başlat
start:
	@test -d $(VENV) || $(MAKE) setup
	@nohup $(UVICORN) lpr.api.main:app --host 0.0.0.0 --port 8000 > lpr.log 2>&1 & echo "LPR arka planda baslatildi (Port 8000). Loglar: lpr.log"

# Tek komutla portu ve süreci tamamen kapat
stop:
	@-fuser -k 8000/tcp 2>/dev/null || true
	@echo "LPR durduruldu."

# Tek komutla yeniden başlat
restart: stop start

# --- First run ---------------------------------------------------------------
# Otomatik sanal ortam oluşturma, paket yükleme ve lisanslama
setup:
	@echo "[+] Sanal ortam ve bagimliliklar hazirlaniyor..."
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .
	$(PYTHON) scripts/setup_dev.py
	@echo "[+] Kurulum tamamlandi. 'make run' ile baslatabilirsiniz."

init:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PYTHON) scripts/setup_dev.py

# Durum ve sistem kontrolü
status:
	$(PYTHON) -m lpr.cli status

doctor:
	$(PYTHON) -m lpr.cli doctor

# --- Dashboard stylesheet ----------------------------------------------------
css:
	$(PYTHON) scripts/build_web_css.py

css-check:
	$(PYTHON) scripts/build_web_css.py --check

# --- Paket Kurulumları ------------------------------------------------------
install:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

install-gui:
	$(PYTHON) -m pip install -e ".[gui]"

dev:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PYTHON) -m pip install -e ".[gui,dev]"

# --- Test ve Kod Kalitesi ---------------------------------------------------
lint:
	$(RUFF) check .
	$(MYPY) src

fmt:
	$(RUFF) check --fix .
	$(RUFF) format .

test: css-check
	$(PYTEST)

test-fast:
	$(PYTEST) tests/test_dataset.py tests/test_evaluation.py tests/test_normalize.py \
	       tests/test_voting.py tests/test_config.py tests/test_camera_sources.py \
	       tests/test_env_example.py -q

secrets:
	$(PYTEST) tests/test_secrets.py -q

# --- Detection model pipeline ------------------------------------------------
DATASET ?= datasets/plates
EVAL_IMAGES ?= $(DATASET)/images/test

dataset-scaffold:
	$(PYTHON) scripts/fetch_dataset.py --scaffold $(DATASET)

dataset-check:
	$(PYTHON) scripts/fetch_dataset.py --check $(DATASET)/data.yaml

train:
	$(PYTHON) scripts/train_plate_detector.py --data $(DATASET)/data.yaml --min-map 0.85

export-onnx:
	$(PYTHON) scripts/export_onnx.py

evaluate:
	$(PYTHON) scripts/evaluate.py --images $(EVAL_IMAGES) --device both \
	       --json accuracy-report.json

# --- Çalıştırma Alternatifleri ----------------------------------------------
run-api: run

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
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov $(VENV)
