# syntax=docker/dockerfile:1
#
# Headless LPR API service image. The Tkinter GUI client (src/lpr/ui) is
# NOT part of this image -- it runs natively on the operator's desktop
# (Windows 11 / Ubuntu 24.04) and talks to this container over HTTP/WS.
#
# Build:  docker build -f docker/Dockerfile -t lpr-api .    (context = repo root)
# Or via docker/docker-compose.yml (build.context: .. handles that for you).

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------------------
# Stage 1: builder -- compiles / resolves wheels into a throwaway venv.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

# Build-time-only system packages (compilers, headers). None of this ships
# in the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build

COPY requirements.txt ./

# Which PyTorch build goes in. Defaults to the CPU wheels, which keep the
# image around 800 MB against ~2.5 GB for a CUDA build -- so a plain
# `docker build` still produces the small, portable image.
#
# docker/docker-compose.yml overrides this with a CUDA index
# (https://download.pytorch.org/whl/cu124) because the deployed gate box has an
# NVIDIA card, and a CPU-only wheel is the reason `torch.cuda.is_available()`
# returned false in the container even with the device correctly passed
# through: the driver was there, the CUDA-capable torch was not.
#
# No nvidia/cuda base image is needed for stage 2. The CUDA runtime libraries
# are pulled in as nvidia-*-cu12 wheel dependencies of torch itself, and the
# host driver is injected at runtime by the NVIDIA Container Toolkit.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        --index-url "${TORCH_INDEX_URL}" \
        --extra-index-url https://pypi.org/simple \
        -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime -- slim image with only what's needed to run the service.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

# Native libraries required at runtime by opencv-python-headless, torch and git.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        libsm6 \
        libxext6 \
        libgomp1 \
        ca-certificates \
        curl \
        gnupg \
        git \
    && rm -rf /var/lib/apt/lists/*

# The OTA client: `docker compose ... up -d --build`, run from *inside* this
# container against the host's engine through the mounted socket.
#
# The CLI and the compose plugin only, never the daemon -- the engine stays on
# the host. Without them `lpr.updater` finds no `docker`, falls back to the v1
# `docker-compose` binary, finds that missing too, and every update fails at the
# build step with "Komut bulunamadı: docker-compose" *after* having already
# pulled the new code. That leaves the checkout advanced and the running image
# stale, which is the worst of the possible outcomes and exactly what happened
# on the deployed box.
#
# Set OTA_CLIENT=0 to build without them (~90 MB smaller) on a site that
# updates by hand; system_update.enabled should be false there too.
ARG OTA_CLIENT=1
RUN if [ "${OTA_CLIENT}" = "1" ]; then \
        install -m 0755 -d /etc/apt/keyrings && \
        curl -fsSL https://download.docker.com/linux/debian/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
        chmod a+r /etc/apt/keyrings/docker.gpg && \
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" \
            > /etc/apt/sources.list.d/docker.list && \
        apt-get update && \
        apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin && \
        rm -rf /var/lib/apt/lists/*; \
    fi

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin lpr

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    LPR_APP__HEADLESS=true \
    # Model caches, pointed at /app/models because that is a bind-mounted host
    # volume (see docker/docker-compose.yml) while $HOME is a container layer
    # that `up --build` throws away. Without these, every rebuild re-downloaded
    # the EasyOCR networks (~100 MB) on the next cold start, and a flaky link
    # at that moment hung startup instead of failing.
    #
    # EASYOCR_MODULE_PATH is EasyOCR's own env hook and covers the code paths
    # that never see our model_storage_directory argument; TORCH_HOME does the
    # same for torch.hub. lpr.config's ocr.model_dir is the authoritative
    # setting for the service itself.
    EASYOCR_MODULE_PATH=/app/models/easyocr \
    TORCH_HOME=/app/models/torch \
    # Ultralytics pip-installs missing extras mid-run by default (lap for
    # ByteTrack, onnxruntime-gpu for ONNX). Everything needed is already in
    # the image, so make a surprise 250 MB download at the gate a loud error
    # instead: a container that cannot reach PyPI would hang or fail anyway.
    YOLO_AUTOINSTALL=false

WORKDIR /app

COPY src/ /app/src/
COPY config.yaml /app/config.yaml
# The browser dashboard is static content served at /web. It is part of the
# image, not a volume: it ships with the code it talks to and nothing writes
# to it at runtime.
COPY web/ /app/web/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# data/ and models/ are NOT copied into the image -- they are host volumes
# (see docker/docker-compose.yml) so captured frames, the sqlite database,
# and model weights persist across container recreation and are shared with
# scripts/fetch_models.py run on the host.
RUN mkdir -p /app/data /app/models/easyocr /app/models/torch && chown -R lpr:lpr /app

USER lpr

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${LPR_API__PORT:-8000}/health" || exit 1

ENTRYPOINT ["entrypoint.sh"]
