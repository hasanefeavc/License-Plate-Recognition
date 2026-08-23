# syntax=docker/dockerfile:1
#
# Headless LPR API service image. The Tkinter GUI client (src/lpr/ui) is
# NOT part of this image -- it runs natively on the operator's desktop
# (Windows 11 / Ubuntu 24.04) and talks to this container over HTTP/WS.
#
# Build:  docker build -f docker/Dockerfile -t lpr-api .   (context = repo root)
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

# CPU-only torch/torchvision wheels keep the image well under the size of a
# CUDA build. To switch to GPU: drop the --index-url line below (or point it
# at e.g. https://download.pytorch.org/whl/cu121) and use a
# nvidia/cuda base image instead of python:slim for stage 2 as well.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        --extra-index-url https://pypi.org/simple \
        -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime -- slim image with only what's needed to run the service.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

# Native libraries required at runtime by opencv-python-headless and torch.
# (No compilers, no dev headers -- those stayed in the builder stage.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        libsm6 \
        libxext6 \
        libgomp1 \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin lpr

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    LPR_APP__HEADLESS=true \
    # Ultralytics pip-installs missing extras mid-run by default (lap for
    # ByteTrack, onnxruntime-gpu for ONNX). Everything needed is already in
    # the image, so make a surprise 250 MB download at the gate a loud error
    # instead: a container that cannot reach PyPI would hang or fail anyway.
    YOLO_AUTOINSTALL=false

WORKDIR /app

COPY src/ /app/src/
COPY config.yaml /app/config.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# data/ and models/ are NOT copied into the image -- they are host volumes
# (see docker/docker-compose.yml) so captured frames, the sqlite database,
# and model weights persist across container recreation and are shared with
# scripts/fetch_models.py run on the host.
RUN mkdir -p /app/data /app/models && chown -R lpr:lpr /app

USER lpr

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${LPR_API__PORT:-8000}/health" || exit 1

ENTRYPOINT ["entrypoint.sh"]
