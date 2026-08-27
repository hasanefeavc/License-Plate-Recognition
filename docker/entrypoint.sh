#!/bin/sh
# Container entrypoint for the headless LPR API service.
# POSIX sh (not bash) so it stays portable across minimal base images.
set -eu

# Mark the mounted repo safe for git operations inside the container
# to prevent "detected dubious ownership in repository at '/repo'" errors.
git config --global --add safe.directory /repo 2>/dev/null || true

DATA_DIR="${LPR_APP__DATA_DIR:-/app/data}"
MODELS_DIR="${LPR_APP__MODELS_DIR:-/app/models}"
MODEL_FILE="${MODELS_DIR}/plate_yolov8n.pt"

mkdir -p "${DATA_DIR}" "${MODELS_DIR}"

if [ ! -w "${DATA_DIR}" ]; then
    echo "entrypoint: WARNING: ${DATA_DIR} is not writable by this container's user" >&2
fi
if [ ! -w "${MODELS_DIR}" ]; then
    echo "entrypoint: WARNING: ${MODELS_DIR} is not writable by this container's user" >&2
fi

if [ ! -f "${MODEL_FILE}" ]; then
    echo "entrypoint: WARNING: detection model not found at ${MODEL_FILE}" >&2
    echo "entrypoint: run 'python scripts/fetch_models.py' on the host (models/ is a bind-mounted volume) to fetch a baseline model." >&2
fi

HOST="${LPR_API__HOST:-0.0.0.0}"
PORT="${LPR_API__PORT:-8000}"

echo "entrypoint: starting lpr.api.main:app on ${HOST}:${PORT}"
exec uvicorn lpr.api.main:app --host "${HOST}" --port "${PORT}"
