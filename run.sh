#!/usr/bin/env bash
# One-command launcher for Linux and macOS.
#
# Why this exists alongside the Makefile: `make run` assumes make, a `venv/`
# that is already populated, and a developer who knows what a virtualenv is.
# This script assumes none of that -- it is the file somebody pastes into a
# terminal on a machine that has just been handed to them, and it has to either
# start the service or say, in one sentence, what is stopping it. `run.bat` is
# the same script for Windows; the two are kept in step deliberately, so a site
# can be supported over the phone with one set of instructions.
#
# It is idempotent: dependencies are installed only when they are actually
# stale (see the sentinel below), so the second run starts the server in the
# time it takes to import the ML stack.
set -euo pipefail

# The repo root, not the caller's working directory. Everything below uses
# relative paths, so this is what makes `bash /somewhere/else/run.sh` work.
cd -- "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --- output ------------------------------------------------------------------

# Colour only when stdout is a terminal that wants it. A launcher's output ends
# up in support e-mails and CI logs at least as often as on a screen, and escape
# codes in either are noise. NO_COLOR is the cross-tool convention
# (https://no-color.org); TERM=dumb is what Emacs shell-mode and cron set.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW=''
fi

step() { printf '%s==>%s %s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}" "$*"; }
info() { printf '%s    %s%s\n' "${C_DIM}" "$*" "${C_RESET}"; }
warn() { printf '%s[!] %s%s\n' "${C_YELLOW}" "$*" "${C_RESET}" >&2; }
fail() { printf '%s[x] %s%s\n' "${C_RED}${C_BOLD}" "$*" "${C_RESET}" >&2; }

# Ctrl+C during setup stops the script rather than leaving a half-installed
# environment that looks finished. The sentinel is only written after a
# successful install, so an interrupt here simply means the next run installs
# again. 130 is the conventional "terminated by SIGINT" status.
on_interrupt() {
    printf '\n'
    warn "Kesildi."
    exit 130
}
trap on_interrupt INT

# --- interpreter -------------------------------------------------------------

# Kept in step with `requires-python` in pyproject.toml. Checking here rather
# than letting pip refuse the install means the error names the real problem
# ("your Python is the wrong version") instead of arriving as a resolver
# message forty lines into an install log.
PY_MAJOR=3
PY_MIN_MINOR=11
PY_MAX_MINOR=13

python_ok() {
    # Compared numerically by the interpreter itself. Parsing `--version` in
    # shell is where this check usually goes wrong: "3.9" sorts after "3.11" as
    # a string and before it as a version.
    "$1" -c 'import sys
major, low, high = (int(value) for value in sys.argv[1:4])
sys.exit(0 if (major, low) <= sys.version_info[:2] <= (major, high) else 1)' \
        "$PY_MAJOR" "$PY_MIN_MINOR" "$PY_MAX_MINOR" 2>/dev/null
}

py_version() { "$1" -c 'import sys; print(sys.version.split()[0])' 2>/dev/null; }

no_python() {
    fail "Uygun bir Python bulunamadı."
    cat >&2 <<EOF

    Bu proje Python ${PY_MAJOR}.${PY_MIN_MINOR} - ${PY_MAJOR}.${PY_MAX_MINOR} gerektiriyor (bkz. pyproject.toml).

      Ubuntu/Debian : sudo apt install python3 python3-venv python3-pip
      Fedora        : sudo dnf install python3 python3-pip
      macOS         : brew install python@3.12  (ya da https://www.python.org/downloads/)

    Kurduktan sonra bu betiği yeniden çalıştırın.
EOF
    exit 1
}

# --- virtualenv --------------------------------------------------------------

# An existing `venv/` wins because that is what the Makefile hardcodes
# (`VENV ?= venv`): a checkout already set up with `make setup` must not
# silently grow a second, half-installed environment beside the first. A fresh
# clone gets `.venv/`, which is the name editors and tooling autodetect. Both
# are gitignored.
if [ -d venv ]; then
    VENV_DIR="venv"
else
    VENV_DIR=".venv"
fi
VENV_PY="${VENV_DIR}/bin/python"

# The version check runs against the environment that will actually run the
# service, and a machine that already has one needs no system interpreter at
# all. Checking the system Python first would refuse to start a perfectly good
# 3.12 virtualenv on a host whose /usr/bin/python3 has moved on to 3.14 -- a
# distro upgrade away on every Linux desktop, and the wrong answer, because the
# system interpreter is not the one that would run anything.
if [ -x "$VENV_PY" ]; then
    if ! python_ok "$VENV_PY"; then
        fail "${VENV_DIR}/ içindeki Python $(py_version "$VENV_PY") desteklenmiyor."
        warn "Desteklenen aralık: ${PY_MAJOR}.${PY_MIN_MINOR} - ${PY_MAJOR}.${PY_MAX_MINOR}."
        warn "'${VENV_DIR}' klasörünü silip bu betiği yeniden çalıştırın."
        exit 1
    fi
    info "Sanal ortam: ${VENV_DIR}/ (Python $(py_version "$VENV_PY"))"
else
    # `python3` first, then the explicitly versioned names, then bare `python`.
    # The versioned ones are not padding: a distro that has moved `python3` on
    # to an unsupported release almost always still ships the previous one as
    # `python3.12`, and without this the launcher would tell a machine that can
    # perfectly well run the service to go and install Python.
    PYTHON=""
    for candidate in python3 python3.13 python3.12 python3.11 python; do
        if command -v "$candidate" >/dev/null 2>&1 && python_ok "$candidate"; then
            PYTHON="$candidate"
            break
        fi
    done
    [ -n "$PYTHON" ] || no_python

    info "Python $(py_version "$PYTHON") -- $(command -v "$PYTHON")"
    step "Sanal ortam oluşturuluyor: ${VENV_DIR}/"
    if ! "$PYTHON" -m venv "$VENV_DIR"; then
        fail "Sanal ortam oluşturulamadı."
        warn "Debian/Ubuntu'da ayrı bir paket gerekir: sudo apt install python3-venv"
        exit 1
    fi
fi

# --- dependencies ------------------------------------------------------------

# Installing on every launch would add tens of seconds to a start that should
# be instant; skipping unconditionally would leave a site running last month's
# requirements after a `git pull`. The sentinel holds a hash of the two files
# that decide what gets installed, so "stale" is answered by content rather
# than by a timestamp -- which matters because git does not preserve mtimes,
# and a mtime comparison on a fresh clone answers either "always stale" or
# "never stale" depending on checkout order.
SENTINEL="${VENV_DIR}/.deps_installed"
DEPS_INPUTS=(requirements.txt pyproject.toml)

deps_hash() {
    "$VENV_PY" -c 'import hashlib, pathlib, sys
digest = hashlib.sha256()
for name in sys.argv[1:]:
    path = pathlib.Path(name)
    # The name is hashed too, so a file appearing or disappearing changes the
    # digest even when the remaining contents are unchanged.
    digest.update(name.encode())
    digest.update(path.read_bytes() if path.is_file() else b"")
print(digest.hexdigest())' "${DEPS_INPUTS[@]}"
}

install_deps() {
    # Removed first: an install interrupted halfway must never leave a sentinel
    # behind claiming the environment is complete.
    rm -f "$SENTINEL"
    "$VENV_PY" -m pip install --upgrade pip || return 1
    "$VENV_PY" -m pip install -r requirements.txt || return 1
    "$VENV_PY" -m pip install -e . || return 1
}

WANTED="$(deps_hash)"
CURRENT=""
if [ -f "$SENTINEL" ]; then
    CURRENT="$(tr -d '[:space:]' < "$SENTINEL")"
fi

if [ "$WANTED" != "$CURRENT" ]; then
    if [ -n "$CURRENT" ]; then
        step "Bağımlılıklar değişmiş, güncelleniyor (birkaç dakika sürebilir)"
    else
        step "Bağımlılıklar kuruluyor (ilk çalıştırma, birkaç dakika sürebilir)"
    fi
    if ! install_deps; then
        fail "Bağımlılıklar kurulamadı."
        warn "İnternet bağlantısını kontrol edip betiği yeniden çalıştırın."
        exit 1
    fi
    printf '%s\n' "$WANTED" > "$SENTINEL"

    # Directories, signing keys, a local licence and a `.env`. Idempotent, and
    # deliberately non-fatal: the API's degraded-mode contract means it starts
    # and reports what is missing, which is more useful to whoever is standing
    # at the gate than a launcher that refuses to run.
    if ! "$VENV_PY" scripts/setup_dev.py; then
        warn "scripts/setup_dev.py başarısız oldu; servis eksik yapılandırmayla başlayacak."
    fi
else
    info "Bağımlılıklar güncel (${SENTINEL})"
fi

# --- runtime directories -----------------------------------------------------

# The application creates these itself, but doing it here means a permission
# problem on the data volume surfaces now, with a path in the message, instead
# of as a swallowed warning on the snapshot writer's thread an hour later.
mkdir -p data data/snapshots

# --- launch ------------------------------------------------------------------

printf '\n'
step "LPR servisi başlatılıyor"
info "Panel:    http://localhost:8000"
info "Durdurma: Ctrl+C"
printf '\n'

# `exec` so the Python process replaces this shell: Ctrl+C then reaches uvicorn
# directly, it runs its own graceful shutdown (the lifespan teardown stops the
# pipeline and joins the camera threads), and the exit status the caller sees
# is the server's own rather than this shell's. Nothing may run after this
# line -- that is the point of using exec rather than a plain call.
#
# Host and port come from config.yaml / .env (api.host, api.port), which is why
# they are not passed here; the URL printed above is the shipped default.
exec "$VENV_PY" -m lpr.api.main
