#!/usr/bin/env bash
set -Eeuo pipefail

# Always run from the repository root, regardless of the caller's directory.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
fail() {
  code=$?
  printf "\n${RED}[CROPTer ERROR]${RESET} Setup or launch failed (exit %s).\n" "$code" >&2
  printf "Project: %s\n" "$ROOT" >&2
  printf "Details: rerun with: bash -x %q\n" "$ROOT/run.sh" >&2
  exit "$code"
}
trap fail ERR

if ! command -v python3 >/dev/null 2>&1; then
  printf "${RED}python3 was not found. On Kali: sudo apt install python3-full python3-venv python3-pip${RESET}\n" >&2
  exit 127
fi

if [[ ! -d .venv ]]; then
  printf "${CYAN}[SETUP]${RESET} Creating project virtual environment...\n"
  python3 -m venv .venv
fi

PY="$ROOT/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  printf "${RED}Virtual environment is incomplete: %s${RESET}\n" "$PY" >&2
  printf "Try: rm -rf %q/.venv && python3 -m venv %q/.venv\n" "$ROOT" "$ROOT" >&2
  exit 1
fi

# Editable install is idempotent and keeps dependencies inside this project's venv.
if ! "$PY" -c 'import cropter' >/dev/null 2>&1 || ! "$PY" -m pip show cropter >/dev/null 2>&1; then
  printf "${CYAN}[SETUP]${RESET} Installing CROPTer into its isolated .venv...\n"
  "$PY" -m pip install -e .
fi

printf "${GREEN}[OK]${RESET} Launching CROPTer UI\n"
exec "$PY" -m cropter.tui
