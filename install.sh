#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="release"
PREFIX="${HOME}/.local"

usage() {
  cat <<'EOF'
Install mcpx from this repository.

Usage:
  ./install.sh [--debug] [--prefix <dir>] [--help]

Options:
  --debug         Build debug binary instead of release
  --prefix <dir>  Install prefix (binary goes to <dir>/bin/mcpx)
  --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      PROFILE="debug"
      shift
      ;;
    --prefix)
      if [[ $# -lt 2 ]]; then
        echo "error: --prefix requires a value" >&2
        exit 1
      fi
      PREFIX="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required but was not found in PATH." >&2
  echo "Install Rust from https://rustup.rs/ and try again." >&2
  exit 1
fi

cd "${ROOT_DIR}"

echo "Building mcpx (${PROFILE})..."
if [[ "${PROFILE}" == "release" ]]; then
  cargo build --release -p mcpx
  SOURCE_BIN="${ROOT_DIR}/target/release/mcpx"
else
  cargo build -p mcpx
  SOURCE_BIN="${ROOT_DIR}/target/debug/mcpx"
fi

if [[ ! -x "${SOURCE_BIN}" ]]; then
  echo "error: built binary not found: ${SOURCE_BIN}" >&2
  exit 1
fi

INSTALL_BIN_DIR="${PREFIX}/bin"
INSTALL_BIN="${INSTALL_BIN_DIR}/mcpx"
mkdir -p "${INSTALL_BIN_DIR}"
cp "${SOURCE_BIN}" "${INSTALL_BIN}"
chmod +x "${INSTALL_BIN}"

echo "Installed: ${INSTALL_BIN}"
if [[ ":${PATH}:" != *":${INSTALL_BIN_DIR}:"* ]]; then
  echo "warning: ${INSTALL_BIN_DIR} is not on your PATH." >&2
  echo "Add this to your shell config:" >&2
  echo "  export PATH=\"${INSTALL_BIN_DIR}:\$PATH\"" >&2
fi

echo "Done. Try:"
echo "  ${INSTALL_BIN} --help"
