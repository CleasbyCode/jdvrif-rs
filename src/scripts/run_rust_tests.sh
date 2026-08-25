#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUST_PORT_DIR="$ROOT_DIR/rust_port"
CPP_TESTS_DIR="$ROOT_DIR/src/tests"
RUST_BIN="${JDVRIF_RUST_BIN:-$RUST_PORT_DIR/target/release/jdvrif-rs}"

NO_BUILD=0
PASSTHRU=()

usage() {
    cat <<'EOF'
Usage: rust_port/src/scripts/run_rust_tests.sh [options]

Options:
  --no-build      Reuse the existing release binary (cargo test still runs).
  -h, --help      Show this help.

Any other options are passed through to each C++-tree binary test suite.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            NO_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            PASSTHRU+=("$1")
            shift
            ;;
    esac
done

if [[ "$NO_BUILD" -eq 0 ]]; then
    (
        cd "$RUST_PORT_DIR"
        cargo build --release
    )
fi

if [[ ! -x "$RUST_BIN" ]]; then
    echo "Rust binary not found/executable: $RUST_BIN" >&2
    echo "Build it first with: (cd $RUST_PORT_DIR && cargo build --release)" >&2
    exit 1
fi

(
    cd "$RUST_PORT_DIR"
    cargo test
)

SUITES=(
    run_golden_tests.sh
    run_roundtrip_tests.sh
)

for suite in "${SUITES[@]}"; do
    suite_path="$CPP_TESTS_DIR/$suite"
    if [[ ! -f "$suite_path" ]]; then
        echo "C++-tree test suite not found: $suite_path" >&2
        exit 1
    fi
    bash "$suite_path" --bin "$RUST_BIN" "${PASSTHRU[@]}"
done
