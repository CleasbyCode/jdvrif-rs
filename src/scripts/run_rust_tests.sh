#!/bin/bash

set -euo pipefail

RUST_PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT_DIR="$(dirname "$RUST_PORT_DIR")"
CPP_TESTS_DIR="${JDVRIF_CPP_TESTS_DIR:-$ROOT_DIR/src/tests}"
if [[ -z "${JDVRIF_CPP_TESTS_DIR:-}" && ! -d "$CPP_TESTS_DIR" ]]; then
    # The C++ tests may also sit beside src/ at the repository root.
    CPP_TESTS_DIR="$ROOT_DIR/tests"
fi
RUST_TARGET_DIR="${CARGO_TARGET_DIR:-$RUST_PORT_DIR/target}"
if [[ "$RUST_TARGET_DIR" != /* ]]; then
    RUST_TARGET_DIR="$RUST_PORT_DIR/$RUST_TARGET_DIR"
fi
RUST_BIN="${JDVRIF_RUST_BIN:-$RUST_TARGET_DIR/release/jdvrif-rs}"

NO_BUILD=0
PASSTHRU=()

usage() {
    cat <<'EOF'
Usage: rust_port/src/scripts/run_rust_tests.sh [options]

Options:
  --no-build      Reuse the existing release binary (cargo test still runs).
  -h, --help      Show this help.

Any other options are passed through to each platform regression suite.
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
        cargo build --release --locked
    )
fi

if [[ ! -x "$RUST_BIN" ]]; then
    echo "Rust binary not found/executable: $RUST_BIN" >&2
    echo "Build it first with: (cd $RUST_PORT_DIR && cargo build --release)" >&2
    exit 1
fi

(
    cd "$RUST_PORT_DIR"
    cargo test --locked
)

bash "$RUST_PORT_DIR/src/scripts/run_jpeg_safety_tests.sh"

SUITES=(
    run_golden_tests.sh
    run_roundtrip_tests.sh
    run_reddit_tests.sh
    run_twitter_tests.sh
)

for suite in "${SUITES[@]}"; do
    if [[ "$suite" == "run_reddit_tests.sh" ]]; then
        # Rust's streaming zlib output is interoperable but not byte-identical
        # to C++ libdeflate, so this copy makes only that size assertion
        # compressor-neutral. All carrier and behavioral checks stay current.
        suite_path="$RUST_PORT_DIR/src/scripts/$suite"
    else
        suite_path="$CPP_TESTS_DIR/$suite"
    fi
    if [[ ! -f "$suite_path" ]]; then
        echo "C++-tree test suite not found: $suite_path" >&2
        exit 1
    fi
    bash "$suite_path" --bin "$RUST_BIN" "${PASSTHRU[@]}"
done

python3 "$RUST_PORT_DIR/src/scripts/run_recovery_snapshot_test.py" \
    "$RUST_BIN" "$CPP_TESTS_DIR/testdata/covers/cover_default.jpg"

# A wrong PIN must be rejected from the first frame, read where the ciphertext
# sits, without copying it anywhere first (mirrors the C++ smoke test). Under an
# 8 MiB RLIMIT_FSIZE, recovery can only report the bad PIN if it never writes
# the 32 MiB ciphertext out.
(
    work="$(mktemp -d "${TMPDIR:-/tmp}/jdvrif-rs-wrong-pin.XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    cd "$work"
    cp "$CPP_TESTS_DIR/testdata/covers/cover_default.jpg" cover.jpg
    head -c $((32 * 1024 * 1024)) /dev/urandom > payload.bin
    "$RUST_BIN" conceal cover.jpg payload.bin > conceal.log 2>&1
    image="$(sed -n 's/.*Saved "file-embedded" JPG image: \(.*\) ([0-9][0-9]* bytes)\..*/\1/p' conceal.log | tail -n 1)"
    pin="$(sed -nE 's/.*Recovery KEY: \[\*\*\*([1-9A-HJ-NP-Za-km-z-]+)\*\*\*\].*/\1/p' conceal.log | tail -n 1)"
    [[ -n "$image" && -n "$pin" ]] || { echo "conceal of the large payload failed" >&2; exit 1; }
    wrong_pin=1111-1111-1111-1111-1111-126X
    if [[ "$pin" == "$wrong_pin" ]]; then wrong_pin=112d-rXXU-ifSr-RnXL-GbXg-8Egs; fi
    rm -f payload.bin
    if (ulimit -f 8192 && printf '%s\n' "$wrong_pin" | "$RUST_BIN" recover "$image" > recover.log 2>&1); then
        echo "Rust recovery unexpectedly accepted a wrong PIN" >&2
        exit 1
    fi
    if ! grep -Fq 'Invalid recovery KEY or file is corrupt.' recover.log || [[ -e payload.bin ]]; then
        echo "Rust wrong PIN was not rejected before staging I/O:" >&2
        cat recover.log >&2
        exit 1
    fi
    echo "[PASS] Rust wrong PIN is rejected without staging the ciphertext"
)
