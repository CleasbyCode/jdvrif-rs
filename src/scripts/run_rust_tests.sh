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

# A wrong KEY must be rejected from the first frame, read where the ciphertext
# sits, without copying it anywhere first (mirrors the C++ smoke test). Under an
# 8 MiB RLIMIT_FSIZE, recovery can only report the bad KEY if it never writes
# the 32 MiB ciphertext out.
(
    work="$(mktemp -d "${TMPDIR:-/tmp}/jdvrif-rs-wrong-key.XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    cd "$work"
    cp "$CPP_TESTS_DIR/testdata/covers/cover_default.jpg" cover.jpg
    head -c $((32 * 1024 * 1024)) /dev/urandom > payload.bin
    "$RUST_BIN" conceal cover.jpg payload.bin > conceal.log 2>&1
    image="$(sed -n 's/.*Saved "file-embedded" JPG image: \(.*\) ([0-9][0-9]* bytes)\..*/\1/p' conceal.log | tail -n 1)"
    key="$(sed -nE 's/.*Recovery KEY: \[\*\*\*([1-9A-HJ-NP-Za-km-z-]+)\*\*\*\].*/\1/p' conceal.log | tail -n 1)"
    [[ -n "$image" && -n "$key" ]] || { echo "conceal of the large payload failed" >&2; exit 1; }
    wrong_key=1111-1111-1111-1111-1111-126X
    if [[ "$key" == "$wrong_key" ]]; then wrong_key=112d-rXXU-ifSr-RnXL-GbXg-8Egs; fi
    rm -f payload.bin
    if (ulimit -f 8192 && printf '%s\n' "$wrong_key" | "$RUST_BIN" recover "$image" > recover.log 2>&1); then
        echo "Rust recovery unexpectedly accepted a wrong KEY" >&2
        exit 1
    fi
    if ! grep -Fq 'Invalid recovery KEY or file is corrupt.' recover.log || [[ -e payload.bin ]]; then
        echo "Rust wrong KEY was not rejected before staging I/O:" >&2
        cat recover.log >&2
        exit 1
    fi
    echo "[PASS] Rust wrong KEY is rejected without staging the ciphertext"
)

# Refused core-dump hardening must warn and carry on (mirrors the C++ smoke
# test). An LD_PRELOAD shim fails setrlimit(RLIMIT_CORE) and/or
# prctl(PR_SET_DUMPABLE) with EPERM as $REFUSE says; other calls pass through.
if command -v cc >/dev/null 2>&1; then
(
    work="$(mktemp -d "${TMPDIR:-/tmp}/jdvrif-rs-refusal.XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    cd "$work"
    cat > refuse.c <<'SHIM'
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
static int refused(const char* what) {
    const char* r = getenv("REFUSE");
    return r && strstr(r, what);
}
int setrlimit(__rlimit_resource_t res, const struct rlimit* lim) {
    if (res == RLIMIT_CORE && refused("core")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_setrlimit, res, lim);
}
int prctl(int op, ...) {
    va_list ap;
    unsigned long a[4];
    va_start(ap, op);
    for (int i = 0; i < 4; ++i) a[i] = va_arg(ap, unsigned long);
    va_end(ap);
    if (op == PR_SET_DUMPABLE && refused("dump")) { errno = EPERM; return -1; }
    return (int)syscall(SYS_prctl, op, a[0], a[1], a[2], a[3]);
}
SHIM
    cc -shared -fPIC -O2 -o refuse.so refuse.c
    for refuse in "core,dump" core dump none; do
        case "$refuse" in
            core,dump) expect="RLIMIT_CORE 0 and PR_SET_DUMPABLE 0" ;;
            core) expect="RLIMIT_CORE 0," ;;
            dump) expect="PR_SET_DUMPABLE 0," ;;
            none) expect="" ;;
        esac
        mkdir "run_$refuse"
        if ! (cd "run_$refuse" && REFUSE="$refuse" LD_PRELOAD="$work/refuse.so" "$RUST_BIN" conceal \
                "$CPP_TESTS_DIR/testdata/covers/cover_default.jpg" \
                "$CPP_TESTS_DIR/testdata/payloads/payload_text.txt" > out.log 2> err.log) \
            || ! compgen -G "run_$refuse/jrif_*.jpg" > /dev/null; then
            echo "Rust conceal [$refuse] did not finish after a refused hardening call:" >&2
            cat "run_$refuse/out.log" "run_$refuse/err.log" >&2
            exit 1
        fi
        if [[ -z "$expect" ]]; then
            if grep -q 'Warning' "run_$refuse/err.log"; then
                echo "Rust warned although nothing was refused:" >&2
                cat "run_$refuse/err.log" >&2
                exit 1
            fi
        elif ! grep -Fq "Warning: The system refused $expect" "run_$refuse/err.log" \
            || ! grep -Fq "Continuing anyway." "run_$refuse/err.log"; then
            echo "Rust [$refuse] missing or wrong hardening warning:" >&2
            cat "run_$refuse/err.log" >&2
            exit 1
        fi
    done
    echo "[PASS] Rust refused core-dump hardening warns and carries on"
)
else
    echo "[SKIP] Rust refused core-dump hardening warns (no C compiler)"
fi
