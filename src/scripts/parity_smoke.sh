#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# C++ reference binary is produced by src/compile_jdvrif.sh in the src/ dir.
CPP_BIN="${JDVRIF_CPP_BIN:-${JDVRIF_LEGACY_BIN:-$ROOT_DIR/src/jdvrif}}"
RUST_PORT_DIR="$ROOT_DIR/rust_port"
RUST_BIN="${JDVRIF_RUST_BIN:-$RUST_PORT_DIR/target/release/jdvrif-rs}"

if [[ ! -x "$CPP_BIN" ]]; then
    echo "C++ binary not found/executable: $CPP_BIN" >&2
    echo "Build it first with: bash $ROOT_DIR/src/compile_jdvrif.sh" >&2
    exit 1
fi

(
    cd "$RUST_PORT_DIR"
    cargo build --release
)

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

"$CPP_BIN" --info > "$tmp_dir/cpp_info.txt"
"$RUST_BIN" --info > "$tmp_dir/rust_info.txt"

# Rust intentionally has Cargo build instructions and the `jdvrif-rs` binary
# name. Drop only the build section and normalize only that program name; all
# remaining v8.2 guidance must match the current C++ output.
normalize_info() { # $1 = info file, $2 = "1" to fold jdvrif-rs -> jdvrif
    python3 - "$1" "$2" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
if sys.argv[2] == "1":
    lines = [l.replace("jdvrif-rs", "jdvrif") for l in lines]
build = next(
    i for i, line in enumerate(lines)
    if line.strip().startswith(("Build & run (", "Compile & run ("))
)
usage = next(i for i, line in enumerate(lines) if line.strip() == "Usage")
# Drop from the build section's opening divider up to (not incl.) Usage's divider.
out = lines[:build - 1] + lines[usage - 1:]
sys.stdout.write("\n".join(out))
PY
}

normalize_info "$tmp_dir/cpp_info.txt"  0 > "$tmp_dir/cpp_shared.txt"
normalize_info "$tmp_dir/rust_info.txt" 1 > "$tmp_dir/rust_shared.txt"

if ! diff -u "$tmp_dir/cpp_shared.txt" "$tmp_dir/rust_shared.txt"; then
    echo "Parity mismatch: shared --info content differs." >&2
    exit 1
fi

for source in reddit_steg.h reddit_steg.cpp; do
    if ! cmp -s "$ROOT_DIR/src/$source" "$RUST_PORT_DIR/src/$source"; then
        echo "Parity mismatch: Rust src/$source differs from the current C++ source." >&2
        diff -u "$ROOT_DIR/src/$source" "$RUST_PORT_DIR/src/$source" || true
        exit 1
    fi
done

echo "Parity smoke passed: shared --info content matches (build section + program name intentionally differ)."
echo "Reddit carrier source parity passed: src reddit_steg.{h,cpp} matches C++."
