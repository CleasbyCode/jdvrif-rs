#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# C++ reference binary is produced by src/compile_jdvrif.sh in the src/ dir.
CPP_BIN="${JDVRIF_CPP_BIN:-${JDVRIF_LEGACY_BIN:-$ROOT_DIR/src/jdvrif}}"
RUST_PORT_DIR="$ROOT_DIR/rust_port"
RUST_BIN="${JDVRIF_RUST_BIN:-$RUST_PORT_DIR/target/release/jdvrif-rs}"

NO_BUILD=0
KEEP_ARTIFACTS=0
ARTIFACT_ROOT=""
PASS_COUNT=0

usage() {
    cat <<'USAGE'
Usage: rust_port/src/scripts/parity_full.sh [options]

Options:
  --no-build               Reuse existing Rust binary.
  --artifacts-dir <dir>    Write artifacts under <dir> instead of a temp dir.
  --keep                   Keep artifacts directory after run.
  -h, --help               Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            NO_BUILD=1
            shift
            ;;
        --artifacts-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --artifacts-dir" >&2
                exit 2
            fi
            ARTIFACT_ROOT="$2"
            shift 2
            ;;
        --keep)
            KEEP_ARTIFACTS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

need_cmd ffmpeg
need_cmd python3
need_cmd cmp
need_cmd diff
need_cmd sed
need_cmd head

if [[ ! -x "$CPP_BIN" ]]; then
    echo "C++ binary not found/executable: $CPP_BIN" >&2
    echo "Build it first with: bash $ROOT_DIR/src/compile_jdvrif.sh" >&2
    exit 1
fi

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

AUTO_CLEAN=0
if [[ -z "$ARTIFACT_ROOT" ]]; then
    ARTIFACT_ROOT="$(mktemp -d)"
    AUTO_CLEAN=1
else
    mkdir -p "$ARTIFACT_ROOT"
fi

cleanup() {
    if [[ "$AUTO_CLEAN" -eq 1 && "$KEEP_ARTIFACTS" -eq 0 ]]; then
        rm -rf "$ARTIFACT_ROOT"
    fi
}
trap cleanup EXIT

log() {
    echo "[parity] $*"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $1"
}

extract_embedded_image() {
    sed -n 's/.*Saved "file-embedded" JPG image: \([^ ]*\) (.*/\1/p' "$1" | tail -n 1
}

extract_pin() {
    sed -n 's/.*Recovery PIN: \[\*\*\*\([0-9][0-9]*\)\*\*\*\].*/\1/p' "$1" | tail -n 1
}

extract_recovered_file() {
    sed -n 's/.*Extracted hidden file: \([^ ]*\) (.*/\1/p' "$1" | tail -n 1
}

# Rust intentionally has Cargo build instructions and the `jdvrif-rs` binary
# name. Normalize only those differences; all other v8.2 guidance must match.
normalize_info() { # $1 = info file, $2 = "1" to fold jdvrif-rs -> jdvrif
    python3 - "$1" "$2" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
if sys.argv[2] == "1":
    lines = [line.replace("jdvrif-rs", "jdvrif") for line in lines]
build = next(
    i for i, line in enumerate(lines)
    if line.strip().startswith(("Build & run (", "Compile & run ("))
)
usage = next(i for i, line in enumerate(lines) if line.strip() == "Usage")
out = lines[:build - 1] + lines[usage - 1:]
sys.stdout.write("\n".join(out))
PY
}

wrong_pin_for() {
    python3 - <<PY
pin = int("$1")
mod = 2 ** 64
candidate = (pin + 1) % mod
if candidate == pin:
    candidate = (pin + 2) % mod
print(candidate)
PY
}

run_conceal_capture() {
    local bin="$1"
    local option="$2"
    local cover="$3"
    local payload="$4"
    local out_dir="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    pushd "$out_dir" >/dev/null
    if [[ -n "$option" ]]; then
        "$bin" conceal "$option" "$cover" "$payload" > conceal.log 2>&1
    else
        "$bin" conceal "$cover" "$payload" > conceal.log 2>&1
    fi

    local embedded_image
    local pin
    embedded_image="$(extract_embedded_image conceal.log)"
    pin="$(extract_pin conceal.log)"

    if [[ -z "$embedded_image" || -z "$pin" || ! -f "$embedded_image" ]]; then
        echo "Failed to parse conceal output in: $out_dir" >&2
        cat conceal.log >&2
        exit 1
    fi

    mv "$embedded_image" embedded.jpg
    popd >/dev/null

    printf '%s|%s\n' "$out_dir/embedded.jpg" "$pin"
}

run_recover_compare() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local payload="$4"
    local out_dir="$5"
    local tag="$6"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    cp "$image" "$out_dir/input.jpg"

    pushd "$out_dir" >/dev/null
    if ! printf '%s\n' "$pin" | "$bin" recover input.jpg > recover.log 2>&1; then
        echo "Recover failed for $tag" >&2
        cat recover.log >&2
        exit 1
    fi

    local recovered_file
    recovered_file="$(extract_recovered_file recover.log)"
    if [[ -z "$recovered_file" || ! -f "$recovered_file" ]]; then
        echo "Failed to parse recovered output for $tag" >&2
        cat recover.log >&2
        exit 1
    fi

    if ! cmp -s "$recovered_file" "$payload"; then
        echo "Recovered payload mismatch for $tag" >&2
        exit 1
    fi

    popd >/dev/null
    pass "$tag"
}

run_wrong_pin_once() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local out_dir="$4"
    local tag="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    cp "$image" "$out_dir/input.jpg"
    local wrong_pin
    wrong_pin="$(wrong_pin_for "$pin")"

    pushd "$out_dir" >/dev/null
    if printf '%s\n' "$wrong_pin" | "$bin" recover input.jpg > recover.log 2>&1; then
        echo "Wrong PIN unexpectedly succeeded for $tag" >&2
        cat recover.log >&2
        exit 1
    fi

    if ! grep -q "Invalid recovery PIN" recover.log; then
        echo "Wrong PIN error message missing for $tag" >&2
        cat recover.log >&2
        exit 1
    fi

    if [[ ! -s input.jpg ]]; then
        echo "Image should not be destroyed after one bad PIN for $tag" >&2
        exit 1
    fi

    popd >/dev/null
    pass "$tag"
}

run_repeated_wrong_pin_no_destroy() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local out_dir="$4"
    local tag="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    cp "$image" "$out_dir/input.jpg"
    local wrong_pin
    wrong_pin="$(wrong_pin_for "$pin")"

    pushd "$out_dir" >/dev/null
    local i
    for i in 1 2 3 4; do
        if printf '%s\n' "$wrong_pin" | "$bin" recover input.jpg > "recover_$i.log" 2>&1; then
            echo "Wrong PIN unexpectedly succeeded on attempt $i for $tag" >&2
            cat "recover_$i.log" >&2
            exit 1
        fi

        if ! grep -q "Invalid recovery PIN" "recover_$i.log"; then
            echo "Wrong PIN error message missing on attempt $i for $tag" >&2
            cat "recover_$i.log" >&2
            exit 1
        fi
    done

    if [[ ! -s input.jpg ]]; then
        echo "Image should remain intact after repeated bad PINs for $tag" >&2
        exit 1
    fi

    popd >/dev/null
    pass "$tag"
}

run_negative_truncated_file() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local out_dir="$4"
    local tag="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    cp "$image" "$out_dir/input.jpg"

    python3 - <<PY
from pathlib import Path
p = Path("$out_dir/input.jpg")
data = p.read_bytes()
sig = b"mntrRGB"
idx = data.find(sig)
if idx < 8:
    raise SystemExit("ICC signature not found")
start = idx - 8
file_size_offset = start + 0x2CA
encrypted_start = start + 0x33B
if file_size_offset + 4 > len(data):
    raise SystemExit("file-size field out of range")
embedded_size = int.from_bytes(data[file_size_offset:file_size_offset+4], "big")
if embedded_size < 32:
    raise SystemExit("embedded payload unexpectedly small")
payload_end = encrypted_start + embedded_size
if payload_end > len(data):
    raise SystemExit("embedded payload range out of bounds")
truncate_at = encrypted_start + (embedded_size // 2)
if truncate_at <= encrypted_start or truncate_at >= len(data):
    raise SystemExit("invalid truncate position")
p.write_bytes(data[:truncate_at])
PY

    pushd "$out_dir" >/dev/null
    if printf '%s\n' "$pin" | "$bin" recover input.jpg > recover.log 2>&1; then
        echo "Truncated-file recover unexpectedly succeeded for $tag" >&2
        cat recover.log >&2
        exit 1
    fi
    popd >/dev/null
    pass "$tag"
}

run_negative_corrupt_size_metadata() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local out_dir="$4"
    local tag="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    cp "$image" "$out_dir/input.jpg"

    python3 - <<PY
from pathlib import Path
p = Path("$out_dir/input.jpg")
data = bytearray(p.read_bytes())
sig = b"mntrRGB"
idx = data.find(sig)
if idx < 8:
    raise SystemExit("ICC signature not found")
start = idx - 8
file_size_index = 0x2CA
offset = start + file_size_index
if offset + 4 > len(data):
    raise SystemExit("file-size index out of range")
data[offset:offset+4] = (0xFFFFFFF0).to_bytes(4, "big")
p.write_bytes(data)
PY

    pushd "$out_dir" >/dev/null
    if printf '%s\n' "$pin" | "$bin" recover input.jpg > recover.log 2>&1; then
        echo "Corrupt-size recover unexpectedly succeeded for $tag" >&2
        cat recover.log >&2
        exit 1
    fi
    popd >/dev/null
    pass "$tag"
}

run_filename_collision_recovery() {
    local bin="$1"
    local image="$2"
    local pin="$3"
    local payload="$4"
    local out_dir="$5"
    local tag="$6"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    cp "$image" "$out_dir/input.jpg"

    local payload_name
    payload_name="$(basename "$payload")"

    pushd "$out_dir" >/dev/null
    printf 'occupied\n' > "$payload_name"

    if ! printf '%s\n' "$pin" | "$bin" recover input.jpg > recover.log 2>&1; then
        echo "Filename-collision recover failed for $tag" >&2
        cat recover.log >&2
        exit 1
    fi

    local recovered_file
    recovered_file="$(extract_recovered_file recover.log)"
    if [[ -z "$recovered_file" || ! -f "$recovered_file" ]]; then
        echo "Failed to parse recovered output for $tag" >&2
        cat recover.log >&2
        exit 1
    fi
    if [[ "$recovered_file" == "$payload_name" ]]; then
        echo "No unique filename generated for $tag" >&2
        exit 1
    fi
    if ! cmp -s "$recovered_file" "$payload"; then
        echo "Filename-collision recovered payload mismatch for $tag" >&2
        exit 1
    fi

    popd >/dev/null
    pass "$tag"
}

run_invalid_filename_conceal() {
    local bin="$1"
    local cover="$2"
    local bad_payload="$3"
    local out_dir="$4"
    local tag="$5"

    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    pushd "$out_dir" >/dev/null
    if "$bin" conceal "$cover" "$bad_payload" > conceal.log 2>&1; then
        echo "Invalid-filename conceal unexpectedly succeeded for $tag" >&2
        cat conceal.log >&2
        exit 1
    fi
    if ! grep -q "Unsupported control or path-separator characters in filename arguments" conceal.log; then
        echo "Invalid-filename error message missing for $tag" >&2
        cat conceal.log >&2
        exit 1
    fi
    popd >/dev/null
    pass "$tag"
}

assert_icc_multiseg_min() {
    local image="$1"
    local min_segments="$2"
    local tag="$3"

    local segments
    segments="$(python3 - <<PY
from pathlib import Path
p = Path("$image")
data = p.read_bytes()
sig = b"mntrRGB"
idx = data.find(sig)
if idx < 8:
    raise SystemExit(2)
start = idx - 8
off = start + 0x2C8
if off + 2 > len(data):
    raise SystemExit(3)
print(int.from_bytes(data[off:off+2], "big"))
PY
)"

    if [[ -z "$segments" || "$segments" -lt "$min_segments" ]]; then
        echo "ICC segment count check failed for $tag (got: ${segments:-none})" >&2
        exit 1
    fi

    pass "$tag"
}

assert_icc_profile_signatures() {
    local image="$1"
    local tag="$2"

    local result
    result="$(python3 - <<PY
from pathlib import Path

data = Path("$image").read_bytes()
mntr = data.find(b"mntrRGB")
if mntr < 0:
    raise SystemExit("mntrRGB signature not found")
acsp = mntr + 24
if acsp + 4 > len(data):
    raise SystemExit("acsp range out of bounds")
if data[acsp:acsp+4] != b"acsp":
    got = data[acsp:acsp+4]
    raise SystemExit(f"acsp signature mismatch at offset {acsp}: got={got!r}")
print("ok")
PY
)" || {
        echo "ICC signature integrity check failed for $tag" >&2
        return 1
    }

    if [[ "$result" != "ok" ]]; then
        echo "ICC signature integrity check failed for $tag" >&2
        return 1
    fi

    pass "$tag"
}

assert_bluesky_pshop() {
    local image="$1"
    local expected="$2"
    local tag="$3"

    local has_pshop
    has_pshop="$(python3 - <<PY
from pathlib import Path
data = Path("$image").read_bytes()
print(1 if b"Photoshop 3.0" in data else 0)
PY
)"

    if [[ "$has_pshop" -ne "$expected" ]]; then
        echo "Bluesky Photoshop segment check failed for $tag (expected $expected, got $has_pshop)" >&2
        exit 1
    fi

    pass "$tag"
}

run_case() {
    local case_name="$1"
    local option="$2"
    local cover="$3"
    local payload="$4"
    local expect_multiseg="$5"
    local expect_bluesky_pshop="$6"

    local case_dir="$ARTIFACT_ROOT/cases/$case_name"
    mkdir -p "$case_dir"

    log "case=$case_name option='${option:-none}'"

    local cpp_pair
    cpp_pair="$(run_conceal_capture "$CPP_BIN" "$option" "$cover" "$payload" "$case_dir/cpp_conceal")"
    IFS='|' read -r cpp_image cpp_pin <<< "$cpp_pair"

    local rust_pair
    rust_pair="$(run_conceal_capture "$RUST_BIN" "$option" "$cover" "$payload" "$case_dir/rust_conceal")"
    IFS='|' read -r rust_image rust_pin <<< "$rust_pair"

    if [[ -z "$option" ]]; then
        assert_icc_profile_signatures "$cpp_image" "$case_name cpp ICC profile signatures"
        assert_icc_profile_signatures "$rust_image" "$case_name rust ICC profile signatures"
    fi

    if [[ "$expect_multiseg" -eq 1 ]]; then
        assert_icc_multiseg_min "$cpp_image" 2 "$case_name cpp multiseg"
        assert_icc_multiseg_min "$rust_image" 2 "$case_name rust multiseg"
    fi

    if [[ "$expect_bluesky_pshop" -ge 0 ]]; then
        assert_bluesky_pshop "$cpp_image" "$expect_bluesky_pshop" "$case_name cpp bluesky segment"
        assert_bluesky_pshop "$rust_image" "$expect_bluesky_pshop" "$case_name rust bluesky segment"
    fi

    run_recover_compare "$CPP_BIN" "$cpp_image" "$cpp_pin" "$payload" "$case_dir/recover_cpp_from_cpp" "$case_name recover cpp<-cpp"
    run_recover_compare "$RUST_BIN" "$rust_image" "$rust_pin" "$payload" "$case_dir/recover_rust_from_rust" "$case_name recover rust<-rust"
    run_recover_compare "$RUST_BIN" "$cpp_image" "$cpp_pin" "$payload" "$case_dir/recover_rust_from_cpp" "$case_name recover rust<-cpp"
    run_recover_compare "$CPP_BIN" "$rust_image" "$rust_pin" "$payload" "$case_dir/recover_cpp_from_rust" "$case_name recover cpp<-rust"

    run_wrong_pin_once "$CPP_BIN" "$cpp_image" "$cpp_pin" "$case_dir/wrongpin_cpp_on_cpp" "$case_name wrong-pin cpp on cpp-image"
    run_wrong_pin_once "$RUST_BIN" "$cpp_image" "$cpp_pin" "$case_dir/wrongpin_rust_on_cpp" "$case_name wrong-pin rust on cpp-image"
    run_wrong_pin_once "$CPP_BIN" "$rust_image" "$rust_pin" "$case_dir/wrongpin_cpp_on_rust" "$case_name wrong-pin cpp on rust-image"
    run_wrong_pin_once "$RUST_BIN" "$rust_image" "$rust_pin" "$case_dir/wrongpin_rust_on_rust" "$case_name wrong-pin rust on rust-image"

    if [[ "$expect_multiseg" -eq 1 && -z "$option" ]]; then
        run_repeated_wrong_pin_no_destroy "$CPP_BIN" "$cpp_image" "$cpp_pin" "$case_dir/repeat_wrongpin_cpp_on_cpp" "$case_name repeated wrong-pin cpp on cpp-image"
        run_repeated_wrong_pin_no_destroy "$RUST_BIN" "$cpp_image" "$cpp_pin" "$case_dir/repeat_wrongpin_rust_on_cpp" "$case_name repeated wrong-pin rust on cpp-image"
        run_repeated_wrong_pin_no_destroy "$CPP_BIN" "$rust_image" "$rust_pin" "$case_dir/repeat_wrongpin_cpp_on_rust" "$case_name repeated wrong-pin cpp on rust-image"
        run_repeated_wrong_pin_no_destroy "$RUST_BIN" "$rust_image" "$rust_pin" "$case_dir/repeat_wrongpin_rust_on_rust" "$case_name repeated wrong-pin rust on rust-image"

        run_negative_truncated_file "$CPP_BIN" "$cpp_image" "$cpp_pin" "$case_dir/truncated_cpp_on_cpp" "$case_name truncated cpp on cpp-image"
        run_negative_truncated_file "$RUST_BIN" "$cpp_image" "$cpp_pin" "$case_dir/truncated_rust_on_cpp" "$case_name truncated rust on cpp-image"
        run_negative_truncated_file "$CPP_BIN" "$rust_image" "$rust_pin" "$case_dir/truncated_cpp_on_rust" "$case_name truncated cpp on rust-image"
        run_negative_truncated_file "$RUST_BIN" "$rust_image" "$rust_pin" "$case_dir/truncated_rust_on_rust" "$case_name truncated rust on rust-image"

        run_negative_corrupt_size_metadata "$CPP_BIN" "$cpp_image" "$cpp_pin" "$case_dir/corruptsize_cpp_on_cpp" "$case_name corrupt-size cpp on cpp-image"
        run_negative_corrupt_size_metadata "$RUST_BIN" "$cpp_image" "$cpp_pin" "$case_dir/corruptsize_rust_on_cpp" "$case_name corrupt-size rust on cpp-image"
        run_negative_corrupt_size_metadata "$CPP_BIN" "$rust_image" "$rust_pin" "$case_dir/corruptsize_cpp_on_rust" "$case_name corrupt-size cpp on rust-image"
        run_negative_corrupt_size_metadata "$RUST_BIN" "$rust_image" "$rust_pin" "$case_dir/corruptsize_rust_on_rust" "$case_name corrupt-size rust on rust-image"

        run_filename_collision_recovery "$CPP_BIN" "$cpp_image" "$cpp_pin" "$payload" "$case_dir/collision_cpp_on_cpp" "$case_name collision cpp on cpp-image"
        run_filename_collision_recovery "$RUST_BIN" "$cpp_image" "$cpp_pin" "$payload" "$case_dir/collision_rust_on_cpp" "$case_name collision rust on cpp-image"
        run_filename_collision_recovery "$CPP_BIN" "$rust_image" "$rust_pin" "$payload" "$case_dir/collision_cpp_on_rust" "$case_name collision cpp on rust-image"
        run_filename_collision_recovery "$RUST_BIN" "$rust_image" "$rust_pin" "$payload" "$case_dir/collision_rust_on_rust" "$case_name collision rust on rust-image"
    fi
}

log "artifacts=$ARTIFACT_ROOT"

FIXTURES_DIR="$ARTIFACT_ROOT/fixtures"
mkdir -p "$FIXTURES_DIR/covers" "$FIXTURES_DIR/payloads"

log "building fixtures"
ffmpeg -hide_banner -loglevel error -y -f lavfi -i testsrc2=size=1280x960:rate=1 -frames:v 1 -q:v 10 "$FIXTURES_DIR/covers/cover_default.jpg"
ffmpeg -hide_banner -loglevel error -y -f lavfi -i smptebars=size=900x900:rate=1 -frames:v 1 -q:v 12 "$FIXTURES_DIR/covers/cover_bluesky.jpg"

cat > "$FIXTURES_DIR/payloads/payload_text.txt" <<'PAYLOAD'
This is a Rust vs cpp parity payload.
Line 2 validates conceal/recover interoperability.
Line 3 ensures deterministic extraction comparison.
PAYLOAD

head -c 220000 /dev/urandom > "$FIXTURES_DIR/payloads/payload_multi.bin"
head -c 62000 /dev/urandom > "$FIXTURES_DIR/payloads/bsingle.bin"
head -c 80000 /dev/urandom > "$FIXTURES_DIR/payloads/bsplit.bin"
head -c 150000 /dev/urandom > "$FIXTURES_DIR/payloads/bxmp.bin"
printf 'bad filename payload\n' > "$FIXTURES_DIR/payloads/bad:name.txt"

log "running shared --info diff"
"$CPP_BIN" --info > "$ARTIFACT_ROOT/cpp_info.txt"
"$RUST_BIN" --info > "$ARTIFACT_ROOT/rust_info.txt"
normalize_info "$ARTIFACT_ROOT/cpp_info.txt"  0 > "$ARTIFACT_ROOT/cpp_shared_info.txt"
normalize_info "$ARTIFACT_ROOT/rust_info.txt" 1 > "$ARTIFACT_ROOT/rust_shared_info.txt"
if ! diff -u "$ARTIFACT_ROOT/cpp_shared_info.txt" "$ARTIFACT_ROOT/rust_shared_info.txt" > "$ARTIFACT_ROOT/info.diff"; then
    echo "Shared --info content mismatch (see $ARTIFACT_ROOT/info.diff)" >&2
    exit 1
fi
pass "shared --info parity"

run_case "default_text" "" "$FIXTURES_DIR/covers/cover_default.jpg" "$FIXTURES_DIR/payloads/payload_text.txt" 0 -1
run_case "default_multiseg" "" "$FIXTURES_DIR/covers/cover_default.jpg" "$FIXTURES_DIR/payloads/payload_multi.bin" 1 -1
run_case "bluesky_single" "-b" "$FIXTURES_DIR/covers/cover_bluesky.jpg" "$FIXTURES_DIR/payloads/bsingle.bin" 0 0
run_case "bluesky_split" "-b" "$FIXTURES_DIR/covers/cover_bluesky.jpg" "$FIXTURES_DIR/payloads/bsplit.bin" 0 1
run_case "bluesky_xmp" "-b" "$FIXTURES_DIR/covers/cover_bluesky.jpg" "$FIXTURES_DIR/payloads/bxmp.bin" 0 1
run_case "reddit_text" "-r" "$FIXTURES_DIR/covers/cover_default.jpg" "$FIXTURES_DIR/payloads/payload_text.txt" 0 -1

run_invalid_filename_conceal "$CPP_BIN" "$FIXTURES_DIR/covers/cover_default.jpg" "$FIXTURES_DIR/payloads/bad:name.txt" "$ARTIFACT_ROOT/invalid_name_cpp" "invalid-name conceal cpp"
run_invalid_filename_conceal "$RUST_BIN" "$FIXTURES_DIR/covers/cover_default.jpg" "$FIXTURES_DIR/payloads/bad:name.txt" "$ARTIFACT_ROOT/invalid_name_rust" "invalid-name conceal rust"

log "all checks passed"
echo "Parity full passed: $PASS_COUNT checks"
echo "Artifacts: $ARTIFACT_ROOT"
