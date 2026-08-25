#!/usr/bin/env bash
# Cross-interop matrix: conceal with binary A, recover with binary B, both ways,
# across {default, -b Bluesky, -r Reddit}. Proves C++ <-> Rust interop for the
# current build. This focused format check does not compare --info output; use
# parity_smoke.sh for shared CLI documentation parity.
#
# Usage: bash rust_port/scripts/interop_matrix.sh
#   COVER_DIR                       override cover-image directory
#                                   (default: src/tests/testdata/covers)
#   JDVRIF_CPP_BIN / JDVRIF_RUST_BIN override binaries
#   JDVRIF_LEGACY_BIN               backward-compatible alias for JDVRIF_CPP_BIN
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP="${JDVRIF_CPP_BIN:-${JDVRIF_LEGACY_BIN:-$ROOT_DIR/src/jdvrif}}"
RS="${JDVRIF_RUST_BIN:-$ROOT_DIR/rust_port/target/release/jdvrif-rs}"
COVER_DIR="${COVER_DIR:-$ROOT_DIR/src/tests/testdata/covers}"

for b in "$CPP" "$RS"; do
    if [[ ! -x "$b" ]]; then
        echo "Binary not found/executable: $b" >&2
        echo "Build C++: bash $ROOT_DIR/src/compile_jdvrif.sh ; Rust: (cd $ROOT_DIR/rust_port && cargo build --release)" >&2
        exit 1
    fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
passes=0

extract_pin()      { sed -n 's/.*Recovery PIN: \[\*\*\*\([0-9][0-9]*\)\*\*\*\].*/\1/p' "$1" | tail -n1; }
extract_image()    { sed -n 's/.*Saved "file-embedded" JPG image: \([^ ]*\) (.*/\1/p' "$1" | tail -n1; }
extract_recovered(){ sed -n 's/.*Extracted hidden file: \([^ ]*\) (.*/\1/p' "$1" | tail -n1; }

# conceal with $1, mode $2 ('' | -b | -r), cover $3, payload $4, in dir $5.
# Echoes "<abs image path>|<pin>" or exits nonzero.
do_conceal() {
    local bin="$1" opt="$2" cover="$3" payload="$4" dir="$5"
    rm -rf "$dir"; mkdir -p "$dir"
    pushd "$dir" >/dev/null
    if [[ -n "$opt" ]]; then "$bin" conceal "$opt" "$cover" "$payload" >conceal.log 2>&1
    else                     "$bin" conceal "$cover" "$payload"        >conceal.log 2>&1; fi
    local img pin; img="$(extract_image conceal.log)"; pin="$(extract_pin conceal.log)"
    if [[ -z "$img" || -z "$pin" || ! -f "$img" ]]; then
        echo "CONCEAL_PARSE_FAIL ($bin $opt)"; cat conceal.log; popd >/dev/null; return 1
    fi
    popd >/dev/null
    printf '%s|%s\n' "$dir/$img" "$pin"
}

# recover image $2 with binary $1 using pin $3, expecting bytes == $4. tag $5.
do_recover_compare() {
    local bin="$1" image="$2" pin="$3" payload="$4" tag="$5"
    local dir="$WORK/rec_$tag"
    rm -rf "$dir"; mkdir -p "$dir"
    cp "$image" "$dir/input.jpg"
    pushd "$dir" >/dev/null
    if ! printf '%s\n' "$pin" | "$bin" recover input.jpg >recover.log 2>&1; then
        echo "FAIL[$tag]: recover errored"; cat recover.log; popd >/dev/null; return 1
    fi
    local rec; rec="$(extract_recovered recover.log)"
    if [[ -z "$rec" || ! -f "$rec" ]]; then
        echo "FAIL[$tag]: no recovered file parsed"; cat recover.log; popd >/dev/null; return 1
    fi
    if ! cmp -s "$rec" "$payload"; then
        echo "FAIL[$tag]: recovered bytes differ from original"; popd >/dev/null; return 1
    fi
    popd >/dev/null
    echo "PASS[$tag]"; return 0
}

# Full case: conceal with A and with B, then recover each image with the OTHER
# binary (the cross-interop direction) and compare bytes.
run_case() {
    local label="$1" opt="$2" cover="$3" payload="$4"
    local cpp_pair rs_pair
    cpp_pair="$(do_conceal "$CPP" "$opt" "$cover" "$payload" "$WORK/cpp_$label")" || { fails=$((fails+1)); echo "FAIL[$label]: C++ conceal"; return; }
    rs_pair="$(do_conceal "$RS"  "$opt" "$cover" "$payload" "$WORK/rs_$label")"  || { fails=$((fails+1)); echo "FAIL[$label]: Rust conceal"; return; }
    local cpp_img cpp_pin rs_img rs_pin
    IFS='|' read -r cpp_img cpp_pin <<<"$cpp_pair"
    IFS='|' read -r rs_img  rs_pin  <<<"$rs_pair"

    # cross directions (the interop proof) + self directions (sanity)
    for spec in "rs|$cpp_img|$cpp_pin|${label}_cpp2rs" \
                "cpp|$rs_img|$rs_pin|${label}_rs2cpp" \
                "rs|$rs_img|$rs_pin|${label}_rs2rs" \
                "cpp|$cpp_img|$cpp_pin|${label}_cpp2cpp"; do
        IFS='|' read -r who img pin tag <<<"$spec"
        local bin; [[ "$who" == rs ]] && bin="$RS" || bin="$CPP"
        if do_recover_compare "$bin" "$img" "$pin" "$payload" "$tag"; then
            passes=$((passes+1))
        else
            fails=$((fails+1))
        fi
    done
}

# Payloads: a small text file and a small binary blob (kept well under the
# Bluesky compressed-data limit so -b cases are valid).
printf 'jdvrif interop payload\nline 2\nline 3\n' > "$WORK/p_text.txt"
head -c 5000 /dev/urandom > "$WORK/p_bin.bin"

# 250KB of random data forces multi-segment ICC (segments are ~65KB each),
# exercising the streamed multi-segment math in both directions.
head -c 250000 /dev/urandom > "$WORK/p_multi.bin"
# 150KB incompressible data exceeds EXIF + Photoshop dataset capacity, forcing
# Bluesky's XMP/base64 overflow path in both cross-language directions.
head -c 150000 /dev/urandom > "$WORK/p_bluesky_xmp.bin"
# A recognized archive extension above 10 MiB exercises KDF3 raw-mode AD,
# compression bypass, and the two-byte ICC segment index beyond segment 255.
head -c $((17 * 1024 * 1024)) /dev/urandom > "$WORK/p_raw.zip"

run_case default_text     ""   "$COVER_DIR/cover_default.jpg" "$WORK/p_text.txt"
run_case default_bin      ""   "$COVER_DIR/cover_default.jpg" "$WORK/p_bin.bin"
run_case bluesky_bin      "-b" "$COVER_DIR/cover_bluesky.jpg" "$WORK/p_bin.bin"
run_case bluesky_xmp      "-b" "$COVER_DIR/cover_bluesky.jpg" "$WORK/p_bluesky_xmp.bin"
run_case reddit_text      "-r" "$COVER_DIR/cover_default.jpg" "$WORK/p_text.txt"
run_case default_multiseg ""   "$COVER_DIR/cover_default.jpg" "$WORK/p_multi.bin"
run_case default_raw      ""   "$COVER_DIR/cover_default.jpg" "$WORK/p_raw.zip"

echo "----"
echo "passed=$passes failed=$fails"
if [[ "$fails" -eq 0 ]]; then
    echo "ALL INTEROP CASES PASSED"
else
    echo "$fails CASE(S) FAILED"
    exit 1
fi
