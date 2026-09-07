#!/usr/bin/env python3
"""Verify the Rust CLI recovers its bounded carrier snapshot across PIN entry."""
import os
import pathlib
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

if len(sys.argv) != 3:
    raise SystemExit("Usage: run_recovery_snapshot_test.py <Rust binary> <JPEG cover>")
binary, cover = (str(pathlib.Path(arg).resolve()) for arg in sys.argv[1:])
payload_bytes = b"Rust recovery retains the bounded carrier read before PIN entry.\n"
replacement_size = 512 * 1024 * 1024


def wait_for_pin(proc):
    output = bytearray()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if b"PIN: " in output:
            return bytes(output)
        readable, _, _ = select.select([proc.stdout.fileno()], [], [], 0.05)
        if readable:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
        if proc.poll() is not None:
            break
    raise AssertionError(f"recovery did not reach PIN entry: {output!r}")


with tempfile.TemporaryDirectory(prefix="jdvrif-rust-snapshot-") as temporary:
    work = pathlib.Path(temporary)
    payload = work / "snapshot.txt"
    payload.write_bytes(payload_bytes)
    conceal = subprocess.run(
        [binary, "conceal", "-x", cover, str(payload)], cwd=work,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90,
    )
    assert conceal.returncode == 0, conceal.stdout
    image_match = re.search(rb'Saved "file-embedded" JPG image: (.+) \([0-9]+ bytes\)\.',
                            conceal.stdout)
    pin_match = re.search(rb'Recovery PIN: \[\*\*\*([0-9]+)\*\*\*\]', conceal.stdout)
    assert image_match and pin_match, conceal.stdout
    carrier = work / os.fsdecode(image_match.group(1))
    assert carrier.is_file() and carrier.stat().st_size <= 5 * 1024 * 1024
    pin = pin_match.group(1) + b"\n"

    for action in ("grow", "replace"):
        case = work / action
        case.mkdir()
        image = case / "input.jpg"
        shutil.copyfile(carrier, image)
        original_inode = image.stat().st_ino
        proc = subprocess.Popen(
            [binary, "recover", str(image)], cwd=case,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            prefix = wait_for_pin(proc)
            if action == "grow":
                with image.open("r+b") as stream:
                    stream.truncate(replacement_size)
                assert image.stat().st_ino == original_inode
            else:
                replacement = case / "replacement.jpg"
                with replacement.open("wb") as stream:
                    stream.truncate(replacement_size)
                replacement.replace(image)
                assert image.stat().st_ino != original_inode
            assert image.stat().st_size == replacement_size
            tail, _ = proc.communicate(input=pin, timeout=30)
            output = prefix + tail
            assert proc.returncode == 0, output
            assert b"Complete! Please check your file." in output, output
            assert (case / payload.name).read_bytes() == payload_bytes
            assert image.stat().st_size == replacement_size
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=5)
        print(f"[PASS] Rust recovery uses the pre-PIN snapshot after carrier {action}")
