#!/usr/bin/env python3
"""Isolated probes for the Rust test executable's input and terminal guards."""
import fcntl
import os
import pathlib
import pty
import resource
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time

test_binary = str(pathlib.Path(sys.argv[1]).resolve())
pin_command = [test_binary, "--exact", "decrypt::pin::tests::pin_process_probe", "--nocapture"]
read_command = [test_binary, "--exact", "common::tests::bounded_read_process_probe", "--nocapture"]


def pin_env(mode):
    return dict(os.environ, JDVRIF_PIN_PROBE=mode)


def finish(proc):
    if proc.poll() is None:
        proc.kill()
    proc.communicate(timeout=5)


def wait_for(proc, fd, condition):
    output = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if condition(output):
            return bytes(output)
        readable, _, _ = select.select([fd], [], [], 0.02)
        if readable:
            output.extend(os.read(fd, 4096))
        if proc.poll() is not None:
            break
    if condition(output):  # the last read may have raced the child's exit
        return bytes(output)
    raise AssertionError(f"timed out waiting for child: {output!r}")


with tempfile.TemporaryDirectory(prefix="jdvrif-rust-read-") as work:
    image = pathlib.Path(work) / "input.jpg"
    for size, limit, expected in (
        (32, 32, b"read 32 bytes"),
        (32, 31, b"bounded read rejected"),
        (32, 0, b"bounded read rejected"),
        (512 * 1024 * 1024, 20 * 1024 * 1024, b"bounded read rejected"),
    ):
        with image.open("wb") as stream:
            stream.truncate(size)
        result = subprocess.run(
            read_command, env=dict(os.environ, JDVRIF_READ_PROBE=str(image), JDVRIF_READ_LIMIT=str(limit)),
            capture_output=True, timeout=10,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2),
        )
        assert result.returncode == 0 and expected in result.stdout, result
print("[PASS] opened-file read accepts exact limit and rejects before allocation")

for mode, data in (("pending", b""), ("wait-race", b""),
                   ("ready-race", b"1"), ("drained-race", b"1")):
    proc = subprocess.Popen(pin_command, env=pin_env(mode), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if data:
            proc.stdin.write(data)
            proc.stdin.flush()
        # Hold the pipe open: EOF would hide a blocking read in the race cases.
        proc.wait(timeout=5)
        stdout, stderr = proc.communicate(timeout=5)
        assert proc.returncode == 0 and b"cancelled SIGINT" in stdout, (stdout, stderr)
    finally:
        finish(proc)
print("[PASS] pending and race-window cancellation restores flags and signal masks")

for entered, expected in ((b"1234\b5\n", b"1235"),
                          (b"18446744073709551615\n", b"18446744073709551615"),
                          (b"184467440737095516150\b\n", b"18446744073709551615"),
                          (b" 12 34\t\n", b"1234"),
                          (b"12x\b34\n", b"1234"),
                          (b"1234-\n", b"1234")):
    result = subprocess.run(pin_command, env=pin_env("pin"), input=entered,
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"parsed " + expected + b"\n" in result.stdout, result
for entered in (b"0\n", b"0123\n", b"18446744073709551616\n",
                b"12a34\n", b"12O4\n", b"***1234***\n"):
    result = subprocess.run(pin_command, env=pin_env("pin-invalid"), input=entered,
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"invalid PIN rejected" in result.stdout, result
print("[PASS] piped PIN parsing and correction retain existing behavior")

# 128-bit PINs (D2/D3). Test vector: secret 00..0f.
PIN128 = "112d-rXXU-ifSr-RnXL-GbXg-8Egs"
PIN128_HEX = b"v128 000102030405060708090a0b0c0d0e0f"
for entered in (PIN128, PIN128.replace("-", ""), PIN128.replace("-", " "),
                " " + PIN128 + "\t",
                PIN128 + "---",                        # 32 keystrokes: at the cap
                PIN128[:5] + "x\b" + PIN128[5:],       # corrected stray key
                "-" + PIN128.replace("-", "")[:7] + "-" + PIN128.replace("-", "")[7:]):
    result = subprocess.run(pin_command, env=pin_env("pin"), input=(entered + "\n").encode(),
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"parsed " + PIN128_HEX + b"\n" in result.stdout, (entered, result)
for entered in (PIN128[:-1],                            # 23 characters
                PIN128[:-1] + "0",                      # '0' is not Base58
                PIN128.replace("r", "l", 1),            # 'l' is not Base58
                PIN128 + "----",                        # 33 keystrokes: over the cap
                "YcVf-xkQb-6JRz-qk5k-F2tN-LwUM",        # body is 2^128
                "1111-1111-1111-1111-1111-11xx"):       # all-zero secret
    result = subprocess.run(pin_command, env=pin_env("pin-invalid"), input=(entered + "\n").encode(),
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"invalid PIN rejected" in result.stdout, (entered, result)
print("[PASS] 128-bit PIN parsing, separators, cap and malformed input")

# pin_io_typo: a check-pair mismatch is a typo, reported before any KDF work.
for entered in (PIN128[:-1] + "t", "112D" + PIN128[4:], PIN128.replace("GbXg", "GbXh")):
    result = subprocess.run(pin_command, env=pin_env("pin-typo"), input=(entered + "\n").encode(),
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"typo PIN rejected" in result.stdout, (entered, result)
print("[PASS] pin_io_typo: check-pair mismatch gives PIN_CHECK_ERROR")

# pin_io_backspace: on a terminal the dash is a stored, echoed keystroke, so
# "XXXX-" then one backspace removes the dash, not the fourth character.
master, slave = pty.openpty()
proc = subprocess.Popen(pin_command, env=pin_env("pin"), stdin=slave, stdout=slave,
                        stderr=slave, close_fds=True, start_new_session=True)
try:
    output = bytearray(wait_for(proc, master, lambda data: (b"KEY: " in data or b"PIN: " in data) and not
                                (termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ICANON))))
    for key in PIN128[:4] + "-" + "\x7f" + "-" + PIN128[5:] + "\r":
        os.write(master, key.encode())
        time.sleep(0.005)
    output.extend(wait_for(proc, master, lambda data: b"parsed " in data and b"\n" in
                           data[data.find(b"parsed "):]))
    proc.wait(timeout=5)
    assert proc.returncode == 0, proc.returncode
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=5)
    os.close(master)
    os.close(slave)
text = bytes(output)
echo = text[max(text.find(b"KEY: "), text.find(b"PIN: ")) + 5:]
assert echo.startswith(b"****-\b \b-****-****-****-****-****"), echo[:60]
assert PIN128.encode() not in text and PIN128.replace("-", "").encode() not in text, text
assert b"parsed " + PIN128_HEX in text, text
print("[PASS] pin_io_backspace: dash echoed as '-', backspace erases the dash")

for action in ("interrupt", "suspend"):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    before_flags = fcntl.fcntl(slave, fcntl.F_GETFL)
    proc = subprocess.Popen(pin_command, env=pin_env("pin"), stdin=slave, stdout=slave,
                            stderr=slave, process_group=0, close_fds=True)
    try:
        wait_for(proc, master, lambda data: (b"KEY: " in data or b"PIN: " in data) and not
                 (termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ICANON)))
        if action == "interrupt":
            os.kill(proc.pid, signal.SIGINT)
        else:
            os.kill(proc.pid, signal.SIGTSTP)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                pid, status = os.waitpid(proc.pid, os.WUNTRACED | os.WNOHANG)
                if pid:
                    assert os.WIFSTOPPED(status), status
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("PIN reader did not suspend")
            assert fcntl.fcntl(slave, fcntl.F_GETFL) == before_flags
            # Emulate shell restoration of cooked terminal mode while stopped.
            termios.tcsetattr(slave, termios.TCSANOW, before)
            os.kill(proc.pid, signal.SIGCONT)
            wait_for(proc, master, lambda _: not
                     (termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ICANON)))
            os.write(master, b"123\n")
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.returncode
        assert termios.tcgetattr(slave) == before
        assert fcntl.fcntl(slave, fcntl.F_GETFL) == before_flags
    finally:
        if proc.poll() is None:
            os.kill(proc.pid, signal.SIGCONT)
            proc.kill()
            proc.wait(timeout=5)
        os.close(master)
        os.close(slave)
print("[PASS] PIN interruption and suspend/resume restore terminal state")
