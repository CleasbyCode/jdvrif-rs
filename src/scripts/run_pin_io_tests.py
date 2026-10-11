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
                          (b"184467440737095516150\b\n", b"18446744073709551615")):
    result = subprocess.run(pin_command, env=pin_env("pin"), input=entered,
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"parsed " + expected in result.stdout, result
for entered in (b"0\n", b"0123\n", b"18446744073709551616\n"):
    result = subprocess.run(pin_command, env=pin_env("pin-invalid"), input=entered,
                            capture_output=True, timeout=5)
    assert result.returncode == 0 and b"invalid PIN rejected" in result.stdout, result
print("[PASS] piped PIN parsing and correction retain existing behavior")

for action in ("interrupt", "suspend"):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    before_flags = fcntl.fcntl(slave, fcntl.F_GETFL)
    proc = subprocess.Popen(pin_command, env=pin_env("pin"), stdin=slave, stdout=slave,
                            stderr=slave, process_group=0, close_fds=True)
    try:
        wait_for(proc, master, lambda data: b"PIN: " in data and not
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
