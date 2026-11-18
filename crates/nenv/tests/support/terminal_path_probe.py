"""Prove that foreground process-group setup never executes a PATH helper."""

import errno
import json
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import time

root = pathlib.Path.cwd()
bindir = root / "bin"
bindir.mkdir()
fake = bindir / "sleep"
fake.write_text("#!/bin/sh\necho $$ > path-anchor-ran\nexec /bin/sleep \"$@\"\n")
fake.chmod(0o755)
(root / "neoenv.yaml").write_text(
    json.dumps({"tasks": {"demo": {"uses": "portable", "run": "/usr/bin/printf x | /usr/bin/cat"}}})
)
environment = {
    "PATH": str(bindir),
    "HOME": str(root),
    **{f"NEOENV_{key}_HOME": str(root / key.lower()) for key in ("CONFIG", "DATA", "STATE", "CACHE")},
}
# Execution is refused unless the exact bytes on disk were approved. The child
# execs with its own environment, so the record is written with the same one.
subprocess.run(
    [sys.argv[1], "trust", "add", "--project", "neoenv.yaml"],
    check=True,
    capture_output=True,
    env=environment,
)
pid, master = pty.fork()
if pid == 0:
    os.execve(sys.argv[1], [sys.argv[1], "run", "demo"], environment)

status = None
transcript = bytearray()
try:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.05)[0]:
            try:
                transcript.extend(os.read(master, 4096))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            break
        status = None
    assert status is not None, f"CLI did not finish: {transcript!r}"
    assert os.waitstatus_to_exitcode(status) == 0, transcript
    assert not (root / "path-anchor-ran").exists(), "executed task-controlled sleep"
finally:
    marker = root / "path-anchor-ran"
    if status is None and marker.exists():
        try:
            child = int(marker.read_text())
            descriptor = os.pidfd_open(child)
            try:
                if os.getsid(child) == pid:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        except (ProcessLookupError, PermissionError):
            pass
    if status is None:
        # pid is an unreaped session leader, reserving its process-group ID.
        os.killpg(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(master)
