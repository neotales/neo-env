"""An actual task stops its supervisor after request delivery."""

import os
import pathlib
import signal
import subprocess
import sys
import time


def kill_owned(pid, session):
    try:
        descriptor = os.pidfd_open(pid)
    except (ProcessLookupError, PermissionError):
        return
    try:
        signal.pidfd_send_signal(descriptor, 0)
        if os.getsid(pid) == session:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    finally:
        os.close(descriptor)


process = subprocess.Popen(
    [sys.argv[1], "run", "stalled"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
settled = False
owned_fds = []
try:
    # Authentication of a large debug executable can take much longer than the
    # task deadline on a busy host. Bound startup separately from cleanup.
    deadline = time.monotonic() + 60
    while not pathlib.Path("stop.sent").exists() and time.monotonic() < deadline:
        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            break
        time.sleep(0.01)
    assert pathlib.Path("stop.sent").exists(), "the test did not stop the supervisor"
    stopped = time.monotonic()
    for marker in ("supervisor.pid", "stage.pid"):
        path = pathlib.Path(marker)
        if not path.exists():
            continue
        pid = int(path.read_text())
        descriptor = None
        try:
            descriptor = os.pidfd_open(pid)
            signal.pidfd_send_signal(descriptor, 0)
            if os.getsid(pid) == process.pid:
                owned_fds.append(descriptor)
                descriptor = None
        except (ProcessLookupError, PermissionError):
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
    stdout, stderr = process.communicate(timeout=10)
    settled = True
    elapsed = time.monotonic() - stopped
    assert pathlib.Path("supervisor.pid").exists(), (stdout, stderr)
    assert process.returncode != 0, (stdout, stderr)
    assert b"stalled TimedOut" in stdout, (stdout, stderr)
    assert elapsed < 8, elapsed
    time.sleep(4.2)
    assert not pathlib.Path("escaped").exists(), "stopped supervisor left a live task"
finally:
    for descriptor in owned_fds:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        os.close(descriptor)
    if not settled:
        # Popen has not reaped the direct session leader, anchoring its PID.
        for marker in ("supervisor.pid", "stage.pid"):
            path = pathlib.Path(marker)
            if path.exists():
                kill_owned(int(path.read_text()), process.pid)
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
