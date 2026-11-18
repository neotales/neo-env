"""Run one Rust protocol test under a real, bounded Linux controlling terminal."""
import errno
import os
import pathlib
import pty
import select
import signal
import sys
import time


def kill_owned_child(pid, session):
    """A pidfd targets the original process, never a reused numeric PID."""
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        signal.pidfd_send_signal(descriptor, 0)
        if os.getsid(pid) != session:
            return
        # If PID reuse happened during getsid, the old pidfd is now dead.
        signal.pidfd_send_signal(descriptor, 0)
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


pid, master = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
output = bytearray()
result = None
try:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.02)[0]:
            try:
                output.extend(os.read(master, 4096))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
        assert len(output) <= 65536
        result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is not None:
            break
    assert result is not None, f"PTY child did not settle: {output!r}"
    assert result.si_code == os.CLD_EXITED and result.si_status == 0, output
    print(output.decode(errors="replace"))
finally:
    owner = pathlib.Path("owner.pid")
    if owner.exists():
        kill_owned_child(int(owner.read_text()), pid)
    if result is None:
        # This direct child is still unreaped; its PID/PGID cannot be recycled.
        os.killpg(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    os.close(master)
