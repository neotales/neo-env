"""Bounded PTY fixture. Uses only the standard library; never touches the user's tty."""

import errno
import json
import os
import pathlib
import pty
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time


def approve(binary, configuration="neoenv.yaml"):
    """Write the trust record the run needs.

    Execution is refused unless the exact bytes on disk were approved, and this
    fixture writes the configuration itself. The approval runs before the pty is
    created so it cannot appear in the transcript.
    """
    subprocess.run(
        [binary, "trust", "add", "--project", configuration],
        check=True,
        capture_output=True,
    )


def stage(mode):
    pathlib.Path(f"{mode}.pid").write_text(str(os.getpid()))
    with open("/dev/tty", "rb", buffering=0) as terminal:
        assert os.tcgetpgrp(terminal.fileno()) == os.getpgrp(), "stage is not foreground"
    if mode == "source":
        print("READY_TWO", flush=True)
        assert input() == "second"
        print("SECOND_OK", flush=True)
    elif mode == "sink":
        for line in sys.stdin:
            print(line, end="", flush=True)
    elif mode == "recovery":
        print("READY_RECOVERY", flush=True)
        assert input() == "recovered"
        print("RECOVERED_OK", flush=True)
    elif mode == "tty-only":
        assert sys.stdin.read() == ""
        with open("/dev/tty", "r") as terminal:
            print("READY_TTY", flush=True)
            assert terminal.readline().strip() == "tty"
        print("TTY_OK", flush=True)
    elif mode.startswith("lease-"):
        print("LEASE_READY", flush=True)
        assert input() == "go"
        print("LEASE_DONE", flush=True)
    else:
        # Both stages must receive the *terminal-generated* SIGINT, even when
        # nenv itself is outside the foreground process group.
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)
        pathlib.Path(f"{mode}.pid").write_text(str(os.getpid()))
        print(f"READY_{mode}", file=sys.stderr, flush=True)
        while True:
            time.sleep(1)


def running(pid):
    result = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    return result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith("Z")


def kill_owned_child(pid, session):
    try:
        descriptor = os.pidfd_open(pid)
    except (ProcessLookupError, PermissionError):
        return
    try:
        signal.pidfd_send_signal(descriptor, 0)
        if os.getsid(pid) != session:
            return
        # A recycled PID during getsid makes this original pidfd dead. All
        # actual signals target the fd, never that potentially reused number.
        signal.pidfd_send_signal(descriptor, 0)
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    finally:
        os.close(descriptor)


def probe(mode, binary):
    if mode in {"nested", "nested_copy"}:
        nested_binary = binary
        if mode == "nested_copy":
            nested_binary = str(pathlib.Path.cwd() / "nenv-copy")
            shutil.copy2(binary, nested_binary)
        actions = {
            "finish": {"uses": "shell", "run": f"{shlex.quote(nested_binary)} run inner"},
            "inner": {"uses": "shell", "run": "true"},
        }
    elif mode in {"parallel", "parallel_process"}:
        actions = {
            "a": {"uses": "portable", "run": "python3 terminal_probe.py lease-a"},
            "b": {"uses": "portable", "run": "python3 terminal_probe.py lease-b"},
            "finish": {"needs": ["a", "b"], "uses": "shell", "run": "true"},
        }
    elif mode == "redirected":
        actions = {
            "finish": {
                "uses": "portable",
                "run": "python3 terminal_probe.py tty-only",
            }
        }
    elif mode == "stdin":
        actions = {
            "first": {
                "uses": "shell",
                "run": 'echo $$ > first.pid; printf "READY_ONE\\n"; IFS= read -r answer; test "$answer" = first && printf "FIRST_OK\\n"',
            },
            "second": {
                "needs": ["first"],
                "uses": "portable",
                "run": "python3 terminal_probe.py source | python3 terminal_probe.py sink",
            },
            "finish": {
                "needs": ["second"],
                "uses": "portable",
                # Exercise group creation when the first leader can exit before
                # later stages join, and repeated terminal restoration.
                "run": "printf x | cat; " * 32 + "true",
            },
        }
    else:
        actions = {
            "background": {
                "background": True,
                "uses": "shell",
                "run": "echo $$ > background-group.pid; sleep 100 & echo $! > background.pid; printf 'BACKGROUND_READY\\n'; wait",
            },
            "foreground": {
                "needs": ["background"],
                "uses": "portable",
                "run": "python3 terminal_probe.py left | python3 terminal_probe.py right",
            },
            "finish": {
                "needs": ["foreground"],
                "uses": "shell",
                "run": "touch wrong",
            },
        }
    if mode == "suspend":
        actions["finish"] = {
            "needs": ["foreground"],
            "force": "outcome.foreground == cancelled",
            "uses": "portable",
            "run": "python3 terminal_probe.py recovery",
        }
    # JSON is a YAML subset and needs no third-party fixture dependency.
    pathlib.Path("neoenv.yaml").write_text(json.dumps({"tasks": actions}))
    approve(binary)
    pid, master = pty.fork()
    if pid == 0:
        if mode == "interrupt_ignored":
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        if mode == "redirected":
            with open("/dev/null", "rb") as devnull:
                os.dup2(devnull.fileno(), 0)
        if mode == "parallel_process":
            os.execv(sys.executable, [sys.executable, "terminal_probe.py", "runner", binary])
        os.execv(binary, [binary, "run", "finish"])
    transcript = bytearray()
    result = None

    def read_until(marker, seconds=5):
        deadline = time.monotonic() + seconds
        while marker not in transcript and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                transcript.extend(data)
                assert len(transcript) <= 65536, "unbounded fixture output"
        assert marker in transcript, f"missing {marker!r}: {transcript!r}"
        foreground = os.tcgetpgrp(master)
        return foreground

    try:
        if mode in {"nested", "nested_copy"}:
            pass
        elif mode in {"parallel", "parallel_process"}:
            read_until(b"LEASE_READY")
            # The other supervisor reaches the lease while the first owns the tty.
            deadline = time.monotonic() + 0.2
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.02)[0]:
                    transcript.extend(os.read(master, 4096))
            assert transcript.count(b"LEASE_READY") == 1, transcript
            os.write(master, b"go\n")
            deadline = time.monotonic() + 5
            while transcript.count(b"LEASE_READY") < 2 and time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    transcript.extend(os.read(master, 4096))
            assert transcript.count(b"LEASE_READY") == 2, transcript
            os.write(master, b"go\n")
        elif mode == "redirected":
            read_until(b"READY_TTY")
            os.write(master, b"tty\n")
            read_until(b"TTY_OK")
        elif mode == "stdin":
            read_until(b"READY_ONE")
            deadline = time.monotonic() + 3
            while os.tcgetpgrp(master) == pid and time.monotonic() < deadline:
                select.select([], [], [], 0.01)
            assert os.tcgetpgrp(master) != pid, "stdin reader never received the foreground terminal"
            os.write(master, b"first\n")
            read_until(b"FIRST_OK")
            assert read_until(b"READY_TWO") != pid
            os.write(master, b"second\n")
            read_until(b"SECOND_OK")
        else:
            read_until(b"BACKGROUND_READY")
            left_group = read_until(b"READY_left")
            right_group = read_until(b"READY_right")
            assert left_group == right_group and left_group != pid
            os.write(master, b"\x1a" if mode == "suspend" else b"\x03")
            if mode == "suspend":
                read_until(b"READY_RECOVERY", seconds=3)
                os.write(master, b"recovered\n")
                read_until(b"RECOVERED_OK", seconds=3)

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None:
                break
            if select.select([master], [], [], 0.01)[0]:
                try:
                    transcript.extend(os.read(master, 4096))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
        assert result is not None, f"CLI did not settle: {transcript!r}"
        while select.select([master], [], [], 0)[0]:
            try:
                data = os.read(master, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
            if not data:
                break
            transcript.extend(data)
            assert len(transcript) <= 65536
        if mode in {"nested", "nested_copy"}:
            assert result.si_code != os.CLD_EXITED or result.si_status != 0, transcript
            assert b"nested foreground nenv cannot acquire" in transcript, transcript
        elif mode in {"stdin", "redirected", "parallel", "parallel_process"}:
            assert result.si_code == os.CLD_EXITED and result.si_status == 0, transcript
        else:
            assert result.si_code != os.CLD_EXITED or result.si_status != 0, transcript
            assert not pathlib.Path("wrong").exists()
            assert b"foreground Cancelled" in transcript, transcript
            assert b"background Cancelled" in transcript, transcript
            if mode == "suspend":
                assert b"finish Succeeded" in transcript, transcript
            for name in ["left", "right", "background"]:
                child = int(pathlib.Path(f"{name}.pid").read_text())
                assert not running(child), f"{name} survived terminal Ctrl-C"
        print(f"PTY {mode}: passed")
    finally:
        # Fixture ownership includes every group, even when an assertion fails.
        for name in ["background-group", "background", "left", "right", "first", "source", "sink", "recovery", "tty-only", "lease-a", "lease-b"]:
            path = pathlib.Path(f"{name}.pid")
            if path.exists():
                child = int(path.read_text())
                kill_owned_child(child, pid)
        if result is None:
            # The direct child remains unreaped, anchoring this one PGID.
            os.killpg(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(master)


def probe_distinct_terminals(binary):
    pathlib.Path("neoenv.yaml").write_text(json.dumps({"tasks": {
        "a": {"uses": "portable", "run": "python3 terminal_probe.py lease-a"},
        "b": {"uses": "portable", "run": "python3 terminal_probe.py lease-b"},
    }}))
    approve(binary)
    children = []
    transcript = {}
    try:
        for name in ("a", "b"):
            pid, master = pty.fork()
            if pid == 0:
                os.execv(binary, [binary, "run", name])
            children.append((pid, master, name))
            transcript[master] = bytearray()
        deadline = time.monotonic() + 8
        while any(b"LEASE_READY" not in transcript[fd] for _, fd, _ in children):
            assert time.monotonic() < deadline, f"different ttys blocked each other: {transcript!r}"
            ready, _, _ = select.select([fd for _, fd, _ in children], [], [], 0.05)
            for fd in ready:
                transcript[fd].extend(os.read(fd, 4096))
        for _, fd, _ in children:
            os.write(fd, b"go\n")
        for pid, fd, _ in children:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None:
                    assert status.si_code == os.CLD_EXITED and status.si_status == 0, transcript
                    break
                if select.select([fd], [], [], 0.05)[0]:
                    try:
                        transcript[fd].extend(os.read(fd, 4096))
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
            else:
                raise AssertionError(f"CLI did not exit: {transcript!r}")
    finally:
        for pid, fd, name in children:
            marker = pathlib.Path(f"lease-{name}.pid")
            if marker.exists():
                kill_owned_child(int(marker.read_text()), pid)
            status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is None:
                os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            os.close(fd)


if sys.argv[1] == "runner":
    children = [subprocess.Popen([sys.argv[2], "run", name]) for name in ("a", "b")]
    sys.exit(any(child.wait() != 0 for child in children))
elif sys.argv[1] == "distinct_terminals":
    probe_distinct_terminals(sys.argv[2])
elif sys.argv[1] in {"source", "sink", "left", "right", "recovery", "tty-only", "lease-a", "lease-b"}:
    stage(sys.argv[1])
else:
    probe(sys.argv[1], sys.argv[2])
