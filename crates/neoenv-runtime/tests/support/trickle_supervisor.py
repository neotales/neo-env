"""Test-only managed supervisor that sends a response one byte at a time."""

import array
import os
import pathlib
import socket
import sys
import time

control = socket.socket(fileno=0)


def receive_exact(size):
    data = bytearray()
    while len(data) < size:
        chunk = control.recv(size - len(data))
        if not chunk:
            raise EOFError("client closed")
        data.extend(chunk)
    return data


assert receive_exact(len(b"NEOENV-OWNED/1\n")) == b"NEOENV-OWNED/1\n"
if len(sys.argv) > 2 and sys.argv[2] == "withhold":
    pathlib.Path(sys.argv[3]).write_text("request received")
    while control.recv(4096):
        pass
    sys.exit(0)
pidfd = os.pidfd_open(os.getpid())
control.sendmsg(
    [b"P"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pidfd]))]
)
os.close(pidfd)
control.sendall(("NEOENV-OWNED/1 " + sys.argv[1] + "\n").encode())
size = int.from_bytes(receive_exact(4), "big")
receive_exact(size)
if len(sys.argv) > 2 and sys.argv[2] == "exit":
    sys.exit(1)
try:
    control.sendall(b"STARTED\n")
    for _ in range(200):
        control.sendall(b"x")
        time.sleep(0.01)
except (BrokenPipeError, ConnectionResetError):
    pass
