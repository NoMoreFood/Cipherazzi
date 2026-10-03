import argparse
import ctypes
import json
import subprocess
import time
from ctypes import wintypes
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--relay", type=Path, required=True)
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--provider", required=True)
parser.add_argument("--connection-file", type=Path, required=True)
parser.add_argument("--signal", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
startup = subprocess.STARTUPINFO()
startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
startup.wShowWindow = subprocess.SW_HIDE
process = subprocess.Popen([str(args.relay.resolve()), "--source", str(args.source.resolve()),
                            "--provider", args.provider, "--connection-file", str(args.connection_file.resolve())],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, startupinfo=startup,
                           creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP)
try:
    deadline = time.monotonic() + 20
    while not args.signal.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("The relay did not reach the blocked database operation.")
        time.sleep(0.05)

    # Deliver a real console stop event after the caller confirms the relay is waiting on its table lock.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    ignore = handler_type(lambda _: True)
    kernel.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel.GetStdHandle.restype = wintypes.HANDLE
    kernel.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
    kernel.SetConsoleCtrlHandler.argtypes = [handler_type, wintypes.BOOL]
    original_handles = [kernel.GetStdHandle(value) for value in (-10, -11, -12)]
    kernel.FreeConsole()
    if not kernel.AttachConsole(process.pid):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel.SetConsoleCtrlHandler(ignore, True)
    watch = time.monotonic()
    try:
        if not kernel.GenerateConsoleCtrlEvent(1, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        stdout, stderr = process.communicate(timeout=5)
    finally:
        kernel.FreeConsole()
        for value, handle in zip((-10, -11, -12), original_handles):
            kernel.SetStdHandle(value, handle)
    result = {"exit_code": process.returncode, "stop_ms": (time.monotonic() - watch) * 1000,
              "stdout": stdout, "stderr": stderr}
    args.output.write_text(json.dumps(result, indent=2))
    raise SystemExit(0 if process.returncode == 0 else 1)
finally:
    if process.poll() is None:
        process.kill()
        process.communicate()
