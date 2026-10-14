"""Optional fixed passive tool adapters. Enable only in a disposable environment."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def inventory():
    return [{"name": name, "available": shutil.which(name) is not None, "purpose": purpose}
            for name, purpose in [("file", "File signature identification"),
                                  ("readelf", "ELF header inspection"),
                                  ("exiftool", "Metadata inspection")]]


def inspect_files(inputs, cancelled):
    reports = []
    for path in inputs[:8]:
        for name, args in [("file", ["-b", "--", str(path)]),
                           ("readelf", ["-h", "--", str(path)]),
                           ("exiftool", ["-j", "--", str(path)])]:
            if cancelled():
                return reports
            executable = shutil.which(name)
            if not executable:
                continue
            if name == "readelf":
                with Path(path).open("rb") as stream:
                    if stream.read(4) != b"\x7fELF":
                        continue
            with tempfile.TemporaryFile() as output:
                command = [executable, *args]
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                           stderr=subprocess.STDOUT, shell=False,
                                           start_new_session=False)
                timed_out = False
                deadline = time.monotonic() + 8
                while process.poll() is None:
                    if cancelled() or time.monotonic() >= deadline:
                        timed_out = not cancelled()
                        process.kill()
                        process.wait()
                        break
                    time.sleep(.05)
                output.seek(0)
                raw = output.read(65537)
                reports.append({"tool": name, "input": Path(path).name,
                                "command": [name, *args[:-1], Path(path).name],
                                "exit_code": process.returncode, "timeout": timed_out,
                                "truncated": len(raw) > 65536,
                                "output": raw[:65536].decode("utf-8", errors="replace")})
    return reports
