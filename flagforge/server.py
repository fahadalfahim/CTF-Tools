"""Loopback web UI, bounded upload API, isolated background analysis processes."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import multiprocessing as mp
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import socket
import threading
import time
from urllib.parse import urlsplit
import uuid
import zipfile

from . import __version__
from .engine import Analyzer
from .native import inventory, inspect_files
from .replay import MAX_BYTES

MAX_BODY = 24 * 1024 * 1024
MAX_INPUT = 16 * 1024 * 1024
STATIC = Path(__file__).parent / "static"


def worker(directory, settings, cancel, events):
    # OS resource limits supplement the analyzer's byte/time budgets on Linux.
    if os.name == "posix":
        os.setsid()
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (100, 100))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory = Path(directory)

    def emit(event):
        try:
            events.put_nowait(event)
        except queue.Full:
            pass

    try:
        inputs = [(item["name"], (directory / item["file"]).read_bytes()) for item in settings["inputs"]]
        analyzer = Analyzer(directory / "artifacts", settings["prefix"], settings["deep"], cancel.is_set, emit, 75)
        result = analyzer.run(inputs)
        for candidate in result["candidates"]:
            if candidate.get("root"):
                root = next(a for a in result["artifacts"] if a["id"] == candidate["root"])
                if root["name"] == "Question text":
                    candidate["warnings"].append("Derived from question text; this may be an example rather than the answer")
        if settings.get("target"):
            result["notes"].append("Remote target saved as context only. This release does not connect to or solve remote services.")
        result["native_reports"] = []
        if settings["native"] and not cancel.is_set():
            emit({"type": "tool", "message": "Running optional passive Linux adapters"})
            result["native_reports"] = inspect_files([directory / i["file"] for i in settings["inputs"]], cancel.is_set)
        result["cancelled"] = cancel.is_set()
        result["version"] = __version__
        (directory / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception as exc:
        (directory / "error.json").write_text(json.dumps({"error": type(exc).__name__ + ": " + str(exc)[:300]}), encoding="utf-8")


def validate_submission(payload):
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object")
    question = payload.get("question", "")
    prefix = payload.get("prefix", "")
    target = payload.get("target", "")
    if not all(isinstance(v, str) for v in (question, prefix, target)):
        raise ValueError("Question, prefix and target must be text")
    if len(question) > 50000 or len(target) > 2048:
        raise ValueError("Question or target is too long")
    if prefix and not re.fullmatch(r"[A-Za-z0-9_\-]{1,48}", prefix):
        raise ValueError("Prefix must be 1–48 letters, digits, underscores or hyphens, without braces")
    files = payload.get("files", [])
    if not isinstance(files, list) or len(files) > 8:
        raise ValueError("Upload at most 8 files")
    decoded = []
    total = 0
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("data"), str) or not isinstance(item.get("name"), str):
            raise ValueError("Invalid file entry")
        name = item["name"].replace("\\", "/").split("/")[-1][:180] or "upload.bin"
        try:
            data = base64.b64decode(item["data"], validate=True)
        except (ValueError, UnicodeError):
            raise ValueError("Invalid base64 upload") from None
        if not data or len(data) > MAX_BYTES:
            raise ValueError("Each file must contain 1 byte to 8 MiB")
        total += len(data)
        decoded.append((name, data))
    if total > MAX_INPUT:
        raise ValueError("Total uploaded files exceed 16 MiB")
    if question.strip():
        decoded.append(("Question text", question.encode("utf-8")))
    if not decoded:
        raise ValueError("Provide question text or at least one file")
    return {"question": question, "prefix": prefix, "target": target,
            "deep": payload.get("deep") is True}, decoded


def export_bundle(directory, result):
    directory = Path(directory)
    buffer = io.BytesIO()
    manifest = {"candidates": result["candidates"], "artifacts": result["artifacts"]}
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        archive.writestr("report.json", json.dumps(result, indent=2))
        archive.writestr("replay.py", (Path(__file__).parent / "replay.py").read_text(encoding="utf-8"))
        archive.writestr("formats.py", (Path(__file__).parent / "formats.py").read_text(encoding="utf-8"))
        archive.writestr("solve.py", EXPORT_SCRIPT)
        archive.writestr("README.txt", "Run: python3 solve.py\nThis reproduces candidate extraction, not platform acceptance.\nOriginal untrusted challenge bytes are in originals/. Do not execute them on your host.\n")
        for artifact in result["artifacts"]:
            if artifact["parent"] is None:
                archive.write(directory / "artifacts" / (artifact["id"] + ".bin"), "originals/" + artifact["id"] + ".bin")
    return buffer.getvalue()


EXPORT_SCRIPT = '''"""Reproduce extracted candidates from original inputs, without server dependencies."""
import hashlib
import json
from pathlib import Path
from replay import transform

base = Path(__file__).resolve().parent
manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
artifacts = {a["id"]: a for a in manifest["artifacts"]}
count = 0
for candidate in manifest["candidates"]:
    if candidate["status"] != "reproduced":
        continue
    root = artifacts[candidate["root"]]
    data = (base / "originals" / (root["id"] + ".bin")).read_bytes()
    if hashlib.sha256(data).hexdigest() != root["sha256"]:
        raise ValueError("Original hash mismatch")
    for step in candidate["steps"]:
        data = transform(data, step)
    leaf = artifacts[candidate["artifact"]]
    if hashlib.sha256(data).hexdigest() != leaf["sha256"]:
        raise ValueError("Derived artifact hash mismatch")
    expected = candidate["value"].encode("ascii")
    offset = candidate["offset"]
    if data[offset:offset + len(expected)] != expected:
        raise ValueError("Candidate mismatch")
    print(candidate["value"])
    count += 1
print(f"{count} extraction(s) reproduced. Platform acceptance has not been checked.")
'''


class JobStore:
    def __init__(self, root, native=False):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.native = native
        self.lock = threading.RLock()
        self.jobs = {}
        self.controls = {}
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.context = mp.get_context("spawn")
        for path in sorted(self.root.glob("*/job.json"))[-100:]:
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
                if not re.fullmatch(r"[a-f0-9]{32}", job["id"]):
                    continue
                if job["status"] in ("queued", "running", "cancelling"):
                    job["status"] = "interrupted"
                self.jobs[job["id"]] = job
            except (ValueError, KeyError, OSError):
                pass

    def save(self, job):
        path = self.root / job["id"] / "job.json"
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(job), encoding="utf-8")
        temp.replace(path)

    def create(self, settings, inputs):
        with self.lock:
            if sum(j["status"] in ("queued", "running", "cancelling") for j in self.jobs.values()) >= 6:
                raise ValueError("Queue is full (6 active jobs). Wait or cancel a job.")
            # Retention is explicit: never silently delete a user's original challenge.
            stored = sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
            if stored > 1024 * 1024 * 1024:
                raise ValueError("Local storage quota reached (1 GiB). Export and manually remove old job folders.")
            job_id = uuid.uuid4().hex
            directory = self.root / job_id
            directory.mkdir()
            entries = []
            for index, (name, data) in enumerate(inputs):
                filename = "input_%d.bin" % index
                (directory / filename).write_bytes(data)
                entries.append({"name": name, "file": filename})
            settings = {**settings, "inputs": entries, "native": self.native}
            (directory / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
            job = {"id": job_id, "created": time.time(), "status": "queued", "events": [],
                   "title": settings["question"].strip()[:70] or inputs[0][0],
                   "files": [name for name, _ in inputs], "deep": settings["deep"]}
            self.jobs[job_id] = job
            cancel = self.context.Event()
            self.controls[job_id] = cancel
            self.save(job)
            self.pool.submit(self.run, job_id, settings, cancel)
            return dict(job)

    def run(self, job_id, settings, cancel):
        directory = self.root / job_id
        events = self.context.Queue(maxsize=512)
        process = self.context.Process(target=worker, args=(str(directory), settings, cancel, events))
        try:
            with self.lock:
                self.jobs[job_id]["status"] = "running"
                self.save(self.jobs[job_id])
            process.start()
            started = time.monotonic()
            cancelled_at = None
            while process.is_alive():
                if cancel.is_set() and cancelled_at is None:
                    cancelled_at = time.monotonic()
                if time.monotonic() - started > 110 or (cancelled_at and time.monotonic() - cancelled_at > 2):
                    if os.name == "posix":
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        process.terminate()
                    break
                try:
                    event = events.get(timeout=.15)
                    with self.lock:
                        self.jobs[job_id]["events"] = (self.jobs[job_id]["events"] + [event])[-200:]
                except queue.Empty:
                    pass
            process.join(timeout=3)
            if process.is_alive():
                process.kill()
                process.join()
            with self.lock:
                job = self.jobs[job_id]
                job["status"] = "cancelled" if cancel.is_set() else "completed" if (directory / "result.json").exists() else "failed"
                if job["status"] == "failed":
                    error_file = directory / "error.json"
                    job["error"] = json.loads(error_file.read_text())["error"] if error_file.exists() else "Worker stopped or exceeded its resource/time budget"
                self.save(job)
        except Exception as exc:
            with self.lock:
                self.jobs[job_id].update(status="failed", error=str(exc)[:200])
                self.save(self.jobs[job_id])
        finally:
            events.close()
            with self.lock:
                self.controls.pop(job_id, None)

    def get(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError(job_id)
            job = json.loads(json.dumps(self.jobs[job_id]))
        result_path = self.root / job_id / "result.json"
        if job["status"] in ("completed", "cancelled", "interrupted") and result_path.exists():
            job["result"] = json.loads(result_path.read_text(encoding="utf-8"))
        return job

    def cancel(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError(job_id)
            if job_id in self.controls:
                self.controls[job_id].set()
                self.jobs[job_id]["status"] = "cancelling"
                self.save(self.jobs[job_id])

    def close(self):
        with self.lock:
            for event in self.controls.values():
                event.set()
        self.pool.shutdown(wait=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "apostrophe/0.1.1"

    def log_message(self, *_args):
        pass

    def send(self, code, body, content_type="application/json", filename=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="' + filename + '"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def trusted(self):
        host = self.headers.get("Host", "")
        if host not in self.server.allowed_hosts:
            self.send(403, {"error": "Use the local localhost or 127.0.0.1 address"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in self.server.allowed_hosts}:
            self.send(403, {"error": "Cross-origin requests are not allowed"})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send(403, {"error": "Cross-site requests are not allowed"})
            return False
        return True

    def auth(self):
        provided = self.headers.get("Authorization", "")
        if not secrets.compare_digest(provided, "Bearer " + self.server.token):
            self.send(401, {"error": "Reload the app to refresh the local session"})
            return False
        return True

    def do_GET(self):
        if not self.trusted():
            return
        path = urlsplit(self.path).path
        if path == "/api/session":
            self.send(200, {"token": self.server.token, "version": __version__, "native": self.server.store.native,
                            "tools": inventory(), "limits": {"file_mib": 8, "total_mib": 16, "files": 8}})
            return
        if path.startswith("/api/"):
            if not self.auth():
                return
            if path == "/api/jobs":
                with self.server.store.lock:
                    jobs = [{k: v for k, v in j.items() if k != "events"} for j in self.server.store.jobs.values()]
                self.send(200, sorted(jobs, key=lambda j: j["created"], reverse=True)[:100])
                return
            match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})(/export)?", path)
            if match:
                try:
                    job = self.server.store.get(match[1])
                    if match[2]:
                        if "result" not in job:
                            self.send(409, {"error": "No completed result to export"})
                        else:
                            self.send(200, export_bundle(self.server.store.root / match[1], job["result"]), "application/zip", "apostrophe-" + match[1][:8] + ".zip")
                    else:
                        self.send(200, job)
                except KeyError:
                    self.send(404, {"error": "Job not found"})
                return
            self.send(404, {"error": "Unknown endpoint"})
            return
        routes = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path in routes:
            filename, mime = routes[path]
            self.send(200, (STATIC / filename).read_bytes(), mime)
        else:
            self.send(404, {"error": "Not found"})

    def do_POST(self):
        if not self.trusted() or not self.auth():
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send(415, {"error": "Expected application/json"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("Request is empty, too large or uses unsupported transfer encoding")
            self.connection.settimeout(20)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("Incomplete request")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("Expected a JSON object")
            path = urlsplit(self.path).path
            if path == "/api/jobs":
                settings, inputs = validate_submission(payload)
                self.send(202, self.server.store.create(settings, inputs))
            else:
                match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/cancel", path)
                rerun = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/rerun", path)
                if rerun:
                    self.server.store.get(rerun[1])
                    directory = self.server.store.root / rerun[1]
                    original = json.loads((directory / "settings.json").read_text(encoding="utf-8"))
                    files = [{"name": item["name"], "data": base64.b64encode((directory / item["file"]).read_bytes()).decode("ascii")}
                             for item in original["inputs"] if item["name"] != "Question text"]
                    settings, inputs = validate_submission({"question": original["question"], "target": original["target"],
                        "prefix": payload.get("prefix", original["prefix"]), "deep": payload.get("deep", original["deep"]), "files": files})
                    self.send(202, self.server.store.create(settings, inputs))
                    return
                if not match:
                    self.send(404, {"error": "Unknown endpoint"})
                    return
                self.server.store.cancel(match[1])
                self.send(200, {"status": "cancelling"})
        except KeyError:
            self.send(404, {"error": "Job not found"})
        except (ValueError, UnicodeError) as exc:
            self.send(400, {"error": str(exc)[:240]})
        except TimeoutError:
            self.send(408, {"error": "Upload timed out"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        # Windows SO_REUSEADDR can permit two listeners on the same address,
        # splitting requests across independent sessions and in-memory jobs.
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, store):
        self.store = store
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(12)
        super().__init__(address, Handler)
        port = self.server_address[1]
        self.allowed_hosts = {"localhost:" + str(port), "127.0.0.1:" + str(port)}

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        request.settimeout(20)
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser(description="apostrophe local CTF analysis workbench")
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "0.0.0.0"])
    parser.add_argument("--port", default=8787, type=int)
    parser.add_argument("--data-dir", default=".flagforge")
    parser.add_argument("--native-tools", action="store_true", help="Run fixed passive adapters; use in a disposable container")
    args = parser.parse_args()
    if args.native_tools and os.name != "posix":
        parser.error("Native adapters are supported only on Linux/POSIX; use the container")
    store = JobStore(args.data_dir, args.native_tools)
    server = Server((args.host, args.port), store)
    print("apostrophe running at http://127.0.0.1:%d" % server.server_address[1], flush=True)
    if args.host == "0.0.0.0":
        print("Container binding: publish only to host loopback. This is a single-user local application.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
