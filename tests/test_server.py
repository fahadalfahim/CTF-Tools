import base64
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import subprocess
import sys

from flagforge.server import JobStore, Server


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = JobStore(cls.temp.name)
        cls.server = Server(("127.0.0.1", 0), cls.store)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.store.close(); cls.thread.join(); cls.temp.cleanup()

    def request(self, method, path, payload=None, auth=True, extra=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.server.token
        headers.update(extra or {})
        connection.request(method, path, json.dumps(payload) if payload is not None else None, headers)
        response = connection.getresponse(); status = response.status; data = response.read(); connection.close()
        return status, data

    def test_static_and_session(self):
        status, data = self.request("GET", "/", auth=False)
        self.assertEqual(status, 200); self.assertIn(b"Every flag has a trail", data)
        self.assertIn(b"<title>apostrophe", data)
        self.assertNotIn(b"FlagForge", data)
        status, data = self.request("GET", "/api/session", auth=False)
        self.assertEqual(json.loads(data)["token"], self.server.token)

    def test_second_listener_is_rejected(self):
        with self.assertRaises(OSError):
            duplicate = Server(("127.0.0.1", self.port), self.store)
            duplicate.server_close()

    def test_auth_and_cross_origin(self):
        self.assertEqual(self.request("GET", "/api/jobs", auth=False)[0], 401)
        self.assertEqual(self.request("GET", "/api/session", extra={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("GET", "/api/session", extra={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request("GET", "/api/session", extra={"Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_validation_and_path_traversal(self):
        self.assertEqual(self.request("POST", "/api/jobs", {})[0], 400)
        self.assertEqual(self.request("GET", "/../README.md")[0], 404)
        self.assertEqual(self.request("GET", "/api/jobs/" + "a" * 32)[0], 404)

    def test_job_and_export(self):
        status, data = self.request("POST", "/api/jobs", {"prefix": "flag", "files": [{"name": "x.txt", "data": base64.b64encode(b"ZmxhZ3thcGlfdGVzdH0=").decode()}]})
        self.assertEqual(status, 202)
        job_id = json.loads(data)["id"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status, data = self.request("GET", "/api/jobs/" + job_id)
            job = json.loads(data)
            if job["status"] not in ("queued", "running", "cancelling"):
                break
            time.sleep(.1)
        self.assertEqual(job["status"], "completed", job)
        self.assertIn("flag{api_test}", [c["value"] for c in job["result"]["candidates"]])
        status, bundle = self.request("GET", "/api/jobs/" + job_id + "/export")
        self.assertEqual(status, 200); self.assertTrue(bundle.startswith(b"PK"))
        self.assertTrue((Path(self.temp.name) / job_id / "job.json").exists())

    def test_cancellation(self):
        status, data = self.request("POST", "/api/jobs", {"question": "Decode this " * 2000, "deep": True})
        self.assertEqual(status, 202)
        job_id = json.loads(data)["id"]
        self.assertEqual(self.request("POST", f"/api/jobs/{job_id}/cancel", {})[0], 200)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = json.loads(self.request("GET", "/api/jobs/" + job_id)[1])
            if job["status"] not in ("queued", "running", "cancelling"):
                break
            time.sleep(.1)
        self.assertEqual(job["status"], "cancelled")

    def test_rerun_saved_inputs_with_corrected_prefix(self):
        status, raw = self.request("POST", "/api/jobs", {"question": "Format SMUCTF-CTF{...}", "prefix": "SMUCTF", "files": [{"name": "flag.txt", "data": base64.b64encode(b"SMUCTF-CTF{saved_inputs}").decode()}]})
        self.assertEqual(status, 202)
        original_id = json.loads(raw)["id"]
        status, raw = self.request("POST", f"/api/jobs/{original_id}/rerun", {"prefix": "SMUCTF-CTF", "deep": True})
        self.assertEqual(status, 202)
        rerun_id = json.loads(raw)["id"]
        self.assertNotEqual(original_id, rerun_id)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            job = json.loads(self.request("GET", "/api/jobs/" + rerun_id)[1])
            if job["status"] not in ("queued", "running", "cancelling"):
                break
            time.sleep(.1)
        self.assertEqual(job["status"], "completed", job)
        self.assertIn("SMUCTF-CTF{saved_inputs}", [candidate["value"] for candidate in job["result"]["candidates"]])
        self.assertEqual(self.request("POST", f"/api/jobs/{original_id}/rerun", [])[0], 400)


class PersistenceAndLaunchTests(unittest.TestCase):
    def test_new_launch_command(self):
        result = subprocess.run([sys.executable, "-m", "apostrophe", "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("apostrophe local CTF", result.stdout)

    def test_legacy_launch_command(self):
        result = subprocess.run([sys.executable, "-m", "flagforge.server", "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("apostrophe local CTF", result.stdout)

    def test_restart_keeps_completed_and_marks_unfinished(self):
        with tempfile.TemporaryDirectory() as directory:
            for index, status in enumerate(("completed", "running", "queued")):
                job_id = str(index) * 32
                folder = Path(directory) / job_id
                folder.mkdir()
                (folder / "job.json").write_text(json.dumps({"id": job_id, "status": status, "created": index, "events": []}), encoding="utf-8")
                if status == "completed":
                    (folder / "result.json").write_text('{"candidates": []}', encoding="utf-8")
            store = JobStore(directory)
            try:
                self.assertEqual(store.get("0" * 32)["status"], "completed")
                self.assertEqual(store.get("0" * 32)["result"], {"candidates": []})
                self.assertEqual(store.get("1" * 32)["status"], "interrupted")
                self.assertEqual(store.get("2" * 32)["status"], "interrupted")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
