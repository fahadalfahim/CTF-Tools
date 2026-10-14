import base64
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from flagforge.engine import Analyzer, fingerprint
from flagforge.replay import MAX_BYTES, transform
from flagforge.server import export_bundle, validate_submission

FLAG = b"flag{evidence_before_confidence}"


class EngineTests(unittest.TestCase):
    def analyze(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            return Analyzer(directory, **kwargs).run([("input.bin", data)])

    def values(self, result):
        return {candidate["value"] for candidate in result["candidates"]}

    def test_direct_reproduced(self):
        result = self.analyze(b"prefix " + FLAG, prefix="flag")
        candidate = result["candidates"][0]
        self.assertEqual(candidate["status"], "reproduced")
        self.assertEqual(candidate["offset"], 7)
        self.assertEqual(candidate["steps"], [])

    def test_question_style_embedded_base64(self):
        result = self.analyze(b"Decode this payload:\n" + base64.b64encode(FLAG), prefix="flag")
        self.assertIn(FLAG.decode(), self.values(result))
        self.assertTrue(all(c["status"] == "reproduced" for c in result["candidates"]))

    def test_hex_of_base64(self):
        result = self.analyze(base64.b64encode(FLAG).hex().encode(), prefix="flag")
        self.assertIn(FLAG.decode(), self.values(result))

    def test_zip_gzip_base64_chain(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("payload.gz", gzip.compress(base64.b64encode(FLAG)))
        result = self.analyze(buffer.getvalue(), prefix="flag", deep=True)
        self.assertIn(FLAG.decode(), self.values(result))
        self.assertTrue(any(len(c.get("steps", [])) >= 3 for c in result["candidates"]))

    def test_utf16(self):
        result = self.analyze(FLAG.decode().encode("utf-16-le"), prefix="flag")
        self.assertIn(FLAG.decode(), self.values(result))

    def test_xor(self):
        encoded = bytes(x ^ 173 for x in FLAG)
        self.assertNotIn(FLAG.decode(), self.values(self.analyze(encoded, prefix="flag")))
        self.assertIn(FLAG.decode(), self.values(self.analyze(encoded, prefix="flag", deep=True)))

    def test_rot13_and_reverse(self):
        for op in ("rot13", "reverse"):
            result = self.analyze(transform(FLAG, {"op": op}), prefix="flag")
            self.assertIn(FLAG.decode(), self.values(result))

    def test_wrong_prefix(self):
        self.assertEqual(self.analyze(FLAG, prefix="other")["candidates"], [])

    def test_deep_does_not_invent_shifted_brace_candidates(self):
        result = self.analyze(FLAG, deep=True)
        self.assertEqual(self.values(result), {FLAG.decode()})

    def test_decoy_is_not_accepted(self):
        candidate = self.analyze(b"fake example: " + FLAG, prefix="flag")["candidates"][0]
        self.assertEqual(candidate["status"], "reproduced")
        self.assertTrue(any("decoy" in note for note in candidate["warnings"]))
        self.assertNotIn("confidence", candidate)

    def test_corrupt_zip(self):
        result = self.analyze(b"PK\x03\x04broken")
        self.assertIn("Malformed ZIP archive", result["notes"])

    def test_corrupt_xz(self):
        result = self.analyze(b"\xfd7zXZ\x00corrupt")
        self.assertTrue(any("xz" in note for note in result["notes"]))

    def test_traversal_member_is_only_label(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../../outside.txt", FLAG)
        with tempfile.TemporaryDirectory() as directory:
            result = Analyzer(Path(directory) / "artifacts", prefix="flag").run([("x.zip", buffer.getvalue())])
            self.assertIn(FLAG.decode(), self.values(result))
            self.assertFalse((Path(directory) / "outside.txt").exists())
            self.assertTrue(all(p.name == "result.json" or p.name.startswith("a") for p in (Path(directory) / "artifacts").iterdir()))

    def test_tar_ignores_symlinks(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            link = tarfile.TarInfo("secret"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"; archive.addfile(link)
            member = tarfile.TarInfo("answer.txt"); member.size = len(FLAG); archive.addfile(member, io.BytesIO(FLAG))
        result = self.analyze(buffer.getvalue(), prefix="flag")
        self.assertIn(FLAG.decode(), self.values(result))
        self.assertFalse(any(a["name"] == "TAR: secret" for a in result["artifacts"]))

    def test_decompression_limit(self):
        packed = gzip.compress(b"A" * (MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            transform(packed, {"op": "gzip"})

    def test_cancelled(self):
        result = self.analyze(FLAG, cancelled=lambda: True)
        self.assertEqual(result["candidates"], [])
        self.assertIn("Cancelled by user", result["limits"])

    def test_export_runs_standalone_and_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = Analyzer(root / "artifacts", prefix="flag").run([("payload.txt", base64.b64encode(FLAG))])
            bundle = export_bundle(root, result)
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                archive.extractall(root / "export")
            proc = subprocess.run([sys.executable, str(root / "export" / "solve.py")], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(FLAG.decode(), proc.stdout)
            original = next((root / "export" / "originals").glob("*")); original.write_bytes(b"tampered")
            proc = subprocess.run([sys.executable, str(root / "export" / "solve.py")], capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("hash mismatch", proc.stderr)

    def test_submission_bounds(self):
        for payload in ([], {}, {"files": [None]}, {"prefix": ".*", "question": "abc"}, {"files": [{"name": "x", "data": "%%%"}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_submission(payload)

    def test_filename_normalization(self):
        settings, inputs = validate_submission({"files": [{"name": "../../x.bin", "data": base64.b64encode(FLAG).decode()}]})
        self.assertEqual(inputs[0][0], "x.bin")

    def test_binary_fingerprint(self):
        self.assertEqual(fingerprint(b"\x7fELF" + b"\0" * 30)["type"], "ELF executable")


if __name__ == "__main__":
    unittest.main()
