import tempfile
import unittest

from flagforge.diagnostics import inspect_sources, suggested_prefixes
from flagforge.engine import Analyzer


class DiagnosticTests(unittest.TestCase):
    def analyze(self, inputs, prefix=""):
        with tempfile.TemporaryDirectory() as directory:
            return Analyzer(directory, prefix=prefix).run(inputs)

    def test_hyphenated_prefix_auto_pattern(self):
        result = self.analyze([("payload.txt", b"SMUCTF-CTF{real_payload}")])
        self.assertEqual(result["candidates"][0]["value"], "SMUCTF-CTF{real_payload}")

    def test_wrong_prefix_is_diagnosed_not_silently_changed(self):
        inputs = [("Question text", b"Expected format SMUCTF-CTF{...}"), ("payload", b"SMUCTF-CTF{real_payload}")]
        result = self.analyze(inputs, "SMUCTF")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["suggested_prefixes"], ["SMUCTF-CTF"])
        self.assertTrue(any("mismatch" in note for note in result["notes"]))
        corrected = self.analyze(inputs, "SMUCTF-CTF")
        self.assertIn("SMUCTF-CTF{real_payload}", [candidate["value"] for candidate in corrected["candidates"]])

    def test_source_json_challenge_needs_solver(self):
        inputs = [("token_service.py", b"import hashlib\nstate = (state * a + c) % modulus\n"),
                  ("reset_dump.json", b'{"logs":[1,2,3], "vault":"encrypted"}')]
        result = self.analyze(inputs, "flag")
        self.assertEqual(result["outcome"], "needs_solver")
        self.assertEqual(result["candidates"], [])
        self.assertEqual({f["kind"] for f in result["diagnostics"]}, {"prng", "crypto", "structured_data"})
        self.assertEqual(next(f for f in result["diagnostics"] if f["kind"] == "prng")["line"], 2)

    def test_uploaded_source_is_not_executed(self):
        result = inspect_sources([("x.py", b"raise RuntimeError('must not execute')\n")])
        self.assertEqual(result[0]["kind"], "source")

    def test_no_plaintext_result_and_cancel_outcomes(self):
        self.assertEqual(self.analyze([("text", b"hello world")])["outcome"], "no_match")
        with tempfile.TemporaryDirectory() as directory:
            result = Analyzer(directory, cancelled=lambda: True).run([("text", b"hello")])
        self.assertEqual(result["outcome"], "budget_exhausted")

    def test_only_question_drives_prefix_hint(self):
        self.assertEqual(suggested_prefixes([("source.py", b"example{a}"), ("Question text", b"Format ACME-CTF{...}")]), ["ACME-CTF"])


if __name__ == "__main__":
    unittest.main()
