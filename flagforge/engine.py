"""Bounded, deterministic analysis. No uploaded code is executed."""
from collections import Counter, deque
import hashlib
import io
import json
import math
import lzma
from pathlib import Path
import re
import tarfile
import time
import zipfile
import wave
import zlib

from .replay import MAX_BYTES, transform
from .diagnostics import inspect_sources, suggested_prefixes

DEFAULT_PATTERN = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z][A-Za-z0-9_-]{1,47}\{[\x20-\x7e]{1,200}?\}")
TOKEN_PATTERN = re.compile(rb"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/\-]{12,32768}={0,2}(?![A-Za-z0-9_+/=-])")
HEX_PATTERN = re.compile(rb"(?<![A-Fa-f0-9])[A-Fa-f0-9]{16,32768}(?![A-Fa-f0-9])")
BASE32_PATTERN = re.compile(rb"(?<![A-Z2-7])[A-Z2-7]{16,32768}={0,6}(?![A-Z2-7])")
BINARY_PATTERN = re.compile(rb"(?<![01])[01]{8}(?:[ \r\n]?[01]{8}){2,8191}(?![01])")
DECOY = re.compile(rb"\b(example|sample|placeholder|decoy|fake|dummy)\b", re.I)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(data):
    signatures = [(b"\x7fELF", "ELF executable", "Reverse / Pwn"),
                  (b"MZ", "PE executable", "Reverse"), (b"PK\x03\x04", "ZIP archive", "Forensics"),
                  (b"\x1f\x8b", "GZIP stream", "Forensics"), (b"BZh", "BZIP2 stream", "Forensics"),
                  (b"\xfd7zXZ\x00", "XZ stream", "Forensics"),
                  (b"\x89PNG\r\n\x1a\n", "PNG image", "Steganography / OSINT"),
                  (b"\xff\xd8\xff", "JPEG image", "Steganography / OSINT"),
                  (b"%PDF", "PDF document", "Forensics"), (b"\x00asm", "WebAssembly", "Reverse"),
                  (b"\xd4\xc3\xb2\xa1", "PCAP capture", "Forensics"),
                  (b"\xa1\xb2\xc3\xd4", "PCAP capture", "Forensics"),
                  (b"\x0a\x0d\x0d\x0a", "PCAPNG capture", "Forensics")]
    kind, category = "Unknown binary", "Misc / Forensics"
    for magic, label, group in signatures:
        if data.startswith(magic):
            kind, category = label, group
            break
    else:
        if data[257:262] == b"ustar":
            kind, category = "TAR archive", "Forensics"
        elif data and sum(32 <= x < 127 or x in (9, 10, 13) for x in data[:65536]) / len(data[:65536]) > .9:
            kind, category = "Text / encoded content", "Crypto / Misc"
        elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
            kind, category = "WAV audio", "Steganography / Forensics"
    sample = data[:65536]
    entropy = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in Counter(sample).values()) if sample else 0
    return {"type": kind, "category": category, "bytes": len(data), "entropy": round(entropy, 3), "sha256": sha(data)}


class Analyzer:
    def __init__(self, directory, prefix="", deep=False, cancelled=lambda: False, emit=lambda event: None, seconds=60):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.prefix = prefix
        self.deep = deep
        self.cancelled = cancelled
        self.emit = emit
        self.deadline = time.monotonic() + seconds
        self.max_nodes = 300 if deep else 140
        self.max_depth = 6 if deep else 4
        self.total_bytes = 0
        self.artifacts = []
        self.candidates = []
        self.notes = []
        self.seen = set()
        self.flags = set()
        self.queue = deque()
        self.attempts = 0
        self.max_attempts = 1800 if deep else 600
        self.limits = set()
        self.media_scans = 0
        self.pattern = re.compile(re.escape(prefix.encode()) + rb"\{[\x20-\x7e]{1,200}?\}") if prefix else DEFAULT_PATTERN
        # Do not invent 26 arbitrary brace strings by shifting a genuine candidate.
        self.discovery_pattern = self.pattern if prefix else re.compile(rb"(?:flag|FLAG|CTF|ctf|picoCTF|HTB|THM)\{[\x20-\x7e]{1,200}?\}")

    def live(self):
        if self.cancelled():
            self.limits.add("Cancelled by user")
            return False
        if time.monotonic() > self.deadline:
            self.limits.add("Time budget reached")
            return False
        return True

    def note(self, message):
        if message not in self.notes and len(self.notes) < 80:
            self.notes.append(message)

    def add(self, data, name, parent=None, step=None):
        if not data or not self.live():
            return
        depth = 0 if parent is None else parent["depth"] + 1
        if depth > self.max_depth:
            self.limits.add("Transformation depth limit reached")
            return
        digest = sha(data)
        if digest in self.seen:
            return
        if len(self.artifacts) >= self.max_nodes or self.total_bytes + len(data) > 48 * 1024 * 1024:
            self.limits.add("Artifact count or expanded-byte budget reached")
            return
        if len(data) > MAX_BYTES:
            self.note("Skipped oversized artifact: " + name[:100])
            return
        self.seen.add(digest)
        artifact_id = "a%04d" % len(self.artifacts)
        item = {"id": artifact_id, "name": name[:180], "parent": parent["id"] if parent else None,
                "step": step, "depth": depth, **fingerprint(data)}
        (self.directory / (artifact_id + ".bin")).write_bytes(data)
        self.total_bytes += len(data)
        self.artifacts.append(item)
        self.queue.append((item, data))
        self.emit({"type": "artifact", "message": name[:120], "count": len(self.artifacts)})

    def derive(self, data, item, step, label):
        if not self.live():
            return
        if self.attempts >= self.max_attempts:
            self.limits.add("Experiment budget reached")
            return
        self.attempts += 1
        try:
            result = transform(data, step)
            self.add(result, label, item, step)
        except (ValueError, OSError, EOFError, UnicodeError, zipfile.BadZipFile, RuntimeError, tarfile.TarError, zlib.error, wave.Error, lzma.LZMAError) as exc:
            if step["op"] in ("zip", "tar", "gzip", "xz", "bz2", "zlib"):
                self.note("Skipped %s: %s" % (label[:80], str(exc)[:160]))

    def scan(self, item, data):
        for match in self.pattern.finditer(data):
            value = match.group().decode("ascii", errors="replace")
            key = (value, item["id"])
            if key in self.flags:
                continue
            if len(self.candidates) >= 100:
                self.limits.add("Candidate limit reached")
                break
            self.flags.add(key)
            context = data[max(0, match.start() - 70):min(len(data), match.end() + 70)]
            warnings = []
            if DECOY.search(context):
                warnings.append("Nearby text suggests an example, placeholder or decoy")
            if not self.prefix:
                warnings.append("Generic brace pattern; set the competition prefix to reduce false matches")
            candidate = {"value": value, "artifact": item["id"], "offset": match.start(),
                         "status": "candidate", "warnings": warnings,
                         "context": context.decode("utf-8", errors="replace")}
            self.candidates.append(candidate)
            self.emit({"type": "candidate", "message": "Candidate found in " + item["name"]})

    def expand(self, item, data):
        if item["depth"] >= self.max_depth:
            self.limits.add("Transformation depth limit reached")
            return
        for magic, op in [(b"\x1f\x8b", "gzip"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz")]:
            if data.startswith(magic):
                self.derive(data, item, {"op": op}, op + " decoded")
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    entries = archive.infolist()
                    if len(entries) > 64:
                        self.limits.add("Archive member limit reached (64)")
                    for index, entry in enumerate(entries[:64]):
                        if not self.live():
                            break
                        if entry.is_dir():
                            continue
                        if entry.flag_bits & 1:
                            self.note("Encrypted ZIP member requires a password: " + entry.filename[:100])
                            continue
                        if entry.file_size > MAX_BYTES or entry.file_size / max(entry.compress_size, 1) > 200:
                            self.note("Skipped oversized/high-ratio ZIP member: " + entry.filename[:100])
                            continue
                        self.derive(data, item, {"op": "zip", "index": index}, "ZIP: " + entry.filename)
            except (zipfile.BadZipFile, OSError, ValueError):
                self.note("Malformed ZIP archive")
        if data[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                    for index, entry in enumerate(archive):
                        if index >= 64:
                            self.limits.add("Archive member limit reached (64)")
                            break
                        if entry.isfile():
                            self.derive(data, item, {"op": "tar", "index": index}, "TAR: " + entry.name)
            except (tarfile.TarError, OSError, ValueError):
                self.note("Malformed TAR archive")
        # Carve a small number of embedded archive signatures; preserve byte offsets.
        for magic in (b"PK\x03\x04", b"\x1f\x8b\x08"):
            position = data.find(magic, 1)
            if position > 0:
                self.derive(data, item, {"op": "slice", "start": position, "end": len(data)}, "Embedded archive at %d" % position)
        if len(data) <= 256 * 1024:
            for pattern, op in ((HEX_PATTERN, "hex"), (TOKEN_PATTERN, "base64"), (BASE32_PATTERN, "base32"), (BINARY_PATTERN, "binary")):
                for index, match in enumerate(pattern.finditer(data)):
                    if index >= 24:
                        self.limits.add("Encoded token limit reached (24 per type)")
                        break
                    token = match.group()
                    try:
                        decoded = transform(token, {"op": op})
                    except (ValueError, UnicodeError):
                        continue
                    # Keep outputs with plausible text, a signature, or a flag.
                    plausible = decoded and (fingerprint(decoded)["type"] != "Unknown binary" or self.pattern.search(decoded))
                    if plausible:
                        if match.start() == 0 and match.end() == len(data):
                            self.derive(data, item, {"op": op}, op + " decoded")
                        else:
                            self.derive(data, item, {"op": "slice", "start": match.start(), "end": match.end()}, op + " token")
            if b"\x00" in data and len(data) % 2 == 0:
                for op in ("utf16le", "utf16be"):
                    self.derive(data, item, {"op": op}, op + " decoded")
            for marker, op in ((b"%", "url"), (b"&", "html")):
                if marker in data:
                    self.derive(data, item, {"op": op}, op + " decoded")
            for op in ("rot13", "reverse"):
                try:
                    output = transform(data, {"op": op})
                    if self.discovery_pattern.search(output):
                        self.derive(data, item, {"op": op}, op + " decoded")
                except (ValueError, UnicodeError):
                    pass
        if len(data) >= 2 and data[0] == 0x78 and (data[0] * 256 + data[1]) % 31 == 0:
            self.derive(data, item, {"op": "zlib"}, "zlib decoded")
        if self.deep and len(data) <= 65536:
            for key in range(1, 26):
                if not self.live():
                    break
                output = transform(data, {"op": "caesar", "key": key})
                if self.discovery_pattern.search(output):
                    self.derive(data, item, {"op": "caesar", "key": key}, "Caesar shift %d" % key)
        is_png = data.startswith(b"\x89PNG\r\n\x1a\n")
        is_wav = data.startswith(b"RIFF") and data[8:12] == b"WAVE"
        if self.deep and (is_png or is_wav):
            if self.media_scans >= 4:
                self.limits.add("Media scan budget reached (4 artifacts)")
            else:
                self.media_scans += 1
                op = "png_lsb" if is_png else "wav_lsb"
                self.note("Media LSB scan covers only supported formats, selected channels and byte-aligned low bits; other steganography is not covered.")
                channels = ["all", "rgb", 0, 1, 2, 3] if is_png else ["all", 0, 1]
                for channel in channels:
                    for order in ("msb", "lsb"):
                        if not self.live():
                            break
                        step = {"op": op, "channel": channel, "order": order}
                        try:
                            output = transform(data, step)
                            if self.pattern.search(output) or (output and fingerprint(output)["type"] == "Text / encoded content"):
                                self.derive(data, item, step, "%s channel=%s order=%s" % (op, channel, order))
                        except (ValueError, OSError, EOFError, wave.Error, zlib.error) as exc:
                            if channel == "all" and order == "msb":
                                self.note("Media scan skipped: " + str(exc)[:180])
                            break
        # Optional bounded XOR scan, anchored to an actual prefix or common prefixes.
        if self.deep and len(data) <= 65536:
            anchors = [(self.prefix + "{").encode()] if self.prefix else [b"flag{", b"CTF{", b"picoCTF{", b"HTB{"]
            for key in range(1, 256):
                if not self.live():
                    break
                if any(bytes(c ^ key for c in anchor) in data for anchor in anchors):
                    decoded = transform(data, {"op": "xor", "key": key})
                    if self.pattern.search(decoded):
                        self.derive(data, item, {"op": "xor", "key": key}, "Single-byte XOR key %d" % key)

    def verify(self, candidate):
        chain = []
        lookup = {a["id"]: a for a in self.artifacts}
        item = lookup[candidate["artifact"]]
        leaf = item
        while item["parent"]:
            chain.append(item)
            item = lookup[item["parent"]]
        data = (self.directory / (item["id"] + ".bin")).read_bytes()
        if sha(data) != item["sha256"]:
            raise ValueError("Original artifact hash mismatch")
        for child in reversed(chain):
            data = transform(data, child["step"])
            if sha(data) != child["sha256"]:
                raise ValueError("Derived artifact hash mismatch")
        expected = candidate["value"].encode("ascii")
        offset = candidate["offset"]
        if data[offset:offset + len(expected)] != expected or sha(data) != leaf["sha256"]:
            raise ValueError("Candidate reproduction failed")
        candidate["status"] = "reproduced"
        candidate["root"] = item["id"]
        candidate["steps"] = [a["step"] for a in reversed(chain)]

    def run(self, inputs):
        started = time.monotonic()
        inputs = list(inputs)
        suggestions = suggested_prefixes(inputs)
        diagnostics = inspect_sources(inputs)
        if self.prefix and suggestions and self.prefix not in suggestions:
            self.note("Flag prefix mismatch: entered '%s'; question contains %s. Use the exact prefix before '{' and rerun." % (self.prefix, ", ".join(suggestions)))
        for finding in diagnostics:
            self.emit({"type": "diagnostic", "message": finding["message"]})
        for name, data in inputs:
            self.add(data, name)
        while self.queue and self.live():
            item, data = self.queue.popleft()
            self.emit({"type": "check", "message": "Inspecting " + item["name"]})
            self.scan(item, data)
            self.expand(item, data)
        for candidate in self.candidates:
            if not self.live():
                break
            try:
                self.verify(candidate)
            except Exception as exc:
                candidate["warnings"].append("Reproduction failed: " + str(exc)[:160])
        categories = sorted({a["category"] for a in self.artifacts if a["depth"] == 0})
        recommendations = []
        if any("Reverse" in c for c in categories):
            recommendations.append("Binary triage only in this release. Use a decompiler/debugger to trace input validation; uploaded binaries were not executed.")
        if any("OSINT" in c or "Steganography" in c for c in categories):
            recommendations.append("Media inspection is limited: deep mode includes selected PNG/WAV low-bit checks. OCR, other bit planes and public-source corroboration may still be needed.")
        if not self.candidates:
            recommendations.append("No matching candidate found within the implemented checks. Confirm the flag prefix, enable deep scan, or supply decoded/related artifacts.")
            if diagnostics:
                recommendations.insert(0, "This source/data challenge needs algorithm analysis beyond the implemented decoding checks. See diagnostic findings; completion does not mean solved.")
        result = {"artifacts": self.artifacts, "candidates": self.candidates, "notes": self.notes,
                  "outcome": "candidates_found" if self.candidates else "budget_exhausted" if self.limits else "needs_solver" if diagnostics else "no_match",
                  "diagnostics": diagnostics, "suggested_prefixes": suggestions,
                  "limits": sorted(self.limits), "recommendations": recommendations,
                  "stats": {"artifacts": len(self.artifacts), "bytes_examined": self.total_bytes,
                            "experiments": self.attempts, "elapsed_seconds": round(time.monotonic() - started, 2)},
                  "verification_notice": "Reproduced means extraction was replayed from the original bytes. No platform acceptance or challenge correctness is asserted."}
        (self.directory / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
