⚠️ Disclaimer
Warning: This tool is created strictly for educational purposes, CTF competitions, and authorized penetration testing only. Do not use this tool against any system or network without explicit permission. The author is not responsible for any misuse or damage caused by this program.

👨‍💻 Developed by: Fahad Al Fahim

# apostrophe

A working local CTF workbench: upload files or paste a question, run bounded analysis, inspect evidence and download a self-contained extraction script. Python 3.10+; no Python dependencies for the built-in engine. Linux is the deployment target; the built-in engine also runs on Windows.

## Run

From the project directory:

```sh
python3 -m apostrophe
```

Open **http://127.0.0.1:8787**. On Windows use `python` instead of `python3`. Upload `examples/challenge.txt`, set prefix `flag`, and click **Analyze & Solve**. Expected candidate: `flag{evidence_before_confidence}`. Download the bundle, extract it, and run `python3 solve.py` inside the extracted directory.

The service is a single-user loopback application. Session tokens and origin/Host checks protect the browser API, but this is not a multi-user authentication system. Do not expose it to a public network or reverse proxy.

Renamed from FlagForge. The legacy `flagforge` Python import/command, `.flagforge/` storage folder and Compose service/volume names remain compatible so existing investigations continue to work. The UI, public launch command and new downloads use **apostrophe**.

## Linux container with passive tools

```sh
docker compose up --build
```

The image installs `file`, `readelf` and `exiftool`. Compose runs as a non-root user, drops capabilities, uses a read-only root filesystem, bounds resources, publishes on host loopback only, and uses an internal network. Docker is required and the first build needs package-download access. Container deployment has not been verified unless explicitly stated in `VALIDATION.md`.

Native tools parse untrusted files and are optional. On Linux they can also be enabled using `--native-tools`, but prefer the disposable container. No uploaded executable or arbitrary shell command is run. The Python worker has resource limits on POSIX; it is not an OS sandbox by itself. Docker is not an appropriate substitute for a hardened VM for malware execution, which this release does not support.

## Implemented

- Responsive file-drop UI, question input, literal flag prefix and optional deep scan.
- Persistent investigation history; two background worker processes, bounded queue, cancellation and worker deadline.
- Content fingerprints, SHA-256, entropy, original/derived artifact tracking and parent transformation records.
- Direct flag-pattern search; Base64/Base64URL, Base32, hex, binary-byte strings, URL/HTML, UTF-16, targeted ROT13/reverse and bounded single-byte XOR/Caesar checks.
- Deep mode: selected channel/order low-bit extraction for non-interlaced 8-bit PNG (up to 1 million pixels) and PCM WAV (bounded sample count); supports raw brace-pattern flags and some text payloads.
- Bounded ZIP/TAR reading (no filesystem extraction), GZIP/BZIP2/XZ/zlib decoding and limited embedded archive carving.
- Replays each candidate's extraction from original bytes and verifies artifact hashes.
- Flags possible example/decoy context and question-derived candidates.
- Downloadable ZIP containing originals, report, manifest and a dependency-free `solve.py`.
- Optional fixed passive Linux adapters, with output and exit status in the report.

## Honest boundaries

This is **v0.1**, not a universal autonomous solver. No LLM is connected. There is no Ghidra/GDB integration, exploit generation, browser automation, remote service solving, online OSINT, OCR, general cryptanalysis or platform submission. PNG/WAV support covers only selected byte-aligned LSB schemes, not general steganography. The remote field is saved as context only. RE/OSINT-like files receive byte-level triage, not complete category solving. Binary tools' text output is shown but is not treated as verified flag evidence.

### v0.1.1: completed does not mean solved

No-candidate jobs now display **NO MATCH**, **NEEDS SOLVER**, or **LIMIT REACHED** rather than an ambiguous completed badge. Python source receives static import/recurrence triage; JSON receives field/array summaries. These diagnostics route further work; they do not perform PRNG recovery or vault decryption.

Generic flag matching now supports hyphenated prefixes. If the question suggests `SMUCTF-CTF{...}` but you enter `SMUCTF`, a mismatch is shown; select the exact prefix and use **Rerun saved inputs**. Suggestions can also be examples, so they are not silently substituted. Browser API requests time out; expired local sessions are refreshed once and repeated polling failures stop after five attempts.

"Reproduced" means the extraction process ran again successfully. It does **not** establish that the competition accepts the string. The verifier deliberately does not display a made-up accuracy percentage. The same transformation implementation is used for extraction and replay; replay catches provenance/corruption issues but is not an independent mathematical proof. Flags use printable ASCII brace patterns in this release. Set the correct prefix to reduce false matches. A no-result outcome is not proof of absence.

## Limits

Up to 8 uploads, 8 MiB each, 16 MiB total; question up to 50,000 characters. Each investigation processes at most 140 artifacts (300 deep), 48 MiB of artifact content, depth 4 (6 deep), and 600 transformations (1,800 deep). Archives are limited to 64 members, ZIP expansion ratio 200, and 8 MiB/member. Encoded token scanning is bounded and heuristic: some multilayer encodings will be missed. Analysis has a 75-second cooperative deadline and the worker a 110-second hard deadline. A single decompression or parser operation may be stopped only by the hard deadline. Cancellation requests receive a 2-second grace period.

Inputs/results remain under `.flagforge/` (or the container's named volume) until you remove them. The 1 GiB admission quota prevents accepting more jobs once exceeded; in-flight jobs may temporarily exceed it. Original filenames are labels only; all on-disk filenames are generated. Archives are never unpacked using member paths. A restarted interrupted job is marked interrupted; there is no resume feature. Re-submit the input to rerun.

## Tests

```sh
python3 -m unittest discover -s tests -v
node --check flagforge/static/app.js
```

Tests cover extraction/replay, encoded/archive combinations, incorrect prefixes, false-candidate handling, corrupt archives, archive path traversal, API validation/auth/origin checks, cancellation and export reproduction. See `VALIDATION.md` for actual results and unverified areas.

## Extension direction

Keep future planners separate from the execution broker. Add versioned capability adapters, independent challenge checkers and a held-out benchmark before increasing autonomy. Remote targets require enforced network scope. Agent-generated code requires stronger execution isolation. Add image/PCAP/RE capabilities one at a time, each with real challenge fixtures and honest verification states.
