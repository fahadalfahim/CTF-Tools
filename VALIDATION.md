# apostrophe validation record

Date: 2026-10-01. Environment: Windows, Python 3.10.11, Node.js 24.19.0.

## Completed checks

- `python -m unittest discover -s tests -v`: **42 tests passed** (4.669 seconds on the no-result diagnosis run).
- `node --check flagforge/static/app.js`: passed.
- `python -m compileall -q apostrophe flagforge tests`: passed on the rename/review run.
- Actual browser use: pasted an encoded question, set prefix `flag`, submitted, observed completed job and `flag{evidence_before_confidence}` with three artifacts and two transformations.
- Actual browser file upload: selected `examples/challenge.txt`, enabled deep inspection, submitted, observed the same expected candidate, evidence hashes and reproduced status.
- Browser console: no captured errors or warnings during those flows.
- Visual inspection: the workbench and completed result were rendered and inspected in the in-app browser. No exhaustive device/accessibility audit was performed.
- Export test: unpacked the generated bundle, executed its standalone solver successfully, then changed original bytes and confirmed that hash verification failed.

## Rename and reliability review

- Renamed the UI, logo, download names, distribution and public launcher to `apostrophe`; old imports and stored investigations remain compatible.
- Verified both `python -m apostrophe --help` and the legacy launch command.
- Added restart coverage for completed results and interrupted jobs.
- Found two legacy servers listening on port 8787 on Windows. Stopped them after confirming there were no active jobs and restarted one renamed server.
- Fixed Windows socket binding with `SO_EXCLUSIVEADDRUSE`. Added a regression test that rejects a second listener on the same port.
- Linux/Docker limitations below remain; this review does not certify those environments.

## Coverage highlights

Nested ZIP/GZIP/Base64; hex of Base64; direct extraction; UTF-16; XOR; Caesar; ROT13; reversed text; Base32; URL and HTML encoding; binary-byte strings; zlib; PNG low bits (all five filter types on a single-row grayscale fixture); WAV PCM low bits; malformed ZIP/XZ/zlib; bad PNG CRC; decompression limit; TAR symlink exclusion; ZIP path traversal resistance; literal prefix validation; decoy warnings; prevention of invented shifted candidates; HTTP auth/origin/Host checks; persistent output creation; job cancellation.

## Not verified

- Native Linux execution, POSIX resource/process-group limits and passive tool adapters: this host has no installed WSL distribution or Docker executable.
- Docker image build and Compose deployment; the supplied configuration must be verified on the target Linux machine.
- Full PNG color/filter/interlace combinations, WAV formats or arbitrary real-world malformed files. Supported PNG formats are deliberately limited; interlaced and palette PNG are rejected by the low-bit decoder.
- A real held-out competition benchmark, platform submissions or measured solve accuracy.
- Multi-user or Internet-facing deployment, penetration testing, exhaustive fuzzing or long-duration load tests.

Passing these tests verifies specific behaviors, not absence of bugs or a guarantee of challenge correctness. This release provides a functioning deterministic workbench; it does not implement the entire autonomous AI architecture discussed in planning.

## v0.1.1 no-result investigation

The supplied screenshot shows COMPLETED, zero candidates and 0.02 seconds, not a still-running worker. The current workbench has no PRNG state-recovery/encrypted-vault solver. The screenshot also suggests a possible SMUCTF versus SMUCTF-CTF prefix mismatch; the original files are required to confirm the exact expected format.

Added regression tests for hyphenated prefixes, explicit mismatch diagnostics, static Python recurrence/import detection without execution, structured JSON triage, no-result/limited outcomes and rerunning stored inputs with a corrected prefix. JavaScript syntax validation passed. The screenshot's `token_service.py` and `reset_dump.json` are not present in this workspace; this real challenge has not been solved or evaluated.

Live worker smoke: a synthetic Python modular-recurrence source plus JSON log was submitted through the local API and its saved result asserted `needs_solver`, `SMUCTF-CTF` prefix suggestion and a mismatch note. Python compilation passed. Browser visual verification for v0.1.1 was blocked by the browser tool's URL policy; it was not retried through another browser surface. Earlier visual checks describe v0.1.0 only.
