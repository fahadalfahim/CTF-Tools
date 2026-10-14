"""Static routing and actionable diagnostics; uploaded Python is never executed."""
import ast
import json
import re


def suggested_prefixes(inputs):
    suggestions = set()
    for name, data in inputs:
        if name != "Question text":
            continue
        for match in re.finditer(rb"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_-]{1,47})\{", data):
            suggestions.add(match[1].decode("ascii"))
    return sorted(suggestions)[:8]


def inspect_sources(inputs):
    findings = []
    for name, data in inputs:
        if len(data) > 256 * 1024:
            continue
        if name.lower().endswith(".py"):
            try:
                tree = ast.parse(data.decode("utf-8-sig"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                findings.append({"file": name, "kind": "source", "message": "Python source could not be statically parsed.", "next_step": "Supply valid source and its accompanying data files."})
                continue
            modules = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.add(node.module)
            recurrence = next((node for node in ast.walk(tree) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
                               and any(isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mult) for child in ast.walk(node.left))), None)
            if recurrence:
                findings.append({"file": name, "line": recurrence.lineno, "kind": "prng",
                    "message": "Modular multiplication recurrence detected; this may implement a predictable generator.",
                    "evidence": (ast.get_source_segment(data.decode("utf-8-sig"), recurrence) or "")[:300],
                    "next_step": "Compare the recurrence with logged outputs. Full versus truncated outputs require different state-recovery methods; a decoder scan cannot determine the state."})
            crypto = sorted(module for module in modules if module.startswith(("Crypto", "cryptography", "hashlib", "random")))
            if crypto:
                findings.append({"file": name, "kind": "crypto", "message": "Crypto/random-related imports: " + ", ".join(crypto),
                    "next_step": "Trace generator output → key derivation → cipher/mode/nonce → vault decryption using the supplied source and logs."})
            if not recurrence and not crypto:
                findings.append({"file": name, "kind": "source", "message": "Python source detected. Only static triage and implemented transformations were run.",
                    "next_step": "Inspect input checks and algorithm structure; this release does not automatically execute or reason through arbitrary source."})
        elif name.lower().endswith(".json"):
            try:
                obj = json.loads(data)
            except (ValueError, UnicodeError, RecursionError):
                continue
            if isinstance(obj, dict):
                fields = list(obj)[:20]
                arrays = {key: len(value) for key, value in obj.items() if isinstance(value, list)}
                findings.append({"file": name, "kind": "structured_data", "message": "JSON fields: " + ", ".join(fields),
                    "evidence": "Array lengths: " + json.dumps(arrays)[:300],
                    "next_step": "Match these fields to the source's output format; identify logs, ciphertext, IV/nonce and parameters."})
    return findings[:24]
