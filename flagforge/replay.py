"""Shared, dependency-free transformation implementation; copied into exports.

Archives are read into bounded memory, never extracted onto the filesystem.
"""
import base64
import bz2
import codecs
import gzip
import io
import lzma
import html
import re
import tarfile
from urllib.parse import unquote_to_bytes
import zipfile

try:
    from .formats import inflate, media_transform
except ImportError:
    from formats import inflate, media_transform

MAX_BYTES = 8 * 1024 * 1024


def bounded_read(stream, limit=MAX_BYTES):
    result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError("Expanded content exceeds the per-artifact limit")
    return result


def transform(data, step):
    op = step["op"]
    if op == "slice":
        result = data[step["start"]:step["end"]]
    elif op == "base64":
        clean = b"".join(data.split())
        result = base64.b64decode(clean + b"=" * (-len(clean) % 4), altchars=b"-_", validate=True)
    elif op == "hex":
        result = bytes.fromhex(data.decode("ascii"))
    elif op == "base32":
        clean = b"".join(data.split()).upper()
        result = base64.b32decode(clean + b"=" * (-len(clean) % 8))
    elif op == "url":
        result = unquote_to_bytes(data)
    elif op == "html":
        result = html.unescape(data.decode("utf-8")).encode("utf-8")
    elif op == "binary":
        clean = b"".join(data.split())
        if not re.fullmatch(rb"[01]+", clean) or len(clean) % 8:
            raise ValueError("Binary encoding must contain full bytes")
        result = bytes(int(clean[i:i + 8], 2) for i in range(0, len(clean), 8))
    elif op == "caesar":
        key = step["key"]
        result = bytes((x - 65 + key) % 26 + 65 if 65 <= x <= 90 else (x - 97 + key) % 26 + 97 if 97 <= x <= 122 else x for x in data)
    elif op == "zlib":
        result = inflate(data)
    elif op in ("png_lsb", "wav_lsb"):
        result = media_transform(data, step)
    elif op == "rot13":
        result = codecs.decode(data.decode("ascii"), "rot_13").encode("ascii")
    elif op == "reverse":
        result = data[::-1]
    elif op == "xor":
        result = bytes(x ^ step["key"] for x in data)
    elif op == "utf16le":
        result = data.decode("utf-16-le").encode("utf-8")
    elif op == "utf16be":
        result = data.decode("utf-16-be").encode("utf-8")
    elif op in ("gzip", "bz2", "xz"):
        opener = {"gzip": gzip.GzipFile, "bz2": bz2.BZ2File, "xz": lzma.LZMAFile}[op]
        if op == "gzip":
            stream = opener(fileobj=io.BytesIO(data))
        else:
            stream = opener(io.BytesIO(data))
        with stream:
            result = bounded_read(stream)
    elif op == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entry = archive.infolist()[step["index"]]
            if entry.file_size > MAX_BYTES:
                raise ValueError("ZIP member too large")
            with archive.open(entry) as stream:
                result = bounded_read(stream)
    elif op == "tar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for index, entry in enumerate(archive):
                if index == step["index"]:
                    if not entry.isfile() or entry.size > MAX_BYTES:
                        raise ValueError("Unsupported TAR member")
                    with archive.extractfile(entry) as stream:
                        result = bounded_read(stream)
                    break
            else:
                raise ValueError("Missing TAR member")
    else:
        raise ValueError("Unknown transformation: " + op)
    if len(result) > MAX_BYTES:
        raise ValueError("Artifact too large")
    return result
