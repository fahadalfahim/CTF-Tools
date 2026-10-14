import base64
import io
import struct
import tempfile
import unittest
from urllib.parse import quote_from_bytes
import wave
import zlib

from flagforge.engine import Analyzer
from flagforge.formats import png_pixels

FLAG = b"flag{media_evidence}"


def chunk(kind, content):
    return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content) & 0xffffffff)


def png_fixture(pixels, mode=0):
    width = len(pixels)
    if mode in (1, 4):
        filtered = bytes((value - (pixels[i - 1] if i else 0)) % 256 for i, value in enumerate(pixels))
    elif mode == 3:
        filtered = bytes((value - (pixels[i - 1] // 2 if i else 0)) % 256 for i, value in enumerate(pixels))
    else:
        filtered = pixels
    header = struct.pack(">IIBBBBB", width, 1, 8, 0, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes([mode]) + filtered)) + chunk(b"IEND", b"")


class MediaCodecTests(unittest.TestCase):
    def result(self, data, deep=False):
        with tempfile.TemporaryDirectory() as directory:
            return Analyzer(directory, prefix="flag", deep=deep).run([("fixture", data)])

    def assert_flag(self, data, deep=False):
        result = self.result(data, deep)
        self.assertIn(FLAG.decode(), [c["value"] for c in result["candidates"]], result)
        self.assertTrue(all(c["status"] == "reproduced" for c in result["candidates"]))

    def test_extended_codecs(self):
        encodings = [base64.b32encode(FLAG), quote_from_bytes(FLAG).encode(),
                     b"".join(("%08d" % int(bin(x)[2:])).encode() for x in FLAG),
                     FLAG.replace(b"{", b"&#123;").replace(b"}", b"&#125;"), zlib.compress(FLAG)]
        for data in encodings:
            with self.subTest(data=data):
                self.assert_flag(data)

    def test_caesar(self):
        encoded = bytes((x - 97 + 5) % 26 + 97 if 97 <= x <= 122 else x for x in FLAG)
        self.assert_flag(encoded, deep=True)

    def test_png_lsb(self):
        pixels = bytes(128 | ((byte >> bit) & 1) for byte in FLAG for bit in range(7, -1, -1))
        for mode in range(5):
            with self.subTest(mode=mode):
                data = png_fixture(pixels, mode)
                self.assertEqual(png_pixels(data)[0], pixels)
                self.assert_flag(data, deep=True)

    def test_png_checksum_rejected(self):
        data = bytearray(png_fixture(b"\x80" * 32)); data[29] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            png_pixels(bytes(data))
        result = self.result(bytes(data), deep=True)
        self.assertTrue(any("checksum" in note for note in result["notes"]))

    def test_wav_lsb(self):
        buffer = io.BytesIO()
        samples = bytes(128 | ((byte >> bit) & 1) for byte in FLAG for bit in range(7, -1, -1))
        with wave.open(buffer, "wb") as sound:
            sound.setnchannels(1); sound.setsampwidth(1); sound.setframerate(8000); sound.writeframes(samples)
        self.assert_flag(buffer.getvalue(), deep=True)

    def test_corrupt_zlib_is_a_note_not_crash(self):
        result = self.result(b"\x78\x9cgarbage")
        self.assertTrue(any("zlib" in note for note in result["notes"]))


if __name__ == "__main__":
    unittest.main()
