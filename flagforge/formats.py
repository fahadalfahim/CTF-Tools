"""Small bounded media readers for reproducible CTF bit-plane experiments.

PNG: non-interlaced 8-bit grayscale/RGB/gray-alpha/RGBA only.
WAV: uncompressed PCM; extracts the low bit of each selected sample.
No user-provided file paths or code are interpreted.
"""
import io
import struct
import wave
import zlib

LIMIT = 8 * 1024 * 1024


def inflate(data, limit=LIMIT):
    decoder = zlib.decompressobj()
    result = decoder.decompress(data, limit + 1)
    if len(result) > limit or decoder.unconsumed_tail:
        raise ValueError("Decompressed stream exceeds budget")
    if not decoder.eof:
        raise ValueError("Incomplete compressed stream")
    return result


def png_pixels(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Not PNG")
    position = 8
    compressed = bytearray()
    dimensions = None
    ended = False
    while position + 12 <= len(data):
        length = struct.unpack_from(">I", data, position)[0]
        if length > LIMIT or position + length + 12 > len(data):
            raise ValueError("Invalid PNG chunk length")
        kind = data[position + 4:position + 8]
        content = data[position + 8:position + 8 + length]
        crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        if zlib.crc32(kind + content) & 0xffffffff != crc:
            raise ValueError("PNG checksum mismatch")
        if kind == b"IHDR":
            if dimensions is not None or length != 13 or position != 8:
                raise ValueError("Invalid PNG header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", content)
            channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
            if not channels or depth != 8 or compression or filtering or interlace:
                raise ValueError("PNG LSB supports only non-interlaced 8-bit grayscale/RGB/RGBA")
            if not width or not height or width * height > 1_000_000:
                raise ValueError("PNG pixel budget exceeded")
            dimensions = width, height, channels
        elif kind == b"IDAT":
            if dimensions is None:
                raise ValueError("PNG data before header")
            compressed.extend(content)
            if len(compressed) > LIMIT:
                raise ValueError("PNG compressed-data budget exceeded")
        elif kind == b"IEND":
            ended = True
            break
        position += length + 12
    if dimensions is None or not ended:
        raise ValueError("Incomplete PNG")
    width, height, channels = dimensions
    stride = width * channels
    expected = height * (stride + 1)
    raw = inflate(bytes(compressed), expected)
    if len(raw) != expected:
        raise ValueError("PNG scanline size mismatch")
    pixels = bytearray()
    previous = bytearray(stride)
    for row_index in range(height):
        offset = row_index * (stride + 1)
        mode = raw[offset]
        row = bytearray(raw[offset + 1:offset + stride + 1])
        if mode > 4:
            raise ValueError("Unknown PNG filter")
        for index in range(stride):
            a = row[index - channels] if index >= channels else 0
            b = previous[index]
            c = previous[index - channels] if index >= channels else 0
            if mode == 1:
                predictor = a
            elif mode == 2:
                predictor = b
            elif mode == 3:
                predictor = (a + b) // 2
            elif mode == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                predictor = a if pa <= pb and pa <= pc else b if pb <= pc else c
            else:
                predictor = 0
            row[index] = (row[index] + predictor) & 255
        pixels.extend(row)
        previous = row
    return bytes(pixels), channels


def pack_low_bits(values, order="msb"):
    result = bytearray()
    byte = count = 0
    for value in values:
        if order == "msb":
            byte = (byte << 1) | (value & 1)
        else:
            byte |= (value & 1) << count
        count += 1
        if count == 8:
            result.append(byte)
            byte = count = 0
    return bytes(result)


def media_transform(data, step):
    if step["op"] == "png_lsb":
        pixels, channels = png_pixels(data)
        channel = step.get("channel", "all")
        if channel == "rgb":
            if channels not in (3, 4):
                raise ValueError("Not RGB")
            values = (value for index, value in enumerate(pixels) if index % channels < 3)
        elif channel == "all":
            values = pixels
        else:
            if not 0 <= channel < channels:
                raise ValueError("Missing PNG channel")
            values = pixels[channel::channels]
        return pack_low_bits(values, step.get("order", "msb"))
    if step["op"] == "wav_lsb":
        with wave.open(io.BytesIO(data), "rb") as sound:
            width = sound.getsampwidth()
            channels = sound.getnchannels()
            if sound.getcomptype() != "NONE" or width not in (1, 2, 3, 4) or channels > 8:
                raise ValueError("WAV LSB supports PCM samples and up to 8 channels")
            frames = min(sound.getnframes(), 262144 // max(channels, 1))
            samples = sound.readframes(frames)
            channel = step.get("channel", "all")
            if channel == "all":
                values = samples[::width]
            else:
                if not 0 <= channel < channels:
                    raise ValueError("Missing WAV channel")
                values = samples[channel * width::channels * width]
            return pack_low_bits(values, step.get("order", "msb"))
    raise ValueError("Unknown media operation")
