"""Inspect 8-bit RGB/RGBA PNG rows; explicitly convert RGB to opaque RGBA.

Copyright (c) 2026 Andrei Pemberton
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import warnings
import zlib

from PIL import Image

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# These ancillary chunks keep their interpretation when RGB gains opaque alpha.
COPY_CHUNKS = {b"cHRM", b"gAMA", b"iCCP", b"sRGB", b"cICP", b"mDCv", b"cLLi",
               b"sBIT", b"bKGD", b"pHYs", b"tIME", b"tEXt", b"zTXt", b"iTXt", b"eXIf"}


class AlignmentError(ValueError):
    """Unsupported content or a refused filesystem operation."""


def checked_path(value: str | Path, *, output: bool = False) -> Path:
    path = Path(value)
    if ".." in path.parts:
        raise AlignmentError("Parent traversal is not accepted; give a direct path")
    path = Path(os.path.abspath(path))
    # Reject links/junctions in every existing component, without resolving through them.
    for item in [*reversed(path.parents), path]:
        if item.name:
            base = item.name.split(".", 1)[0].upper()
            reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                        *(f"LPT{i}" for i in range(1, 10))}
            if item.name.endswith((" ", ".")) or ":" in item.name or base in reserved:
                raise AlignmentError("Unsafe or ambiguous Windows path component")
        try:
            info = item.lstat()
        except FileNotFoundError:
            if output and item == path:
                continue
            raise AlignmentError("Every parent directory and the source must already exist") from None
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0)
                                       & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise AlignmentError("Symlinks and reparse points are not accepted")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise AlignmentError("A parent path is not a directory")
    if output:
        if path.suffix.lower() != ".png":
            raise AlignmentError("Output must have a .png extension")
        if path.exists():
            raise AlignmentError("Output already exists; no overwrite is supported")
    elif not path.is_file():
        raise AlignmentError("Source must be a regular file")
    return path


def parse_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise AlignmentError("Source must be a PNG, regardless of its filename")
    chunks = []
    offset = len(PNG_SIGNATURE)
    while offset < len(data):
        if offset+12 > len(data):
            raise AlignmentError("Truncated PNG chunk")
        length, kind = struct.unpack_from(">I4s", data, offset)
        end = offset+12+length
        if end > len(data):
            raise AlignmentError("PNG chunk exceeds source length")
        payload = data[offset+8:offset+8+length]
        crc, = struct.unpack_from(">I", data, offset+8+length)
        if zlib.crc32(kind+payload) & 0xFFFFFFFF != crc:
            raise AlignmentError("PNG chunk CRC mismatch")
        if len(kind) != 4 or not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
            raise AlignmentError("Invalid PNG chunk type")
        chunks.append((kind, payload))
        offset = end
        if kind == b"IEND":
            if payload or offset != len(data):
                raise AlignmentError("Unexpected PNG end or trailing data")
            break
    if not chunks or chunks[0][0] != b"IHDR" or chunks[-1][0] != b"IEND":
        raise AlignmentError("PNG header or end missing")
    if sum(k == b"IHDR" for k, _ in chunks) != 1 or not any(k == b"IDAT" for k, _ in chunks):
        raise AlignmentError("PNG header/data structure invalid")
    return chunks


def read_png(source: str | Path) -> tuple[Path, bytes, Image.Image, list[tuple[bytes, bytes]]]:
    path = checked_path(source)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise AlignmentError("Source must remain a regular file")
        data = stream.read()
    chunks = parse_chunks(data)
    header = chunks[0][1]
    if len(header) != 13:
        raise AlignmentError("Invalid PNG IHDR length")
    width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", header)
    if depth != 8 or color not in (2, 6):
        raise AlignmentError("Only native 8-bit RGB and RGBA PNGs are supported")
    if not width or not height or compression or filtering or interlace not in (0, 1):
        raise AlignmentError("Unsupported PNG header")
    if any(kind in (b"acTL", b"fcTL", b"fdAT", b"tRNS") for kind, _ in chunks):
        raise AlignmentError("Animated PNGs and transparency-key PNGs are not supported")
    for kind, _ in chunks:
        if kind in (b"IHDR", b"IDAT", b"IEND", b"PLTE") or kind in COPY_CHUNKS:
            continue
        # Preserve unknown ancillary chunks only when PNG marks them safe to copy.
        if not (kind[0:1].islower() and kind[3:4].islower()):
            raise AlignmentError("Unsupported PNG chunk cannot safely be copied")
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG" or image.mode not in ("RGB", "RGBA") or getattr(image, "n_frames", 1) != 1:
                    raise AlignmentError("Unsupported decoded image format")
                image.load()
                result = image.copy()
        except AlignmentError:
            raise
        except ValueError as error:
            # Pillow rejects some malformed/over-limit metadata with ValueError.
            raise AlignmentError(f"PNG decoder rejected source: {error}") from error
    if result.size != (width, height) or result.mode != {2: "RGB", 6: "RGBA"}[color]:
        raise AlignmentError("PNG header and decoded image disagree")
    return path, data, result, chunks


def row_report(image: Image.Image) -> dict:
    width, height = image.size
    channels = len(image.getbands())
    tight = width*channels
    stride = (tight+3)//4*4
    return {"width": width, "height": height, "mode": image.mode, "bit_depth": 8,
            "channels": channels, "tight_row_bytes": tight, "assumed_unpack_alignment": 4,
            "assumed_unpack_row_length": 0, "gl_row_stride_bytes": stride,
            "padding_bytes_per_row": stride-tight, "row_stride_mismatch": stride != tight,
            "multi_row_unpack_risk": height > 1 and stride != tight,
            "tight_buffer_bytes": tight*height,
            "last_row_end_if_alignment4": stride*(height-1)+tight,
            "extra_bytes_required_if_alignment4": (stride-tight)*(height-1),
            "scope": "Decoded unsigned-byte channels under stated GL assumptions; no live GL state query."}


def inspect_png(source: str | Path) -> dict:
    _, data, image, _ = read_png(source)
    return {"operation": "report_only", "source_sha256": hashlib.sha256(data).hexdigest(), **row_report(image)}


def encode_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload))+kind+payload+struct.pack(">I", zlib.crc32(kind+payload) & 0xFFFFFFFF)


def opaque_png(image: Image.Image, original_chunks: list[tuple[bytes, bytes]]) -> bytes:
    buffer = io.BytesIO()
    rgba = image.convert("RGBA")
    # Encode only pixel data; preserve original ancillary payloads explicitly below.
    rgba.info.clear()
    rgba.save(buffer, format="PNG")
    generated = parse_chunks(buffer.getvalue())
    header = generated[0][1]
    idats = [(kind, value) for kind, value in generated if kind == b"IDAT"]
    output = bytearray(PNG_SIGNATURE)
    wrote_data = False
    for kind, payload in original_chunks:
        if kind == b"IHDR":
            payload = header
        elif kind == b"IDAT":
            if not wrote_data:
                for new_kind, new_value in idats:
                    output.extend(encode_chunk(new_kind, new_value))
                wrote_data = True
            continue
        elif kind == b"sBIT":
            if len(payload) != 3 or any(bit < 1 or bit > 8 for bit in payload):
                raise AlignmentError("Unsupported RGB significant-bits chunk")
            payload += b"\x08"  # Added alpha uses all eight bits.
        output.extend(encode_chunk(kind, payload))
    return bytes(output)


def convert_rgb_to_rgba(source: str | Path, output: str | Path) -> dict:
    source_path, source_data, image, chunks = read_png(source)
    if image.mode != "RGB":
        raise AlignmentError("Source is already RGBA; leave its existing alpha unchanged")
    # This check also detects hard-link aliases before the general no-overwrite rule.
    candidate = Path(os.path.abspath(output))
    if candidate.exists() and os.path.samefile(source_path, candidate):
        raise AlignmentError("Output aliases the source")
    destination = checked_path(output, output=True)
    payload = opaque_png(image, chunks)
    with Image.open(io.BytesIO(payload)) as verified:
        verified.load()
        if verified.mode != "RGBA" or verified.size != image.size:
            raise AlignmentError("Output mode/dimensions failed verification")
        if verified.convert("RGB").tobytes() != image.tobytes() or verified.getchannel("A").getextrema() != (255, 255):
            raise AlignmentError("Output pixel identity/opaque-alpha check failed")
        after = row_report(verified)
    fd, temporary = tempfile.mkstemp(prefix=".png-alignment-", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        checked_path(destination, output=True)
        # Atomic create-if-absent: never replace an existing file, even after a race.
        # Fail closed on filesystems without hard-link support; no unsafe fallback.
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"operation": "converted_rgb_to_opaque_rgba", "before": row_report(image), "after": after,
            "source_sha256": hashlib.sha256(source_data).hexdigest(),
            "output_sha256": hashlib.sha256(payload).hexdigest(), "rgb_pixels_identical": True,
            "alpha": 255, "dimensions_preserved": True,
            "metadata": "Ancillary payloads retained; RGB sBIT gains an 8-bit alpha entry."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="One exact PNG path; default operation only reports")
    parser.add_argument("--output", help="Explicit NEW .png path to convert RGB to opaque RGBA")
    args = parser.parse_args(argv)
    try:
        result = convert_rgb_to_rgba(args.source, args.output) if args.output else inspect_png(args.source)
    except (AlignmentError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
