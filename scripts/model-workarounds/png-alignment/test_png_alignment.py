"""Synthetic regression fixtures only; no game textures or external images."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from PIL import Image, PngImagePlugin

import png_alignment as guard


class AlignmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def rgb(self, width=1254, height=4, name="synthetic.png", **save_args):
        # Distinct channels and rows make byte shifting visible to assertions.
        pixels = bytes((x*17+y*43+channel*79) % 256
                       for y in range(height) for x in range(width) for channel in range(3))
        path = self.root/name
        Image.frombytes("RGB", (width, height), pixels).save(path, **save_args)
        return path, pixels

    def test_1254_rgb_stride_and_default_cli_is_read_only(self):
        source, _ = self.rgb(height=1254)
        before = source.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(guard.main([str(source)]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual((report["tight_row_bytes"], report["gl_row_stride_bytes"]), (3762, 3764))
        self.assertEqual(report["extra_bytes_required_if_alignment4"], 2506)
        self.assertTrue(report["multi_row_unpack_risk"])
        self.assertEqual(before, source.read_bytes())
        self.assertEqual(list(self.root.iterdir()), [source])

    def test_aligned_rgb_and_single_row_scope(self):
        aligned, _ = self.rgb(width=1024)
        report = guard.inspect_png(aligned)
        self.assertEqual(report["gl_row_stride_bytes"], 3072)
        self.assertFalse(report["multi_row_unpack_risk"])
        one_row, _ = self.rgb(height=1, name="one-row.png")
        single = guard.inspect_png(one_row)
        self.assertTrue(single["row_stride_mismatch"])
        self.assertFalse(single["multi_row_unpack_risk"])
        self.assertEqual(single["extra_bytes_required_if_alignment4"], 0)

    def test_conversion_preserves_every_rgb_byte_and_simulated_unpack(self):
        source, original_pixels = self.rgb()
        original_file = source.read_bytes()
        destination = self.root/"opaque.png"
        report = guard.convert_rgb_to_rgba(source, destination)
        self.assertEqual(report["after"]["tight_row_bytes"], 5016)
        self.assertFalse(report["after"]["row_stride_mismatch"])
        with Image.open(destination) as image:
            self.assertEqual(image.mode, "RGBA")
            self.assertEqual(image.size, (1254, 4))
            self.assertEqual(image.convert("RGB").tobytes(), original_pixels)
            self.assertEqual(image.getchannel("A").getextrema(), (255, 255))
            data = image.tobytes()
        # The default GL stride reads the wrong start for original row 1.
        self.assertNotEqual(original_pixels[3764:3764+3], original_pixels[3762:3762+3])
        # Every new RGBA row begins exactly where four-byte GL alignment expects.
        for row in range(4):
            rgb_row = original_pixels[row*3762:(row+1)*3762]
            rgba_row = data[row*5016:(row+1)*5016]
            self.assertEqual(bytes(v for i, v in enumerate(rgba_row) if i % 4 != 3), rgb_row)
        self.assertEqual(source.read_bytes(), original_file)
        self.assertTrue(report["rgb_pixels_identical"])

    def test_rgba_report_retains_alpha_and_conversion_rejects(self):
        source = self.root/"existing-alpha.png"
        image = Image.frombytes("RGBA", (3, 1), bytes([10, 20, 30, 0, 40, 50, 60, 127, 70, 80, 90, 255]))
        image.save(source)
        original = source.read_bytes()
        self.assertEqual(guard.inspect_png(source)["mode"], "RGBA")
        with self.assertRaisesRegex(guard.AlignmentError, "already RGBA"):
            guard.convert_rgb_to_rgba(source, self.root/"unexpected.png")
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse((self.root/"unexpected.png").exists())

    def test_rgb_transparency_key_rejected(self):
        source, _ = self.rgb(width=3, transparency=(0, 79, 158))
        with self.assertRaisesRegex(guard.AlignmentError, "transparency-key"):
            guard.convert_rgb_to_rgba(source, self.root/"flattened.png")
        self.assertFalse((self.root/"flattened.png").exists())

    def test_unsupported_formats_and_bit_depth_rejected(self):
        for mode in ("P", "L", "LA", "I;16"):
            with self.subTest(mode=mode):
                path = self.root/(mode.replace(";", "-")+".png")
                Image.new(mode, (2, 2)).save(path)
                with self.assertRaises(guard.AlignmentError):
                    guard.inspect_png(path)
        fake = self.root/"not-png.png"
        Image.new("RGB", (2, 2)).save(fake, format="JPEG")
        with self.assertRaises(guard.AlignmentError):
            guard.inspect_png(fake)

    def test_animated_png_rejected(self):
        path = self.root/"animated.png"
        first = Image.new("RGB", (4, 4), "red")
        second = Image.new("RGB", (4, 4), "blue")
        first.save(path, save_all=True, append_images=[second], duration=100, loop=0)
        with self.assertRaisesRegex(guard.AlignmentError, "Animated"):
            guard.inspect_png(path)

    def test_source_alias_existing_output_and_directory_rejected(self):
        source, _ = self.rgb()
        original = source.read_bytes()
        with self.assertRaises(guard.AlignmentError):
            guard.convert_rgb_to_rgba(source, source)
        hard_link = self.root/"hard-link.png"
        os.link(source, hard_link)
        with self.assertRaisesRegex(guard.AlignmentError, "aliases"):
            guard.convert_rgb_to_rgba(source, hard_link)
        other = self.root/"keep.png"
        other.write_bytes(b"existing content")
        with self.assertRaises(guard.AlignmentError):
            guard.convert_rgb_to_rgba(source, other)
        directory = self.root/"directory.png"
        directory.mkdir()
        with self.assertRaises(guard.AlignmentError):
            guard.convert_rgb_to_rgba(source, directory)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(other.read_bytes(), b"existing content")

    def test_symlink_and_linked_parent_rejected(self):
        source, _ = self.rgb()
        linked = self.root/"source-link.png"
        parent_link = self.root/"parent-link"
        try:
            linked.symlink_to(source)
            parent_link.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Host does not permit synthetic symlink creation: {exc}")
        with self.assertRaises(guard.AlignmentError):
            guard.inspect_png(linked)
        with self.assertRaises(guard.AlignmentError):
            guard.convert_rgb_to_rgba(source, parent_link/"unsafe.png")
        with self.assertRaises(guard.AlignmentError):
            guard.convert_rgb_to_rgba(source, linked)

    def test_unsafe_paths_rejected_without_creating_parents(self):
        source, _ = self.rgb()
        for destination in [self.root/"missing"/"new.png", self.root/".."/"outside.png",
                            self.root/"NUL.png", self.root/"output.jpg"]:
            with self.subTest(destination=str(destination)):
                with self.assertRaises(guard.AlignmentError):
                    guard.convert_rgb_to_rgba(source, destination)
        self.assertFalse((self.root/"missing").exists())

    def test_reparse_and_symlink_metadata_rejected_without_following(self):
        source, _ = self.rgb()
        original_lstat = Path.lstat
        for mode, attributes in [(stat.S_IFLNK, 0), (stat.S_IFREG, 0x400)]:
            def fake_lstat(path, *args, **kwargs):
                if path == source:
                    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                return original_lstat(path, *args, **kwargs)
            with patch.object(Path, "lstat", fake_lstat):
                with self.assertRaisesRegex(guard.AlignmentError, "Symlinks and reparse"):
                    guard.checked_path(source)

    def test_atomic_destination_race_never_overwrites(self):
        source, _ = self.rgb()
        destination = self.root/"raced.png"
        real_link = os.link
        def racing_link(temporary, target):
            Path(target).write_bytes(b"concurrent creator")
            return real_link(temporary, target)
        with patch.object(guard.os, "link", side_effect=racing_link):
            with self.assertRaises(FileExistsError):
                guard.convert_rgb_to_rgba(source, destination)
        self.assertEqual(destination.read_bytes(), b"concurrent creator")
        self.assertEqual(list(self.root.glob(".png-alignment-*")), [])

    def test_unsupported_atomic_link_has_no_partial_output(self):
        source, _ = self.rgb()
        destination = self.root/"not-created.png"
        with patch.object(guard.os, "link", side_effect=OSError("unsupported filesystem")):
            with self.assertRaises(OSError):
                guard.convert_rgb_to_rgba(source, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".png-alignment-*")), [])

    def test_color_and_text_chunks_preserved_and_sbit_adjusted(self):
        info = PngImagePlugin.PngInfo()
        info.add(b"gAMA", struct.pack(">I", 45455))
        info.add(b"sBIT", bytes([8, 8, 8]))
        info.add_text("fixture", "Only synthetic pixels")
        source, pixels = self.rgb(width=3, pnginfo=info)
        destination = self.root/"metadata.png"
        guard.convert_rgb_to_rgba(source, destination)
        before = dict(guard.parse_chunks(source.read_bytes()))
        after = dict(guard.parse_chunks(destination.read_bytes()))
        self.assertEqual(before[b"gAMA"], after[b"gAMA"])
        self.assertEqual(before[b"tEXt"], after[b"tEXt"])
        self.assertEqual(after[b"sBIT"], bytes([8, 8, 8, 8]))
        with Image.open(destination) as image:
            self.assertEqual(image.convert("RGB").tobytes(), pixels)

    def test_malformed_png_fails_before_output(self):
        source, _ = self.rgb(width=3)
        broken = bytearray(source.read_bytes())
        broken[29] ^= 1  # IHDR CRC byte.
        source.write_bytes(broken)
        with self.assertRaisesRegex(guard.AlignmentError, "CRC"):
            guard.convert_rgb_to_rgba(source, self.root/"bad.png")
        self.assertFalse((self.root/"bad.png").exists())

    def assert_decoder_error_is_clean(self, kind, payload, expected_error):
        source, _ = self.rgb(width=3, height=2)
        chunks = guard.parse_chunks(source.read_bytes())
        chunks.insert(1, (kind, payload))
        original = guard.PNG_SIGNATURE + b"".join(guard.encode_chunk(k, p) for k, p in chunks)
        source.write_bytes(original)
        destination = self.root/"refused.png"
        script = Path(__file__).with_name("png_alignment.py")
        for arguments in ([str(source)], [str(source), "--output", str(destination)]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-B", str(script), *arguments],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertTrue(result.stderr.startswith("error: PNG decoder rejected source:"))
                self.assertIn(expected_error, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse(destination.exists())
                self.assertEqual(list(self.root.glob(".png-alignment-*")), [])

    def test_truncated_phys_reports_clean_decoder_error(self):
        self.assert_decoder_error_is_clean(b"pHYs", b"\x01", "Truncated pHYs chunk")

    def test_oversized_ztxt_reports_clean_decoder_error(self):
        text = b"A" * (PngImagePlugin.MAX_TEXT_CHUNK + 1)
        payload = b"fixture\x00\x00" + zlib.compress(text)
        self.assert_decoder_error_is_clean(b"zTXt", payload, "Decompressed data too large")


if __name__ == "__main__":
    unittest.main()
