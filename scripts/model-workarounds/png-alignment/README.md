# JKGM PNG row alignment helper

**Current upstream already contains the PNG unpack-state fix**, merged in [PR #487](https://github.com/shinyquagsire23/OpenJKDF2/pull/487). This utility is an optional inspection/conversion tool for older affected builds. The experiments and test results below describe their original snapshots, not a new renderer defect or a new runtime qualification.

This source-only Python example detects a PNG row-layout risk in an inspected OpenJKDF2 JKGM upload path and can write an **opaque RGBA copy of an RGB PNG while preserving every decoded RGB byte and both dimensions**. By default it only prints a JSON report. It includes original code and synthetic tests; no game assets, reference artwork, generated artwork, model weights, or private paths are included.

## Why a 1254-pixel RGB texture can shear

An 8-bit RGB row at width 1254 occupies `1254 * 3 = 3762` bytes. Under `GL_UNPACK_ALIGNMENT=4`, OpenGL advances to the next row at byte 3764. If the application provides tightly packed rows, that two-byte discrepancy accumulates across rows. The initial unpack alignment is 4; row length and alignment are separate state values. [Khronos glPixelStore reference](https://registry.khronos.org/OpenGL-Refpages/gl4/html/glPixelStore.xhtml), [Khronos-maintained reference source](https://github.com/KhronosGroup/OpenGL-Refpages/blob/main/gl4/glPixelStore.xml).

For an opaque RGBA copy, the same width uses `1254 * 4 = 5016` bytes, already divisible by four. A width change or power-of-two resize is unnecessary for this row-layout issue.

| Decoded format | Width | Tight row bytes | GL stride at alignment 4 | Difference |
|---|---:|---:|---:|---:|
| RGB, 8-bit channels | 1254 | 3762 | 3764 | 2 |
| RGBA, 8-bit channels | 1254 | 5016 | 5016 | 0 |
| RGB, 8-bit channels | 1024 | 3072 | 3072 | 0 |

The helper reports these assumptions; it does not query a running engine's OpenGL state. For a one-row image, the row-stride mismatch remains reportable but cannot accumulate into a subsequent row, so `multi_row_unpack_risk` is false.

## Inspected engine scope and actual observation

The pinned public upstream revision is `shinyquagsire23/OpenJKDF2` **`0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac`**. Its JKGM PNG reader allocates and copies tightly packed rows. The upload path resets `GL_UNPACK_ROW_LENGTH` but leaves its alignment-setting call commented, then uploads unsigned-byte color data. This establishes a row-layout risk when the current unpack alignment is 4. [PNG row allocation and copy](https://github.com/shinyquagsire23/OpenJKDF2/blob/0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac/src/Platform/GL/jkgm.cpp#L195), [commented alignment call](https://github.com/shinyquagsire23/OpenJKDF2/blob/0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac/src/Platform/GL/jkgm.cpp#L719), [albedo upload](https://github.com/shinyquagsire23/OpenJKDF2/blob/0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac/src/Platform/GL/jkgm.cpp#L753).

The local runtime experiment used source revision `4dc57962e46a72662b59d36c30f15eacef6234b5`, with the same relevant row-copy/alignment behavior. Changing only a 1254×1254 face PNG from RGB to opaque RGBA removed the observed gray/sheared face. Decoded RGB pixels, dimensions, model geometry, UVs, archive, engine, and rendering settings were unchanged. The test used the Windows engine under Wine64, Xvfb and Mesa llvmpipe. The two runs had different randomized world spawn positions and therefore are not a pixel-aligned screenshot comparison. The current GL alignment and possible buffer overread were not directly measured. `observed-case.json` records this sanitized observation separately from the synthetic tests.

This is an asset-format workaround for the inspected path. It is an original implementation of a familiar OpenGL pixel-storage correction; it makes no first-invention claim. It is not evidence about every OpenJKDF2 revision, native Windows GPU behavior, MotS graphics, legacy retail JK, or other upload paths. A renderer can also address the cause by setting and managing the appropriate unpack alignment. This tool does not patch a renderer.

## Usage

Requires Python 3.10 or newer and Pillow. Install into your own environment:

```sh
python -m pip install -r requirements.txt
```

Inspect one exact path, without writing an image:

```sh
python png_alignment.py texture.png
```

Explicitly create a **new** PNG in an existing directory:

```sh
python png_alignment.py texture.png --output texture-opaque-rgba.png
```

The output is an 8-bit RGBA PNG with alpha 255 for every pixel. The tool decodes its output and verifies dimensions, RGB byte identity, and opaque alpha before creating the destination. It never resizes, filters, recolors, swaps channels, or overwrites the source. PNG compressed bytes and interlacing may change; decoded RGB bytes do not. Color-management and other accepted ancillary chunk payloads are retained exactly, except that RGB `sBIT` gains an eight-bit alpha entry. Unknown chunks that PNG does not mark safe to copy are rejected.

Existing RGBA images can be inspected. A requested conversion of RGBA is rejected, so existing alpha is left untouched. Animated PNG, transparency-key PNG, palette, grayscale, 16-bit channels, non-PNG files, and unsupported chunks are rejected instead of being flattened or silently normalized.

Success exits 0, including a report that identifies a risk. Invalid input or a refused conversion exits 2. JSON reports go to stdout and errors to stderr.

## Filesystem behavior

Source/output aliases, hard-link aliases, symlinks, Windows reparse points, parent traversal, missing output parents, directories as outputs, ambiguous Windows names, and existing output files are refused. There is no overwrite option. A complete output is written and synced to a uniquely named temporary file in the destination directory, then installed using an atomic create-if-absent hard link. A competing destination creator wins without being overwritten. The temporary file is removed afterward. A filesystem without hard-link support causes a safe failure rather than a fallback that can replace existing files.

These checks are intended for ordinary local asset work. They are not a security boundary against another process maliciously replacing parent directories during execution. The helper does not create directories, browse other images, discover assets, or write to a game install.

## Tests

```sh
python -B -m unittest -v
```

The suite synthesizes its PNGs in temporary directories. Tests cover the 1254 RGB row arithmetic, aligned RGB, a single-row case, a simulated misaligned read, RGB identity after conversion, alpha handling, transparency and unsupported-format rejection, ancillary metadata preservation, malformed CRCs, aliases, path restrictions, and a destination creation race. It also exercises symlink/reparse metadata rejection without requiring privileged link creation. A separate real-symlink integration test skips itself when the host does not permit creating symlinks.

Verified locally with Python 3.13.15 and Pillow 12.3.0: **15 tests run, 14 passed, 1 skipped** because the Windows account lacked symlink-creation privilege. The actual engine experiment predates this standalone helper; its visual result verifies the same RGB-to-opaque-RGBA operation, while this helper's implementation is verified by its own tests. Source checksums and literal source line references are in `source-audit.json`.

MIT licensed. Copyright (c) 2026 Andrei Pemberton.
