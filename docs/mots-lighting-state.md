# MotS lighting state boundaries

The world pass explicitly selects RGB or mono mode. Deferred alpha surfaces restore world vertex, UV and dynamic-light arrays after thing rendering, select local-corner RGB channel blocks (or scalar fallback), and use the world RGB clipper for both sphere outcomes. RGB Gouraud faces retain channel differences instead of taking the mono uniform-light shortcut.

Model RGB draws calculate dynamic-only scratch light; primitives add static channels once. Mono draws retain their per-vertex scalar base. Solid RGB cache values remain normalized until byte encoding, with a luminance attribute for SDL rendering. The existing scalar iterator and per-channel palette additions are preserved.

Level geometry temporarily binds world-owned ARCH channels after validating declared geosets, meshes, vertex coverage and channel presence. Bindings restore on success or rejected draws, and independently owned dynamic scratch stays separate. Invalid ARCH data uses scalar model fallback in RGB mode. Placed ARCH indices are applied after template inheritance and before initialization/named overrides. The ARCH reader and storage formats are unchanged. POV weapon and saber drawing explicitly selects mono mode before drawing/flushing.

## Asset-free validation

Run from the repository root:

```sh
python3 src/Tests/run_mots_lighting_test.py --sanitize
python3 src/Tests/run_pov_lighting_test.py --sanitize
```

The first runner compiles complete extracted production alpha/ARCH functions, RGB primitives/clippers and light calculations, the actual model lighting call, contiguous solid-cache conversion blocks, and placed-thing loader/template/tokenizer functions. It checks literal expected colors, indices, pointer restoration, repeated draws, allocation failure, and placement ordering. The loader runs with and without JKM_LIGHTING. Safe controls reject changed alpha mode, scale, palette channels, scalar iteration, double base light and placement ordering. The unsafe old typed-pointer output path is never reconstructed. The POV runner executes the actual function in SDL/QOL and legacy configurations, including a safe mode-reset removal control.

Extraction fails closed when its unique boundaries change. Small fixture structs and explicit IO/projection/submission stubs do not verify the full engine ABI or a rendered frame. No game assets, network, GL context or capture hooks are needed. ASan/UBSan are optional via --sanitize; default leak detection can be overridden with ASAN_OPTIONS for restricted hosts. Such overrides must be disclosed with results.

Manual acceptance still requires MotS RGB/ARCH opaque and translucent scenes, alternating shared model instances, clipped surfaces, and POV transitions on actual rendering backends. CPU outputs do not establish rendered parity, full-game acceptance or Windows compatibility.

Adapted from andreipemberton's fork lighting work (9510c47), as reconciled with upstream in fork revision 6fa54630a123485d8c7b602c47992613a1f397b5. This topic is independent of the host-test infrastructure PR.
