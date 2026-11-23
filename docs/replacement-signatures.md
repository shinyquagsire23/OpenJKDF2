# Replacement signature selection

A replacement with the original texture signature takes precedence over a path/cel entry. Path/cel remains a fallback when no signature matches. Metadata population retains the first encountered claimant for each signature; this does not establish deterministic filesystem metadata enumeration order. Lookup uses find and leaves both maps unchanged when nothing matches.

The shared helper is called by metadata registration and shortcut selection in jkgm.cpp. Signature-only matches now retain the matching signature entry rather than creating an empty path record. PNG decoding/unpack state, texture cache size and slot reuse are unchanged; this topic adds no upload diagnostics or capture feature.

Run `python3 src/Tests/run_replacement_signatures_test.py --sanitize` from the repository root. The fixture executes the actual production registration loop body and contiguous shortcut decision/early-return block with synthetic caches and a disabled upload callback. It covers duplicate claims, signature-only records, conflicting paths, path fallback and repeated misses without map mutation. Expectations are literal markers and map sizes. Extraction fails closed if unique source boundaries change. This verifies selection behavior; JSON parsing, metadata enumeration, PNG/GL upload and an actual replacement-pack draw still require integration acceptance. Sanitizers default to leak detection; restricted hosts can override ASAN_OPTIONS and must disclose that limitation.

Adapted from andreipemberton's matching work (b4b4d39), preserved in fork revision 6fa54630a123485d8c7b602c47992613a1f397b5. The source-test utility is self-contained and has no dependency on the unmerged host-test infrastructure PR.
