# Model authoring and compatibility utilities

The optional tools in [scripts/model-workarounds](../scripts/model-workarounds/README.md)
operate on explicitly selected local files. They contain source, synthetic
fixtures and per-tool MIT licenses. They do not install game data or change
the engine's model, animation or material limits.

| Utility | Purpose | Boundary |
| --- | --- | --- |
| KEY-domain guard | Inspect KEY/PUP animation indices before adding rigid detail to a numbered rig. | The caller must supply the intended animation corpus. Exporter hierarchy metadata is trusted; a passing report does not certify a model. |
| PNG alignment helper | Inspect row layout or create an opaque RGBA copy with identical decoded RGB pixels and dimensions. | Mainly a workaround for older affected builds; current upstream already manages unpack state after PR #487. |
| MPC selection helper | Preview or explicitly update one character's model field with a verified backup. | Plain-text version 1 MPC only; keep the game closed. Does not repair geometry, animation or a missing installed model. |
| Texture-mode helper | Create a separate 3DO candidate changing only mesh/face mode fields. | Uses existing engine modes. Does not validate complete geometry or promise a visual correction in every backend. |

## Animation and model limits

Added detail must avoid indices addressed by the chosen KEY corpus. The guard
reserves the full declared animation domain, including sparse KEY allocations,
before placing detail. Its configured mesh/node limits describe its inspected
source snapshot; they are not a limit increase or proof of compatibility with
every executable. See the tool README for the exact constraints and primary
source references.

Model selection, preview behavior, rig compatibility, material appearance and
multiplayer replication are separate acceptance questions. A tool that changes
an MPC field proves only that edit; it cannot establish the others. Technical
notes and observed examples in the packages retain their original revision and
environment. They are historical evidence, not new tests of the current engine.

## Running the synthetic suites

Use Python 3.10 or later. Install Pillow into your own environment from
`scripts/model-workarounds/png-alignment/requirements.txt`, then run:

```sh
python -B scripts/model-workarounds/run_tests.py
```

The aggregate runner invokes all four package suites with the current Python
interpreter and fails when a suite fails. Tests create synthetic files in
temporary directories. Platform-specific link tests report any skip explicitly.
The focused workflow runs these Python suites; engine and real-EGL regressions
are separate contributions.

## Credit and provenance

These utilities and their synthetic fixtures are adapted from the CodaLilitari
OpenJKDF2-MotS-Fixes project. Original per-tool copyright/license notices and
historical contributor references are retained. The techniques have existing
authoring precedents; this contribution supplies inspectable implementations
and tests, not a claim of first invention. No art, retail files or private
runtime workspace is distributed here.
