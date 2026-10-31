# Model authoring and texture compatibility tools

This directory consolidates the original small examples alongside the engine source.
Start with [the compatibility and scope guide](../../docs/MODEL_WORKAROUNDS.md).

- [KEY-domain guard](key-domain-guard/README.md): reserves the intended animation
  domain before adding rigid model detail. Python standard library only.
- [PNG alignment helper](png-alignment/README.md): reports tightly packed RGB row
  risk and can create an opaque RGBA copy without changing decoded color pixels.
  Requires Pillow. Useful for affected renderer builds predating upstream PR #487.
- [MPC selection helper](mpc-selection/README.md): previews or changes only the
  model field in one exact multiplayer profile, with a verified backup before
  writing. This implements historical direct-selection practice. Close the game
  first. Python standard library only.
- [Texture-mode candidate helper](texture-mode/README.md): reports affine versus
  perspective mode and can create a separate 3DO changing only those mesh/face
  fields. Preserves every other byte. Python standard library only.

Run `python -B scripts/model-workarounds/run_tests.py` from the repository root.
The tests use synthetic fixtures and temporary files, never game assets.
Each tool carries its original MIT license. The engine correction follows the
engine repository's existing license.
