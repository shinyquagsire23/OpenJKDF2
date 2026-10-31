# Explicit MPC model selection

This editor accepts plain-text **version 1** MPC files only. Upstream can also read original MotS version 2 files, but this standalone tool does not decode or edit that format.

This small Python helper previews or changes the `model:` field of one explicitly
named JK/MotS multiplayer `.mpc` character file. It leaves every other byte in
that file unchanged, including force powers, MotS personality, saber materials,
sound class, comments and LF/CRLF newlines. It does not edit the `.plr` settings
file, discover profiles, install a model, or change an archive.

Direct MPC selection is historical practice, including in the inspected TDIR
launcher. This is an original implementation of that technique, not a new
engine feature or a claim of first invention. The broader
[compatibility findings](../../../docs/MODEL_WORKAROUNDS.md) distinguish model
selection, preview support and correct animation.

## Use

Requires Python 3.10 or later; only the standard library is used. First install
the model and its dependencies into the intended mod path, create an ordinary
multiplayer character if necessary, and exit the game completely. Determine the
exact `.mpc` path yourself. The helper neither searches for it nor checks whether
the named model is installed.

From this directory, substitute your exact profile path and installed model
basename in these commands:

```sh
python -B set_mpc_model.py "./profiles/example.mpc" custom.3do
python -B set_mpc_model.py "./profiles/example.mpc" custom.3do --apply
```

The first command is a read-only preview. JSON output reports the resolved path,
old and new model names, before/after SHA-256 values, and whether the bytes would
change. Only `--apply` writes. A changed profile receives a unique adjacent
backup named `example.mpc.<UTC timestamp>.<random suffix>.bak`; the original
bytes are flushed and verified in that backup before the profile is written.
The final JSON identifies the retained backup. Reapplying the same model makes
no write and no additional backup.

The model must be an ASCII `.3do` basename of at most 31 bytes. Exactly one
`version 1` declaration and one `model:` line are required. A non-MPC path,
symlink, parent symlink, Windows reparse point, or multiply hard-linked profile
is rejected. The tool compares the profile again before writing and checks the
opened file identity; it aborts if an intervening change is detected.

Keep the game closed for the entire operation. These checks do not lock the
profile against another process or defend against every concurrent filesystem
change. The profile update is in place, not an atomic replacement: an interrupted
write may need recovery from the retained backup. To undo an applied change,
close the game, verify that the reported backup is the intended original file,
and restore its bytes to that same explicit `.mpc` path. A game session may save
later character changes, so do not restore a backup without considering those
changes.

Load the existing character in the normal multiplayer menu. Re-entering or
saving through a model chooser can change the selection again. A selected model
still needs a compatible rig, KEY/PUP animations and materials. Editing an MPC
does not repair any of those or guarantee that a model preview will work.

## Observed scope

The Organic Hybrid model used in the investigation passed the actual Load
Character screen, rotating/animated Edit Character preview, and normal MPC-to-
multiplayer selection in both JK and MotS. The editor was exited with Cancel;
the original edited MPC was then selected. A conditional in-game model query
confirmed the selected model without assigning one, and each MPC remained byte
identical after its run. Tall hair/head geometry sometimes clipped the fixed
preview viewport, but the preview remained animated and selectable.

Those were private Windows-engine runs under Wine64, Xvfb and Mesa llvmpipe
using source revision `4dc57962e46a72662b59d36c30f15eacef6234b5`, not native
Windows GPU or remote-peer tests. Their diagnostic did not force a model or
override lighting. No retail game files or model assets are distributed here.

A separate owned original-engine JK executable did not reach game startup under
the available Wine 10 experimental WOW64 runtime. The stock control with no mod
path failed with the same startup stack-overflow error as the staged mod runs.
That test does not establish either retail model compatibility or a model fault;
the underlying startup cause remains unresolved. Original MotS was not tested.

## Tests and license

```sh
python -B -m unittest -v
```

Tests generate synthetic profiles in temporary directories. They cover exact
byte preservation for JK/MotS-shaped data and both newline forms, malformed
input, preview/apply/backup behavior, linked-path refusal, backup verification
failure, an intervening save, and the CLI's read-only default. No game assets or
real user profiles are required. See [LICENSE](LICENSE) for the MIT license.
