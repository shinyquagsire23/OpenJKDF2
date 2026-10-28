# Background OpenGL render probe

This opt-in diagnostic keeps the desktop OpenGL renderer and its postprocessing
active in a hidden, non-focusable SDL window. It does not use `-headless`, change
drivers, or require a DirectDraw wrapper. Probe launch, input and output behavior
is opt-in. Use a disposable, locally owned game-data/profile copy as the working
directory: ordinary startup still reads and may create game/profile settings.

```text
openjkdf2-64.exe -renderprobe -autostart -sp -episode swprobe -map probe.jkl
  -renderout C:/private-probe/captures -renderwidth 1920 -renderheight 1080
  -renderframes 180 -renderdelayms 4000 -renderbloom 1 -renderssao 1
```

Run this as one command. The output directory must already exist and be an
absolute local ASCII path (spaces are accepted as one quoted OS argument).
UNC/device paths, `..` components and overwrites are rejected. The working
directory must already contain a four-byte `resource/jk_.cd`; the probe does not
open an installer or file picker to obtain missing data. Provide actual valid
game/episode data and normal autostart arguments. `-headless` is incompatible.
The separate `-capture` inspection mode and `OPENJKDF2_CAPTURE_REQUEST` must
also be absent; combining capture modes is rejected before window creation.

Options are case insensitive, support `-` or `/`, and are parsed before SDL
window creation. Defaults: width 1280, height 720, frames 300, delay 3000 ms,
bloom off, SSAO off. Limits: width 640-4096, height 480-2160, frames 3-18000,
delay 0-60000 ms, effect values 0 or 1. Other graphics settings (SSAA, texture
filter, gamma) come from the case's profile; the probe logs their resolved values.
Vsync, fullscreen, high-DPI window mode and software world rasterization are
disabled for the probe only. The world uses the OpenGL renderer.

The delay starts at the first fully rendered gameplay frame. After the delay,
three captures occur at the ceiling of one third, two thirds, and all requested
gameplay frames. `frame-NNNNNN.png` captures the **post-composite back buffer,
including HUD, before `rdFinishFrame` swaps it**. Ordinary screenshots already
read the finished window in this baseline; the probe adds automated sampling
and settings receipts. Each image gets an adjacent
`.png.txt` metadata file with requested and actual drawable/window/scene-FBO
dimensions, effective settings, actual bloom/SSAO draw toggles, software-renderer
state, hidden-window flags, OpenGL vendor, renderer, version and readback error
status. Metadata and PNGs must be checked together.

The run reports `RENDERPROBE_CAPTURE` and finally `RENDERPROBE_COMPLETE` through
inherited stdout, then leaves the normal loop, shuts down and returns exit code
0 after all three captures. Failures report
`RENDERPROBE_FAILED`. Argument errors exit 2, capture errors 3, and a 120-second
in-loop wall-time deadline exits 4. Fatal game-data errors exit 5 without opening
a recovery installer or picker. An early orderly stop exits 6; engine startup
failure exits 7. A process-level timeout is still needed for a
driver or startup hang that prevents engine ticks. Success-path shutdown does
not rewrite the player profile with temporary probe graphics overrides.

The probe avoids console allocation, window focus/raising, text input, mouse
warping/grabbing and game input polling. Unfocused rendering continues. It
captures only its own OpenGL drawable, never the Windows desktop or other apps.
Engine shader, window, and game-data error dialogs are redirected to stderr in
probe mode. OS crash handling is unchanged; use a background process launcher
with redirected streams and a finite timeout.

Argument validation can be tested without starting SDL or a game:

```text
cc -std=c99 -Wall -Wextra -Werror -Isrc tests/render_probe_options.c -o probe-options
./probe-options
```

This feature does not increase 3DO mesh or animation-node budgets, validate a
multiplayer match, or establish that every postprocessing effect is visibly
exercised by every scene. Use a fixed pose/camera and matching case settings,
include scenes that actually trigger the effect, and inspect each output.

The existing postprocessing attribute-location guards are preserved.
Capture metadata keeps pre-readback and readback errors separate so an image
can be saved successfully without concealing earlier rendering diagnostics.
`scene_fbo_extra` is a bitmask: bloom is bit 1, SSAO is bit 2, and both is 3.

Each JKGM albedo upload in probe mode emits a `RENDERPROBE_JKGM_UPLOAD` JSON
receipt naming the material, cel and source path, with decoded dimensions,
texture ID and queried GPU level dimensions/internal format. `uploaded` means
fresh GPU texture storage matches the decoded dimensions; `storage_mismatch`
and `decode_failed` identify failures. These read-only queries do not consume
GL errors. Receipts establish an upload, including precaching; they do not by
themselves prove that a particular mesh used the texture in the captured frame.

The probe does not enable posed capture's dummy-audio path. Isolated probe
audio suppression is a launcher/environment choice. Simulation remains timed
and nondeterministic; frame counts and a fixed view do not freeze simulation.
