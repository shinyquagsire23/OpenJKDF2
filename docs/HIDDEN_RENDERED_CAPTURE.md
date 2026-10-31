# Hidden rendered inspection capture

This opt-in inspection feature keeps a hidden OpenGL renderer active and writes
a posed frame with world metadata. It uses ordinary timed simulation. Full game
and Windows runtime acceptance must be performed with the exact build under test.

## Invocation and resource scope

Set `OPENJKDF2_CAPTURE_REQUEST` to an absolute request-file path and invoke:

```text
openjkdf2-64.exe -capture -autostart -sp -motsCompat -noHUD -episode JKM -map s1l1_rebelbase.jkl
```

The request is at most 4096 bytes, with LF line endings and this format:

```text
sed-engine-capture-v1
960 640 80 3 30000
-5.19905 5.10426 3.003014 0 180 0 98.0306723659185
C:\explicit\new-session\rebelbase.ppm
```

Line two supplies width, height, sector, capture frame, and timeout milliseconds.
Line three supplies position XYZ, pitch/yaw/roll in degrees, and **horizontal**
FOV. The last line is an absolute new `.ppm` output path. Limits are 64–2048 per
dimension, at most 2,097,152 pixels, frame 1–120, timeout 1–60 seconds, and FOV
20–140 degrees. Numbers must be finite and bounded. Episode/map arguments accept
only bounded ASCII names, with no directory traversal. Capture permits only its
explicitly reviewed switches. The `-capture` flag without its request is rejected
before SDL startup.

Use an explicitly staged, writable working directory containing
`.openjkdf2-capture-session` and `resource/jk_.cd`. Capture bypasses installation
discovery and uses that session's ordinary resources and profile. Do not put the
marker in an existing personal game installation. Profile creation and other
ordinary runtime writes stay in the staged session.

[Test-RebelBaseHiddenCapture.ps1](../src/Tests/Test-RebelBaseHiddenCapture.ps1)
is a reproducible launcher for the owned original MotS Rebel Base check. It
requires explicit baseline, engine-directory and new output-directory paths;
copies four exact resource inputs and the engine dependencies; verifies staged
hashes; launches hidden with redirected streams; and imposes an independent
45-second child-process deadline. It rechecks original and staged resource hashes
afterward. It neither modifies the baseline nor discovers other installations.

## Desktop and audio behavior

Capture keeps a GL context and creates hidden, nonfocusable windows. A shared
SDL policy applies to initial creation and recreation, error dialogs, raise,
fullscreen, relative mouse mode, mouse warps, text input, cursor changes, and URL
opens. Captures ignore keyboard/mouse/controller input. The Windows console and
crash dialog paths are suppressed, the updater check is skipped, and installer
entry points fail before opening native UI. Unexpected in-engine confirmation or
error dialogs terminate the capture with a diagnostic. The singleplayer briefing
acknowledgment wait is skipped for capture, render probe and ordinary headless mode.

OpenAL uses the existing headless dummy/no-device path throughout capture. MCI
music startup/play also returns before opening a backend. The render window stays
alive; this does not reuse `Main_bHeadless`, which would destroy the GL context.

The engine deadline is cooperative. It cannot interrupt a blocked driver, load,
or script between event pumps. An outer process timeout remains mandatory.

## Camera, output and evidence

The capture applies the declared position, orientation, sector and FOV after the
ordinary camera update, before scene drawing. Only frames with that explicit
camera application count. Readback occurs on the render thread after composition
and before buffer swap. The first-person weapon and HUD are disabled. Pixel-pack
state and dimensions are checked before writing.

The image is a lossless binary PPM (RGB8, top row first) and the sidecar is
`<image>.json`. Both use exclusive file creation, refuse existing paths and are
removed on ordinary write failures. A process crash can leave incomplete files;
acceptance requires exit zero, a valid sidecar and exact PPM header/data length.
The launcher verifies these conditions. It separately records binary, request
and resource hashes; the engine sidecar explicitly says that the engine itself
did not verify resource hashes.

The engine uses ordinary timed simulation and the staged profile's visual
settings. Camera pose alone does not freeze AI, animation, COGs, light pulses or
runtime RNG. Near/far clipping, pixel-center conventions and renderer effects
also remain distinct from the editor. The engine matrix's forward direction is
local +Y: pitch 0/yaw 180/roll 0 looks along world -Y. SED's camera FOV is vertical,
so its 75-degree view at 960×640 corresponds nominally to 98.0306723659185 degrees
horizontal in this engine request.

## Focused validation and runtime acceptance

`ASAN_OPTIONS=detect_leaks=0 python src/Tests/run_capture_test.py --output NEW_DIR`
executes the actual parser/writer and UI policy with synthetic fixtures under
AddressSanitizer and UndefinedBehaviorSanitizer. The three groups cover request
limits, frame gating, orientation, exclusive output creation, SP/MP launch
restrictions and ordinary/probe/capture desktop policy. No SDL window is linked.
Disable leak detection only where the host cannot run LeakSanitizer.

A Windows build and a launch with caller-owned game data remain required to
qualify hidden-window behavior, redirected streams, audio suppression, camera
placement, three PNG probe frames, and PPM/world-state receipts. Historical fork
runs do not qualify this adapted revision. No game assets are distributed here.

## Multiplayer and actual character selection

The capture parser also accepts exactly one explicit `-mp` mode instead of
`-sp`, plus an optional staged `-path startup` directory and `-character Reviewed`.
The path is a single ASCII directory name with no separators or dots. The
character is an existing MPC basename: ASCII letters, digits, `_` or `-`, at
most 31 characters. It is resolved inside the selected profile's ordinary
`player/<profile>/<character>.mpc` directory. Capture still requires the explicit
session marker and uses no installation discovery.

```text
openjkdf2-64.exe -capture -autostart -mp -motsCompat -noHUD -episode JKM_MP -map k1.jkl -path startup -character Reviewed
```

The `-character` option is also available to ordinary multiplayer autostart.
Without it, the existing Kyle default remains. SP, non-autostart, repeated and
invalid character arguments fail with exit code 6. Selection loads the native
MPC descriptor and bins, checks rank against the host's allowed range, and passes
that descriptor through normal multiplayer creation. A failed read exits rather
than falling back to the menu. This does not implement a replacement inventory
system or bypass character eligibility.

The image sidecar now records the actual game mode, world, local player's loaded
model/soundclass, model hierarchy-node count and requested host model. Soundclass
names are nullable in builds without debug struct names. The actual model may
differ from the request if ordinary game rules intentionally select a uniform;
consumers must check both fields. Paths and names in the JSON are escaped.

The inherited MPC reader and game rules remain in use. These contract tests do
not qualify arbitrary character files, full-body visibility, animation, audible
sound, multiplayer peer agreement, or retail/editor pixel parity.
