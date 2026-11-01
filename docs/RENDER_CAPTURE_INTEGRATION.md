# Capture integration and build boundaries

The hidden-render-capture topic depends on named-character autostart. The latter
owns `-character`, profile fallback, host rank validation and the existing MPC
reader connection; this topic supplies capture launch restrictions and rendering.

`CMakeLists.txt` discovers `src/Main/stdCapture.c` through the existing
`src/*/*.c` source glob and removes `src/Tests/*.c` from engine sources. No new
CMake registration is required. Camera/world metadata uses the SDL renderer and
QOL feature gates; non-SDL builds retain inert camera/default metadata helpers.
The probe requires desktop modern OpenGL and PNG support (`TARGET_CAN_JKGM`).
Posed capture rejects GL11, WASM, Android and iOS backends before window creation.

The ordinary composed screenshot path is unchanged. Probe-specific upload
observations report albedo decode/storage, and do not prove on-screen mesh use.
This topic does not add lighting changes, replacement-selection changes, or an
activation-slot policy. Both capture modes use timed nondeterministic simulation.
Their cooperative deadlines cannot interrupt blocked startup or driver calls;
launchers must enforce an outer process deadline. Posed capture suppresses audio;
probe-only audio suppression remains an environment/launcher decision.

See [probe usage](render-probe.md) and [posed capture usage](HIDDEN_RENDERED_CAPTURE.md).
The Windows PowerShell launcher accepts explicit local paths and distributes no
retail inputs. It samples only windows owned by its child process; intermittent
sampling cannot rule out every transient window.
