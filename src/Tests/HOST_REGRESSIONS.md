# Pixel unpack regression

This PR contains one CMake/CTest regression. It does not need a separate
registry, evidence collector, or tests of that orchestration. CI is path
filtered and its console/CTest output is the validation record.

On Linux with a C++17 compiler, CMake, EGL/OpenGL development headers and a
Mesa software driver:

```sh
cmake -S src/Tests/cmake/pixel-unpack -B /tmp/openjk-pixel-unpack
cmake --build /tmp/openjk-pixel-unpack --parallel 1
ctest --test-dir /tmp/openjk-pixel-unpack --output-on-failure -V
```

CTest has a 30-second deadline and uses a private surfaceless EGL context;
there is no game window, retail asset or full engine initialization.

The fixture compiles the production `jkgm_texture_upload.cpp`, whose upload
function is also called for albedo, emissive and displacement in `jkgm.cpp`.
It checks exact readback for representative RGB/RGBA/BGR/BGRA rows, including
1254-pixel RGB rows that are not aligned to four bytes. Removing the guard
from this compiled production function fails the byte oracle. A padded
input allocation keeps that negative control within its supplied buffer.

Separate guard-state checks cover incoming alignments 1, 2, 4 and 8 with
nonzero row length and skip values, including scope exit. The production
upload must restore all unpack fields and leave pack alignment unchanged.
An unguarded GL control demonstrates the original row mismatch.

The shared upload function normalizes state only around each actual upload;
a PNG load failure now leaves caller state untouched without requiring a
long-lived guard across decoding. This is a behavior-preserving refactor
of upload state handling, not a new image decoder.

This test covers the shared compiled upload boundary. It does not execute
the full material replacement/cache path, PNG error handling, driver matrix,
or gameplay. The four representative uploads replace the earlier 128-case
matrix; the four incoming-alignment restoration checks remain meaningful.
The normal platform build uses its existing SDL/GL declarations. The host
build uses desktop GL declarations to avoid SDL initialization/dependencies;
the compiled upload implementation is identical.
