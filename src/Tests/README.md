# Engine subsystem tests

The resource and COG lifecycle tests link `sith_engine`, using the same headers,
objects and platform libraries as the game. They generate small fixtures in
separate build directories and need no retail assets, display or network peer.
There is no test-specific Python runner or extraction of production functions.

On a configured Linux or macOS development machine:

```sh
TARGET_BUILD_TESTS=1 cmake -S . -B /tmp/openjkdf2-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/openjkdf2-tests --target resource_test cog_test --parallel 2
ctest --test-dir /tmp/openjkdf2-tests --output-on-failure --no-tests=error
```

- `resource_lifecycle` loads generated BM files through the normal file and
  surface services, checks pixel rows, palette, transparency and frame metadata,
  writes and reloads them, and tears them down. It also loads MATs with several
  cels and mipmaps, checks texinfo bindings and packed pixel rows at different
  depths and widths, and rejects malformed layout/truncated pixel data through
  the public loader. Both success and failure paths use the real cleanup.
- `cog_lifecycle` parses generated COG files with the production compiler, binds
  them through the public thing-argument parser, executes message bytecode, and
  checks script-cache reuse with independent instance symbols and JK/MotS class
  policy. It frees the world and shuts down and restarts the COG subsystem in
  the same process across the JK/MotS cases. It also covers disabled/paused
  scripts, missing handlers, missing files and capacity exhaustion. Client pulse
  cases avoid sending a network message; this is not a remote-peer multiplayer
  test. Full-game restart or mode-switch behavior is not tested.

The resource test uses the existing headless path to bypass GPU uploads. It
checks bitmap conversion metadata and colorkey behavior, but does not claim
converted SDL surface pixels: the SDL VBuffer conversion routine currently
returns its input surface. Rendering, retail equivalence and campaign behavior
are outside these subsystem tests. The resource suite requires the normal
desktop immediate-loading configuration, not the optional deferred/LRU mode.
The existing macOS rasterizer targets and
their platform restrictions remain unchanged. Fixed-point builds are excluded.
