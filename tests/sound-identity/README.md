# Multiplayer sound identity regression

Build and run without game assets or engine dependencies:

```sh
cmake -S tests/sound-identity -B build-sound-tests
cmake --build build-sound-tests --config Release
ctest --test-dir build-sound-tests -C Release --output-on-failure
```

The test includes the production resolver with stub sound loaders. It deliberately
maps the same sound index to the wrong sound on the receiving peer, and checks
filename resolution for global, attached, positional, JK weapon and MotS weapon
message layouts. It also covers missing sounds, empty names, malformed/truncated
extensions, path traversal, static-world indices and the legacy no-sound sentinel.
Legacy messages retain index-based playback; mixed-version games therefore do
not gain the fix for messages sent by an unpatched peer.
