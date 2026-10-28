# Game clocks inside fixed physics steps

In the normal fixed-step update, `sithMain` temporarily rewinds and advances
`sithTime_g_msecGameTime`. Previously it left `sithTime_g_secGameTime` at the
outer-frame value. Events, pulses, sleeping COGs and other substep consumers could
therefore observe different times through `GetGameTime` and `GetFlexGameTime`.
Several pulses within one rendered frame could read exactly the same flex time.

The correction saves the outer seconds value, derives seconds from the existing
integer game clock before every substep's first consumer, and restores the saved
seconds after the loop. The conversion matches `sithTime_SetFrameTime` and
`sithTime_SetGameTime`. It introduces no second accumulator and preserves the
existing integer step duration, rounding, rollover, event ordering and frame
count. The unstepped branch and special submode-8 branch are unchanged.

For example, a 33 ms outer frame starting at 1000 ms runs five 150 Hz steps.
Their existing integer timestamps are 1000, 1006, 1012, 1018 and 1024 ms. Seconds
now follow those timestamps instead of remaining at 1.033 for every step. Both
clocks return to their outer-frame values after the loop.

This intentionally retains integer truncation to 6 ms at 150 Hz. It also retains
float32 clock precision: sufficiently long sessions can still have equal
successive floating-point timestamps. Neither behavior is solved by accumulating
a different floating-point clock. Slow motion is applied by the existing time
update before scheduling; the correction applies the same conversion to those
resulting integer timestamps. Multiplayer uses the same fix because it already
uses the stepped integer clock, including its configured 150 Hz or 50 Hz branch.
Mixed-version multiplayer compatibility and gameplay effects still need runtime
validation; the test does not claim them.

## Focused regression

Run from the source root:

```sh
python3 -B src/Tests/run_stepped_clock_test.py --cc gcc --sanitize --negative-controls
```

The runner compiles the complete normal stepped/unstepped conditional from
`sithMain`, all of `sithTime.c`, the actual COG clock getters,
`sithCog_ProcessCog`, and `sithEvent_Process`. Other game systems and the COG VM
are observation seams. The tests check consumer-visible clock pairs, literal
pulse/timer/sleep/event times, consecutive frames, no-step frames, unstepped
single-player, both multiplayer step rates, slow motion, pause/resume, time
reset, unsigned wrap and late-session float precision. Both millisecond and
microsecond time configurations are compiled.

The test also runs 2,560 frames with irregular, quantized clock intervals across
fixed and unstepped single-player, both multiplayer rates, and slow motion. It
checks COG-to-COG integer time ordering and the carried-remainder bound. At an
unchanged 150 Hz rate, round-to-nearest keeps the remainder within approximately
plus or minus 3.333 ms. A claimed 4 ms frame with a 6 ms carried remainder is not
reachable from that scheduler's preceding frames. A real 3 ms zero-step frame
followed by 4 ms executes one step. This invariant assumes an unchanged timestep;
it is not a proof about arbitrary external clock or tickrate changes.

Negative controls independently omit the substep seconds assignment, omit the
outer seconds restoration, and use milliseconds as seconds. They must fail the
same behavioral assertions. The fixture does not execute collision geometry,
the full COG VM, rendering or network transport, and does not establish the
cause or resolution of a reported mod's fatal movement.

## Original-executable comparison

A private static audit of an owned JK 1.01 executable (SHA256
`4509cd690634ba20e132bd16e713f91e144b17e2beaaad5e678f1ddb189b51d9`) traced the
registered time getters to integer and float globals at `0x836c5c` and
`0x836c60`. Time advance at `0x4dd8d0`, explicit frame-time update at `0x4dd9f0`,
and game-time reset at `0x4ddac0` all derive seconds from integer game time.
The update at `0x4c4df0` calls time advance before events and COG processing.
Every retained disassembly byte was checked against that executable.

This supports clock coherence; it does not establish bitwise equivalence to
retail. Retail uses a float32 `0.001` multiplier and an x87 integer conversion,
while the existing OpenJKDF2 conversion casts the integer to float32 before a
double literal multiply. The patch follows OpenJKDF2's existing conversion,
preserving its current precision behavior. No executable or disassembly is
needed by the public regression test.
