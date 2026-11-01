# Game clocks inside fixed physics steps

In the normal fixed-step update, `sithMain` temporarily rewinds and advances
`sithTime_g_msecGameTime`. Previously it left `sithTime_g_secGameTime` at the
outer-frame value. Events, pulses, sleeping COGs and other substep consumers could
therefore observe different times through `GetGameTime` and `GetFlexGameTime`.
Several pulses within one rendered frame could read exactly the same flex time.

The correction saves both outer clock values, derives seconds from the existing
integer game clock before every substep's first consumer, and restores the saved
values after the loop. When at least one step is scheduled, both clocks move to
the first simulated timestamp **before** the single control update. Input-created
weapon and inventory deadlines then use the same timeline as their consumers.
Control still receives the original outer-frame delta and runs once per frame.
When no step is scheduled, controls retain the original outer timestamp.

The conversion matches `sithTime_SetFrameTime` and `sithTime_SetGameTime`. It
introduces no second accumulator and preserves the existing integer step
duration, rounding, rollover, number of steps and consumer call order. The
unstepped branch and special submode-8 branch are unchanged. Preserving those
mechanics does not preserve all timing outcomes: the changed seconds values
affect decisions made by actual game consumers.

For example, a 33 ms outer frame starting at 1000 ms runs five 150 Hz steps.
Their existing integer timestamps are 1000, 1006, 1012, 1018 and 1024 ms. Seconds
now follow those timestamps instead of remaining at 1.033 for every step. Both
clocks return to their outer-frame values after the loop.

## Deliberate timing changes and pending acceptance

This revision is a proposal pending native gameplay acceptance. It must not be
described as retail timing parity or as a clock-getter-only change.

An already-active weapon or inventory repeat rearms from current seconds plus
its interval. It can therefore fire several times in one long rendered frame.
The normal turret instinct has a similar seconds gate. AI actor/instinct
`nextUpdate` scheduling remains integer-based; not every AI timer changes.

Moving controls to the first simulated timestamp also changes new actions. A
new press may catch up during that frame; a mount deadline expiring later in the
same frame is not yet eligible when controls run. These are explicit tradeoffs
of using one simulated timeline, not concealed side effects. With controls left
at frame-end, a bin activated there and cancelled in the first earlier substep
can return a negative elapsed duration. The revised ordering removes that
synthetic cross-phase case without clamping or rewriting the inventory API.

The actual-type fixture measures the following cases in both time configurations:

| Controlled case | Previous PR: outer controls / stepped seconds | This revision |
|---|---:|---:|
| Held repeat, 100 ms frame, 25 ms interval | 3 weapon / 3 bin / 3 turret calls | 3 / 3 / 3 |
| New activation, same frame/interval | 1 weapon / 1 bin | 3 / 3 |
| SetFireWait during controls, same frame/interval | 0 weapon calls | 2 |
| Mount deadline 1.05 s within a 1.0–1.1 s frame | Press accepted | Press deferred |
| Activate bin in controls, cancel in first substep | About -0.1 s elapsed | 0 s elapsed |
| Three-ms frame scheduling zero steps | One control activation at 1.003 s | Identical observations |

The pre-PR incoherent-seconds control produces one held-repeat call rather than
three in the 100 ms case, and one rather than five in a 500 ms / 100 ms interval
case. Those counts concern controlled messages and function calls, not observed
projectiles or damage in a game level. The cancellation case is deliberately
constructed; it is not a demonstrated stock-script or mod bug.

Native acceptance still needs held fire, new press/release, weapon mounting,
bin activation/cancellation, and turret behavior at normal and deliberately low
frame rates, with content/configuration identified. Multiplayer, save/load and
retail comparisons remain separate acceptance work. Earlier clock-getter-only
captures do not qualify these additional control-timestamp semantics.

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
python3 -B src/Tests/run_clock_consumers_test.py --cc gcc --sanitize
```

The runner compiles the complete normal stepped/unstepped conditional from
`sithMain`, all of `sithTime.c`, the actual COG clock getters,
`sithCog_ProcessCog`, and `sithEvent_Process`. Other game systems and the COG VM
are observation seams. The tests check consumer-visible clock pairs, literal
pulse/timer/sleep/event times, consecutive frames, no-step frames, unstepped
single-player, both multiplayer step rates, slow motion, pause/resume, time
reset, unsigned wrap and late-session float precision. Both millisecond and
microsecond time configurations are compiled.

The consumer runner includes the actual type headers and compiles complete
production time, normal update, weapon repeat/activation, inventory
activation/deactivation/repeat, AI scheduler and turret instinct bodies. It also
executes the actual mount-wait guard. It compares this revision with both the
prior outer-control policy and the older incoherent-seconds policy. The normal
branch's source still has a bounded extraction seam; full translation units are
not linked. Aim math, input polling, world/player iteration, COG dispatch and
projectile creation are controlled callbacks. Thus real structure layouts are
checked, but the VM, renderer, content and network are not executed.

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

A further bounded check identifies the normal-frame control call at `0x4c4ed3`
to the handler loop at `0x4d6f80`, after time advance at `0x4c4e6e` and before
thing update at `0x4c4ee8`. Retail processes those phases at one frame timestamp;
there is no equivalent fixed-substep rewind here. That supports coherent
consumer clocks but does not choose start-versus-end placement for OpenJKDF2's
stepped simulation. The new placement is an explicit engine policy proposal.

This supports clock coherence; it does not establish bitwise equivalence to
retail. Retail uses a float32 `0.001` multiplier and an x87 integer conversion,
while the existing OpenJKDF2 conversion casts the integer to float32 before a
double literal multiply. The patch follows OpenJKDF2's existing conversion,
preserving its current precision behavior. No executable or disassembly is
needed by the public regression test.
