# Rejected backpack-count item flags

The receiver already checks backpack count bounds. This correction stages the
incoming item flags until that existing check succeeds, so a rejected count
does not change the item's flags. It changes no creation cap, pickup/getter
behavior, outbound clamp, structure layout or valid packet field order.

```sh
python3 -B src/Tests/run_backpack_test.py --cc gcc --ubsan --negative-controls
```

The test compiles the complete production `types.h` (including `SithThing` and
`SithItemInfo`) for both QOL and non-QOL, with the supported null-sound header
configuration. It executes the actual receiver item case using bounded byte-read
seams. Negative, zero, valid boundary and excessive counts check exact item
flags/state, valid contents and non-backpack updates. Both layouts reject the
safe early-flags control at the intended assertion. The unmodified upstream
receiver also fails that assertion; no legacy over-capacity creator is run.

QOL declares 16 entries, while non-QOL retains the original 12-entry layout.
This test does not change or endorse the separate original-layout creator's
16-write behavior. Any non-QOL safety/fidelity redesign needs its own storage
and compatibility decision. Injected invalid local counts are not presented
as a demonstrated normal-build creator/getter defect.

The fixture covers the item case, not the entire message. Earlier common thing
fields can already have changed, and packet-length validation, transport,
endian portability, full-engine linking and joined-peer runtime are outside
this evidence. No assets or game session are used.

Adapted from andreipemberton's backpack regression contribution
`4dc57962e46a72662b59d36c30f15eacef6234b5`, fork snapshot
`6fa54630a123485d8c7b602c47992613a1f397b5`; narrowed correction by Coda Lilitari.
