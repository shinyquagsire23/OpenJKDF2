# Team update ordering regression

Resolve MotS class/team mappings before player state mutation or score/model/broadcast work.

Run from the repository root with Python 3 and a native GCC/Clang compiler:

```sh
python3 -B src/Tests/run_team_model_test.py --cc gcc --ubsan
```

The standard-library-only runner extracts current production code, compiles a
synthetic fixture with `-Wall -Wextra -Werror`, executes it in a temporary
directory, and prints production input SHA-256 hashes. It verifies those inputs
are unchanged. `source_test_utils.py` is self-contained; no unmerged PR or
fork-only runner is required. No retail data is used.

The fixture uses upstream's five-row MotS table and helper unchanged and
independent model-name expectations for personalities 0 through 4 and teams 0
through 4. It runs complete extracted MotS/JK saber handlers and the team
handler with actual packet macros. Rejected MotS class mappings preserve all
player descriptors and the thing, with and without a local player thing, and
perform no model, sound, saber, score or broadcast side effects. Valid teams,
missing model loads, disabled team modes, and JK behavior remain covered.
The historical unsafe table-indexing mutants are intentionally omitted.

This is native host unit coverage with reduced engine stubs. It does not
establish full engine ABI/link compatibility, platform hardware behavior,
joined-peer synchronization or multiplayer runtime acceptance. No new
multiplayer runtime qualification is claimed. The existing platform workflows
remain responsible for normal engine build coverage.

Adapted from andreipemberton's original synthetic fixtures and fixes in
CodaLilitari/OpenJKDF2-MotS-Fixes, source snapshot
`6fa54630a123485d8c7b602c47992613a1f397b5`, preserving current upstream fixes.
Original contribution: `1bfba38600e2ccee7bbd7fbe5f6b5d947b7cc78a` by andreipemberton.
