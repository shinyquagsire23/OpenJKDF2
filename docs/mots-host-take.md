# MotS host item lifecycle regression

Honor the MotS no-actor sentinel in the host Take path using the existing item lifecycle.

Run from the repository root with Python 3 and a native GCC/Clang compiler:

```sh
python3 -B src/Tests/run_takeitem_test.py --cc gcc --sanitize
```

The standard-library-only runner extracts current production code, compiles a
synthetic fixture with `-Wall -Wextra -Werror`, executes it in a temporary
directory, and prints production input SHA-256 hashes. It verifies those inputs
are unchanged. `source_test_utils.py` is self-contained; no unmerged PR or
fork-only runner is required. No retail data is used.

Complete production `sithDSSThing_Take` and `sithItem_SetItemTaken` functions
execute with synthetic transport/COG callbacks and deterministic RNG. Coverage
includes host MotS sentinel acknowledgment and native respawn scheduling,
normal actor calls in JK and MotS, JK sentinel rejection, unknown actors,
client forwarding, disabled/destroyed/non-item guards, and the native lifecycle
entry calling back into the host path. ASan and UBSan are enabled with
`--sanitize`; leak detection is disabled because this fixture allocates no
memory and restricted runners may prevent LeakSanitizer process inspection.

This is native host unit coverage with reduced engine stubs. It does not
establish full engine ABI/link compatibility, platform hardware behavior,
joined-peer synchronization or multiplayer runtime acceptance. No new
multiplayer runtime qualification is claimed. The existing platform workflows
remain responsible for normal engine build coverage.

Adapted from andreipemberton's original synthetic fixtures and fixes in
CodaLilitari/OpenJKDF2-MotS-Fixes, source snapshot
`6fa54630a123485d8c7b602c47992613a1f397b5`, preserving current upstream fixes.
Original contribution: `5fa4644d03080fef69d7137eaa2c8f295c47bd63` by andreipemberton.
