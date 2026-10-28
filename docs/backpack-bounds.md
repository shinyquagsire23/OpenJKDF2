# Backpack bounds regression

Bound creation, pickup, accessors and DSS item state to the physical backpack array.

Run from the repository root with Python 3 and a native GCC/Clang compiler:

```sh
python3 -B src/Tests/run_backpack_test.py --cc gcc --ubsan
```

The standard-library-only runner extracts current production code, compiles a
synthetic fixture with `-Wall -Wextra -Werror`, executes it in a temporary
directory, and prints production input SHA-256 hashes. It verifies those inputs
are unchanged. `source_test_utils.py` is self-contained; no unmerged PR or
fork-only runner is required. No retail data is used.

Both actual `SithItemInfo` declarations are compiled: non-QOL capacity 12 and
QOL capacity 16, verified against independent literal runner expectations.
Coverage includes stored-bin descriptor selection, JK/MotS creator order and
capacity, bounded pickup/getters, outbound count clamping without source
mutation, and rejected inbound counts preserving item fields. The DSS fixture
executes the production item switch cases with typed token stubs; it tests
field order rather than transport encoding. Common thing fields assigned
before the item case are outside this preservation guarantee. This change does
not make the entire state message transactional or add packet-length checking.

This is native host unit coverage with reduced engine stubs. It does not
establish full engine ABI/link compatibility, platform hardware behavior,
joined-peer synchronization or multiplayer runtime acceptance. No new
multiplayer runtime qualification is claimed. The existing platform workflows
remain responsible for normal engine build coverage.

Adapted from andreipemberton's original synthetic fixtures and fixes in
CodaLilitari/OpenJKDF2-MotS-Fixes, source snapshot
`6fa54630a123485d8c7b602c47992613a1f397b5`, preserving current upstream fixes.
Original contribution: `4dc57962e46a72662b59d36c30f15eacef6234b5` by andreipemberton.
