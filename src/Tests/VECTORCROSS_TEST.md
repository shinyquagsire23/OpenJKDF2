# COG VectorCross operand order

`VectorCross(a, b)` should return the conventional ordered cross product
`a × b`, as retail Jedi Knight does. The COG stack pops arguments right to
left. The wrapper therefore receives `b` first and `a` second; it must call
`rdVector_Cross3(&out, &inB, &inA)`. The native vector-math helper already has
the conventional operand order and needs no change.

## Current contribution status, 2026-10-28

Upstream `798f930402525a23b94671d85b97b00390342fa0` already contains the
corrected wrapper call. This contribution adds regression coverage and its
CI job without changing the production implementation. On that upstream
source, GCC 13.3 and UBSan pass all 40 case/binding combinations and 520
assertions, and the old operand-order control fails the expected direction
assertion. The source hashes are printed by the runner.

## Historical reproduction, 2026-10-26

SM Sith Lord reported the reversed COG result. The report was
independently checked against the implementations and reproduced in game on
26 October 2026 with the same literal-vector probe under Wine:

| Engine | `VectorCross(X, Y)` | `VectorCross(Y, X)` |
| --- | --- | --- |
| Retail JK 1.01 | `(0, 0, 1)` | `(0, 0, -1)` |
| OpenJKDF2 0.9.9, build `814b684c` | `(0, 0, -1)` | `(0, 0, 1)` |
| Retained pre-fix fork test binary | `(0, 0, -1)` | `(0, 0, 1)` |

Here `X = (1, 0, 0)` and `Y = (0, 1, 0)`. The relevant COG expressions are:

```cog
PrintVector(VectorCross('1 0 0', '0 1 0'));
PrintVector(VectorCross('0 1 0', '1 0 0'));
```

This establishes a COG verb-order discrepancy. It does not establish a cause
for any separate movement or physics issue. Scripts that deliberately
compensated for the reversed result may need adjustment.

## Run the regression

From the repository root, using a native GCC or Clang compiler:

```sh
python3 src/Tests/run_vectorcross_test.py --cc gcc --ubsan
```

Python's standard library is sufficient. No engine build, game assets,
submodules, or third-party Python packages are required. Omit `--ubsan` only
when the compiler lacks UndefinedBehaviorSanitizer. `--source-root PATH` can
select an explicit source checkout or snapshot.

The runner extracts the complete current production bodies of
`sithCogFunction_VectorCross`, `rdVector_Cross3`, `sithCogExec_PopSymbol`,
`sithCogExec_PopVector`, `sithCogExec_PushStack`, and
`sithCogExec_PushVector`, plus the current COG value enum. It compiles those
bodies with the sibling test harness in a temporary directory and removes
the generated files on exit.

Ten vector cases cover standard axes in both orders, signed nontrivial
integer and fractional vectors, parallel vectors, and zero vectors. Each
runs with literal/literal, symbol/literal, literal/symbol, and symbol/symbol
arguments. Checks include result type and components, consumption of two
arguments, exactly one return value, and preservation of an underlying
stack sentinel: **40 case/binding combinations and 520 assertions**.

The runner then restores only the old wrapper operand order and requires
that mutation to fail the `X × Y = +Z` assertion. It also verifies that its
production source inputs remained unchanged and prints their hashes.


## Scope

The test uses actual production wrapper, vector-math and stack-conversion
functions with minimal surrounding structs and a symbol-lookup test
double. It covers desktop float values with uncompressed, fixed stacks.
It does not compile the parser or the complete engine, certify the game
ABI, exercise compressed/dynamic stacks or stack overflow, or establish
multiplayer/gameplay behavior. The pre-fix game probe and the compiled
regression are separate evidence; a rebuilt game's acceptance remains a
separate check.
