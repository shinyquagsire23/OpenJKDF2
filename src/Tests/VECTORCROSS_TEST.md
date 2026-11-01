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
assertion. This paragraph describes the original extractor-based run; the current build is described below.

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

On a Linux host, install a C compiler, CMake, and `cogapp` in a Python virtual
environment, then run:

```sh
python3 -m venv /tmp/openjk-test-venv
/tmp/openjk-test-venv/bin/pip install cogapp
/tmp/openjk-test-venv/bin/python src/Tests/run_vectorcross_test.py --cc gcc --ubsan
```

The runner delegates to `cmake -S src/Tests/cmake/vectorcross`, builds serially in a temporary
directory, and invokes CTest. Its build and test subprocesses have deadlines.
It does not extract or modify source text. No game assets or submodules are
needed. The normal `globals.h.cog` generator supplies the real declarations.

The target compiles complete `sithCogFunction.c`, `sithCogExec.c`,
`sithCogParse.c`, `rdVector.c`, `stdPlatform.c`, and `jk.c` translation units
with the fixture and production headers. Unused functions are removed by
linker section GC; this is a host regression, not a complete engine link.
The fixture supplies only the host-services and global-symbol-table roots;
symbol lookup, stack conversion, vector math, and the verb are production code.

Ten vector cases cover axes in both orders, signed integer and fractional
vectors, parallel vectors, and zero vectors, each with four literal/symbol
bindings. Result type/components, stack consumption, and the underlying
sentinel give **40 case/binding combinations and 520 assertions**. The test
oracle uses mathematical results, with no dependency on production local
variable names or expression spelling. Historical negative-control evidence
above remains distinct from this normal test command.

A full configured game build also exposes `vectorcross_test` and CTest when
`-DTARGET_BUILD_TESTS=ON` is set on macOS, retaining the existing platform gate. That target links
`sith_engine` and requires its usual dependencies and generated globals. It has not been
configured or linked in the Linux host validation.
This is an additional entry point, not a claim that the small host CI run
has built or initialized the full engine.

## Scope

The host target uses the real desktop QOL float, uncompressed fixed-stack
structures. It compiles the parser TU for its real symbol lookup but does
not parse a COG script or initialize a game. Compressed/dynamic stacks,
overflow behavior, multiplayer and gameplay remain separate acceptance.
The upstream baseline's PushStack overflow-size expression produces a
compiler warning with the real QOL stack size; the path is not exercised
here and its separate element-size fix is outside this regression PR.
