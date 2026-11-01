# Compatible team update regression

This is test-only coverage of existing upstream behavior. Production `jkDSS.c`
is unchanged from the upstream base; no team assignment is reordered.

```sh
python3 -B src/Tests/run_team_model_test.py --cc gcc --ubsan
```

The runner extracts upstream's five-row model table, bounded helper, complete
JK/MotS saber handlers and team handler, using actual packet macros. Literal
expectations cover valid models and colors. An out-of-range personality returns
no team model; an otherwise valid active-team request still assigns the team
and synchronizes scores, with or without a local player thing, without loading
or broadcasting a replacement model. Invalid player/team requests remain
rejected; disabled team modes, model-load failures and JK controls are retained.
A lookup failure and a rejected team request are different outcomes.

The compatible-behavior test fails against the previously proposed early
rejection, then passes against the unchanged upstream function. No unsafe
historical table-index mutant is executed.
The fixture uses reduced structs and controlled asset/transport callbacks. It
is not a full engine translation-unit/ABI build, renderer test, retail session
or joined-peer multiplayer qualification. Temporary files stay outside the
checkout and production input hashes are checked before and after execution.

Adapted from andreipemberton's original synthetic coverage, contribution
`1bfba38600e2ccee7bbd7fbe5f6b5d947b7cc78a`, preserved in fork snapshot
`6fa54630a123485d8c7b602c47992613a1f397b5`; compatibility correction by Coda Lilitari.
