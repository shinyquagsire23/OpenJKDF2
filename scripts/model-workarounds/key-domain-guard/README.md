# KEY-domain-aware rigid-detail guard

A small Python CLI that prevents added model detail from occupying animation indices used by the intended Jedi Knight / Mysteries of the Sith KEY corpus. It scans exact KEY files or every literal KEY reference in explicitly selected PUP files, plans reserved invisible leaves, and checks a simple JSON hierarchy summary.

This package contains original code, synthetic fixtures, and a sanitized observation summary. It contains no retail KEY data, TDIR/JKE models, textures, reference art, game executables, profiles, or extracted engine source. Python 3.10 or later is sufficient; there are no external dependencies.

## Why a detail child at index 18 can go wrong

An 18-node model has indices 0 through 17. It is tempting to attach the first extra mesh at index 18. However, the animation corpus can address more indices than that base model exposes. In the inspected JK corpus, four stock KEYs declared 19 joints and included node 18: `kyfall.key`, `kyidle1b.key`, `kyidle2b.key`, and `kysbsabr.key`. The inspected MotS corpus had three such files: `kyfall.key`, `kyidle1b.key`, and `kysbsabr.key`.

A neutral detail child placed at that index can receive an unintended local animation transform. A model can load successfully and still articulate incorrectly. This guard computes the reservation from the supplied animation corpus instead of assuming that detail always starts at 18 or 19.

The conservative rule is:

```text
first_detail_index = max(base_node_count, largest_declared_KEY_JOINTS)
```

Every actual `NODE` block is also collected and checked against the declared allocation. Sparse KEYs reserve the whole declared domain: `JOINTS 32` with only nodes 0 and 31 still requires 32 slots. An out-of-allocation node is rejected rather than being accepted as a useful extension.

Added slots between the base hierarchy and the first safe detail index must have no mesh and no children. A detail node has a neutral local transform and attaches directly to its intended base animation node. Base indices, joint meanings, weapon roles, and existing animation semantics remain an authoring responsibility.

## Run the synthetic demonstration

Run these commands from this directory. They work without any installed game.

```console
python -B key_domain_guard.py examples/keys/synthetic-base.key examples/keys/synthetic-extra-slot.key --base-nodes 18 --detail-chunks 1
```

The plan reserves invisible slot 18 and puts the one detail node at 19. The resulting hierarchy has 20 nodes. There is deliberately no default base-node count; pass the count of the base rig being extended.

Scan the same files through a synthetic PUP and inspect the naive hierarchy:

```console
python -B key_domain_guard.py --pup examples/synthetic.pup --key-dir examples/keys --base-nodes 18 --detail-chunks 1 --hierarchy examples/naive-18.json
```

Expected exit status: **1**, with errors identifying a detail mesh occupying required reserved slot 18. Now inspect the repaired hierarchy:

```console
python -B key_domain_guard.py --pup examples/synthetic.pup --key-dir examples/keys --base-nodes 18 --detail-chunks 1 --hierarchy examples/fixed-19.json
```

Expected exit status: **0**. The fixed fixture makes index 18 an invisible leaf and places the detail at index 19 under base node 15. These are synthetic topology examples, not character geometry or game-ready animation files. The fixture names and node positions do not encode retail assets.

The sparse case demonstrates why 19 is not another universal constant:

```console
python -B key_domain_guard.py examples/keys/synthetic-sparse.key --base-nodes 18 --detail-chunks 1
python -B -m unittest -v
```

The sparse case starts detail at 32. The test suite covers naive/fixed reservation, sparse high slots, the 64-slot boundary, malformed/negative index declarations, duplicates, binary inputs, noninteger counts, reserved descendants, bad parents, cycles, neutral-transform declarations, mesh limits, PUP resolution, path traversal, and input-overwrite protection.

## Use your own files

Supply only the KEYs intended for the particular model and gameplay configuration. Exact positional KEY paths may be combined with one or more `--pup` arguments and one explicit `--key-dir`. A PUP scan collects literal references across all its modes, including modes with `BasedOn` declarations. Repeated references are deduplicated. Filenames are resolved case-insensitively within that flat directory; absent, ambiguous, unsupported, or escaping paths are rejected. The program does not recursively search other game directories.

PUP scanning does **not** discover KEYs selected by COG scripts, other game code, runtime substitutions, or dynamically built filenames. Add those KEY files explicitly. A partial corpus gives only a partial guarantee. A new weapon, puppet, or script can invalidate an earlier reservation, so rerun the guard when the reachable animations change.

`--detail-chunks` specifies the proposed number of new detail nodes. `--hierarchy` independently checks a concrete export summary; its node count is reported, and need not equal a separately requested hypothetical plan. `--output report.json` writes a JSON report atomically. It refuses to replace an input KEY, PUP, or hierarchy file, including aliases. Reports use basename labels and hashes rather than absolute input paths. They can still disclose filenames; review a report before publishing it.

Exit statuses are 0 for a valid plan/summary, 1 for hierarchy or mesh constraint failures, and 2 for malformed input or command-line errors.

## Hierarchy-summary format

See [fixed-19.json](examples/fixed-19.json) for a complete example. The schema is intentionally small:

- `schema_version` is integer 1.
- `nodes` is an ordered list with contiguous integer `index` values starting at 0. Each node has `role` (`base`, `reserved`, or `detail`), `parent` (index, or null only for the root), and `mesh` (a mesh ID or null). Detail nodes also declare `neutral_transform: true`.
- `meshes` lists unique IDs, `primitive: "triangles"`, and integer `vertex_count`, `uv_count`, and `face_count` values measured by the exporter.

The guard permits at most **64 hierarchy slots**, **512 vertices per mesh**, **768 UV vertices per mesh**, and **512 triangle faces per mesh**. These caps match the inspected OpenJKDF2 source configuration and loader checks: [64 puppet nodes](https://github.com/shinyquagsire23/OpenJKDF2/blob/0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac/src/engine_config.h), [model loader limits](https://github.com/shinyquagsire23/OpenJKDF2/blob/0dbd1ea8bb2211c158f6af928b5e4fb14dfa0dac/src/Primitives/rdModel3.c). They are not a promise of compatibility with every build or original retail executable. Shred18's historical working budget of 500 triangulated faces per mesh remains a reasonable more conservative authoring target.

The JSON check trusts exporter metadata. It does not parse 3DO geometry, recompute triangle counts, inspect pivots or matrices, prove that a declared neutral transform is actually neutral, or inspect the rendered result. The KEY scanner validates index-footprint declarations; it is not a complete parser for marker tables, entry values, or animation timing. Passing this tool does not certify an arbitrary KEY or 3DO as safe to load.

## Evidence, scope, and credit

[observed-comparison.json](examples/observed-comparison.json) preserves a content-free summary of the local motivating experiment. Two earlier model builds loaded and advanced through four stock KEYs in a headless MP host, yet their neutral detail transforms differed from the intended parent by approximately 1.93 and 1.92 in the measured matrix components. Revised builds that reserved the animation domain measured 0.0 error for those observed children under the same four-key probe. The comparison reports finite advancing pose samples and the actual numerical gate, not a render-quality verdict. Geometry segmentation also changed between those evolving builds, so it is not a one-variable performance benchmark. The synthetic fixtures isolate the index-reservation rule in this standalone package.

This is a **newly implemented guard and reproducible code example from this project**, not a claim that no one has ever used this technique. Model segmentation, extra hierarchy nodes, custom KEY rigs, and direct multiplayer profile selection have substantial prior art. Credit Shred18 and the TDIR team for [The Destruction Is Real](https://www.massassi.net/levels/files/2727.shtml), Shred18 for [Jedi Knight Enhanced](https://www.massassi.net/levels/files/3087.shtml), and the [historical triangulated-mesh discussion](https://forums.massassi.net/Editing_Forums/Jedi_Knight_and_Mysteries_of_the_Sith_Editing_Forum/thread_34814_page_1.html). OpenJKDF2 supplies the engine implementation being studied.

The guard does not implement a profile bypass. Selecting a model directly can avoid a preview path, but does not fix animation-index collisions. This package makes no claim of original retail JK compatibility, rendered photorealism, profile-picker compatibility, complete TC compatibility, or interoperability with a remote multiplayer peer.
