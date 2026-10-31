# Explicit 3DO texture modes

Original JK and MotS support affine texture mode 0 and perspective-corrected
mode 1. Both the mesh declaration and each face field matter: the model renderer
selects the lower applicable mode. Setting faces to 1 while leaving the mesh at
0 does not request perspective-corrected rendering.

The inspected TDIR and JKE character meshes use 1. Our earlier exporter used 0
as its default. This small helper prepares a separate candidate by changing only
the one-byte mesh/face mode tokens, across every geoset. Comments, whitespace,
geometry, UVs, normals, hierarchy, lighting and material names stay byte-identical.
It refuses existing output files. It contains no game assets and requires only
Python's standard library.

```sh
python texture_mode.py /exact/path/model.3do
python texture_mode.py /exact/path/model.3do --mode 1
python texture_mode.py /exact/path/model.3do --mode 1 --output /new/path/model.3do
python -B -m unittest -v
```

Without `--output`, the command only prints a report. The output directory must
already exist. Changing back to 0 is supported explicitly. Input must be ASCII
3DO 2.1 with ordinary sequential face tables. This is a field scanner, not a
complete model validator. It rejects missing mode declarations and truncated
face tables, but does not certify geometry, stock animations, renderer behavior,
gameplay or multiplayer compatibility. Keep the game closed when staging files.

This is a historical authoring technique, not a newly discovered engine exploit.
The expected benefit concerns oblique/moving texture mapping. It is not a proven
fix for a uniform color cast or a substitute for well-authored textures.

Sources: [Massassi 3DO specification](https://www.massassi.net/jkspecs/3do.htm),
[JKE author package](https://www.massassi.net/levels/files/3087.shtml), and the inspected
engine's `src/types_enums.h`, `src/Primitives/rdModel3.c` and `src/Engine/rdActive.c`.
