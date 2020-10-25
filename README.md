# OpenJKDF2

![in game](https://i.imgur.com/GH5Hgkx.png)

## Compiling

`qmake openjkdf2.pro && make && ./openjkdf2 JK.EXE`

## Notes

The game currently runs (almost) perfectly with the 8bpp software renderer or DirectX with 3D acceleration.

Filenames are case-sensitive to whatever the game wants. Notable files are `resource/jk_.cd`, `resource/Res1hi.gob`, `resource/Res2.gob`, `resource/video/01-02a.smk`, `episode/JK1.gob`, `episode/JK1CTF.gob`, and `JK1MP.gob` in order to get to the menu.

For the JKDF2 decompilation, see `df2_reimpl/`.

### Droidworks

Star Wars: Droid Works can be run using the `-forceswrend -nojk` options. Filenames are also case sensitive: `dwCD.GOB`, `dwHD.GOB`, `dwMin.GOB`, `dwStream.GOB`, plus some stuff in Movie.
