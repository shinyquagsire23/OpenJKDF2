# Dreamcast soundtrack (CDDA)

Drop the Dark Forces II / Jedi Knight soundtrack **Ogg** files here and they'll be
authored onto the Dreamcast disc as **Red Book CD audio (CDDA)** tracks, played by the
GD-ROM in hardware (no CPU-expensive Ogg/Vorbis decoding).

## How to use

1. Copy the **GOG** DF2 soundtrack Oggs into this folder. GOG names them by a flat track
   number that encodes the source CD in the tens digit:
   - **Disk 1:** `Track12.ogg` … `Track18.ogg`  (7 songs)
   - **Disk 2:** `Track22.ogg` … `Track32.ogg`  (11 songs)
2. Build the Dreamcast target normally. If `ffmpeg` is on your `PATH`, each Ogg is
   transcoded to 44.1 kHz / 16-bit stereo WAV and authored as a CDDA track via
   `mkdcdisc --cdda`.

## Track numbering

`mkdcdisc` authors audio tracks (in numeric filename order) **before** the data track,
so the 18 Oggs become CD tracks **1–18** and the game's data track is last. The
Dreamcast `stdMci` maps the GOG numbers onto those CD tracks:

| GOG track | Disk | CD track |
|-----------|------|----------|
| 12–18     | 1    | 1–7      |
| 22–32     | 2    | 8–18     |

(See `stdMci_dcCddaTrack` in `src/Win95/stdMci.c` — adjust it there if your track set
differs.) Files are sorted numerically, so `Track12.ogg` correctly precedes
`Track22.ogg`; keep the set complete so the sequential CD numbering stays aligned.

## Notes

- Requires `ffmpeg` on the build host. Without it (or with no Oggs here), the disc still
  builds — just silent.
- These Oggs are copyrighted game assets and are **not** committed (see `.gitignore`).
- CDDA plays on real hardware; emulator support varies (Flycast can play CDDA from a
  `.cdi` with audio tracks).
