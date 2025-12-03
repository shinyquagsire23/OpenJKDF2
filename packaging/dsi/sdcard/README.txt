# OpenJKDF2 DSi Readme

Place assets in sdcard:/jk1/ and sdcard:/mots/ as follows:

```
sdcard:/mots
├── episode
│   ├── cutscenes.goo
│   ├── JKM_KFY.goo
│   ├── JKM_MP.goo
│   ├── JKM_SABER.goo
│   ├── JKM.goo
└── resource
    ├── jk_.cd
    ├── Jkmres.goo
    └── JKMsndLO.goo
```

```
sdcard:/jk1
├── episode
│   ├── JK1.gob
│   ├── JK1CTF.gob
│   └── JK1MP.gob
└── resource
    ├── jk_.cd
    ├── Res1hi.gob
    └── Res2.gob
```

## Other notes:
 - This game likely will not work in most emulators, currently.
 - Expect lots of crashes in MoTS for DSi.
 - Expect some rendering differences between DSi and other platforms.
 - Expect most mods to not work, and then be pleasantly surprised if they do.
 - Cutscenes are currently not supported.
 - Music is currently not supported.
 - Sparse (non-GOB) assets are currently not supported for Episodes, for optimization reasons.
 - Nintendo DS and Nitro devkits are currently NOT supported, even with a RAM expansion.
  - 3DS units WILL utilize the extra 16MiB of RAM available to them.
 - The HUD GUI is currently not implemented, however items and force powers can still be used.
 - Savegames are NOT cross-compatible between DSi and other platforms, but WILL be made compatible in a future release, which WILL break your saves.

# Controls
 - A button = Fire
 - B button = Crouch
 - X button = Activate
 - Y button = Jump
 - L button = Inventory Next
 - R button = Weapon next
 - Start = Escape Menu
 - Select = Use last selected force power/item
 - D-pad down = Force next
 - D-pad left/right = Turn
 - D-pad up = Forward
 - Touch screen = Free Look
 - Hold Select and then press X button to Noclip