# DF2 Reimplementation

This directory contains a function-by-function reimplementation of DF2 in C. Files are organized as closely to the original game as possible, based on symbols from the Grim Fandango Remaster Android/Linux/macOS port. It also contains the original versions of `byacc` and `flex` for COG script parsing.

## Methodology
The bulk of research and documentation occurs in IDA. Every function has been identified to a file prefix (ie `stdHashTable_`) with a corresponding .c/.h file. RenderDroid (`rd*`) and LEC stdlib (`std*`) functions are 90% canonically named, based on symbols from Grim Fandango Remastered.

Reverse engineering is a parallel effort between structure documentation and function identification. Once structures are sufficiently documented, Hex-Rays can be used for decompilation. While most Hex-Rays output works outright, many loops and structures require manual intervention. Output is generally cleaned and tidied to remove redunant stack variables or too-deep nesting. `sizeof` and obvious inlining and macros should also be adjusted as appropriate.

Engine variables and yet-to-be-decompiled functions are referenced using `define` macros and static function pointers, respectively. Once a file is decompiled enough that an engine variable is no longer referenced by non-decompiled code, the variables can be declared in their respective C files. For decompiled functions which are only referenced by non-decompiled functions, a `hook_function` call is added in `main.c` to redirect code execution to `df2_reimpl.dll` from `JK.EXE`.

Progress is tracked using `analyze.py`, `output.map` and `ida_copypaste_funclist_nostdlib.txt`: After compiling `df2_reimpl.dll`, symbols can be compared against the `.idb` to determine how much of the original `.text` is actually in use, and how much has been hooked and replaced.

If you'd like a copy of my IDB to examine functions which haven't been decompiled yet (or for any other use), let me know.

## Usage
`df2_reimpl` supports both the KVM target from the directory above as well as WINE/Windows, though no guarantees are made for the addition of ie jkgfxmod, other patches nor other hooks. Since KVM has some issues with imports/exports and stdlib, `df2_reimpl.dll` is compiled with `-Wl,-e_hook_init -nostartfiles`, while `df2_reimpl_win.dll` is compiled without those linker flags.

Hooking is done by patching JK.EXE with `JK-hook.ips` (using Lunar IPS or similar). This patch replaces `Window_Main` at offset 0x10db50 with the following:
```
68 70 E7 50 00 FF 15 98 05 8F 00 68 80 E7 50 00 50 FF 15 1C 05 8F 00 FF D0 C3 00 00 00 00 00 00 64 66 32 5F 72 65 69 6D 70 6C 2E 64 6C 6C 00 00 68 6F 6F 6B 5F 69 6E 69 74 5F 77 69 6E 00 00 00
```
which is just some small shellcode for
```
int (*v1)(void); 
v1 = GetProcAddress(LoadLibraryA("df2_reimpl.dll"), "hook_init_win");
return v1();
```
OpenJKDF2 then calls the necessary `VirtualProtect` functions from `hook_init_win`, hooks all the functions it needs and then calls its own implementation of `Window_Main` which was replaced with the loader.

TL;DR for Windows users
- Patch JK.EXE with `JK-hook.ips`
- Compile df2_reimpl
- Copy `df2_reimpl_win.dll` to the same folder as `JK.EXE`, renamed to `df2_reimpl.dll`

## Linux Partial Compilation

`openjkdf2` supports an experimental partial compilation for Linux/SDL2, using `make -f Makefile.linux`. `openjkdf2` can then be copied to the same directory as JK.EXE and run. It can currently access the player selection, singleplayer, options, and level loading screen before reaching unimplemented code.

`mmap` is used to maintain all `.rodata`, `.data`, and `.bss` variables in the same addresses as `JK.EXE`, however if `openjkdf2` invokes an unimplemented function, it will segfault at the unimplemented function address.

## Current Progress

Generated using `analyze.py`. Some filenames may be inaccurate or incomplete (see `ida_copypaste_funclist_nostdlib.txt` for a full function name listing).

```
[file]                         [size]     [% of text]   [% complete]  [decomp / total] 
DirectX                        0x1e       0.003%        100.000%        5 / 5          
sithCorpse                     0x27       0.004%        100.000%        1 / 1          
jkGob                          0x29       0.004%        100.000%        2 / 2          
jkGuiDecision                  0x45       0.006%        100.000%        3 / 3          
sithStrTable                   0x5b       0.008%        100.000%        4 / 4          
sithCopyright                  0x67       0.010%        100.000%        1 / 1          
jkStrings                      0x89       0.013%        100.000%        5 / 5          
jkGuiGeneral                   0xc5       0.018%        100.000%        3 / 3          
jkSmack                        0xee       0.022%        100.000%        4 / 4          
rdFace                         0xf6       0.023%        100.000%        4 / 4          
jkGuiControlOptions            0x105      0.024%        100.000%        3 / 3          
stdHashKey                     0x107      0.024%        100.000%       10 / 10         
rdCanvas                       0x113      0.026%        100.000%        4 / 4          
jkGuiEsc                       0x18f      0.037%        100.000%        3 / 3          
rdroid                         0x1f6      0.047%        100.000%       27 / 27         
sithHeader                     0x1f9      0.047%        100.000%        1 / 1          
sithTime                       0x213      0.049%        100.000%        6 / 6          
jkGuiSingleTally               0x21b      0.050%        100.000%        4 / 4          
jkGuiSetup                     0x240      0.053%        100.000%        4 / 4          
jkGuiSound                     0x274      0.058%        100.000%        3 / 3          
sithItem                       0x275      0.058%        100.000%        5 / 5          
jkGuiGameplay                  0x2b2      0.064%        100.000%        3 / 3          
stdMemory                      0x2ba      0.065%        100.000%        7 / 7          
sithTimer                      0x2e3      0.069%        100.000%        9 / 9          
stdMci                         0x2ef      0.070%        100.000%        7 / 7          
jkGuiObjectives                0x308      0.072%        100.000%        4 / 4          
jkControl                      0x331      0.076%        100.000%        4 / 4          
Windows                        0x39a      0.086%        100.000%       11 / 11         
stdString                      0x3b3      0.088%        100.000%       11 / 11         
jkGuiDialog                    0x3e0      0.092%        100.000%        6 / 6          
sithModel                      0x3f1      0.094%        100.000%        8 / 8          
rdThing                        0x42f      0.099%        100.000%       12 / 12         
stdGdi                         0x430      0.099%        100.000%       10 / 10         
sithKeyFrame                   0x44e      0.102%        100.000%        5 / 5          
stdPcx                         0x45e      0.104%        100.000%        2 / 2          
rdMath                         0x47d      0.107%        100.000%        6 / 6          
rdLight                        0x49f      0.110%        100.000%        8 / 8          
stdFnames                      0x4ee      0.117%        100.000%       14 / 14         
sithSprite                     0x4f1      0.117%        100.000%        6 / 6          
jkGui                          0x4fb      0.118%        100.000%       10 / 10         
jkGuiTitle                     0x4fb      0.118%        100.000%       10 / 10         
sithMaterial                   0x4fd      0.118%        100.000%        9 / 9          
wuRegistry                     0x5b2      0.135%        100.000%       12 / 12         
stdHashTable                   0x5d6      0.139%        100.000%       10 / 10         
sithExplosion                  0x61d      0.145%        100.000%        4 / 4          
stdGob                         0x6dd      0.163%        100.000%       14 / 14         
sith                           0x72b      0.170%        100.000%       16 / 16         
jkGuiPlayer                    0x73a      0.172%        100.000%        5 / 5          
rdSprite                       0x76d      0.176%        100.000%        5 / 5          
stdConffile                    0x78d      0.179%        100.000%       13 / 13         
sithTemplate                   0x79d      0.181%        100.000%       10 / 10         
sithParticle                   0x7f5      0.189%        100.000%       10 / 10         
jkGuiSingleplayer              0x8d8      0.210%        100.000%        7 / 7          
sithCogSector                  0x93a      0.219%        100.000%       22 / 22         
jkGuiForce                     0x9dd      0.234%        100.000%       11 / 11         
sithSound                      0xa00      0.238%        100.000%       13 / 13         
rdParticle                     0xa0d      0.239%        100.000%       10 / 10         
sithCogSound                   0xa97      0.252%        100.000%       14 / 14         
rdKeyframe                     0xa99      0.252%        100.000%        8 / 8          
rdCamera                       0xaa8      0.253%        100.000%       26 / 26         
jkGuiSaveLoad                  0xb21      0.264%        100.000%        9 / 9          
rdPolyLine                     0xb42      0.267%        100.000%        6 / 6          
rdVector                       0xd29      0.313%        100.000%       55 / 55         
sithCogPlayer                  0xdf0      0.331%        100.000%       42 / 42         
sithCogSurface                 0xe92      0.346%        100.000%       38 / 38         
stdConsole                     0xfff      0.380%        100.000%       20 / 20         
sithCogYACC                    0x152b     0.503%        100.000%       10 / 10         
jkRes                          0x15b6     0.516%        100.000%       23 / 23         
sithCogParse                   0x1b2a     0.645%        100.000%       26 / 26         
sithCogVm                      0x22f7     0.830%        100.000%       42 / 42         
sithRender                     0x23de     0.852%        100.000%       22 / 22         
sithCogUtil                    0x26c2     0.921%        100.000%      119 / 119        
rdModel3                       0x2a7e     1.009%        100.000%       23 / 23         
rdMatrix                       0x2c85     1.057%        100.000%       56 / 56         
jkGuiRend                      0x2cd7     1.065%        100.000%       68 / 68         
jkPlayer                       0x2da2     1.084%        100.000%       45 / 45         
sithWeapon                     0x32a8     1.203%        100.000%       33 / 33         
sithCogThing                   0x3a4c     1.385%        100.000%      142 / 142        
jkCutscene                     0x443      0.101%        11.549%         1 / 7          
sithThingPlayer                0x460      0.104%        0.000%          0 / 4          
smack                          0x466      0.104%        0.000%          0 / 6          
jkGuiMain                      0x4b1      0.111%        77.352%         4 / 6          
sithDplay                      0x53c      0.124%        2.090%          1 / 17         
sithActor                      0x559      0.127%        47.115%         2 / 5          
Video                          0x5dc      0.139%        19.800%         3 / 5          
DebugConsole                   0x5de      0.139%        0.000%          0 / 13         
stdFileUtil                    0x687      0.155%        24.237%         5 / 11         
sithAIClass                    0x689      0.155%        83.981%         4 / 7          
rdPrimit2                      0x69a      0.157%        0.000%          0 / 5          
stdBmp                         0x6b8      0.160%        0.000%          0 / 3          
sithCogScript                  0x6ca      0.161%        67.837%         7 / 9          
sithAnimClass                  0x6cc      0.161%        86.954%         3 / 5          
Window                         0x6db      0.163%        70.769%         6 / 13         
jkAI                           0x6e7      0.164%        5.490%          1 / 5          
jkGuiControlSaveLoad           0x732      0.171%        0.000%          0 / 6          
jkGuiMultiplayer               0x749      0.173%        0.000%          0 / 3          
jkGuiMap                       0x793      0.180%        0.000%          0 / 8          
stdStrTable                    0x7b6      0.183%        82.877%         4 / 6          
Main                           0x87b      0.201%        96.868%         3 / 4          
jkGuiMultiTally                0x8aa      0.206%        0.000%          0 / 7          
jkCredits                      0x8e4      0.211%        3.207%          1 / 6          
sithCogAI                      0x943      0.220%        52.299%        12 / 20         
jkGuiNet                       0x94e      0.221%        0.000%          0 / 10         
stdColor                       0x97e      0.225%        0.000%          0 / 11         
jkGame                         0x98f      0.227%        37.393%         5 / 13         
stdSound                       0x9bf      0.231%        0.000%          0 / 27         
sithSave                       0x9bf      0.231%        38.758%         4 / 7          
rdMaterial                     0xa2d      0.242%        74.779%         7 / 9          
sithSoundClass                 0xa46      0.244%        56.844%         7 / 16         
stdPalEffects                  0xa66      0.247%        8.866%          5 / 21         
jkGuiKeyboard                  0xb57      0.269%        0.000%          0 / 14         
jkGuiNetHost                   0xbc6      0.280%        0.000%          0 / 6          
sithMapView                    0xbf8      0.284%        0.000%          0 / 9          
stdLbm                         0xc24      0.288%        0.000%          0 / 3          
rdColormap                     0xcf4      0.308%        47.738%         7 / 12         
sithTrackThing                 0xd6b      0.319%        9.578%          1 / 13         
jkGuiMouse                     0xdb5      0.326%        0.000%          0 / 14         
DirectDraw                     0xdd4      0.328%        0.000%          0 / 16         
jkEpisode                      0xdd9      0.329%        91.819%         5 / 10         
stdPlatform                    0xdde      0.329%        13.437%        10 / 43         
sithUnk4                       0xdfd      0.332%        15.638%         4 / 12         
jkHudInv                       0xe43      0.339%        15.037%         3 / 9          
sithPlayer                     0xe72      0.343%        46.782%        11 / 27         
stdBitmap                      0xeb6      0.349%        37.440%         4 / 14         
rdPuppet                       0x101f     0.383%        57.039%         4 / 19         
DirectPlay                     0x10cc     0.399%        0.000%          0 / 31         
VBuffer                        0x10dc     0.400%        0.000%          0 / 4          
stdGif                         0x1162     0.413%        0.000%          0 / 4          
sithDebugConsole               0x11b2     0.420%        0.000%          0 / 20         
jkCog                          0x11b8     0.421%        17.394%         5 / 40         
sithPuppet                     0x1222     0.431%        12.495%         5 / 17         
sithCamera                     0x124b     0.434%        81.209%         9 / 23         
sithCollide                    0x12a8     0.443%        92.588%         9 / 12         
jkGuiDisplay                   0x12ff     0.451%        0.000%          0 / 11         
stdControl                     0x1323     0.455%        0.776%          1 / 23         
jkGuiJoystick                  0x13f0     0.474%        0.000%          0 / 19         
jkMain                         0x16cd     0.542%        69.762%        27 / 53         
rdPrimit3                      0x16e0     0.543%        54.013%         3 / 9          
sithWorld                      0x1718     0.548%        70.856%        16 / 22         
stdFont                        0x181a     0.572%        67.488%        10 / 20         
stdMath                        0x182a     0.574%        63.369%        16 / 23         
rdActive                       0x1a55     0.625%        2.626%          3 / 8          
sithSurface                    0x1c6a     0.675%        53.533%        17 / 35         
jkHud                          0x1c9b     0.679%        0.178%          1 / 17         
jkDev                          0x1e60     0.721%        0.617%          1 / 39         
sithCog                        0x1ed3     0.732%        79.483%        17 / 28         
jkSaber                        0x1f4a     0.743%        37.665%        10 / 40         
sithInventory                  0x2150     0.791%        99.179%        60 / 62         
sithMulti                      0x252a     0.883%        0.105%          1 / 35         
jkGuiBuildMulti                0x258b     0.892%        0.000%          0 / 24         
sithSoundSys                   0x2626     0.906%        5.171%          3 / 37         
stdDisplay                     0x267b     0.914%        0.264%          2 / 37         
sithControl                    0x2723     0.930%        34.944%         9 / 32         
sithAI                         0x2771     0.937%        23.027%        14 / 35         
sithUnk3                       0x2827     0.954%        82.420%        15 / 22         
std3D                          0x2c4a     1.052%        0.000%          0 / 39         
sithAICmd                      0x2cc0     1.063%        4.958%          1 / 22         
rdCache                        0x331c     1.214%        43.557%        13 / 16         
sithThing                      0x3c2e     1.429%        71.550%        34 / 53         
sithSector                     0x79f9     2.897%        22.424%        20 / 96         
rdClip                         0x81f2     3.086%        53.120%        11 / 17         
rdRaster                       0xf04d     5.707%        0.195%          1 / 89         
rdZRaster                      0x15fb4    8.353%        0.000%          0 / 73         
rdAFRaster                     0x1620d    8.409%        0.000%          0 / 122        
rdNRaster                      0x304d4    18.355%       0.000%          0 / 87         
---------------------------------------------------------------------------------

Total completion:
-----------------
31.950% by weight
53.991% by weight excluding rasterizer
1721 / 3165 functions
1721 / 2794 functions excluding rasterizer

Subsystem Breakdown (Not Decomp'd)
----------------------------------
[subsys]       [% of text]  [TODO / total]
sith           10.218%         416 / 1320
stdPlatform    0.285%           33 / 43
std            4.721%          195 / 360
jkGui          3.667%          124 / 284
rd             3.534%           47 / 345
jk             3.275%          179 / 322
Raster         40.813%         370 / 371
other          1.537%           80 / 120
-----------------------------------------
total          68.050%        1444 / 3165

Subsystem Breakdown (Not Decomp'd, Excl Raster)
-----------------------------------------------
[subsys]       [% of text]  [TODO / total]
sith           17.267%         416 / 1320
stdPlatform    0.482%           33 / 43
std            7.978%          195 / 360
jkGui          6.196%          124 / 284
rd             5.972%           47 / 345
jk             5.535%          179 / 322
other          2.598%           80 / 120
-----------------------------------------
total          46.027%        1074 / 2794

```
