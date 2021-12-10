OpenJKDF2 is usable as a hook-and-replace DLL with the original JK.EXE (v1.0) to allow for quality-of-life improvements and multiplayer, since the SDL2 and 64-bit versions do not currently have DirectPlay functions implemented.

`df2_reimpl` supports both the KVM target (OpenJKDF2-KVM) as well as WINE/Windows, though no guarantees are made for the addition of jkgfxmod, nor other patches and hooks. Since KVM has some issues with imports/exports and stdlib, `df2_reimpl_kvm.dll` is compiled with `-Wl,-e_hook_init -nostartfiles`, while `df2_reimpl.dll` is compiled without those linker flags.

Hooking is done by patching JK.EXE with `JK-hook.ips` (using Lunar IPS or similar). This patch replaces `Window_Main` at offset 0x10db50 with the following:
```
68 70 E7 50 00 FF 15 98 05 8F 00 68 80 E7 50 00 50 FF 15 1C 05 8F 00 FF E0 C3 00 00 00 00 00 00 64 66 32 5F 72 65 69 6D 70 6C 2E 64 6C 6C 00 00 68 6F 6F 6B 5F 69 6E 69 74 5F 77 69 6E 00 00 00
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
- Compile df2_reimpl with `make`
- Copy `df2_reimpl.dll` to the same folder as `JK.EXE`