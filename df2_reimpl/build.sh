#!/bin/bash

i686-w64-mingw32-gcc -c -o main.o main.c &&
i686-w64-mingw32-gcc -c -o hook.o hook.c &&
i686-w64-mingw32-gcc -c -o jk.o jk.c &&
i686-w64-mingw32-gcc -c -o cog.o cog.c &&
i686-w64-mingw32-gcc -c -o jkl.o jkl.c &&
i686-w64-mingw32-gcc -o df2_reimpl.dll -s -shared main.o hook.o jk.o cog.o jkl.o -Wl,--subsystem,windows -Wl,-e_hook_init -nostartfiles
