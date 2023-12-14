#!/bin/zsh

BINDIR="build_win64"
EXE="$BINDIR/openjkdf2-64.exe"
GNS="$BINDIR/libGameNetworkingSockets.dll"
PREFIX="x86_64-w64-mingw32"

paths=("/usr/local/mingw64/bin"
    "/usr/local/mingw64/bin/x64"
     "/usr/$PREFIX/bin"
    "/usr/lib/gcc/$PREFIX/7.3-posix"
    "/usr/$PREFIX/lib"
    "/opt/homebrew/Cellar/mingw-w64/9.0.0_2/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/opt/homebrew/Cellar/mingw-w64/9.0.0_2/toolchain-x86_64/x86_64-w64-mingw32/bin"
    "/usr/local/Cellar/mingw-w64/9.0.0_2/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/usr/local/Cellar/mingw-w64/9.0.0_2/toolchain-x86_64/x86_64-w64-mingw32/bin"
    "/opt/homebrew/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/opt/homebrew/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/x86_64-w64-mingw32/bin"
    "/usr/local/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/usr/local/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/x86_64-w64-mingw32/bin"
    "/opt/homebrew/Cellar/mingw-w64/11.0.0/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/opt/homebrew/Cellar/mingw-w64/11.0.0/toolchain-x86_64/x86_64-w64-mingw32/bin"
    "/usr/local/Cellar/mingw-w64/11.0.0/toolchain-x86_64/x86_64-w64-mingw32/lib"
    "/usr/local/Cellar/mingw-w64/11.0.0/toolchain-x86_64/x86_64-w64-mingw32/bin")

function findAndCopyDLL() {
    for i in "${paths[@]}"
    do
        FILE="$i/$1"
        if [ -f $FILE ]; then
           cp $FILE $BINDIR
           echo "Found $1 in $i"
           copyForOBJ $FILE
           return 0
        fi
    done

    return 1
}

function copyForOBJ() {
    dlls=`$PREFIX-objdump -p $1 | grep 'DLL Name:' | sed -e "s/\t*DLL Name: //g"`
    while read -r filename; do
        findAndCopyDLL $filename
    done <<< "$dlls"
}

copyForOBJ $EXE
if [ -f $GNS ]; then
    copyForOBJ $GNS
fi