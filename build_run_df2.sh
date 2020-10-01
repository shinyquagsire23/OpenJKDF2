#!/bin/bash

cd df2_reimpl && ./build.sh && cd .. && cp df2_reimpl/df2_reimpl.dll DF2/ && qmake openjkdf2.pro && make && ./openjkdf2 -cwd DF2/ JK.EXE
