freeglut 3.0.0-1.mp for MinGW

This package contains freeglut import libraries, headers, and Windows DLLs.
These allow 32 and 64 bit GLUT applications to be compiled on Windows using
MinGW. Both static and shared versions of the library are included.

For more information on freeglut, visit http://freeglut.sourceforge.net/.


Installation

Create a folder on your PC which is readable by all users, for example
“C:\Program Files\Common Files\MinGW\freeglut\” on a typical Windows system.
Copy the “lib\” and “include\” folders from this zip archive to that location.

The appropriate freeglut DLL can either be placed in the same folder as your
application, or can be installed in a system-wide folder which appears in your
%PATH% environment variable. Be careful not to mix the 32 bit DLL up with the 64
bit DLL, as they are not interchangeable.


Compiling 32 bit Applications

If you want your application to be compatible with GLUT, you should
“#include <GL/glut.h>”. If you want to use freeglut specific extensions, you
should “#include <GL/freeglut.h>” instead.

Given a source file “test.c”, which you want to compile to an application
“test.exe” dynamically linking to the DLL, you can compile and link it with the
following commands (replacing the include and lib paths with the ones you
created above if necessary):

  gcc -c -o test.o test.c -I"C:\Program Files\Common Files\MinGW\freeglut\include"
  gcc -o test.exe test.o -L"C:\Program Files\Common Files\MinGW\freeglut\lib" -lfreeglut -lopengl32 -Wl,--subsystem,windows

Don’t forget to either include the freeglut DLL when distributing applications,
or provide your users with some method of obtaining it if they don’t already
have it!


Compiling 64 bit Applications

Building 64 bit applications is almost identical to building 32 bit applications.
The only difference is that you should change the library path on the command
line to point to the x64 directory:

  gcc -c -o test.o test.c -I"C:\Program Files\Common Files\MinGW\freeglut\include"
  gcc -o test.exe test.o -L"C:\Program Files\Common Files\MinGW\freeglut\lib\x64" -lfreeglut -lopengl32 -Wl,--subsystem,windows


Static Linking

To statically link the freeglut library into your application, it’s necessary to
define “FREEGLUT_STATIC” when compiling the object files. It’s also necessary to
link the static version of the freeglut library, along with the GDI and Windows
multimedia libraries which freeglut depends upon:

  gcc -c -o test.o test.c -D FREEGLUT_STATIC -I"C:\Program Files\Common Files\MinGW\freeglut\include"
  gcc -o test.exe test.o -L"C:\Program Files\Common Files\MinGW\freeglut\lib" -lfreeglut_static -lopengl32 -lwinmm -lgdi32 -Wl,--subsystem,windows

The “-Wl,--subsystem,windows” is needed in each case so that the application
builds as a Windows GUI application rather than a console application. If you
are using GLU functions you should also include “-lglu32” on the command line.

When statically linking a 64 bit build, you should change the library path as
detailed under the “Compiling 64 bit Applications” section.


Full Tutorial

Please visit http://www.transmissionzero.co.uk/computing/using-glut-with-mingw/
for a complete guide on using GLUT and freeglut with MinGW.


Cross-Compilation

I’ve not covered the setup of freeglut for use in cross-compilation, i.e. when
building Windows freeglut applications using a Linux system. Setting freeglut up
with MinGW on other operating systems can be done following the instructions
above, except that the paths will be different.


Problems?

If you have problems using this package (compiler / linker errors etc.), please
check that you have followed all of the steps in this readme file correctly.
Almost all of the problems which are reported with these packages are due to
missing a step or not doing it correctly, for example trying to build a 32 bit
app against the 64 bit import library. If you have followed all of the steps
correctly but your application still fails to build, try building a very simple
but functional program (the example at
http://www.transmissionzero.co.uk/computing/using-glut-with-mingw/ is ideal). A
lot of people try to build very complex applications after installing these
packages, and often the error is with the application code or other library
dependencies rather than freeglut.

If you still can’t get it working after trying to compile a simple application,
then please get in touch via http://www.transmissionzero.co.uk/contact/,
providing as much detail as you can. Please don’t complain to the freeglut guys
unless you’re sure it’s a freeglut bug, and have reproduced the issue after
compiling freeglut from the latest SVN version—if that’s still the case, I’m sure
they would appreciate a bug report or a patch.


Changelog

2015-03-15: Release 3.0.0-1.mp

  • First 3.0.0 MinGW release. I’ve built the package using MinGW, and the only
    change I’ve made is to the DLL version resource—I’ve changed the description
    so that my MinGW and MSVC builds are distinguishable from each other (and
    other builds) using Windows Explorer.


Transmission Zero
2015-03-15

http://www.transmissionzero.co.uk/
