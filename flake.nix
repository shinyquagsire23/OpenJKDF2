# Build:  nix build 'git+file:.?submodules=1'
# Shell:  nix develop 'git+file:.?submodules=1'
# The ?submodules=1 is required because the build uses vendored deps from
# git submodules (SDL2, OpenAL, zlib, libpng, GLEW, PhysFS, freeglut).
{
  description = "OpenJKDF2 - Function-by-function reimplementation of Jedi Knight: Dark Forces II";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        version = "0.9.8";
        gitRev = if self ? rev then self.rev else "dirty";
        gitRevShort = builtins.substring 0 8 gitRev;

        # System-level deps needed by vendored SDL2/OpenAL builds at compile time,
        # and by the project itself (curl, gtk3, GL).
        # SDL2 and OpenAL dynamically load most of these at runtime, but need
        # headers + pkg-config during the build.
        systemDeps = with pkgs; [
          # GL
          libGL
          libGLU
          glew

          # X11 (SDL2 compile-time headers)
          libx11
          libxext
          libxcursor
          libxinerama
          libxi
          libxrandr
          libxscrnsaver
          libxxf86vm

          # Wayland (SDL2 compile-time)
          wayland
          wayland-protocols
          wayland-scanner
          libxkbcommon
          libdecor

          # Audio backends (SDL2/OpenAL compile-time)
          alsa-lib
          libpulseaudio
          pipewire

          # DBus (SDL2)
          dbus

          # OpenAL (found by cmake's FindOpenAL, then overridden by vendored build)
          openal

          # Audio codecs (for SDL_mixer when not using vendored)
          libogg
          libvorbis
          libopus
          opusfile

          # Project deps
          curl
          gtk3
        ];
      in {
        packages = {
          default = pkgs.stdenv.mkDerivation {
            pname = "openjkdf2";
            inherit version;

            src = ./.;

            nativeBuildInputs = with pkgs; [
              cmake
              pkg-config
              python3
              python3Packages.cogapp
              clang
            ];

            buildInputs = systemDeps;

            # Nix sandbox patches:
            # 1. GNS needs git for its patch step and the cmake flag can't
            #    override the non-cache set() in plat_feat_full_sdl2.cmake.
            # 2. SDL_mixer's vendored ogg/vorbis/opus are nested submodules
            #    that nix doesn't fetch. Use system packages instead.
            postPatch = ''
              substituteInPlace cmake_modules/plat_feat_full_sdl2.cmake \
                --replace-fail 'set(TARGET_USE_GAMENETWORKINGSOCKETS TRUE)' \
                               'set(TARGET_USE_GAMENETWORKINGSOCKETS FALSE)'
              substituteInPlace cmake_modules/build_sdl_mixer.cmake \
                --replace-fail '-DSDL2MIXER_VENDORED:BOOL=TRUE' \
                               '-DSDL2MIXER_VENDORED:BOOL=FALSE'
              # When using system ogg/vorbis/opus, the vendored static lib paths
              # from SDL_MIXER_DEPS don't exist. Replace the entire if/else block
              # with a simple set. Use ''$ to produce literal $ in nix strings.
              substituteInPlace cmake_modules/build_sdl_mixer.cmake \
                --replace-fail \
'if(PLAT_MSVC)
    set(SDL_MIXER_DEPS  "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}vorbisfile''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}vorbis''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}ogg''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}opusfile''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}opus''${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )
elseif(TARGET_ANDROID)
    set(SDL_MIXER_DEPS  SDL::SDL) # ????
else()
    set(SDL_MIXER_DEPS  SDL::SDL
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}vorbisfile''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}vorbis''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}ogg''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}opusfile''${CMAKE_STATIC_LIBRARY_SUFFIX}"
                        "''${SDL_MIXER_ROOT}/lib/''${CMAKE_STATIC_LIBRARY_PREFIX}opus''${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )
endif()' \
                'find_package(PkgConfig REQUIRED)
pkg_check_modules(OGG REQUIRED IMPORTED_TARGET ogg)
pkg_check_modules(VORBIS REQUIRED IMPORTED_TARGET vorbis)
pkg_check_modules(VORBISFILE REQUIRED IMPORTED_TARGET vorbisfile)
pkg_check_modules(OPUS REQUIRED IMPORTED_TARGET opus)
pkg_check_modules(OPUSFILE REQUIRED IMPORTED_TARGET opusfile)
set(SDL_MIXER_DEPS SDL::SDL PkgConfig::OGG PkgConfig::VORBIS PkgConfig::VORBISFILE PkgConfig::OPUS PkgConfig::OPUSFILE)'
            '';

            preConfigure = ''
              export OPENJKDF2_RELEASE_COMMIT="${gitRev}"
              export OPENJKDF2_RELEASE_COMMIT_SHORT="${gitRevShort}"
              export CC=clang
              export CXX=clang++
            '';

            cmakeFlags = [
              "-DPLAT_LINUX_64=TRUE"
            ];

            # The vendored build system uses ExternalProject for deps (SDL2, OpenAL,
            # zlib, libpng, GLEW, PhysFS, etc.) which need to be built first.
            # The PROTOBUF target handles protobuf if GNS is enabled.
            buildPhase = ''
              runHook preBuild
              make -j$NIX_BUILD_CORES openjkdf2 2>&1
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              cp openjkdf2 $out/bin/
              runHook postInstall
            '';

            meta = with pkgs.lib; {
              description = "Open-source reimplementation of Star Wars Jedi Knight: Dark Forces II";
              homepage = "https://github.com/shinyquagsire23/OpenJKDF2";
              license = licenses.mit;
              platforms = [ "x86_64-linux" "aarch64-linux" ];
              mainProgram = "openjkdf2";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cmake
            pkg-config
            python3
            python3Packages.cogapp
            clang
            gdb
            valgrind
          ];

          buildInputs = systemDeps;

          shellHook = ''
            export OPENJKDF2_RELEASE_COMMIT="$(git log -1 --format='%H' 2>/dev/null || echo dev)"
            export OPENJKDF2_RELEASE_COMMIT_SHORT="$(git rev-parse --short=8 HEAD 2>/dev/null || echo dev)"
            export CC=clang
            export CXX=clang++
            echo "OpenJKDF2 dev shell ready"
            echo "  Build: cmake -B build -DPLAT_LINUX_64=TRUE && cmake --build build -j\$(nproc)"
          '';
        };
      }
    );
}
