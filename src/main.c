#include <stdint.h>
#include <stdio.h>

#include "hook.h"
#include "jk.h"
#include "types.h"

#include "General/stdMath.h"

#ifndef NO_JK_MMAP
#include "Cog/sithCog.h"
#include "Cog/sithCogExec.h"
#include "Cog/jkCog.h"
#include "Cog/sithCogYACC.h"
#include "Cog/sithCogFunction.h"
#include "Cog/sithCogFunctionThing.h"
#include "Cog/sithCogFunctionPlayer.h"
#include "Cog/sithCogFunctionAI.h"
#include "Cog/sithCogFunctionSurface.h"
#include "Cog/sithCogFunctionSector.h"
#include "Cog/sithCogFunctionSound.h"
#include "Cog/y.tab.h"
#include "General/stdBitmap.h"
#include "General/stdBmp.h"
#include "General/util.h"
#include "General/stdLbm.h"
#include "General/stdMath.h"
#include "General/stdJSON.h"
#include "Primitives/rdVector.h"
#include "General/stdMemory.h"
#include "General/stdColor.h"
#include "General/stdConffile.h"
#include "General/stdFont.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "General/stdHashTable.h"
#include "General/stdLinklist.h"
#include "General/stdString.h"
#include "General/stdStrTable.h"
#include "General/sithStrTable.h"
#include "General/stdPcx.h"
#include "General/Darray.h"
#include "General/stdPalEffects.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIMain.h"
#include "Gui/jkGUIGeneral.h"
#include "Gui/jkGUIForce.h"
#include "Gui/jkGUIEsc.h"
#include "Gui/jkGUIDecision.h"
#include "Gui/jkGUISaveLoad.h"
#include "Gui/jkGUISingleplayer.h"
#include "Gui/jkGUISingleTally.h"
#include "Gui/jkGUIControlOptions.h"
#include "Gui/jkGUIObjectives.h"
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIGameplay.h"
#include "Gui/jkGUIDisplay.h"
#include "Gui/jkGUISound.h"
#include "Gui/jkGUIKeyboard.h"
#include "Gui/jkGUIMouse.h"
#include "Gui/jkGUIJoystick.h"
#include "Gui/jkGUITitle.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Gui/jkGUIBuildMulti.h"
#include "Gui/jkGUIMultiTally.h"
#include "Engine/rdroid.h"
#include "Engine/rdActive.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdLight.h"
#include "Engine/rdMaterial.h"
#include "Raster/rdCache.h"
#include "Engine/rdColormap.h"
#include "Engine/rdClip.h"
#include "Engine/rdCanvas.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdThing.h"
#include "Engine/sithCamera.h"
#include "Devices/sithControl.h"
#include "Gameplay/sithTime.h"
#include "Main/sithMain.h"
#include "Main/sithCommand.h"
#include "Main/InstallHelper.h"
#include "World/sithModel.h"
#include "Engine/sithParticle.h"
#include "Engine/sithPhysics.h"
#include "Engine/sithPuppet.h"
#include "Dss/sithGamesave.h"
#include "World/sithSprite.h"
#include "World/sithSurface.h"
#include "World/sithTemplate.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithKeyFrame.h"
#include "Gameplay/sithOverlayMap.h"
#include "World/sithMaterial.h"
#include "Engine/sithRender.h"
#include "Engine/sithRenderSky.h"
#include "Devices/sithSound.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdPolyLine.h"
#include "Primitives/rdParticle.h"
#include "Primitives/rdSprite.h"
#include "Primitives/rdMatrix.h"
#include "Raster/rdFace.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdPrimit2.h"
#include "Primitives/rdPrimit3.h"
#include "Raster/rdRaster.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "World/sithWorld.h"
#include "Gameplay/sithInventory.h"
#include "World/jkPlayer.h"
#include "Gameplay/jkSaber.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "World/sithMap.h"
#include "Engine/sithIntersect.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/sithTrackThing.h"
#include "Devices/sithConsole.h"
#include "Win95/DirectX.h"
#include "Win95/stdComm.h"
#include "Win95/std.h"
#include "Win95/stdGob.h"
#include "Win95/stdMci.h"
#include "Win95/stdGdi.h"
#include "Platform/stdControl.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdConsole.h"
#include "Win95/stdSound.h"
#include "Win95/Window.h"
#include "Win95/Windows.h"
#include "Platform/wuRegistry.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "AI/sithAICmd.h"
#include "AI/sithAIAwareness.h"
#include "Main/jkAI.h"
#include "Main/jkCredits.h"
#include "Main/jkCutscene.h"
#include "Main/jkDev.h"
#include "Main/jkMain.h"
#include "Main/jkSmack.h"
#include "Main/jkGame.h"
#include "Main/jkGob.h"
#include "Main/jkRes.h"
#include "Main/jkStrings.h"
#include "Main/jkControl.h"
#include "Main/jkEpisode.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/Main.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "Dss/jkDSS.h"
#include "Devices/sithComm.h"
#include "stdPlatform.h"
#else
#include "General/stdString.h"
#include "Win95/Window.h"
#include "Main/jkMain.h"
#include "Main/Main.h"
#endif // NO_JK_MMAP

extern char openjkdf2_aOrigCwd[512];

void do_hooks();

#ifdef ARCH_WASM
#include <emscripten.h>
#endif // ARCH_WASM

#ifdef WIN64_STANDALONE
#include "exchndl.h"

#include <windows.h>
#endif

#ifdef PLATFORM_PHYSFS
#include <physfs.h>
#endif

#ifdef LINUX
#ifndef ARCH_WASM
void crash_handler_basic(int sig);

#include <sys/mman.h>
#include <execinfo.h>
#include <signal.h>
#endif // !ARCH_WASM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "SDL2_helper.h"
#endif // LINUX

#ifdef TARGET_TWL
#include <nds.h>
#include <fat.h>
#include <nds/arm9/dldi.h>
#include "Platform/TWL/dlmalloc.h"

// Keep all of this in DTCM to avoid stalls in the IRQ handler
FAST_DATA volatile int std3D_bEnableTwlVrr = 0;
FAST_DATA volatile int std3D_twlLastFinishedFrame = 0;
FAST_DATA volatile int std3D_twlFinishedFrame = 0;
FAST_DATA volatile int std3D_stalledHblanks = 0;
FAST_DATA volatile int std3D_twlTargetHblanks = 93;

/*
// just 50Hz
FAST_FUNC void hblank_handler() {
    // Don't run during the VBL period
    if (!std3D_bEnableTwlVrr || REG_VCOUNT < 202 || REG_VCOUNT > 202)
        return;
    if (std3D_twlFinishedFrame != std3D_twlLastFinishedFrame && false) {
        std3D_twlLastFinishedFrame = std3D_twlFinishedFrame;

        // If we finish early or are done holding, move to the next frame
        //REG_VCOUNT = 260;
        std3D_stalledHblanks = 30;
    }
    else {
        // Hold VCOUNT until the frame is finished
        
        std3D_stalledHblanks++;
        if (std3D_stalledHblanks < 62) {
            REG_VCOUNT = 202;
        }
        else {
            std3D_stalledHblanks = 0;
            REG_VCOUNT = 203;
        }
    }
}
*/

// VRR implementation for NDS:
// ---
// Since we can change the VCOUNT register, we can both advance
// VCOUNT from 193 -> 214 (~65Hz), or we can delay VCOUNT down to about ~45Hz.
//
// Rather than setting discrete refresh rates, we adjust VCOUNT
// slightly depending on when the frame gets finished, possibly multiple times
// per frame. 
//
// If the frame is not finished for multiple vsyncs, the screen will
// default to the lowest non-flickering refresh rate (~45Hz).
//
FAST_FUNC void hblank_handler() {
    // GBATek says the safe period is from 202..212,
    // but it seems to actually be 193..214 --
    // unless the GPU is doing a lot of work, then it seems to bump to 202
    const int hblankMin = 202;
    const int hblankMax = 214;
    int vcountCur = REG_VCOUNT;
    if (!std3D_bEnableTwlVrr || vcountCur < hblankMin || vcountCur >= hblankMax)
        return;

    // If the GPU is busy, let vcount keep going until we can hijack it safely
    // (if this is not checked, the screen will output corrupt triangles/frames
    //  in high-tri areas)
    if (GFX_STATUS & (1<<27)) {
        ;
    }
    else if (std3D_twlFinishedFrame != std3D_twlLastFinishedFrame) {
        std3D_twlLastFinishedFrame = std3D_twlFinishedFrame;

        // If we finish early or are done holding, move to the next frame
        // and skip ahead
        REG_VCOUNT = hblankMax;
    }
    else {
        // Hold VCOUNT until the frame is finished
        
        // 62 hblanks = 4ms = 50Hz, scanlines start to show
        // 62*2 hblanks = 8ms = ~40Hz, flickers
        // 93 hblanks = 6ms = ~45Hz?

        std3D_stalledHblanks++;
        if (std3D_stalledHblanks > std3D_twlTargetHblanks+(hblankMax-hblankMin)) {
            REG_VCOUNT = hblankMax;
            std3D_stalledHblanks = 0;
        }
        else {
            REG_VCOUNT = vcountCur;
        }
    }
}
#endif

// HACK: minGW fails on the Github runner??
#ifdef WIN64_MINGW
void __attribute__((weak)) __stack_chk_fail(void)
{

}

void* __attribute__((weak)) __memcpy_chk(void * dest, const void * src, size_t len, size_t destlen)
{
    return memcpy(dest, src, len);
}
#endif // WIN64_MINGW

#ifdef TARGET_TWL
extern mspace openjkdf2_mem_alt_mspace;
extern mspace openjkdf2_mem_main_mspace;

extern intptr_t openjkdf2_mem_alt_mspace_start;
extern intptr_t openjkdf2_mem_alt_mspace_end;
extern intptr_t openjkdf2_mem_main_mspace_start;
extern intptr_t openjkdf2_mem_main_mspace_end;

extern int openjkdf2_mem_alt_mspace_wordonly;
#ifdef __cplusplus
extern "C"
{
#endif
    extern void debugRamEnableCache();
    extern void nwramEnableCache();
#ifdef __cplusplus
}
#endif
#endif // TARGET_TWL

#ifdef TARGET_DREAMCAST
#include <kos.h>
#include "Platform/Dreamcast/dcFault.h"
// KOS reads these at startup (must be at file scope). INIT_DEFAULT brings up IRQs,
// threads and the standard subsystems; INIT_CONTROLLER enables maple input.
KOS_INIT_FLAGS(INIT_DEFAULT | INIT_CONTROLLER);
#endif // TARGET_DREAMCAST

int main(int argc, char** argv)
{
#ifdef TARGET_DREAMCAST
    // Added: on-screen CPU fault reporter (KOS default only prints to serial)
    dcFault_Install();

    // Added: bring the PVR + VRAM overflow arena up before any engine allocations,
    // so GUI font/bitmap vbuffers loaded pre-first-frame can land in VRAM.
    extern void std3D_EarlyInit(void);
    std3D_EarlyInit();

#ifdef DC_AUTOBOOT_MAP
    // Added: boot straight into a map (debug/testing; define DC_AUTOBOOT_MAP to
    // a jkl name, e.g. -DDC_AUTOBOOT_MAP=\"01narshadda.jkl\").
    static char* dcAutobootArgv[] = { "openjkdf2", "-autostart", "-sp",
                                      "-episode", "JK1", "-map", DC_AUTOBOOT_MAP };
    argc = 7;
    argv = dcAutobootArgv;
    {
        extern int jkGuiTitle_bSkipLoadingWait; // Added: don't wait for input at the load screen
        jkGuiTitle_bSkipLoadingWait = 1;
    }
#endif
#endif

#if defined(TARGET_TWL) && defined(TWL_AUTOBOOT_MAP)
    // Added: NDS/DSi twin of DC_AUTOBOOT_MAP (TWL_AUTOBOOT_MAP env at build time)
    static char* twlAutobootArgv[] = { "openjkdf2", "-autostart", "-sp",
                                       "-episode", "JK1", "-map", TWL_AUTOBOOT_MAP };
    argc = 7;
    argv = twlAutobootArgv;
    extern int jkGuiTitle_bSkipLoadingWait; // Added: don't wait for input at the load screen
    jkGuiTitle_bSkipLoadingWait = 1;
#endif
#ifdef ARCH_WASM
    EM_ASM(
        FS.mkdir('/jk1/player');
        FS.mkdir('/mots/player');
        FS.mkdir('/jk1/persist');
        FS.mkdir('/mots/persist');

        //FS.mount(NODEFS, { root: './jk1/episode' }, '/jk1/episode');
        //FS.createLazyFile('/jk1/episode', "jk1demo.gob", "jk1/episode/jk1demo.gob", true, false);
        //FS.createLazyFile('/jk1/episode', "jk1mpdem.gob", "jk1/episode/jk1mpdem.gob", true, false);

        FS.mount(IDBFS, {}, '/jk1/player');
        FS.mount(IDBFS, {}, '/mots/player');
        FS.mount(IDBFS, {}, '/jk1/persist');
        FS.mount(IDBFS, {}, '/mots/persist');

        // Then sync
        FS.syncfs(true, function (err) {
            // Error
        });
    );
#endif // ARCH_WASM

#if 0
    int numSamples = 700;
    int sprevi = 1<<16; // Radius.
    int sprev2i = 0; // 284 = 180deg
    for (int i = 0; i <= numSamples; i++) {
        int cor = (sprevi - sprev2i);
        int sir = (sprev2i + sprevi) * (3.14159/568.85); // optional, for rescale
        printf( "%d: %d %d, %f %f\n", i, sir, cor, (flex32_t)flexdirect(sir), (flex32_t)flexdirect(cor));
        int si = (sprevi<<1)-(sprevi>>13)-sprev2i; // controls omega
        sprev2i = sprevi;
        sprevi = si;
    }


    for (int i = 0; i < 360; i++) {
        flex_t sinTest, cosTest;
        stdMath_SinCosVeryApproximate(i, &sinTest, &cosTest);

        flex_t sinTest2, cosTest2;
        stdMath_SinCos(i, &sinTest2, &cosTest2);

        printf("%d: %f %f %f %f\n", i, (flex32_t)sinTest, (flex32_t)cosTest, (flex32_t)sinTest2, (flex32_t)cosTest2);
    }
#endif

#ifdef TARGET_TWL
    REG_SQRTCNT = SQRT_64;
    REG_DIVCNT = DIV_64_32;

    irqSet(IRQ_HBLANK, hblank_handler);
    irqEnable(IRQ_HBLANK);

    defaultExceptionHandler();
    consoleDebugInit(DebugDevice_NOCASH);

    lcdMainOnTop();

    videoSetMode(MODE_0_3D);

    videoSetModeSub(MODE_0_2D);
    vramSetBankH(VRAM_H_SUB_BG);
    vramSetBankI(VRAM_I_SUB_BG_0x06208000);
    //setBrightness(2, 0);

    consoleInit(NULL, 0, BgType_Text4bpp, BgSize_T_256x256, 23, 2, false, true);

    printf("Waddup\n");

    if (isDSiMode()) {
        *(u32*)0x4004008 |= 0x8F; // Use revised DSi circuits
        //REG_EXMEMCNT &= ~(1<<15); // ARM9 gets memory priority (don't use, causes audio chirping)

        //setCpuClock(1);
        debugRamEnableCache();
        nwramEnableCache();
    }
    else {
        sysSetCartOwner(BUS_OWNER_ARM9);
    }

    // TODO: DS mode slot2 can't r/w u8s
#if 0
    if (!isDSiMode()) {
        *((vu16*)0x09FC00B4) = 0x00A5;
        *((vu16*)0x09FC0000) = 0x6;

        peripheralSlot2DisableCache();

        size_t alt_sz = 0x2000000 - 0x1000;
        openjkdf2_mem_alt_mspace_start = (intptr_t)0x08000000;
        openjkdf2_mem_alt_mspace_end = openjkdf2_mem_alt_mspace_start + alt_sz;

        for (int i = 0; i < 10; i++) {
            strcpy((char*)(openjkdf2_mem_alt_mspace_start + (i*0x1000)), "Testing if the RAM is sticking.\n");
            printf("%.100s\n", (const char*)(openjkdf2_mem_alt_mspace_start + (i*0x1000)));
        }

        *((vu16*)0x08000000) = 0xDAAD;
        *((vu8*)0x08000002) = 0xd5;
        *((vu8*)0x08000003) = 0xd5;
        *((vu32*)0x08000004) = 0xF00FDAD5;
        printf("%08x %08x %08x %08x %02x %04x %08x\n", *((u32*)openjkdf2_mem_alt_mspace_start + 0), *((u32*)openjkdf2_mem_alt_mspace_start + 1), *((u32*)openjkdf2_mem_alt_mspace_start + 2), *((u32*)openjkdf2_mem_alt_mspace_start + 3));
        printf("%02x %04x %08x\n", *((vu8*)0x08000002), *((vu16*)0x08000000), *((vu32*)0x08000004));
        

        openjkdf2_mem_alt_mspace = create_mspace_with_base((void*)openjkdf2_mem_alt_mspace_start, alt_sz, 0);

        printf("Added extra 0x%zx bytes to heap from %s.\n", alt_sz, "EDGBA");

        openjkdf2_bIsLowMemoryPlatform = 1;
        openjkdf2_bIsExtraLowMemoryPlatform = 0;
    } 
    else 
#endif

    // TODO: DS mode slot2 can't r/w u8s
    if (peripheralSlot2Init(SLOT2_PERIPHERAL_EXTRAM)) {
        peripheralSlot2Open(SLOT2_PERIPHERAL_EXTRAM);
        peripheralSlot2EnableCache(true);

        size_t alt_sz = peripheralSlot2RamSize() - 0x1000;
        openjkdf2_mem_alt_mspace_start = (intptr_t)peripheralSlot2RamStart();
        openjkdf2_mem_alt_mspace_end = openjkdf2_mem_alt_mspace_start + alt_sz;        

        openjkdf2_mem_alt_mspace = create_mspace_with_base((void*)openjkdf2_mem_alt_mspace_start, alt_sz, 0);
        openjkdf2_mem_alt_mspace_wordonly = !isDSiMode();

        stdPlatform_Printf("Added extra 0x%zx bytes to heap from %s.\n", alt_sz, peripheralSlot2GetName()); // Added: mirror to emu log

        openjkdf2_bIsLowMemoryPlatform = 1;
        openjkdf2_bIsExtraLowMemoryPlatform = 0;
    }
    else {
        stdPlatform_Printf("No extra RAM available to use.\n"); // Added: mirror to emu log

        openjkdf2_bIsLowMemoryPlatform = 1;
        openjkdf2_bIsExtraLowMemoryPlatform = 1;
    }

    printf("DLDI name:\n%s\n\n", io_dldi_data->friendlyName);
    printf("DSi mode: %d\n\n", isDSiMode());

    bool init_ok = fatInitDefault();
    if (!init_ok)
    {
        perror("fatInitDefault()");
    }
    else
    {
        char *cwd = getcwd(NULL, 0);
        printf("Current dir: %s\n\n", cwd);
        free(cwd);
    }

    // Millisecond timer
    TIMER0_CR = TIMER_ENABLE|TIMER_DIV_1024;
    TIMER1_CR = TIMER_ENABLE|TIMER_CASCADE;

    printf("heap free=0x%x\n  allocated=0x%x\n", (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd(), (intptr_t)getHeapEnd() - (intptr_t)getHeapStart());

    printf("heap start=%p\n  end=%p\n  limit=%p\n", (intptr_t)getHeapStart(), (intptr_t)getHeapEnd(), (intptr_t)getHeapLimit());

    printf("ext heap start=%p, size=%x\n", peripheralSlot2RamStart(), peripheralSlot2RamSize());
    //*(u32*)0x0D000000 = 0x12345678;
    //printf("%x %x\n", *(u32*)0x0C000000, *(u32*)0x0D000000);

#if 0
    // This memleaks with jkRes_pHS! but not with pLowLevelHS so it's my fault, somewhere
    int i = 0;
    while(1) {
        FILE* f = fopen("test_nonexistant.txt", "rb");
        printf("Opened file %d\n", i);
        if (f) {
            fclose(f);
            printf("Closed file %d\n", i);
        }

        stdPlatform_PrintHeapStats();
        i++;
    }
#endif

    // Nice for debugging
#if 0
    while (1) {
        scanKeys();
        u16 keys_held = keysHeld();
        if (!!(keys_held & KEY_A)) {
            break;
        }
    }
#endif

#ifdef TARGET_TWL
    scanKeys();
    u16 keys_held = keysHeld();

    if (!!(keys_held & KEY_B)) {
        Main_bMotsCompat = !Main_bMotsCompat;
    }

    const char* tmpDir = fatGetDefaultDrive();
    chdir(tmpDir);

    char *cwd = getcwd(NULL, 0);
        printf("Current dir: %s\n\n", cwd);
        free(cwd);
#endif

#if 0
    FILE* test = fopen("sd:/test_write.txt", "wb");
    if (test) {
        fwrite("asdf", 4, 1, test);
        printf("Got file open!\n");
        fclose(test);
    }
    else {
        printf("Failed to open.\n");
    }
#endif


#endif
#ifdef TARGET_DREAMCAST
    printf("OpenJKDF2 starting on Sega Dreamcast (KallistiOS)\n");

    // KOS auto-mounts the standard VFS points (/cd GD-ROM, /pc dc-load host,
    // /ram, /sd, /vmu). Game data is expected on the disc; fall back to the
    // dc-load host directory for development.
    if (chdir("/cd") != 0) {
        chdir("/pc");
    }

    {
        char *cwd = getcwd(NULL, 0);
        if (cwd) {
            printf("Current dir: %s\n", cwd);
            free(cwd);
        }
    }

    openjkdf2_bIsLowMemoryPlatform = 1;
    openjkdf2_bIsExtraLowMemoryPlatform = 0;
#endif // TARGET_DREAMCAST
#ifdef WIN64_STANDALONE
    int skipConsoleWindow = 0;
    if ((SDL_GetHintBoolean("SteamClientLaunch", 0) || SDL_GetHintBoolean("SteamOS", 0) || SDL_GetHintBoolean("SteamDeck", 0)) && SDL_GetHintBoolean("SteamGamepadUI", 0)) {
        skipConsoleWindow = 1;
    }

    FILE* fp;
    if (!skipConsoleWindow) {
        AllocConsole();
        freopen_s(&fp, "CONIN$", "r", stdin);
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stdout);
    }

    int can_has_crashdumps = 1;

    OSVERSIONINFOEX info;
    ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
    info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO)&info);//info requires typecasting

    // Apparently Windows 7 has a security update kb4507456
    // which is required for api-ms-win-downlevel-kernel32-l2-1-0.dll.
    // So only try and load drmingw on Win8+ for now.
    //if (info.dwMajorVersion >= 6 && info.dwMinorVersion > 1) {
    //    can_has_crashdumps = 1;
    //}

    if (can_has_crashdumps) {
        HMODULE hLib = LoadLibrary("exchndl.dll");
        if (hLib) {
            void (*pfnExcHndlInit)(void) = GetProcAddress(hLib, "ExcHndlInit");
            pfnExcHndlInit();
        }
    }
#endif // WIN64_STANDALONE

#if !defined(ARCH_WASM) && !defined(TARGET_ANDROID) && !defined(TARGET_TWL)
    openjkdf2_pExecutablePath = argv[0];
#endif // !ARCH_WASM

#ifdef LINUX

#if !defined(ARCH_WASM) && !defined(TARGET_ANDROID)
    signal(SIGSEGV, crash_handler_basic);
    //signal(SIGINT, int_handler);
#endif // !ARCH_WASM

#ifndef ARCH_64BIT
#if !defined(ARCH_WASM) && !defined(TARGET_ANDROID)
    mmap((void*)0x400000, 0x122000, PROT_READ | PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
    mmap((void*)0x522000, 0x500000, PROT_READ | PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
    
    // Fill with illegal instructions
    for (int i = 0; i < 0x500000; i += 2)
    {
        *(uint8_t*)(0x400000+i) = 0x0f;
        *(uint8_t*)(0x400000+i+1) = 0x0b;
    }
    
    // Zero .rodata, .data and .bss before loading
    memset((void*)0x525000, 0, 0x3DE000);
    
    FILE* f = fopen("JK.EXE", "rb");
    if (!f) {
        printf("Failed to open `JK.EXE`! Make sure the file exists in the current working directory.");
        exit(-1);
    }
    
    // text
    fseek(f, 0x400, SEEK_SET);
#ifndef LINUX_TMP
    printf("Using JK.EXE blob...\n");
    fread((void*)0x401000, 0x120200, 1, f);
#endif // !LINUX_TMP

#ifndef NO_JK_MMAP
    // rdata
    fseek(f, 0x120600, SEEK_SET);
    fread((void*)0x522000, 0x2200, 1, f);

    // data
    fseek(f, 0x122800, SEEK_SET);
    fread((void*)0x525000, 0x2DA00, 1, f);
#endif // !NO_JK_MMAP
    fclose(f);
    
    do_hooks();
    
    mprotect((void*)0x400000, 0x122000, PROT_READ | PROT_EXEC);
#endif // !ARCH_WASM
#endif // !ARCH_64BIT
#endif // LINUX

#ifdef PLATFORM_PHYSFS
    PHYSFS_init(argv[0]);
    PHYSFS_permitSymbolicLinks(0);
#endif

    getcwd(openjkdf2_aOrigCwd, sizeof(openjkdf2_aOrigCwd));

    openjkdf2_bOrigWasDF2 = 1;
    for (int i = 1; i < argc; i++) {
        if (!__strcmpi(argv[i], "-motsCompat") || !__strcmpi(argv[i], "/motsCompat")) {
            openjkdf2_bOrigWasDF2 = 0; // Running MoTS.
        }
        else if (!__strcmpi(argv[i], "-path") || !__strcmpi(argv[i], "/path")) {
            openjkdf2_bOrigWasDF2 = 0; // Running some kind of mod.
        }
    }

    while (1)
    {
        OpenJKDF2_Globals_Reset();

        // Set the mod path
        if (openjkdf2_restartMode == OPENJKDF2_RESTART_PATH) {
            stdString_SafeStrCopy(Main_path, openjkdf2_aRestartPath, 128);
        }

        openjkdf2_restartMode = OPENJKDF2_RESTART_NONE;
        memset(openjkdf2_aRestartPath, 0, sizeof(openjkdf2_aRestartPath));
        Window_Main_Linux(argc, argv);

        printf("openjkdf2_bOrigWasRunningFromExistingInstall %x\n", openjkdf2_bOrigWasRunningFromExistingInstall);
        printf("openjkdf2_bIsRunningFromExistingInstall %x\n", openjkdf2_bIsRunningFromExistingInstall);
        printf("openjkdf2_bOrigWasDF2 %x\n", openjkdf2_bOrigWasDF2);

        openjkdf2_bIsFirstLaunch = 0;
        if (openjkdf2_restartMode != OPENJKDF2_RESTART_NONE) {
            // Purge any cmdline args that will get in the way.
            for (int i = 1; i < argc; i++) {
                if (!__strcmpi(argv[i], "-motsCompat") || !__strcmpi(argv[i], "/motsCompat")) {
                    argv[i] = "";
                }
                else if (!__strcmpi(argv[i], "-path") || !__strcmpi(argv[i], "/path")) {
                    argv[i] = "";
                    argv[i+1] = "";
                }
            }

            // Scenario: User has an existing JK.EXE/JKM.EXE replacement install, and wants to run the other game.
            // If we keep the current working directory, it will trigger the jk_.cd checks and not restart correctly.
            // So we override the cwd to the LocalData directory to prevent this.
            if ((openjkdf2_bOrigWasRunningFromExistingInstall && openjkdf2_bOrigWasDF2 && (openjkdf2_restartMode == OPENJKDF2_RESTART_MOTS))
                || (openjkdf2_bOrigWasRunningFromExistingInstall && !openjkdf2_bOrigWasDF2 && (openjkdf2_restartMode == OPENJKDF2_RESTART_DF2))) 
            {
                openjkdf2_bSkipWorkingDirData = 1;
            }
            else {
                openjkdf2_bSkipWorkingDirData = 0;
                chdir(openjkdf2_aOrigCwd);
            }
        }

        if (openjkdf2_restartMode == OPENJKDF2_RESTART_MOTS) {
            Main_bMotsCompat = 1;
            continue;
        }
        else if (openjkdf2_restartMode == OPENJKDF2_RESTART_DF2) {
            Main_bMotsCompat = 0;
            continue;
        }
        else if (openjkdf2_restartMode == OPENJKDF2_RESTART_PATH) {
            continue;
        }
#ifndef ARCH_WASM
        break;
#endif
    }

#ifdef PLATFORM_PHYSFS
    PHYSFS_deinit();
#endif

#ifdef TARGET_TWL
    while (1) {
        scanKeys();
        u16 keys_held = keysHeld();
        if (!!(keys_held & KEY_A)) {
            break;
        }
    }
#endif

    return 1;
}

#ifdef LINUX

//#include "external/libbacktrace/backtrace.h"

#if !defined(ARCH_WASM) && !defined(TARGET_ANDROID)

#if 0
static int
full_callback(void *data __attribute__((unused)), uintptr_t pc, 
              const char *filename, int lineno, const char *function)
{  
   printf("0x%lx %s \t%s:%d\n", (unsigned long) pc, 
          function == NULL ? "???" : function,
          filename == NULL ? "???" : filename, lineno);

   return strcmp(function, "main") == 0 ? 1 : 0;
}


static void
error_callback(void *data, const char *msg, int errnum)
{
   printf("Something went wrong in libbacktrace: %s\n", msg);
}
#endif

static void full_write(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t ret = write(fd, buf, len);

        if ((ret == -1) && (errno != EINTR))
                break;

        buf += (size_t) ret;
        len -= (size_t) ret;
    }
}

void print_backtrace(void)
{
    static const char start[] = "BACKTRACE:\n----------------------\n";
    static const char end[] = "\n\nPlease report this bug to https://github.com/shinyquagsire23/OpenJKDF2/issues\n"
                              "or email me at mtinc2@gmail.com, thanks!\n"
                              "----------------------\n";

    void *bt[1024];
    int bt_size;
    char **bt_syms;
    int i;

    bt_size = backtrace(bt, 1024);
    bt_syms = backtrace_symbols(bt, bt_size);
    full_write(STDERR_FILENO, start, strlen(start));
    for (i = 1; i < bt_size; i++) {
            size_t len = strlen(bt_syms[i]);
            full_write(STDERR_FILENO, bt_syms[i], len);
            full_write(STDERR_FILENO, "\n", 1);
    }
    full_write(STDERR_FILENO, end, strlen(end));

    char* crash_print = (char*)malloc(1024);
    strcpy(crash_print, start);
    for (i = 1; i < bt_size; i++) {
        strcat(crash_print, bt_syms[i]);
        strcat(crash_print, "\n");
    }
    strcat(crash_print, end);

    FILE* f = fopen("crash.log", "a");
    if (f)
    {
        fwrite(crash_print, 1, strlen(crash_print), f);
        fclose(f);
    }

#if 0
#ifdef SDL2_RENDER
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Crash!", crash_print, NULL);
#endif
#endif

    free(crash_print);

    free(bt_syms);
}

void crash_handler_basic(int sig) 
{
    print_backtrace();
    signal(SIGSEGV, SIG_DFL); // Pass error to OS; MacOS has nicer crash diagnostics
}

void crash_handler_full(int sig) 
{
    //struct backtrace_state *lbstate;

    //printf ("Backtrace:\n");
    //lbstate = backtrace_create_state (openjkdf2_pExecutablePath, 1, error_callback, NULL);      
    //backtrace_full(lbstate, 0, full_callback, error_callback, 0);
    exit(1);
}

void int_handler(int sig) {
    //exit(0);
    signal(SIGINT, int_handler);
}
#endif // ARCH_WASM

#endif // LINUX

#ifndef WIN64_STANDALONE
#ifdef WIN32
__declspec(dllexport) void hook_init(void);

__declspec(dllexport) int WinMain_(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd)
{
    Window_Main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, "Jedi Knight");
    return 0;
}

__declspec(dllexport) void hook_init_win(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd)
{
    openjkdf2_bIsKVM = 0;

    DWORD old;
    VirtualProtect((void*)0x401000, 0x522000-0x401000, PAGE_EXECUTE_READWRITE, &old);
    
    hook_init();
    
    VirtualProtect((void*)0x401000, 0x522000-0x401000, old, NULL);
    
    Window_Main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, "Jedi Knight");
}

void _pei386_runtime_relocator(){}

__declspec(dllexport) void hook_init(void)
{
    jk_init();
    do_hooks();
}
#endif // WIN32

int yyparse();
void do_hooks()
{
#ifndef NO_JK_MMAP
#ifndef LINUX
    hook_function(WinMain_ADDR, WinMain_);
#endif // LINUX
    
    // stdPlatform
    hook_function(stdPlatform_Startup_ADDR, stdPlatform_Startup);
    hook_function(stdPlatform_Assert_ADDR, stdPlatform_Assert);
    hook_function(stdPlatform_AllocHandle_ADDR, stdPlatform_AllocHandle);
    hook_function(stdPlatform_FreeHandle_ADDR, stdPlatform_FreeHandle);
    hook_function(stdPlatform_ReallocHandle_ADDR, stdPlatform_ReallocHandle);
    hook_function(stdPlatform_LockHandle_ADDR, stdPlatform_LockHandle);
    hook_function(stdPlatform_UnlockHandle_ADDR, stdPlatform_UnlockHandle);
    hook_function(stdPlatform_InitServices_ADDR, stdPlatform_InitServices);
    hook_function(stdPlatform_GetDateTime_ADDR, stdPlatform_GetDateTime);
    
    // jkMain
    hook_function(jkMain_GuiAdvance_ADDR, jkMain_GuiAdvance);
    hook_function(jkMain_EscapeMenuTick_ADDR, jkMain_EscapeMenuTick);
    hook_function(jkMain_GameplayTick_ADDR, jkMain_GameplayTick);
    hook_function(jkMain_TitleShow_ADDR, jkMain_TitleShow);
    hook_function(jkMain_TitleTick_ADDR, jkMain_TitleTick);
    hook_function(jkMain_TitleLeave_ADDR, jkMain_TitleLeave);
    hook_function(jkMain_MainShow_ADDR, jkMain_MainShow);
    hook_function(jkMain_MainTick_ADDR, jkMain_MainTick);
    hook_function(jkMain_MainLeave_ADDR, jkMain_MainLeave);
    hook_function(jkMain_MissionReload_ADDR, jkMain_MissionReload);
    hook_function(jkMain_MenuReturn_ADDR, jkMain_MenuReturn);
    hook_function(jkMain_CdSwitchShow_ADDR, jkMain_CdSwitchShow);
    hook_function(jkMain_EndLevelScreenShow_ADDR, jkMain_EndLevelScreenShow);
    hook_function(jkMain_EndLevelScreenTick_ADDR, jkMain_EndLevelScreenTick);
    hook_function(jkMain_EndLevelScreenLeave_ADDR, jkMain_EndLevelScreenLeave);
    hook_function(jkMain_VideoShow_ADDR, jkMain_VideoShow);

    // jkEpisode
    hook_function(jkEpisode_LoadVerify_ADDR, jkEpisode_LoadVerify);
    
    // jkHud
    hook_function(jkHud_Startup_ADDR, jkHud_Startup);
    hook_function(jkHud_Shutdown_ADDR, jkHud_Shutdown);
    hook_function(jkHud_Open_ADDR, jkHud_Open);
    hook_function(jkHud_Close_ADDR, jkHud_Close);
    hook_function(jkHud_ClearRects_ADDR, jkHud_ClearRects);
    hook_function(jkHud_Draw_ADDR, jkHud_Draw);
    hook_function(jkHud_GetWeaponAmmo_ADDR, jkHud_GetWeaponAmmo);
    hook_function(jkHud_Chat_ADDR, jkHud_Chat);
    hook_function(jkHud_SendChat_ADDR, jkHud_SendChat);
    hook_function(jkHud_SetTargetColors_ADDR, jkHud_SetTargetColors);
    hook_function(jkHud_SetTarget_ADDR, jkHud_SetTarget);
    hook_function(jkHud_EndTarget_ADDR, jkHud_EndTarget);
    hook_function(jkHud_SortPlayerScore_ADDR, jkHud_SortPlayerScore);
    hook_function(jkHud_SortTeamScore_ADDR, jkHud_SortTeamScore);
    hook_function(jkHud_Tally_ADDR, jkHud_Tally);
    
    // jkHudInv
    hook_function(jkHudInv_ItemDatLoad_ADDR, jkHudInv_ItemDatLoad);
    hook_function(jkHudInv_ClearRects_ADDR, jkHudInv_ClearRects);
    hook_function(jkHudInv_Draw_ADDR, jkHudInv_Draw);
    hook_function(jkHudInv_InputInit_ADDR, jkHudInv_InputInit);
    hook_function(jkHudInv_InitItems_ADDR, jkHudInv_InitItems);
    hook_function(jkHudInv_LoadItemRes_ADDR, jkHudInv_LoadItemRes);
    hook_function(jkHudInv_Close_ADDR, jkHudInv_Close);
    hook_function(jkHudInv_Startup_ADDR, jkHudInv_Startup);
    hook_function(jkHudInv_Shutdown_ADDR, jkHudInv_Shutdown);
    
    // jkCog
    hook_function(jkCog_RegisterVerbs_ADDR, jkCog_RegisterVerbs);
    hook_function(jkCog_Startup_ADDR, jkCog_Startup);
    
    // jkCredits
    hook_function(jkCredits_Startup_ADDR, jkCredits_Startup);
    
    // jkCutscene
    hook_function(jkCutscene_Startup_ADDR, jkCutscene_Startup);
    hook_function(jkCutscene_Shutdown_ADDR, jkCutscene_Shutdown);
    //hook_function(jkCutscene_sub_421310_ADDR, jkCutscene_sub_421310);
    hook_function(jkCutscene_sub_421410_ADDR, jkCutscene_sub_421410);
    hook_function(jkCutscene_smack_related_loops_ADDR, jkCutscene_smack_related_loops);
    hook_function(jkCutscene_PauseShow_ADDR, jkCutscene_PauseShow);
    hook_function(jkCutscene_Handler_ADDR, jkCutscene_Handler);
    
    // jkDev
    hook_function(jkDev_Close_ADDR, jkDev_Close);

#ifdef LINUX
    //hook_function(jkDev_PrintUniString_ADDR, jkDev_PrintUniString);
#endif
    
    // sithCog
    hook_function(sithCog_Startup_ADDR, sithCog_Startup);
    hook_function(sithCog_Shutdown_ADDR, sithCog_Shutdown);
    hook_function(sithCog_ParseSymbolRef_ADDR, sithCog_ParseSymbolRef);
    hook_function(sithCog_ThingSendMessage_ADDR, sithCog_ThingSendMessage);
    hook_function(sithCog_SectorSendMessage_ADDR, sithCog_SectorSendMessage);
    hook_function(sithCog_SectorSendMessageEx_ADDR, sithCog_SectorSendMessageEx);
    hook_function(sithCog_SendMessageEx_ADDR, sithCog_SendMessageEx);
    hook_function(sithCog_FreeWorldCogs_ADDR, sithCog_FreeWorldCogs);
    hook_function(sithCog_UpdateThingTimer_ADDR, sithCog_UpdateThingTimer);
    hook_function(sithCog_GetCogByIndex_ADDR, sithCog_GetCogByIndex);
    hook_function(sithCogFunction_Startup_ADDR, sithCogFunction_Startup);
    hook_function(sithCogFunctionThing_Startup_ADDR, sithCogFunctionThing_Startup);
    hook_function(sithCogFunctionAI_Startup_ADDR, sithCogFunctionAI_Startup);
    hook_function(sithCogFunctionSurface_Startup_ADDR, sithCogFunctionSurface_Startup);
    hook_function(sithCogFunctionSound_Startup_ADDR, sithCogFunctionSound_Startup);
    hook_function(sithCogFunctionSector_Startup_ADDR, sithCogFunctionSector_Startup);
    hook_function(sithCogFunctionPlayer_Startup_ADDR, sithCogFunctionPlayer_Startup);
    hook_function(sithCog_RegisterFunction_ADDR, sithCog_RegisterFunction);
    hook_function(sithCog_AddIntSymbol_ADDR, sithCog_AddIntSymbol);
    hook_function(sithCog_AddFloatSymbol_ADDR, sithCog_AddFloatSymbol);
    hook_function(sithCog_TimerEventTask_ADDR, sithCog_TimerEventTask);
    hook_function(sithCog_CogStatus_ADDR, sithCog_CogStatus);
    
    // sithComm
    hook_function(sithComm_Startup_ADDR, sithComm_Startup);
    hook_function(sithMessage_Shutdown_ADDR, sithMessage_Shutdown);
    hook_function(sithMessage_RegisterFunction_ADDR, sithMessage_RegisterFunction);
    hook_function(sithComm_SendMsgToPlayer_ADDR, sithComm_SendMsgToPlayer);
    hook_function(sithMessage_FileWrite_ADDR, sithMessage_FileWrite);
    hook_function(sithMessage_ProcessMessages_ADDR, sithMessage_ProcessMessages);
    hook_function(sithMessage_StopProcessMessages_ADDR, sithMessage_StopProcessMessages);
    hook_function(sithMessage_Process_ADDR, sithMessage_Process);
    hook_function(sithComm_SyncWithPlayers_ADDR, sithComm_SyncWithPlayers);
    hook_function(sithComm_ClearMsgTmpBuf_ADDR, sithComm_ClearMsgTmpBuf);
    hook_function(sithComm_cogMsg_Reset_ADDR, sithComm_cogMsg_Reset);

    // sithMulti
    hook_function(sithMulti_map_init_related_ADDR, sithMulti_map_init_related);
    hook_function(sithMulti_sub_4CA3B0_ADDR, sithMulti_ResetNetState);
    hook_function(sithMulti_sub_4CA410_ADDR, sithMulti_CleanupThings);
    hook_function(sithMulti_RemovePlayer_ADDR, sithMulti_RemovePlayer);
    hook_function(sithMulti_ProcessPlayerJoin_ADDR, sithMulti_ProcessPlayerJoin);
    hook_function(sithMulti_FinishJoining_ADDR, sithMulti_FinishJoining);

    // sithCog
    hook_function(sithCog_FreeEntry_ADDR, sithCog_FreeEntry);
    hook_function(sithCog_FreeScriptEntry_ADDR, sithCog_FreeScriptEntry);
    hook_function(sithCog_AllocWorldCogScripts_ADDR, sithCog_AllocWorldCogScripts);
    hook_function(sithCog_AllocWorldCogs_ADDR, sithCog_AllocWorldCogs);
    hook_function(sithCog_LinkCogToThing_ADDR, sithCog_LinkCogToThing);
    hook_function(sithCog_LinkCogToSurface_ADDR, sithCog_LinkCogToSurface);
    hook_function(sithCog_LinkCogToSector_ADDR, sithCog_LinkCogToSector);

    // sithCogVm
    hook_function(sithCogExec_Execute_ADDR, sithCogExec_Execute);
    hook_function(sithCogExec_ExecuteMessage_ADDR, sithCogExec_ExecuteMessage);
    hook_function(sithCogExec_PopSymbol_ADDR, sithCogExec_PopSymbol);
    hook_function(sithCogExec_PopFlex_ADDR, sithCogExec_PopFlex);
    hook_function(sithCogExec_PopInt_ADDR, sithCogExec_PopInt);
    hook_function(sithCogExec_PopArray_ADDR, sithCogExec_PopArray);
    hook_function(sithCogExec_PopVector_ADDR, sithCogExec_PopVector);
    hook_function(sithCogExec_PopCog_ADDR, sithCogExec_PopCog);
    hook_function(sithCogExec_PopThing_ADDR, sithCogExec_PopThing);
    hook_function(sithCogExec_PopTemplate_ADDR, sithCogExec_PopTemplate);
    hook_function(sithCogExec_PopSound_ADDR, sithCogExec_PopSound);
    hook_function(sithCogExec_PopSector_ADDR, sithCogExec_PopSector);
    hook_function(sithCogExec_PopSurface_ADDR, sithCogExec_PopSurface);
    hook_function(sithCogExec_PopMaterial_ADDR, sithCogExec_PopMaterial);
    hook_function(sithCogExec_PopModel3_ADDR, sithCogExec_PopModel3);
    hook_function(sithCogExec_PopKeyframe_ADDR, sithCogExec_PopKeyframe);
    hook_function(sithCogExec_PopString_ADDR, sithCogExec_PopString);
    hook_function(sithCogExec_PushStack_ADDR, sithCogExec_PushStack);
    hook_function(sithCogExec_PushInt_ADDR, sithCogExec_PushInt);
    hook_function(sithCogExec_PushFlex_ADDR, sithCogExec_PushFlex);
    hook_function(sithCogExec_PushVector_ADDR, sithCogExec_PushVector);
    hook_function(sithCogExec_GetOpCode_ADDR, sithCogExec_GetOpCode);
    hook_function(sithCogExec_ResetStack_ADDR, sithCogExec_ResetStack);
    hook_function(sithCogExec_PushCallstack_ADDR, sithCogExec_PushCallstack);
    hook_function(sithCogExec_PopCallstack_ADDR, sithCogExec_PopCallstack);
    hook_function(sithCogExec_PopStack_ADDR, sithCogExec_PopStack);
    hook_function(sithCogExec_GetSymbolValue_ADDR, sithCogExec_GetSymbolValue);
    
    // stdBitmap
    hook_function(stdBitmap_Load_ADDR, stdBitmap_Load);
    hook_function(stdBitmap_LoadFromFile_ADDR, stdBitmap_LoadFromFile);
    hook_function(stdBitmap_LoadEntry_ADDR, stdBitmap_LoadEntry);
    //hook_function(stdBitmap_LoadEntryFromFile_ADDR, stdBitmap_LoadEntryFromFile);
    hook_function(stdBitmap_Free_ADDR, stdBitmap_Free);
    hook_function(stdBitmap_FreeEntry_ADDR, stdBitmap_FreeEntry);
    hook_function(stdBitmap_AppendToFile_ADDR, stdBitmap_AppendToFile);
    hook_function(stdBitmap_Write_ADDR, stdBitmap_Write);
    hook_function(stdBitmap_ConvertColorFormat_ADDR, stdBitmap_ConvertColorFormat);
    hook_function(stdBitmap_New_ADDR, stdBitmap_New);
    hook_function(stdBitmap_NewEntry_ADDR, stdBitmap_NewEntry);
    hook_function(stdBitmap_MemUsage_ADDR, stdBitmap_MemUsage);
    
    // stdMath
    hook_function(stdMath_FlexPower_ADDR, stdMath_FlexPower);
    hook_function(stdMath_NormalizeAngle_ADDR, stdMath_NormalizeAngle);
    hook_function(stdMath_NormalizeAngleAcute_ADDR, stdMath_NormalizeAngleAcute);
    hook_function(stdMath_NormalizeDeltaAngle_ADDR, stdMath_NormalizeDeltaAngle);
    hook_function(stdMath_SinCos_ADDR, stdMath_SinCos);
    hook_function(stdMath_Tan_ADDR, stdMath_Tan);
    hook_function(stdMath_ArcSin1_ADDR, stdMath_ArcSin1);
    hook_function(stdMath_ArcSin2_ADDR, stdMath_ArcSin2);
    hook_function(stdMath_ArcSin3_ADDR, stdMath_ArcSin3);
    hook_function(stdMath_ArcTan1_ADDR, stdMath_ArcTan1);
    hook_function(stdMath_ArcTan2_ADDR, stdMath_ArcTan2);
    hook_function(stdMath_ArcTan3_ADDR, stdMath_ArcTan3);
    hook_function(stdMath_ArcTan4_ADDR, stdMath_ArcTan4);
    hook_function(stdMath_FloorDivMod_ADDR, stdMath_FloorDivMod);
    hook_function(stdMath_Dist2D1_ADDR, stdMath_Dist2D1);
    hook_function(stdMath_Dist2D2_ADDR, stdMath_Dist2D2);
    hook_function(stdMath_Dist2D3_ADDR, stdMath_Dist2D3);
    hook_function(stdMath_Dist2D4_ADDR, stdMath_Dist2D4);
    hook_function(stdMath_Dist3D1_ADDR, stdMath_Dist3D1);
    hook_function(stdMath_Dist3D2_ADDR, stdMath_Dist3D2);
    hook_function(stdMath_Dist3D3_ADDR, stdMath_Dist3D3);
    hook_function(stdMath_Floor_ADDR, stdMath_Floor);
    hook_function(stdMath_Sqrt_ADDR, stdMath_Sqrt);
    
    // rdVector
    hook_function(rdVector_Set2_ADDR, rdVector_Set2);
    hook_function(rdVector_Set3_ADDR, rdVector_Set3);
    hook_function(rdVector_Set4_ADDR, rdVector_Set4);
    hook_function(rdVector_Copy2_ADDR, rdVector_Copy2);
    hook_function(rdVector_Copy3_ADDR, rdVector_Copy3);
    hook_function(rdVector_Copy4_ADDR, rdVector_Copy4);
    hook_function(rdVector_Neg2_ADDR, rdVector_Neg2);
    hook_function(rdVector_Neg3_ADDR, rdVector_Neg3);
    hook_function(rdVector_Neg4_ADDR, rdVector_Neg4);
    hook_function(rdVector_Neg2Acc_ADDR, rdVector_Neg2Acc);
    hook_function(rdVector_Neg3Acc_ADDR, rdVector_Neg3Acc);
    hook_function(rdVector_Neg4Acc_ADDR, rdVector_Neg4Acc);
    hook_function(rdVector_Add2_ADDR, rdVector_Add2);
    hook_function(rdVector_Add3_ADDR, rdVector_Add3);
    hook_function(rdVector_Add4_ADDR, rdVector_Add4);
    hook_function(rdVector_Add2Acc_ADDR, rdVector_Add2Acc);
    hook_function(rdVector_Add3Acc_ADDR, rdVector_Add3Acc);
    hook_function(rdVector_Add4Acc_ADDR, rdVector_Add4Acc);
    hook_function(rdVector_Sub2_ADDR, rdVector_Sub2);
    hook_function(rdVector_Sub3_ADDR, rdVector_Sub3);
    hook_function(rdVector_Sub4_ADDR, rdVector_Sub4);
    hook_function(rdVector_Sub2Acc_ADDR, rdVector_Sub2Acc);
    hook_function(rdVector_Sub3Acc_ADDR, rdVector_Sub3Acc);
    hook_function(rdVector_Sub4Acc_ADDR, rdVector_Sub4Acc);
    hook_function(rdVector_Dot2_ADDR, rdVector_Dot2);
    hook_function(rdVector_Dot3_ADDR, rdVector_Dot3);
    hook_function(rdVector_Dot4_ADDR, rdVector_Dot4);
    hook_function(rdVector_Cross3_ADDR, rdVector_Cross3);
    hook_function(rdVector_Cross3Acc_ADDR, rdVector_Cross3Acc);
    hook_function(rdVector_Len2_ADDR, rdVector_Len2);
    hook_function(rdVector_Len3_ADDR, rdVector_Len3);
    hook_function(rdVector_Len4_ADDR, rdVector_Len4);
    hook_function(rdVector_Normalize2_ADDR, rdVector_Normalize2);
    hook_function(rdVector_Normalize3_ADDR, rdVector_Normalize3);
    hook_function(rdVector_Normalize3Quick_ADDR, rdVector_Normalize3Quick);
    hook_function(rdVector_Normalize4_ADDR, rdVector_Normalize4);
    hook_function(rdVector_Normalize2Acc_ADDR, rdVector_Normalize2Acc);
    hook_function(rdVector_Normalize3Acc_ADDR, rdVector_Normalize3Acc);
    hook_function(rdVector_Normalize3QuickAcc_ADDR, rdVector_Normalize3QuickAcc);
    hook_function(rdVector_Normalize4Acc_ADDR, rdVector_Normalize4Acc);
    hook_function(rdVector_Scale2_ADDR, rdVector_Scale2);
    hook_function(rdVector_Scale3_ADDR, rdVector_Scale3);
    hook_function(rdVector_Scale4_ADDR, rdVector_Scale4);
    hook_function(rdVector_Scale2Acc_ADDR, rdVector_Scale2Acc);
    hook_function(rdVector_Scale3Acc_ADDR, rdVector_Scale3Acc);
    hook_function(rdVector_Scale4Acc_ADDR, rdVector_Scale4Acc);
    hook_function(rdVector_InvScale2_ADDR, rdVector_InvScale2);
    hook_function(rdVector_InvScale3_ADDR, rdVector_InvScale3);
    hook_function(rdVector_InvScale4_ADDR, rdVector_InvScale4);
    hook_function(rdVector_InvScale2Acc_ADDR, rdVector_InvScale2Acc);
    hook_function(rdVector_InvScale3Acc_ADDR, rdVector_InvScale3Acc);
    hook_function(rdVector_InvScale4Acc_ADDR, rdVector_InvScale4Acc);
    hook_function(rdVector_Rotate3_ADDR, rdVector_Rotate3);
    hook_function(rdVector_Rotate3Acc_ADDR, rdVector_Rotate3Acc);
    hook_function(rdVector_ExtractAngle_ADDR, rdVector_ExtractAngle);
    
    // sithCogParse
    hook_function(sithCogParse_FreeParseTree_ADDR, sithCogParse_FreeParseTree);
    hook_function(sithCogParse_Load_ADDR, sithCogParse_Load);
    hook_function(sithCogParse_ParseSectionCode_ADDR, sithCogParse_ParseSectionCode);
    hook_function(sithCogParse_DuplicateSymbolTable_ADDR, sithCogParse_DuplicateSymbolTable);
    hook_function(sithCogParse_AllocSymbolTable_ADDR, sithCogParse_AllocSymbolTable);
    hook_function(sithCogParse_ReallocSymbolTable_ADDR, sithCogParse_ReallocSymbolTable);
    hook_function(sithCogParse_FreeSymbolTable_ADDR, sithCogParse_FreeSymbolTable);
    hook_function(sithCogParse_AddSymbol_ADDR, sithCogParse_AddSymbol);
    hook_function(sithCogParse_SetSymbolValue_ADDR, sithCogParse_SetSymbolValue);
    hook_function(sithCogParse_GetSymbol_ADDR, sithCogParse_GetSymbol);
    hook_function(sithCogParse_GetSymbolByID_ADDR, sithCogParse_GetSymbolByID);
    hook_function(sithCogParse_GetSymbolLabel_ADDR, sithCogParse_GetSymbolLabel);
    hook_function(sithCogParse_MakeLeafNode_ADDR, sithCogParse_MakeLeafNode);
    hook_function(sithCogParse_MakeVectorLeafNode_ADDR, sithCogParse_MakeVectorLeafNode);
    hook_function(sithCogParse_MakeNode_ADDR, sithCogParse_MakeNode);
    hook_function(sithCogParse_GetNextLabel_ADDR, sithCogParse_GetNextLabel);
    hook_function(sithCogParse_LexerSetSymbol_ADDR, sithCogParse_LexerSetSymbol);
    hook_function(sithCogParse_LexerSetString_ADDR, sithCogParse_LexerSetString);
    hook_function(sithCogParse_LexerSetVector_ADDR, sithCogParse_LexerSetVector);
    hook_function(sithCogParse_GenerateLabelTable_ADDR, sithCogParse_GenerateLabelTable);
    hook_function(sithCogParse_GenerateCode_ADDR, sithCogParse_GenerateCode);
    hook_function(sithCogParse_ParseSymbolRef_ADDR, sithCogParse_ParseSymbolRef);
    hook_function(sithCogParse_ParseFlex_ADDR, sithCogParse_ParseFlex);
    hook_function(sithCogParse_ParseInt_ADDR, sithCogParse_ParseInt);
    hook_function(sithCogParse_ParseVector_ADDR, sithCogParse_ParseVector);
    hook_function(sithCogParse_ParseMessage_ADDR, sithCogParse_ParseMessage);
    
    hook_function(sithCogYACC_yyerror_ADDR, yyerror);
    hook_function(sithCogYACC_yyparse_ADDR, yyparse);
    hook_function(sithCogYACC_yylex_ADDR, yylex);
    //hook_function(sithCogYACC_yy_get_next_buffer_ADDR, yy_get_next_buffer);
    hook_function(sithCogYACC_yyrestart_ADDR, yyrestart);
    hook_function(sithCogYACC_yy_switch_to_buffer_ADDR, yy_switch_to_buffer);
    hook_function(sithCogYACC_yy_load_buffer_state_ADDR, yy_load_buffer_state);
    hook_function(sithCogYACC_yy_create_buffer_ADDR, yy_create_buffer);
    hook_function(sithCogYACC_yy_delete_buffer_ADDR, yy_delete_buffer);
    hook_function(sithCogYACC_yy_init_buffer_ADDR, yy_init_buffer);
    //hook_function();
    //hook_function(sithCogYACC_yyparse_ADDR, yyparse);*/
    
    // DirectX
    /*hook_function(DirectX_DirectDrawEnumerateA_ADDR, DirectX_DirectDrawEnumerateA);
    hook_function(DirectX_DirectDrawCreate_ADDR, DirectX_DirectDrawCreate);
    hook_function(DirectX_DirectSoundCreate_ADDR, DirectX_DirectSoundCreate);
    hook_function(DirectX_DirectPlayLobbyCreateA_ADDR, DirectX_DirectPlayLobbyCreateA);
    hook_function(DirectX_DirectInputCreateA_ADDR, DirectX_DirectInputCreateA);*/
    
    // sithDplay
    hook_function(stdComm_Startup_ADDR, stdComm_Startup);
    
    // std
    hook_function(stdStartup_ADDR, stdStartup);
    hook_function(stdShutdown_ADDR, stdShutdown);
    hook_function(stdInitServices_ADDR, stdInitServices);
    hook_function(stdGetReturnString_ADDR, stdGetReturnString);
    hook_function(stdCalcBitPos_ADDR, stdCalcBitPos);
    hook_function(stdReadRaw_ADDR, stdReadRaw);
    hook_function(stdFGetc_ADDR, stdFGetc);
    hook_function(stdFPutc_ADDR, stdFPutc);
    
    // stdColor
    hook_function(stdColor_LoadPalette_ADDR, stdColor_LoadPalette);
    hook_function(stdColor_GammaCorrect_ADDR, stdColor_GammaCorrect);
    hook_function(stdColor_FindClosest_ADDR, stdColor_FindClosest);
    hook_function(stdColor_RGBtoHSV_ADDR, stdColor_RGBtoHSV);
    hook_function(stdColor_HSVtoRGB_ADDR, stdColor_HSVtoRGB);
    hook_function(stdColor_BuildRGB16LUT_ADDR, stdColor_BuildRGB16LUT);
    hook_function(stdColor_BuildRGBAKEY16LUT_ADDR, stdColor_BuildRGBAKEY16LUT);
    hook_function(stdColor_BuildRGBA16LUT_ADDR, stdColor_BuildRGBA16LUT);
    hook_function(stdColor_ColorConvertOneRow_ADDR, stdColor_ColorConvertOneRow);
    hook_function(stdColor_ColorConvertOnePixel_ADDR, stdColor_ColorConvertOnePixel);
    hook_function(stdColor_Indexed8ToRGB16_ADDR, stdColor_Indexed8ToRGB16);
    
    // stdConffile
    hook_function(stdConffile_OpenRead_ADDR, stdConffile_OpenRead);
    hook_function(stdConffile_OpenWrite_ADDR, stdConffile_OpenWrite);
    hook_function(stdConffile_OpenMode_ADDR, stdConffile_OpenMode);
    hook_function(stdConffile_Close_ADDR, stdConffile_Close);
    hook_function(stdConffile_CloseWrite_ADDR, stdConffile_CloseWrite);
    hook_function(stdConffile_WriteLine_ADDR, stdConffile_WriteLine);
    hook_function(stdConffile_Write_ADDR, stdConffile_Write);
    hook_function(stdConffile_Printf_ADDR, stdConffile_Printf);
    hook_function(stdConffile_Read_ADDR, stdConffile_Read);
    hook_function(stdConffile_ReadArgsFromStr_ADDR, stdConffile_ReadArgsFromStr);
    hook_function(stdConffile_ReadArgs_ADDR, stdConffile_ReadArgs);
    hook_function(stdConffile_ReadLine_ADDR, stdConffile_ReadLine);
    hook_function(stdConffile_GetFileHandle_ADDR, stdConffile_GetFileHandle);
    
    // stdFont
    hook_function(stdFont_New_ADDR, stdFont_New);
    hook_function(stdFont_Load_ADDR, stdFont_Load);
    hook_function(stdFont_Write_ADDR, stdFont_Write);
    hook_function(stdFont_Free_ADDR, stdFont_Free);
    hook_function(stdFont_Draw1_ADDR, stdFont_Draw1);
    hook_function(stdFont_Draw2_ADDR, stdFont_Draw2);
    hook_function(stdFont_Draw3_ADDR, stdFont_Draw3);
    hook_function(stdFont_Draw4_ADDR, stdFont_Draw4);
    hook_function(stdFont_sub_434EC0_ADDR, stdFont_sub_434EC0);
    hook_function(stdFont_DrawAscii_ADDR, stdFont_DrawAscii);
    hook_function(stdFont_sub_435190_ADDR, stdFont_sub_435190);
    hook_function(stdFont_sub_4352C0_ADDR, stdFont_sub_4352C0);
    hook_function(stdFont_sub_435570_ADDR, stdFont_sub_435570);
    hook_function(stdFont_sub_4355B0_ADDR, stdFont_sub_4355B0);
    hook_function(stdFont_sub_4355F0_ADDR, stdFont_sub_4355F0);
    hook_function(stdFont_sub_4356B0_ADDR, stdFont_sub_4356B0);
    hook_function(stdFont_sub_4357C0_ADDR, stdFont_sub_4357C0);
    hook_function(stdFont_sub_435810_ADDR, stdFont_sub_435810);
    hook_function(stdFont_sub_4358D0_ADDR, stdFont_sub_4358D0);
    hook_function(stdFont_sub_435950_ADDR, stdFont_sub_435950);
    
    // stdFnames
    hook_function(stdFnames_FindMedName_ADDR, stdFnames_FindMedName);
    hook_function(stdFnames_FindExt_ADDR, stdFnames_FindExt);
    hook_function(stdFnames_AddDefaultExt_ADDR, stdFnames_AddDefaultExt);
    hook_function(stdFnames_StripExt_ADDR, stdFnames_StripExt);
    hook_function(stdFnames_StripExtAndDot_ADDR, stdFnames_StripExtAndDot);
    hook_function(stdFnames_ChangeExt_ADDR, stdFnames_ChangeExt);
    hook_function(stdFnames_StripDirAndExt_ADDR, stdFnames_StripDirAndExt);
    hook_function(stdFnames_CopyExt_ADDR, stdFnames_CopyExt);
    hook_function(stdFnames_CopyMedName_ADDR, stdFnames_CopyMedName);
    hook_function(stdFnames_CopyDir_ADDR, stdFnames_CopyDir);
    hook_function(stdFnames_CopyShortName_ADDR, stdFnames_CopyShortName);
    hook_function(stdFnames_Concat_ADDR, stdFnames_Concat);
    hook_function(stdFnames_MakePath_ADDR, stdFnames_MakePath);
    hook_function(stdFnames_MakePath3_ADDR, stdFnames_MakePath3);
    
    // stdFileUtil
    hook_function(stdFileUtil_NewFind_ADDR, stdFileUtil_NewFind);
    hook_function(stdFileUtil_DisposeFind_ADDR, stdFileUtil_DisposeFind);
    hook_function(stdFileUtil_FindReset_ADDR, stdFileUtil_FindReset);
    hook_function(stdFileUtil_FindNext_ADDR, stdFileUtil_FindNext);
    hook_function(stdFileUtil_FindQuick_ADDR, stdFileUtil_FindQuick);
    hook_function(stdFileUtil_CountMatches_ADDR, stdFileUtil_CountMatches);
    hook_function(stdFileUtil_MkDir_ADDR, stdFileUtil_MkDir);
    hook_function(stdFileUtil_DirExists_ADDR, stdFileUtil_DirExists);
    hook_function(stdFileUtil_RmDir_ADDR, stdFileUtil_RmDir);
    hook_function(stdFileUtil_DelFile_ADDR, stdFileUtil_DelFile);
    
    // stdGob
    hook_function(stdGob_Startup_ADDR, stdGob_Startup);
    hook_function(stdGob_Shutdown_ADDR, stdGob_Shutdown);
    hook_function(stdGob_Load_ADDR, stdGob_Load);
    hook_function(stdGob_LoadEntry_ADDR, stdGob_LoadEntry);
    hook_function(stdGob_Free_ADDR, stdGob_Free);
    hook_function(stdGob_FreeEntry_ADDR, stdGob_FreeEntry);
    hook_function(stdGob_FileOpen_ADDR, stdGob_FileOpen);
    hook_function(stdGob_FileClose_ADDR, stdGob_FileClose);
    hook_function(stdGob_FSeek_ADDR, stdGob_FSeek);
    hook_function(stdGob_FTell_ADDR, stdGob_FTell);
    hook_function(stdGob_FEof_ADDR, stdGob_FEof);
    hook_function(stdGob_FileRead_ADDR, stdGob_FileRead);
    hook_function(stdGob_FileGets_ADDR, stdGob_FileGets);
    hook_function(stdGob_FileGetws_ADDR, stdGob_FileGetws);
    
    // stdMci
    hook_function(stdMci_Startup_ADDR, stdMci_Startup);
    hook_function(stdMci_Shutdown_ADDR, stdMci_Shutdown);
    hook_function(stdMci_Play_ADDR, stdMci_Play);
    hook_function(stdMci_SetVolume_ADDR, stdMci_SetVolume);
    hook_function(stdMci_Stop_ADDR, stdMci_Stop);
    hook_function(stdMci_CheckStatus_ADDR, stdMci_CheckStatus);
    hook_function(stdMci_GetTrackLength_ADDR, stdMci_GetTrackLength);
    
    // stdHashTable
    hook_function(stdHashTable_HashStringToIdx_ADDR, stdHashTable_HashStringToIdx);
    hook_function(stdHashTable_New_ADDR, stdHashTable_New);
    hook_function(stdHashTable_GetBucketTail_ADDR, stdHashTable_GetBucketTail);
    hook_function(stdHashTable_FreeBuckets_ADDR, stdHashTable_FreeBuckets);
    hook_function(stdHashTable_Free_ADDR, stdHashTable_Free);
    hook_function(stdHashTable_SetKeyVal_ADDR, stdHashTable_SetKeyVal);
    hook_function(stdHashTable_GetKeyVal_ADDR, stdHashTable_GetKeyVal);
    hook_function(stdHashTable_FreeKey_ADDR, stdHashTable_FreeKey);
    hook_function(stdHashTable_PrintDiagnostics_ADDR, stdHashTable_PrintDiagnostics);
    hook_function(stdHashTable_Dump_ADDR, stdHashTable_Dump);

    // stdLinkList
    hook_function(stdLinklist_InsertAfter_ADDR, stdLinklist_InsertAfter);
    hook_function(stdLinklist_InsertBefore_ADDR, stdLinklist_InsertBefore);
    hook_function(stdLinklist_InsertAtEnd_ADDR, stdLinklist_InsertAtEnd);
    hook_function(stdLinklist_UnlinkChild_ADDR, stdLinklist_UnlinkChild);
    hook_function(stdLinklist_NumChildren_ADDR, stdLinklist_NumChildren);
    hook_function(stdLinklist_RemoveParent_ADDR, stdLinklist_RemoveParent);
    hook_function(stdLinklist_UnlinkNode_ADDR, stdLinklist_UnlinkNode);
    hook_function(stdLinklist_GetNthChild_ADDR, stdLinklist_GetNthChild);
    hook_function(stdLinklist_GetHead_ADDR, stdLinklist_GetHead);
    hook_function(stdLinklist_GetTail_ADDR, stdLinklist_GetTail);

    // stdPalEffects
    hook_function(stdPalEffects_Open_ADDR, stdPalEffects_Open);
    hook_function(stdPalEffects_Close_ADDR, stdPalEffects_Close);
    hook_function(stdPalEffects_NewRequest_ADDR, stdPalEffects_NewRequest);
    hook_function(stdPalEffects_FreeRequest_ADDR, stdPalEffects_FreeRequest);
    hook_function(stdPalEffects_GetEffectPointer_ADDR, stdPalEffects_GetEffectPointer);
    hook_function(stdPalEffects_FlushAllEffects_ADDR, stdPalEffects_FlushAllEffects);
    hook_function(stdPalEffects_SetPaletteFunc_ADDR, stdPalEffects_SetPaletteFunc);
    hook_function(stdPalEffects_RefreshPalette_ADDR, stdPalEffects_RefreshPalette);
    hook_function(stdPalEffects_ResetEffectsState_ADDR, stdPalEffects_ResetEffectsState);
    hook_function(stdPalEffects_ResetEffect_ADDR, stdPalEffects_ResetEffect);
    hook_function(stdPalEffects_UpdatePalette_ADDR, stdPalEffects_UpdatePalette);
    hook_function(stdPalEffects_GatherEffects_ADDR, stdPalEffects_GatherEffects);
    hook_function(stdPalEffects_SetUnk_ADDR, stdPalEffects_SetStateBools);
    hook_function(stdPalEffects_SetFilter_ADDR, stdPalEffects_SetFilter);
    hook_function(stdPalEffects_SetTint_ADDR, stdPalEffects_SetTint);
    hook_function(stdPalEffects_SetAdd_ADDR, stdPalEffects_SetAdd);
    hook_function(stdPalEffects_SetFade_ADDR, stdPalEffects_SetFade);
    hook_function(stdPalEffects_ApplyFilter_ADDR, stdPalEffects_ApplyFilter);
    hook_function(stdPalEffects_ApplyTint_ADDR, stdPalEffects_ApplyTint);
    hook_function(stdPalEffects_ApplyAdd_ADDR, stdPalEffects_ApplyAdd);
    hook_function(stdPalEffects_ApplyFade_ADDR, stdPalEffects_ApplyFade);
    
    // stdString
    hook_function(stdString_FastCopy_ADDR, stdString_FastCopy);
    hook_function(stdString_snprintf_ADDR, stdString_snprintf);
    hook_function(stdString_CopyBetweenDelimiter_ADDR, stdString_CopyBetweenDelimiter);
    hook_function(stdString_GetQuotedStringContents_ADDR, stdString_GetQuotedStringContents);
    hook_function(stdString_CharToWchar_ADDR, stdString_CharToWchar);
    hook_function(stdString_WcharToChar_ADDR, stdString_WcharToChar);
    hook_function(stdString_WstrRemoveCharsAt_ADDR, stdString_WstrRemoveCharsAt);
    hook_function(stdString_wstrncat_ADDR, stdString_wstrncat);
    hook_function(stdString_CstrCopy_ADDR, stdString_CstrCopy);
    hook_function(stdString_WcharCopy_ADDR, stdString_WcharCopy);
    hook_function(stdString_CStrToLower_ADDR, stdString_CStrToLower);
    
    // stdStrTable
    hook_function(stdStrTable_Load_ADDR, stdStrTable_Load);
    hook_function(stdStrTable_Free_ADDR, stdStrTable_Free);
    hook_function(stdStrTable_GetUniString_ADDR, stdStrTable_GetUniString);
    hook_function(stdStrTable_GetStringWithFallback_ADDR, stdStrTable_GetStringWithFallback);
    hook_function(stdStrTable_ParseLine_ADDR, stdStrTable_ParseLine);
    hook_function(stdStrTable_ParseUniLine_ADDR, stdStrTable_ParseUniLine);

    // stdPcx
    hook_function(stdPcx_Load_ADDR, stdPcx_Load);
    hook_function(stdPcx_Write_ADDR, stdPcx_Write);

    // stdBmp
    hook_function(stdBmp_Load_ADDR, stdBmp_Load);
    hook_function(stdBmp_LoadEntryFromFile_ADDR, stdBmp_LoadEntryFromFile);
    hook_function(stdBmp_Write_ADDR, stdBmp_Write);

    // stdLbm
    hook_function(stdLbm_Compress_ADDR, stdLbm_Compress);

    // util
    hook_function(util_FileExists_ADDR, util_FileExists);
    hook_function(util_unkcomparison1_ADDR, util_RectsOverlap);
    hook_function(util_unkcomparison2_ADDR, util_RectsOverlapExclusive);
    hook_function(util_unkcomparison3_ADDR, util_RectUnion);
    hook_function(util_Weirdchecksum_ADDR, util_Weirdchecksum);

    // sithStrTable
    hook_function(sithStrTable_Startup_ADDR, sithStrTable_Startup);
    hook_function(sithStrTable_Shutdown_ADDR, sithStrTable_Shutdown);
    hook_function(sithStrTable_GetUniString_ADDR, sithStrTable_GetUniString);
    hook_function(sithStrTable_GetUniStringWithFallback_ADDR, sithStrTable_GetUniStringWithFallback);

#ifndef LINUX
    // stdConsole
    hook_function(stdConsole_Startup_ADDR, stdConsole_Startup);
    hook_function(stdConsole_Shutdown_ADDR, stdConsole_Shutdown);
    hook_function(stdConsole_New_ADDR, stdConsole_New);
    hook_function(stdConsole_Free_ADDR, stdConsole_Free);
    hook_function(stdConsole_SetCursorPos_ADDR, stdConsole_SetCursorPos);
    hook_function(stdConsole_GetCursorPos_ADDR, stdConsole_GetCursorPos);
    hook_function(stdConsole_ToggleCursor_ADDR, stdConsole_ToggleCursor);
    hook_function(stdConsole_GetTextAttribute_ADDR, stdConsole_GetTextAttribute);
    hook_function(stdConsole_SetTextAttribute_ADDR, stdConsole_SetTextAttribute);
    hook_function(stdConsole_Flush_ADDR, stdConsole_Flush);
    hook_function(stdConsole_Clear_ADDR, stdConsole_Clear);
    hook_function(stdConsole_Reset_ADDR, stdConsole_Reset);
    hook_function(stdConsole_Putc_ADDR, stdConsole_Putc);
    hook_function(stdConsole_Puts_ADDR, stdConsole_Puts);
    hook_function(stdConsole_ClearBuf_ADDR, stdConsole_ClearBuf);
    hook_function(stdConsole_ClearBuf2_ADDR, stdConsole_ClearBuf2);
    hook_function(stdConsole_WriteBorderMaybe_ADDR, stdConsole_WriteBorderMaybe);
    hook_function(stdConsole_WriteBorderMaybe2_ADDR, stdConsole_WriteBorderMaybe2);
    hook_function(stdConsole_WriteBorderMaybe3_ADDR, stdConsole_WriteBorderMaybe3);
    hook_function(stdConsole_WriteBorderMaybe4_ADDR, stdConsole_WriteBorderMaybe4);
#endif

    // sithDSSCog
    hook_function(sithDSSCog_SendMessage_ADDR, sithDSSCog_SendMessage);
    hook_function(sithDSSCog_ProcessMessage_ADDR, sithDSSCog_ProcessMessage);
    hook_function(sithDSSCog_SyncCogState_ADDR, sithDSSCog_SyncCogState);
    
    // Window
    hook_function(Window_AddMsgHandler_ADDR, Window_AddMsgHandler);
    hook_function(Window_RemoveMsgHandler_ADDR, Window_RemoveMsgHandler); // TODO ???
    //hook_function(Window_msg_main_handler_ADDR, Window_msg_main_handler);
    hook_function(Window_SetDrawHandlers_ADDR, Window_SetDrawHandlers);
    hook_function(Window_GetDrawHandlers_ADDR, Window_GetDrawHandlers);
    
    // Windows
    hook_function(Windows_Startup_ADDR, Windows_Startup);
    hook_function(Windows_Shutdown_ADDR, Windows_Shutdown);
    hook_function(Windows_InitWindow_ADDR, Windows_InitWindow);
    hook_function(Windows_InitGdi_ADDR, Windows_InitGdi);
    hook_function(Windows_ShutdownGdi_ADDR, Windows_ShutdownGdi);
    hook_function(Windows_CalibrateJoystick_ADDR, Windows_CalibrateJoystick);
    hook_function(Windows_DefaultHandler_ADDR, Windows_DefaultHandler);
    hook_function(Windows_GdiHandler_ADDR, Windows_GdiHandler);
    hook_function(Windows_ErrorMsgboxWide_ADDR, Windows_ErrorMsgboxWide);
    hook_function(Windows_ErrorMsgbox_ADDR, Windows_ErrorMsgbox);
    hook_function(Windows_GameErrorMsgbox_ADDR, Windows_GameErrorMsgbox);
    
    // wuRegistry
    hook_function(wuRegistry_Startup_ADDR, wuRegistry_Startup);
    hook_function(wuRegistry_Shutdown_ADDR, wuRegistry_Shutdown);
    hook_function(wuRegistry_SaveInt_ADDR, wuRegistry_SaveInt);
    hook_function(wuRegistry_SaveFloat_ADDR, wuRegistry_SaveFloat);
    hook_function(wuRegistry_GetInt_ADDR, wuRegistry_GetInt);
    hook_function(wuRegistry_GetFloat_ADDR, wuRegistry_GetFloat);
    hook_function(wuRegistry_SaveBool_ADDR, wuRegistry_SaveBool);
    hook_function(wuRegistry_GetBool_ADDR, wuRegistry_GetBool);
    hook_function(wuRegistry_SaveBytes_ADDR, wuRegistry_SaveBytes);
    hook_function(wuRegistry_GetBytes_ADDR, wuRegistry_GetBytes);
    hook_function(wuRegistry_SetString_ADDR, wuRegistry_SetString);
    hook_function(wuRegistry_GetString_ADDR, wuRegistry_GetString);
    
#ifndef LINUX
    // stdGdi
    hook_function(stdGdi_Create8bppPaletted_ADDR, stdGdi_Create8bppPaletted);
    hook_function(stdGdi_CreateRGB_ADDR, stdGdi_CreateRGB);
    hook_function(stdGdi_Create16bppPaletted_ADDR, stdGdi_Create16bppPaletted);
    hook_function(stdGdi_SetPalette_ADDR, stdGdi_SetPalette);
    hook_function(stdGdi_SetPalette2_ADDR, stdGdi_SetPalette2);
    hook_function(stdGdi_GetSystemInfo_ADDR, stdGdi_GetSystemInfo);
    hook_function(stdGdi_SetHwnd_ADDR, stdGdi_SetHwnd);
    hook_function(stdGdi_GetHwnd_ADDR, stdGdi_GetHwnd);
    hook_function(stdGdi_SetHInstance_ADDR, stdGdi_SetHInstance);
    hook_function(stdGdi_GetHInstance_ADDR, stdGdi_GetHInstance);
#else
    hook_function(stdGdi_GetHInstance_ADDR, stdGdi_GetHInstance);
    hook_function(stdGdi_GetHwnd_ADDR, stdGdi_GetHwnd);
#endif
    
    // stdMemory
    hook_function(stdMemory_Startup_ADDR, stdMemory_Startup);
    hook_function(stdMemory_Shutdown_ADDR, stdMemory_Shutdown);
    hook_function(stdMemory_Open_ADDR, stdMemory_Open);
    hook_function(stdMemory_Dump_ADDR, stdMemory_Dump);
    hook_function(stdMemory_BlockAlloc_ADDR, stdMemory_BlockAlloc);
    hook_function(stdMemory_BlockFree_ADDR, stdMemory_BlockFree);
    hook_function(stdMemory_BlockRealloc_ADDR, stdMemory_BlockRealloc);
    
    // rdroid
    hook_function(rdStartup_ADDR, rdStartup);
    hook_function(rdShutdown_ADDR, rdShutdown);
    hook_function(rdOpen_ADDR, rdOpen);
    hook_function(rdClose_ADDR, rdClose);
    hook_function(rdSetRenderOptions_ADDR, rdSetRenderOptions);
    hook_function(rdSetGeometryMode_ADDR, rdSetGeometryMode);
    hook_function(rdSetLightingMode_ADDR, rdSetLightingMode);
    hook_function(rdSetTextureMode_ADDR, rdSetTextureMode);
    hook_function(rdSetSortingMethod_ADDR, rdSetSortingMethod);
    hook_function(rdSetOcclusionMethod_ADDR, rdSetOcclusionMethod);
    hook_function(rdSetZBufferMethod_ADDR, rdSetZBufferMethod);
    hook_function(rdSetCullFlags_ADDR, rdSetCullFlags);
    hook_function(rdSetProcFaceUserData_ADDR, rdSetProcFaceUserData);
    hook_function(rdGetRenderOptions_ADDR, rdGetRenderOptions);
    hook_function(rdGetGeometryMode_ADDR, rdGetGeometryMode);
    hook_function(rdGetLightingMode_ADDR, rdGetLightingMode);
    hook_function(rdGetTextureMode_ADDR, rdGetTextureMode);
    hook_function(rdGetSortingMethod_ADDR, rdGetSortingMethod);
    hook_function(rdGetOcclusionMethod_ADDR, rdGetOcclusionMethod);
    hook_function(rdGetZBufferMethod_ADDR, rdGetZBufferMethod);
    hook_function(rdGetCullFlags_ADDR, rdGetCullFlags);
    hook_function(rdGetProcFaceUserData_ADDR, rdGetProcFaceUserData);
    hook_function(rdSetMipDistances_ADDR, rdSetMipDistances);
    hook_function(rdSetColorEffects_ADDR, rdSetColorEffects);
    hook_function(rdAdvanceFrame_ADDR, rdAdvanceFrame);
    hook_function(rdFinishFrame_ADDR, rdFinishFrame);
    hook_function(rdClearPostStatistics_ADDR, rdClearPostStatistics);
    
    // rdActive
    hook_function(rdActive_Startup_ADDR, rdActive_Startup);
    hook_function(rdActive_AdvanceFrame_ADDR, rdActive_AdvanceFrame);
    hook_function(rdActive_ClearFrameCounters_ADDR, rdActive_ClearFrameCounters);
    
#if 0
    // rdKeyframe
    hook_function(rdKeyframe_RegisterLoader_ADDR, rdKeyframe_RegisterLoader);
    hook_function(rdKeyframe_RegisterUnloader_ADDR, rdKeyframe_RegisterUnloader);
    hook_function(rdKeyframe_NewEntry_ADDR, rdKeyframe_NewEntry);
    hook_function(rdKeyframe_Load_ADDR, rdKeyframe_Load);
    hook_function(rdKeyframe_LoadEntry_ADDR, rdKeyframe_LoadEntry);
    hook_function(rdKeyframe_Write_ADDR, rdKeyframe_Write);
    hook_function(rdKeyframe_Free_ADDR, rdKeyframe_Free);
    hook_function(rdKeyframe_FreeEntry_ADDR, rdKeyframe_FreeEntry);
#endif
    
    // rdLight
    hook_function(rdLight_New_ADDR, rdLight_New);
    hook_function(rdLight_NewEntry_ADDR, rdLight_NewEntry);
    hook_function(rdLight_Free_ADDR, rdLight_Free);
    hook_function(rdLight_FreeEntry_ADDR, rdLight_FreeEntry);
    hook_function(rdLight_CalcVertexIntensities_ADDR, rdLight_CalcVertexIntensities);
    hook_function(rdLight_CalcFaceIntensity_ADDR, rdLight_CalcFaceIntensity);
    
    // rdMaterial
    hook_function(rdMaterial_RegisterLoader_ADDR, rdMaterial_RegisterLoader);
    hook_function(rdMaterial_RegisterUnloader_ADDR, rdMaterial_RegisterUnloader);
    hook_function(rdMaterial_Load_ADDR, rdMaterial_Load);
    hook_function(rdMaterial_LoadEntry_ADDR, rdMaterial_LoadEntry);
    hook_function(rdMaterial_Free_ADDR, rdMaterial_Free);
    hook_function(rdMaterial_FreeEntry_ADDR, rdMaterial_FreeEntry);
    hook_function(rdMaterial_AddToTextureCache_ADDR, rdMaterial_AddToTextureCache);
    hook_function(rdMaterial_ResetCacheInfo_ADDR, rdMaterial_ResetCacheInfo);
    
    // rdPolyLine
    hook_function(rdPolyLine_New_ADDR, rdPolyLine_New);
    hook_function(rdPolyLine_NewEntry_ADDR, rdPolyLine_NewEntry);
    hook_function(rdPolyLine_Free_ADDR, rdPolyLine_Free);
    hook_function(rdPolyLine_FreeEntry_ADDR, rdPolyLine_FreeEntry);
    hook_function(rdPolyLine_Draw_ADDR, rdPolyLine_Draw);
    hook_function(rdPolyLine_DrawFace_ADDR, rdPolyLine_DrawFace);
    
    // rdCache
    hook_function(rdCache_Startup_ADDR, rdCache_Startup);
    hook_function(rdCache_AdvanceFrame_ADDR, rdCache_AdvanceFrame);
    hook_function(rdCache_FinishFrame_ADDR, rdCache_FinishFrame);
    hook_function(rdCache_Reset_ADDR, rdCache_Reset);
    hook_function(rdCache_ClearFrameCounters_ADDR, rdCache_ClearFrameCounters);
    hook_function(rdCache_GetProcEntry_ADDR, rdCache_GetProcEntry);
    hook_function(rdCache_Flush_ADDR, rdCache_Flush);
    hook_function(rdCache_SendFaceListToHardware_ADDR, rdCache_SendFaceListToHardware);
    hook_function(rdCache_ResetRenderList_ADDR, rdCache_ResetRenderList);
    hook_function(rdCache_DrawRenderList_ADDR, rdCache_DrawRenderList);
    hook_function(rdCache_TriCompare_ADDR, rdCache_TriCompare);
    hook_function(rdCache_AddProcFace_ADDR, rdCache_AddProcFace);
    
    // rdColormap
    hook_function(rdColormap_SetCurrent_ADDR, rdColormap_SetCurrent);
    hook_function(rdColormap_SetIdentity_ADDR, rdColormap_SetIdentity);
    hook_function(rdColormap_Load_ADDR, rdColormap_Load);
    hook_function(rdColormap_Free_ADDR, rdColormap_Free);
    hook_function(rdColormap_FreeEntry_ADDR, rdColormap_FreeEntry);
    hook_function(rdColormap_Write_ADDR, rdColormap_Write);
    
    // rdClip
    hook_function(rdClip_Line2_ADDR, rdClip_Line2);
    hook_function(rdClip_CalcOutcode2_ADDR, rdClip_CalcOutcode2);
    hook_function(rdClip_Point3_ADDR, rdClip_Point3);
    hook_function(rdClip_Line3Project_ADDR, rdClip_Line3Project);
    hook_function(rdClip_Line3Ortho_ADDR, rdClip_Line3Ortho);
    hook_function(rdClip_Line3_ADDR, rdClip_Line3);
    
    hook_function(rdClip_SphereInFrustum_ADDR, rdClip_SphereInFrustum);
    
    //hook_function(rdClip_Face3W_ADDR, rdClip_Face3W);
    //hook_function(rdClip_Face3GT_ADDR, rdClip_Face3GT);
    //hook_function(rdClip_Face3S_ADDR, rdClip_Face3S);
    //hook_function(rdClip_Face3GS_ADDR, rdClip_Face3GS);
    
    // rdFace
    hook_function(rdFace_New_ADDR, rdFace_New);
    hook_function(rdFace_NewEntry_ADDR, rdFace_NewEntry);
    hook_function(rdFace_Free_ADDR, rdFace_Free);
    hook_function(rdFace_FreeEntry_ADDR, rdFace_FreeEntry);
    
    // rdMath
    hook_function(rdMath_CalcSurfaceNormal_ADDR, rdMath_CalcSurfaceNormal);
    hook_function(rdMath_DistancePointToPlane_ADDR, rdMath_DistancePointToPlane);
    hook_function(rdMath_DeltaAngleNormalizedAbs_ADDR, rdMath_DeltaAngleNormalizedAbs);
    hook_function(rdMath_DeltaAngleNormalized_ADDR, rdMath_DeltaAngleNormalized);
    hook_function(rdMath_ClampVector_ADDR, rdMath_ClampVector);
    hook_function(rdMath_PointsCollinear_ADDR, rdMath_PointsCollinear);
    
    // rdPrimit2
    hook_function(rdPrimit2_DrawLine_ADDR, rdPrimit2_DrawLine);
    hook_function(rdPrimit2_DrawClippedLine_ADDR, rdPrimit2_DrawClippedLine);
    hook_function(rdPrimit2_DrawCircle_ADDR, rdPrimit2_DrawCircle);
    hook_function(rdPrimit2_DrawRectangle_ADDR, rdPrimit2_DrawRectangle);
    hook_function(rdPrimit2_DrawTriangle_ADDR, rdPrimit2_DrawTriangle);

    // rdPrimit3
    //hook_function(rdPrimit3_ClipFace_ADDR, rdPrimit3_ClipFace);
    hook_function(rdPrimit3_NoClipFace_ADDR, rdPrimit3_NoClipFace);
    hook_function(rdPrimit3_GetScreenCoord_ADDR, rdPrimit3_GetScreenCoord);
    
    // rdRaster
    hook_function(rdRaster_Startup_ADDR, rdRaster_Startup);
    
    // rdCanvas
    hook_function(rdCanvas_New_ADDR, rdCanvas_New);
    hook_function(rdCanvas_NewEntry_ADDR, rdCanvas_NewEntry);
    hook_function(rdCanvas_Free_ADDR, rdCanvas_Free);
    hook_function(rdCanvas_FreeEntry_ADDR, rdCanvas_FreeEntry);
    
    // rdModel3
    hook_function(rdModel3_RegisterLoader_ADDR, rdModel3_RegisterLoader);
    hook_function(rdModel3_RegisterUnloader_ADDR, rdModel3_RegisterUnloader);
    hook_function(rdModel3_ClearFrameCounters_ADDR, rdModel3_ClearFrameCounters);
    hook_function(rdModel3_NewEntry_ADDR, rdModel3_NewEntry);
    hook_function(rdModel3_New_ADDR, rdModel3_New);
    hook_function(rdModel3_Load_ADDR, rdModel3_Load);
    hook_function(rdModel3_LoadPostProcess_ADDR, rdModel3_LoadPostProcess);
    hook_function(rdModel3_WriteText_ADDR, rdModel3_WriteText);
    hook_function(rdModel3_Free_ADDR, rdModel3_Free);
    hook_function(rdModel3_FreeEntry_ADDR, rdModel3_FreeEntry);
    hook_function(rdModel3_FreeEntryGeometryOnly_ADDR, rdModel3_FreeEntryGeometryOnly);
    hook_function(rdModel3_Validate_ADDR, rdModel3_Validate);
    hook_function(rdModel3_CalcBoundingBoxes_ADDR, rdModel3_CalcBoundingBoxes);
    hook_function(rdModel3_BuildExpandedRadius_ADDR, rdModel3_BuildExpandedRadius);
    hook_function(rdModel3_CalcFaceNormals_ADDR, rdModel3_CalcFaceNormals);
    //hook_function(rdModel3_CalcVertexNormals_ADDR, rdModel3_CalcVertexNormals);
    hook_function(rdModel3_FindNamedNode_ADDR, rdModel3_FindNamedNode);
    hook_function(rdModel3_GetMeshMatrix_ADDR, rdModel3_GetMeshMatrix);
    hook_function(rdModel3_ReplaceMesh_ADDR, rdModel3_ReplaceMesh);
    hook_function(rdModel3_Draw_ADDR, rdModel3_Draw);
    hook_function(rdModel3_DrawHNode_ADDR, rdModel3_DrawHNode);
    hook_function(rdModel3_DrawMesh_ADDR,rdModel3_DrawMesh);
    hook_function(rdModel3_DrawFace_ADDR,rdModel3_DrawFace);
    
    // rdParticle
    hook_function(rdParticle_RegisterLoader_ADDR, rdParticle_RegisterLoader);
    hook_function(rdParticle_New_ADDR, rdParticle_New);
    hook_function(rdParticle_NewEntry_ADDR, rdParticle_NewEntry);
    hook_function(rdParticle_Clone_ADDR, rdParticle_Clone);
    hook_function(rdParticle_Free_ADDR, rdParticle_Free);
    hook_function(rdParticle_FreeEntry_ADDR, rdParticle_FreeEntry);
    hook_function(rdParticle_Load_ADDR, rdParticle_Load);
    hook_function(rdParticle_LoadEntry_ADDR, rdParticle_LoadEntry);
    hook_function(rdParticle_Write_ADDR, rdParticle_Write);
    hook_function(rdParticle_Draw_ADDR, rdParticle_Draw);

#if 0
    // rdPuppet
    hook_function(rdPuppet_FreeEntry_ADDR, rdPuppet_FreeEntry);
    hook_function(rdPuppet_SetPause_ADDR, rdPuppet_SetPause);
    hook_function(rdPuppet_SetTrackNoise_ADDR, rdPuppet_SetTrackNoise);
    hook_function(rdPuppet_SetTrackPriority_ADDR, rdPuppet_SetTrackPriority);
    hook_function(rdPuppet_BuildJointMatrices_ADDR, rdPuppet_BuildJointMatrices);
    //hook_function(rdPuppet_UpdateTracks_ADDR, rdPuppet_UpdateTracks);
    hook_function(rdPuppet_AddTrack_ADDR, rdPuppet_AddTrack);
    hook_function(rdPuppet_SetCallback_ADDR, rdPuppet_SetCallback);
    hook_function(rdPuppet_FadeInTrack_ADDR, rdPuppet_FadeInTrack);
    hook_function(rdPuppet_FadeOutTrack_ADDR, rdPuppet_FadeOutTrack);
    hook_function(rdPuppet_SetTrackSpeed_ADDR, rdPuppet_SetTrackSpeed);
    hook_function(rdPuppet_SetStatus_ADDR, rdPuppet_SetStatus);
    hook_function(rdPuppet_PlayTrack_ADDR, rdPuppet_PlayTrack);
    hook_function(rdPuppet_unk_ADDR, rdPuppet_unk);
    //hook_function(rdPuppet_AdvanceTrack_ADDR, rdPuppet_AdvanceTrack);
    hook_function(rdPuppet_RemoveTrack_ADDR, rdPuppet_RemoveTrack);
#endif
    
    // rdSprite
    hook_function(rdSprite_New_ADDR, rdSprite_New);
    hook_function(rdSprite_NewEntry_ADDR, rdSprite_NewEntry);
    hook_function(rdSprite_Free_ADDR, rdSprite_Free);
    hook_function(rdSprite_FreeEntry_ADDR, rdSprite_FreeEntry);
    hook_function(rdSprite_Draw_ADDR, rdSprite_Draw);
    
    // rdThing
    hook_function(rdThing_New_ADDR, rdThing_New);
    hook_function(rdThing_NewEntry_ADDR, rdThing_NewEntry);
    hook_function(rdThing_Free_ADDR, rdThing_Free);
    hook_function(rdThing_FreeEntry_ADDR, rdThing_FreeEntry);
    hook_function(rdThing_SetModel3_ADDR, rdThing_SetModel3);
    hook_function(rdThing_SetCamera_ADDR, rdThing_SetCamera);
    hook_function(rdThing_SetLight_ADDR, rdThing_SetLight);
    hook_function(rdThing_SetSprite3_ADDR, rdThing_SetSprite3);
    hook_function(rdThing_SetPolyline_ADDR, rdThing_SetPolyline);
    hook_function(rdThing_Draw_ADDR, rdThing_Draw);
    hook_function(rdThing_AccumulateMatrices_ADDR, rdThing_AccumulateMatrices);
    
    // rdMatrix
    hook_function(rdMatrix_Build34_ADDR, rdMatrix_Build34);
    hook_function(rdMatrix_BuildFromLook34_ADDR, rdMatrix_BuildFromLook34);
    hook_function(rdMatrix_BuildCamera34_ADDR, rdMatrix_BuildCamera34);
    hook_function(rdMatrix_InvertOrtho34_ADDR, rdMatrix_InvertOrtho34);
    hook_function(rdMatrix_Build44_ADDR, rdMatrix_Build44);
    hook_function(rdMatrix_BuildRotate34_ADDR, rdMatrix_BuildRotate34);
    hook_function(rdMatrix_BuildInverseRotate34_ADDR, rdMatrix_BuildInverseRotate34);
    hook_function(rdMatrix_BuildRotate44_ADDR, rdMatrix_BuildRotate44);
    hook_function(rdMatrix_BuildTranslate34_ADDR, rdMatrix_BuildTranslate34);
    hook_function(rdMatrix_BuildTranslate44_ADDR, rdMatrix_BuildTranslate44);
    hook_function(rdMatrix_BuildScale34_ADDR, rdMatrix_BuildScale34);
    hook_function(rdMatrix_BuildScale44_ADDR, rdMatrix_BuildScale44);
    hook_function(rdMatrix_BuildFromVectorAngle34_ADDR, rdMatrix_BuildFromVectorAngle34);
    hook_function(rdMatrix_LookAt_ADDR, rdMatrix_LookAt);
    hook_function(rdMatrix_ExtractAngles34_ADDR, rdMatrix_ExtractAngles34);
    hook_function(rdMatrix_Normalize34_ADDR, rdMatrix_Normalize34);
    hook_function(rdMatrix_Identity34_ADDR, rdMatrix_Identity34);
    hook_function(rdMatrix_Identity44_ADDR, rdMatrix_Identity44);
    hook_function(rdMatrix_Copy34_ADDR, rdMatrix_Copy34);
    hook_function(rdMatrix_Copy44_ADDR, rdMatrix_Copy44);
    hook_function(rdMatrix_Copy34to44_ADDR, rdMatrix_Copy34to44);
    hook_function(rdMatrix_Copy44to34_ADDR, rdMatrix_Copy44to34);
    hook_function(rdMatrix_Transpose44_ADDR, rdMatrix_Transpose44);
    hook_function(rdMatrix_Multiply34_ADDR, rdMatrix_Multiply34);
    hook_function(rdMatrix_Multiply44_ADDR, rdMatrix_Multiply44);
    hook_function(rdMatrix_PreMultiply34_ADDR, rdMatrix_PreMultiply34);
    hook_function(rdMatrix_PreMultiply44_ADDR, rdMatrix_PreMultiply44);
    hook_function(rdMatrix_PostMultiply34_ADDR, rdMatrix_PostMultiply34);
    hook_function(rdMatrix_PostMultiply44_ADDR, rdMatrix_PostMultiply44);
    hook_function(rdMatrix_PreRotate34_ADDR, rdMatrix_PreRotate34);
    hook_function(rdMatrix_PreRotate44_ADDR, rdMatrix_PreRotate44);
    hook_function(rdMatrix_PostRotate34_ADDR, rdMatrix_PostRotate34);
    hook_function(rdMatrix_PostRotate44_ADDR, rdMatrix_PostRotate44);
    hook_function(rdMatrix_PreTranslate34_ADDR, rdMatrix_PreTranslate34);
    hook_function(rdMatrix_PreTranslate44_ADDR, rdMatrix_PreTranslate44);
    hook_function(rdMatrix_PostTranslate34_ADDR, rdMatrix_PostTranslate34);
    hook_function(rdMatrix_PostTranslate44_ADDR, rdMatrix_PostTranslate44);
    hook_function(rdMatrix_PreScale34_ADDR, rdMatrix_PreScale34);
    hook_function(rdMatrix_PreScale44_ADDR, rdMatrix_PreScale44);
    hook_function(rdMatrix_PostScale34_ADDR, rdMatrix_PostScale34);
    hook_function(rdMatrix_PostScale44_ADDR, rdMatrix_PostScale44);
    hook_function(rdMatrix_SetRowVector34_ADDR, rdMatrix_SetRowVector34);
    hook_function(rdMatrix_SetRowVector44_ADDR, rdMatrix_SetRowVector44);
    hook_function(rdMatrix_GetRowVector34_ADDR, rdMatrix_GetRowVector34);
    hook_function(rdMatrix_GetRowVector44_ADDR, rdMatrix_GetRowVector44);
    hook_function(rdMatrix_TransformVector34_ADDR, rdMatrix_TransformVector34);
    hook_function(rdMatrix_TransformVector34Acc_0_ADDR, rdMatrix_TransformVector34Acc_0);
    hook_function(rdMatrix_TransformVector34Acc_ADDR, rdMatrix_TransformVector34Acc);
    hook_function(rdMatrix_TransformVector44_ADDR, rdMatrix_TransformVector44);
    hook_function(rdMatrix_TransformVector44Acc_ADDR, rdMatrix_TransformVector44Acc);
    hook_function(rdMatrix_TransformPoint34_ADDR, rdMatrix_TransformPoint34);
    hook_function(rdMatrix_TransformPoint34Acc_ADDR, rdMatrix_TransformPoint34Acc);
    hook_function(rdMatrix_TransformPoint44_ADDR, rdMatrix_TransformPoint44);
    hook_function(rdMatrix_TransformPoint44Acc_ADDR, rdMatrix_TransformPoint44Acc);
    hook_function(rdMatrix_TransformPointLst34_ADDR, rdMatrix_TransformPointLst34);
    hook_function(rdMatrix_TransformPointLst44_ADDR, rdMatrix_TransformPointLst44);
    
    // rdCamera
    hook_function(rdCamera_New_ADDR, rdCamera_New);
    hook_function(rdCamera_NewEntry_ADDR, rdCamera_NewEntry);
    hook_function(rdCamera_Free_ADDR, rdCamera_Free);
    hook_function(rdCamera_FreeEntry_ADDR, rdCamera_FreeEntry);
    hook_function(rdCamera_SetCanvas_ADDR, rdCamera_SetCanvas);
    hook_function(rdCamera_SetCurrent_ADDR, rdCamera_SetCurrent);
    hook_function(rdCamera_SetFOV_ADDR, rdCamera_SetFOV);
    hook_function(rdCamera_SetProjectType_ADDR, rdCamera_SetProjectType);
    hook_function(rdCamera_SetOrthoScale_ADDR, rdCamera_SetOrthoScale);
    hook_function(rdCamera_SetAspectRatio_ADDR, rdCamera_SetAspectRatio);
    hook_function(rdCamera_BuildFOV_ADDR, rdCamera_BuildFOV);
    hook_function(rdCamera_SetFrustrum_ADDR, rdCamera_SetFrustrum);
    hook_function(rdCamera_Update_ADDR, rdCamera_Update);
    hook_function(rdCamera_PerspProject_ADDR, rdCamera_PerspProject);
    hook_function(rdCamera_PerspProjectLst_ADDR, rdCamera_PerspProjectLst);
    hook_function(rdCamera_PerspProjectSquare_ADDR, rdCamera_PerspProjectSquare);
    hook_function(rdCamera_PerspProjectSquareLst_ADDR, rdCamera_PerspProjectSquareLst);
    hook_function(rdCamera_OrthoProject_ADDR, rdCamera_OrthoProject);
    hook_function(rdCamera_OrthoProjectLst_ADDR, rdCamera_OrthoProjectLst);
    hook_function(rdCamera_OrthoProjectSquare_ADDR, rdCamera_OrthoProjectSquare);
    hook_function(rdCamera_OrthoProjectSquareLst_ADDR, rdCamera_OrthoProjectSquareLst);
    hook_function(rdCamera_SetAmbientLight_ADDR, rdCamera_SetAmbientLight);
    hook_function(rdCamera_SetAttenuation_ADDR, rdCamera_SetAttenuation);
    hook_function(rdCamera_AddLight_ADDR, rdCamera_AddLight);
    hook_function(rdCamera_ClearLights_ADDR, rdCamera_ClearLights);
    hook_function(rdCamera_AdvanceFrame_ADDR, rdCamera_AdvanceFrame);
    
    // sithMain
    hook_function(sithMain_Startup_ADDR, sithMain_Startup);
    hook_function(sithShutdown_ADDR, sithShutdown);
    hook_function(sithOpenStatic_ADDR, sithOpenStatic);
    hook_function(sithCloseStatic_ADDR, sithCloseStatic);
    hook_function(sithMain_Mode1Init_ADDR, sithMain_Mode1Init);
    hook_function(sithOpenNormal_ADDR, sithOpenNormal);
    hook_function(sithOpenMulti_ADDR, sithOpenMulti);
    hook_function(sithOpen_ADDR, sithOpen);
    hook_function(sithClose_ADDR, sithClose);
    hook_function(sithMain_SetEndLevel_ADDR, sithMain_SetEndLevel);
    hook_function(sithUpdate_ADDR, sithUpdate);
    hook_function(sithDrawScene_ADDR, sithDrawScene);
    hook_function(sithAdvanceRenderTick_ADDR, sithAdvanceRenderTick);
    hook_function(sithMain_set_sithmode_5_ADDR, sithMain_set_sithmode_5);
    hook_function(sithMain_SetEpisodeName_ADDR, sithMain_SetEpisodeName);
    hook_function(sithOpenPostProcess_ADDR, sithOpenPostProcess);
    
    // sithAnimClass
    hook_function(sithAnimClass_Load_ADDR, sithAnimClass_Load);
    hook_function(sithAnimClass_LoadEntry_ADDR, sithAnimClass_LoadEntry);
    hook_function(sithAnimClass_LoadPupEntry_ADDR, sithAnimClass_LoadPupEntry);
    hook_function(sithAnimClass_New_ADDR, sithAnimClass_New);
    hook_function(sithAnimClass_Free_ADDR, sithAnimClass_Free);
    
    // sithCamera
    hook_function(sithCamera_Startup_ADDR, sithCamera_Startup);
    hook_function(sithCamera_ResetAllCameras_ADDR, sithCamera_ResetAllCameras);
    hook_function(sithCamera_NewEntry_ADDR, sithCamera_NewEntry);
    hook_function(sithCamera_Update_ADDR, sithCamera_Update);
    hook_function(sithCamera_SetCurrentCamera_ADDR, sithCamera_SetCurrentCamera);
    hook_function(sithCamera_Open_ADDR, sithCamera_Open);
    hook_function(sithCamera_Close_ADDR, sithCamera_Close);
    hook_function(sithCamera_SetCameraFocus_ADDR, sithCamera_SetCameraFocus);
    hook_function(sithCamera_SetPOVShake_ADDR, sithCamera_SetPOVShake);
    hook_function(sithCamera_GetPrimaryFocus_ADDR, sithCamera_GetPrimaryFocus);
    hook_function(sithCamera_CycleCamera_ADDR, sithCamera_CycleCamera);
    
    // sithControl
    hook_function(sithControl_Open_ADDR, sithControl_Open);
    hook_function(sithControl_Update_ADDR, sithControl_Update);
    hook_function(sithControl_RegisterControlCallback_ADDR, sithControl_RegisterControlCallback);
    hook_function(sithControl_HandlePlayer_ADDR, sithControl_HandlePlayer);
    hook_function(sithControl_RegisterAxisFunction_ADDR, sithControl_RegisterAxisFunction);
    hook_function(sithControl_sub_4D7C30_ADDR, sithControl_Reset);

    // sithPlayerActions
    hook_function(sithPlayerActions_Activate_ADDR, sithPlayerActions_Activate);
    hook_function(sithPlayerActions_JumpWithVel_ADDR, sithPlayerActions_JumpWithVel);
    hook_function(sithPlayerActions_MoveToPlayerPosition_ADDR, sithPlayerActions_MoveToPlayerPosition);
    
    // sithThing
    hook_function(sithThing_Startup_ADDR, sithThing_Startup);
    hook_function(sithThing_Shutdown_ADDR, sithThing_Shutdown);
    hook_function(sithThing_RegisterUnknownFunc_ADDR, sithThing_RegisterUnknownFunc);
    hook_function(sithThing_Update_ADDR, sithThing_Update);
    hook_function(sithThing_DestroyDyingThing_ADDR, sithThing_DestroyDyingThing);
    hook_function(sithThing_GetThingParent_ADDR, sithThing_GetThingParent);
    hook_function(sithThing_GetThingByIndex_ADDR, sithThing_GetThingByIndex);
    hook_function(sithThing_LoadPostProcess_ADDR, sithThing_LoadPostProcess);
    hook_function(sithThing_FreeThing_ADDR, sithThing_FreeThing);
    hook_function(sithThing_Initialize_ADDR, sithThing_Initialize);
    hook_function(sithThing_Reset_ADDR, sithThing_Reset);
    hook_function(sithThing_Create_ADDR, sithThing_Create);
    hook_function(sithThing_SetThingBasedOn_ADDR, sithThing_SetThingBasedOn);
    hook_function(sithThing_SetPositionAndOrient_ADDR, sithThing_SetPositionAndOrient);
    hook_function(sithThing_ExitSector_ADDR, sithThing_ExitSector);
    hook_function(sithThing_EnterSector_ADDR, sithThing_EnterSector);
    hook_function(sithThing_EnterWater_ADDR, sithThing_EnterWater);
    hook_function(sithThing_ExitWater_ADDR, sithThing_ExitWater);
    hook_function(sithThing_CalcThingChecksum_ADDR, sithThing_CalcThingChecksum);
    hook_function(sithThing_FreeThingIndex_ADDR, sithThing_FreeThingIndex);
    hook_function(sithThing_FreeWorldThings_ADDR, sithThing_FreeWorldThings);
    hook_function(sithThing_CreateThing_ADDR, sithThing_CreateThing);
    hook_function(sithThing_AttachThingToSurface_ADDR, sithThing_AttachThingToSurface);
    hook_function(sithThing_AttachThingToThingFace_ADDR, sithThing_AttachThingToThingFace);
    hook_function(sithThing_SetSector_ADDR, sithThing_SetSector);
    hook_function(sithThing_DetachThing_ADDR, sithThing_DetachThing);
    hook_function(sithThing_DestroyThing_ADDR, sithThing_DestroyThing);
    hook_function(sithThing_DamageThing_ADDR, sithThing_DamageThing);
    hook_function(sithThing_AttachThingToThing_ADDR, sithThing_AttachThingToThing);
    hook_function(sithThing_SyncThing_ADDR, sithThing_SyncThing);
    hook_function(sithThing_CanSync_ADDR, sithThing_CanSync);
    hook_function(sithThing_GetGuidThing_ADDR, sithThing_GetGuidThing);
    hook_function(sithActor_DestroyActor_ADDR, sithActor_DestroyActor);
    
    // sithSector
    hook_function(sithAIAwareness_Startup_ADDR, sithAIAwareness_Startup);
    hook_function(sithAIAwareness_Close_ADDR, sithAIAwareness_Close);
    hook_function(sithAIAwareness_sub_4F2B10_ADDR, sithAIAwareness_ProcessEvents);
    hook_function(sithPhysics_ApplyDrag_ADDR, sithPhysics_ApplyDrag);
    hook_function(sithPhysics_UpdateThingPhysics_ADDR, sithPhysics_UpdateThingPhysics);
    hook_function(sithPhysics_UpdatePlayerPhysics_ADDR, sithPhysics_UpdatePlayerPhysics);
    hook_function(sithRenderSky_Update_ADDR, sithRenderSky_Update);
    hook_function(sithSector_AllocWorldSectors_ADDR, sithSector_AllocWorldSectors);
    hook_function(sithSector_NewEntry_ADDR, sithSector_NewEntry);
    hook_function(sithSector_FreeWorldSectors_ADDR, sithSector_FreeWorldSectors);
    hook_function(sithPlayer_Open_ADDR, sithPlayer_Open);
    hook_function(sithPlayer_sub_4C93B0_ADDR, sithPlayer_SetBinItemActive);
    hook_function(sithPlayer_sub_4C93F0_ADDR, sithPlayer_GetBinItemActive);
    hook_function(sithPlayer_idk2_ADDR, sithPlayer_IsInvItemAvailable);
    hook_function(sithRenderSky_HorizonFaceToPlane_ADDR, sithRenderSky_HorizonFaceToPlane);
    hook_function(sithPhysics_SetThingLook_ADDR, sithPhysics_SetThingLook);
    hook_function(sithPhysics_ApplyForce_ADDR, sithPhysics_ApplyForce);
    hook_function(sithRenderSky_CeilingFaceToPlane_ADDR, sithRenderSky_CeilingFaceToPlane);
    hook_function(sithAIAwareness_CreateTransmittingEvent_ADDR, sithAIAwareness_CreateTransmittingEvent);
    hook_function(sithAIAwareness_Update_ADDR, sithAIAwareness_Update);
    hook_function(sithAIAwareness_ProcessEvent_ADDR, sithAIAwareness_ProcessEvent);
    hook_function(sithPhysics_GetThingHeight_ADDR, sithPhysics_GetThingHeight);
    hook_function(sithSector_GetPtrFromIdx_ADDR, sithSector_GetPtrFromIdx);

    // sithDSSThing
    hook_function(sithDSSThing_Pos_ADDR, sithDSSThing_Pos);
    hook_function(sithDSSThing_ProcessPos_ADDR, sithDSSThing_ProcessPos);

#if 0
    //hook_function(sithDSSThing_SendSyncThingFull_ADDR, sithDSSThing_SendSyncThingFull); // TODO: not yet decompiled
    //hook_function(sithDSSThing_SendPlaySoundPos_ADDR, sithDSSThing_SendPlaySoundPos); // TODO: not yet decompiled
    //hook_function(sithDSSThing_ProcessSyncThingFull_ADDR, sithDSSThing_ProcessSyncThingFull); // TODO: not yet decompiled
    //hook_function(sithDSSThing_ProcessPlaySoundPos_ADDR, sithDSSThing_ProcessPlaySoundPos); // TODO: not yet decompiled
    hook_function(sithDSSThing_Attachment_ADDR, sithDSSThing_Attachment);
#endif

#if 0
    hook_function(sithDSS_PuppetStatus_ADDR, sithDSS_PuppetStatus);
    //hook_function(sithDSS_SendSyncAI_ADDR, sithDSS_SendSyncAI); // TODO: not yet decompiled
    //hook_function(sithDSS_SendSyncSurface_ADDR, sithDSS_SendSyncSurface); // TODO: not yet decompiled
    //hook_function(sithDSS_SendSyncSector_ADDR, sithDSS_SendSyncSector); // TODO: not yet decompiled
    //hook_function(sithDSS_SendSyncItemDesc_ADDR, sithDSS_SendSyncItemDesc); // TODO: not yet decompiled
    //hook_function(sithDSS_SendStopAnim_ADDR, sithDSS_SendStopAnim); // TODO: not yet decompiled
    hook_function(sithDSS_SendSyncTimers_ADDR, sithDSS_SendSyncTimers);
    hook_function(sithDSS_SendSyncPalEffects_ADDR, sithDSS_SendSyncPalEffects);
    hook_function(sithDSS_SyncCameras_ADDR, sithDSS_SyncCameras);
    hook_function(sithDSS_SyncGameState_ADDR, sithDSS_SyncGameState);
    hook_function(sithDSS_ProcessPuppetStatus_ADDR, sithDSS_ProcessPuppetStatus);
    //hook_function(sithDSS_ProcessSyncAI_ADDR, sithDSS_ProcessSyncAI); // TODO: not yet decompiled
    //hook_function(sithDSS_ProcessSyncSurface_ADDR, sithDSS_ProcessSyncSurface); // TODO: not yet decompiled
    //hook_function(sithDSS_ProcessSyncSector_ADDR, sithDSS_ProcessSyncSector); // TODO: not yet decompiled
    //hook_function(sithDSS_ProcessSyncItemDesc_ADDR, sithDSS_ProcessSyncItemDesc); // TODO: not yet decompiled
    //hook_function(sithDSS_ProcessStopAnim_ADDR, sithDSS_ProcessStopAnim); // TODO: not yet decompiled
    hook_function(sithDSS_ProcessSyncTimers_ADDR, sithDSS_ProcessSyncTimers);
    hook_function(sithDSS_ProcessSyncPalEffects_ADDR, sithDSS_ProcessSyncPalEffects);
    hook_function(sithDSS_ProcessSyncCameras_ADDR, sithDSS_ProcessSyncCameras);
    hook_function(sithDSS_ProcessSyncGameState_ADDR, sithDSS_ProcessSyncGameState);
#endif
    
    // sithWeapon
    hook_function(sithWeapon_InitDefaults_ADDR, sithWeapon_InitDefaults);
    hook_function(sithWeapon_Startup_ADDR, sithWeapon_Startup);
    hook_function(sithWeapon_Update_ADDR, sithWeapon_Update);
    hook_function(sithWeapon_HandleImpact_ADDR, sithWeapon_HandleImpact);
    hook_function(sithWeapon_sub_4D3920_ADDR, sithWeapon_sub_4D3920);
    hook_function(sithWeapon_ParseArg_ADDR, sithWeapon_ParseArg);
    hook_function(sithWeapon_WeaponFire_ADDR, sithWeapon_WeaponFire);
    hook_function(sithWeapon_WeaponFireProjectile_ADDR, sithWeapon_WeaponFireProjectile);
    hook_function(sithWeapon_DamageWeapon_ADDR, sithWeapon_DamageWeapon);
    hook_function(sithWeapon_ThingCollisionHandler_ADDR, sithWeapon_ThingCollisionHandler);
    hook_function(sithWeapon_SurfaceCollisionHandler_ADDR, sithWeapon_SurfaceCollisionHandler);
    hook_function(sithWeapon_DestroyWeapon_ADDR, sithWeapon_DestroyWeapon);
    hook_function(sithWeapon_CreateWeaponExplosion_ADDR, sithWeapon_CreateWeaponExplosion);
    hook_function(sithWeapon_StartupEntry_ADDR, sithWeapon_StartupEntry);
    hook_function(sithWeapon_ShutdownEntry_ADDR, sithWeapon_ShutdownEntry);

    hook_function(sithWeapon_SetMountWait_ADDR, sithWeapon_SetMountWait);
    hook_function(sithWeapon_SetFireWait_ADDR, sithWeapon_SetFireWait);
    hook_function(sithWeapon_UpdateActorWeaponState_ADDR, sithWeapon_UpdateActorWeaponState);
    hook_function(sithWeapon_ActivateWeapon_ADDR, sithWeapon_ActivateWeapon);
    hook_function(sithWeapon_DeactivateWeapon_ADDR, sithWeapon_DeactivateWeapon);
    hook_function(sithWeapon_AutoSelect_ADDR, sithWeapon_AutoSelect);
    hook_function(sithWeapon_ProcessWeaponControls_ADDR, sithWeapon_ProcessWeaponControls);
    
    hook_function(sithWeapon_FireProjectile_ADDR, sithWeapon_FireProjectile);
    hook_function(sithWeapon_GetPriority_ADDR, sithWeapon_GetPriority);
    hook_function(sithWeapon_GetCurWeaponMode_ADDR, sithWeapon_GetCurWeaponMode);
    hook_function(sithWeapon_SyncPuppet_ADDR, sithWeapon_SyncPuppet);
    hook_function(sithWeapon_WriteConf_ADDR, sithWeapon_WriteConf);
    hook_function(sithWeapon_ReadConf_ADDR, sithWeapon_ReadConf);
    hook_function(sithWeapon_SetFireRate_ADDR, sithWeapon_SetFireRate);
    
    // sithExplosion
    hook_function(sithExplosion_CreateThing_ADDR, sithExplosion_CreateThing);
    hook_function(sithExplosion_Update_ADDR, sithExplosion_Update);
    hook_function(sithExplosion_MakeBlast_ADDR, sithExplosion_MakeBlast);
    hook_function(sithExplosion_ParseArg_ADDR, sithExplosion_ParseArg);
    
    // sithIntersect
#if 0
    hook_function(sithIntersect_IsSphereInSector_ADDR, sithIntersect_IsSphereInSector);
    //hook_function(sithIntersect_sub_5080D0_ADDR, sithIntersect_sub_5080D0); // TODO: not yet decompiled
    //hook_function(sithIntersect_sub_508540_ADDR, sithIntersect_sub_508540); // TODO: not yet decompiled
    hook_function(sithIntersect_CheckSphereFaceIntersectionEx_ADDR, sithIntersect_CheckSphereFaceIntersectionEx);
    hook_function(sithIntersect_CheckSphereHit_ADDR, sithIntersect_CheckSphereHit);
    hook_function(sithIntersect_TestSphereFaceHit_ADDR, sithIntersect_TestSphereFaceHit);
    hook_function(sithIntersect_CheckSphereFaceIntersection_ADDR, sithIntersect_CheckSphereFaceIntersection);
    hook_function(sithIntersect_CheckSphereMeshIntersection_ADDR, sithIntersect_CheckSphereMeshIntersection);
    hook_function(sithIntersect_CheckSphereFaceHitVerticesIntersection_ADDR, sithIntersect_CheckSphereFaceHitVerticesIntersection);
    hook_function(sithIntersect_sub_508070_ADDR, sithIntersect_CheckFaceVerticesIntersection);
#endif

    // sithTime
    hook_function(sithTime_Advance_ADDR, sithTime_Advance);
    hook_function(sithTime_Pause_ADDR, sithTime_Pause);
    hook_function(sithTime_Resume_ADDR, sithTime_Resume);
    hook_function(sithTime_SetFrameTime_ADDR, sithTime_SetFrameTime);
    hook_function(sithTime_Startup_ADDR, sithTime_Startup);
    hook_function(sithTime_SetGameTime_ADDR, sithTime_SetGameTime);
    
    // sithModel
    hook_function(sithModel_Startup_ADDR, sithModel_Startup);
    hook_function(sithModel_Shutdown_ADDR, sithModel_Shutdown);
    hook_function(sithModel_ReadStaticModelsListText_ADDR, sithModel_ReadStaticModelsListText);
    hook_function(sithModel_FreeWorldModels_ADDR, sithModel_FreeWorldModels);
    hook_function(sithModel_Load_ADDR, sithModel_Load);
    hook_function(sithModel_GetModelMemUsage_ADDR, sithModel_GetModelMemUsage);
    hook_function(sithModel_AllocWorldModels_ADDR, sithModel_AllocWorldModels);
    hook_function(sithModel_GetModelByIndex_ADDR, sithModel_GetModelByIndex);
    
    // sithWorld
    hook_function(sithWorld_Startup_ADDR, sithWorld_Startup);
    hook_function(sithWorld_Shutdown_ADDR, sithWorld_Shutdown);
    hook_function(sithWorld_SetLoadProgressCallback_ADDR, sithWorld_SetLoadProgressCallback);
    hook_function(sithWorld_UpdateLoadProgress_ADDR, sithWorld_UpdateLoadProgress);
    hook_function(sithWorld_RegisterTextSectionParser_ADDR, sithWorld_RegisterTextSectionParser);
    hook_function(sithWorld_GetTextSectionParserIndex_ADDR, sithWorld_GetTextSectionParserIndex);
    hook_function(sithWorld_CalcWorldChecksum_ADDR, sithWorld_CalcWorldChecksum);
    hook_function(sithWorld_ResetGeoresource_ADDR, sithWorld_ResetGeoresource);

    // sithInventory
    hook_function(sithInventory_RegisterType_ADDR, sithInventory_RegisterType);
    hook_function(sithInventory_FindNextTypeID_ADDR, sithInventory_FindNextTypeID);
    hook_function(sithInventory_FindPreviousTypeID_ADDR, sithInventory_FindPreviousTypeID);
    hook_function(sithInventory_FindNextItemID_ADDR, sithInventory_FindNextItemID);
    hook_function(sithInventory_FindPreviousItemID_ADDR, sithInventory_FindPreviousItemID);
    hook_function(sithInventory_SelectItem_ADDR, sithInventory_SelectItem);
    hook_function(sithInventory_SelectNextItem_ADDR, sithInventory_SelectNextItem);
    hook_function(sithInventory_SelectPreviousItem_ADDR, sithInventory_SelectPreviousItem);
    hook_function(sithInventory_SelectWeaponFollowing_ADDR, sithInventory_SelectWeaponFollowing);
    hook_function(sithInventory_GetType_ADDR, sithInventory_GetType);
    hook_function(sithInventory_GetCurrentWeapon_ADDR, sithInventory_GetCurrentWeapon);
    hook_function(sithInventory_SetCurrentWeapon_ADDR, sithInventory_SetCurrentWeapon);
    hook_function(sithInventory_GetCurrentItem_ADDR, sithInventory_GetCurrentItem);
    hook_function(sithInventory_SetCurrentItem_ADDR, sithInventory_SetCurrentItem);
    hook_function(sithInventory_GetCurPower_ADDR, sithInventory_GetCurPower);
    hook_function(sithInventory_SetCurPower_ADDR, sithInventory_SetCurPower);
    hook_function(sithInventory_GetWeaponPrior_ADDR, sithInventory_GetWeaponPrior);
    hook_function(sithInventory_GetWeaponFollowing_ADDR, sithInventory_GetWeaponFollowing);
    hook_function(sithInventory_GetPowerPrior_ADDR, sithInventory_GetPowerPrior);
    hook_function(sithInventory_GetPowerFollowing_ADDR, sithInventory_GetPowerFollowing);
    hook_function(sithInventory_SelectPower_ADDR, sithInventory_SelectPower);
    hook_function(sithInventory_SelectPowerPrior_ADDR, sithInventory_SelectPowerPrior);
    hook_function(sithInventory_SelectPowerFollowing_ADDR, sithInventory_SelectPowerFollowing);
    hook_function(sithInventory_ActivateBin_ADDR, sithInventory_ActivateBin);
    hook_function(sithInventory_DeactivateBin_ADDR, sithInventory_DeactivateBin);
    hook_function(sithInventory_BinSendActivate_ADDR, sithInventory_BinSendActivate);
    hook_function(sithInventory_BinSendDeactivate_ADDR, sithInventory_BinSendDeactivate);
    hook_function(sithInventory_ChangeInventory_ADDR, sithInventory_ChangeInventory);
    hook_function(sithInventory_GetInventory_ADDR, sithInventory_GetInventory);
    hook_function(sithInventory_SetInventory_ADDR, sithInventory_SetInventory);
    hook_function(sithInventory_SetInventoryActivated_ADDR, sithInventory_SetInventoryActivated);
    hook_function(sithInventory_IsInventoryActivated_ADDR, sithInventory_IsInventoryActivated);
    hook_function(sithInventory_SetInventoryAvailable_ADDR, sithInventory_SetInventoryAvailable);
    hook_function(sithInventory_IsInventoryAvailable_ADDR, sithInventory_IsInventoryAvailable);
    hook_function(sithInventory_SetCarries_ADDR, sithInventory_SetCarries);
    hook_function(sithInventory_GetCarries_ADDR, sithInventory_GetCarries);
    hook_function(sithInventory_IsBackpackItem_ADDR, sithInventory_IsBackpackItem);
    hook_function(sithInventory_SerializedWrite_ADDR, sithInventory_SerializedWrite);
    hook_function(sithInventory_GetInventoryMinimum_ADDR, sithInventory_GetInventoryMinimum);
    hook_function(sithInventory_GetInventoryMaximum_ADDR, sithInventory_GetInventoryMaximum);
    hook_function(sithInventory_SetInventoryFlags_ADDR, sithInventory_SetInventoryFlags);
    hook_function(sithInventory_GetInventoryFlags_ADDR, sithInventory_GetInventoryFlags);
    hook_function(sithInventory_ClearInventoryFlags_ADDR, sithInventory_ClearInventoryFlags);
    hook_function(sithInventory_BroadcastInventoryMessage_ADDR, sithInventory_BroadcastInventoryMessage);
    hook_function(sithInventory_BroadcastMessage_ADDR, sithInventory_BroadcastMessage);
    hook_function(sithInventory_ResetInventory_ADDR, sithInventory_ResetInventory);
    hook_function(sithInventory_ResetAllTypes_ADDR, sithInventory_ResetAllTypes);
    hook_function(sithInventory_CreateBackpack_ADDR, sithInventory_CreateBackpack);
    hook_function(sithInventory_PickupBackpack_ADDR, sithInventory_PickupBackpack);
    hook_function(sithInventory_GetBackpackItemID_ADDR, sithInventory_GetBackpackItemID);
    hook_function(sithInventory_GetBackpackItemValue_ADDR, sithInventory_GetBackpackItemValue);
    hook_function(sithInventory_GetNumBackpackItems_ADDR, sithInventory_GetNumBackpackItems);
    hook_function(sithInventory_HandleInvSkillKeys_ADDR, sithInventory_HandleInvSkillKeys);
    hook_function(sithInventory_SendFire_ADDR, sithInventory_SendFire);
    hook_function(sithInventory_GetBin_ADDR, sithInventory_GetBin);
    hook_function(sithInventory_GetInventoryType_ADDR, sithInventory_GetInventoryType);
    hook_function(sithInventory_KeybindInit_ADDR, sithInventory_KeybindInit);
    hook_function(sithInventory_SetPowerKeybind_ADDR, sithInventory_SetPowerKeybind);
    hook_function(sithInventory_GetPowerKeybind_ADDR, sithInventory_GetPowerKeybind);
    hook_function(sithInventory_InitInventory_ADDR, sithInventory_InitInventory);
    hook_function(sithInventory_BroadcastKilledMessage_ADDR, sithInventory_BroadcastKilledMessage);
    hook_function(sithInventory_SetBinWait_ADDR, sithInventory_SetBinWait);

    // sithPlayer
    hook_function(sithPlayer_Startup_ADDR, sithPlayer_Startup);
    hook_function(sithPlayer_GetInvItemAmount_ADDR, sithPlayer_GetInvItemAmount);
    hook_function(sithPlayer_SetInvItemAmount_ADDR, sithPlayer_SetInvItemAmount);
    hook_function(sithPlayer_ResetPalEffects_ADDR, sithPlayer_ResetPalEffects);
    hook_function(sithPlayer_SetLocalPlayer_ADDR, sithPlayer_SetLocalPlayer);
    hook_function(sithPlayer_AddDynamicTint_ADDR, sithPlayer_AddDynamicTint);
    hook_function(sithPlayer_KillPlayer_ADDR, sithPlayer_KillPlayer);
    hook_function(sithPlayer_PlayerKilledAction_ADDR, sithPlayer_PlayerKilledAction);
    hook_function(sithPlayer_AddDyamicAdd_ADDR, sithPlayer_AddDyamicAdd);
    hook_function(sithPlayer_GetThingPlayerNumByIndex_ADDR, sithPlayer_GetThingPlayerNumByIndex);

    // sithPhysics
    hook_function(sithPhysics_FindFloor_ADDR, sithPhysics_FindFloor);
    hook_function(sithPhysics_UpdateThing_ADDR, sithPhysics_UpdateThing);
    
    // sithSurface
    hook_function(sithSurface_AllocWorldSurfaces_ADDR, sithSurface_AllocWorldSurfaces);
    hook_function(sithSurface_sub_4E5AD0_ADDR, sithSurface_AllocWorldAdjoins);
    hook_function(sithSurface_FreeWorldSurfaces_ADDR, sithSurface_FreeWorldSurfaces);
    hook_function(sithSurface_SurfaceLightAnim_ADDR, sithSurface_SurfaceLightAnim);
    hook_function(sithSurface_SlideWall_ADDR, sithSurface_SlideWall);
    hook_function(sithSurface_MaterialAnim_ADDR, sithSurface_MaterialAnim);
    hook_function(sithSurface_DetachThing_ADDR, sithSurface_DetachThing);
    hook_function(sithSurface_GetCenterPoint_ADDR, sithSurface_GetCenterPoint);
    hook_function(sithSurface_SlideHorizonSky_ADDR, sithSurface_SlideHorizonSky);
    hook_function(sithSurface_sub_4F00A0_ADDR, sithSurface_sub_4F00A0);
    hook_function(sithSurface_SetThingLight_ADDR, sithSurface_SetThingLight);
    hook_function(sithSurface_HandleThingImpact_ADDR, sithSurface_HandleThingImpact);
    hook_function(sithSurface_GetRdSurface_ADDR, sithSurface_GetRdSurface);
    hook_function(sithSurface_GetByIdx_ADDR, sithSurface_GetByIdx);
    hook_function(sithSurface_SyncFull_ADDR, sithSurface_SyncFull);
    hook_function(sithSurface_Alloc_ADDR, sithSurface_Alloc);
    hook_function(sithSurface_sub_4E63B0_ADDR, sithSurface_sub_4E63B0);

    // sithTemplate
    hook_function(sithTemplate_Startup_ADDR, sithTemplate_Startup);
    hook_function(sithTemplate_Shutdown_ADDR, sithTemplate_Shutdown);
    hook_function(sithTemplate_AllocWorldTemplates_ADDR, sithTemplate_AllocWorldTemplates);
    hook_function(sithTemplate_GetTemplateByIndex_ADDR, sithTemplate_GetTemplateByIndex);
    hook_function(sithTemplate_ReadThingTemplatesListText_ADDR, sithTemplate_ReadThingTemplatesListText);
    hook_function(sithTemplate_OldNew_ADDR, sithTemplate_OldNew);
    hook_function(sithTemplate_OldFree_ADDR, sithTemplate_OldFree);
    hook_function(sithTemplate_FreeWorldTemplates_ADDR, sithTemplate_FreeWorldTemplates);
    hook_function(sithTemplate_GetTemplate_ADDR, sithTemplate_GetTemplate);
    hook_function(sithTemplate_Parse_ADDR, sithTemplate_Parse);
    
    // sithTrackThing
    hook_function(sithTrackThing_SkipToFrame_ADDR, sithTrackThing_SkipToFrame);
    hook_function(sithTrackThing_MoveToFrame_ADDR, sithTrackThing_MoveToFrame);
    hook_function(sithTrackThing_RotatePivot_ADDR, sithTrackThing_RotatePivot);
    hook_function(sithTrackThing_Rotate_ADDR, sithTrackThing_Rotate);
    hook_function(sithTrackThing_Arrivedidk_ADDR, sithTrackThing_Arrivedidk);
    hook_function(sithTrackThing_sub_4FACC0_ADDR, sithTrackThing_CalcMoveDirection);
    hook_function(sithTrackThing_PrepareForOrient_ADDR, sithTrackThing_PrepareForOrient);
    hook_function(sithTrackThing_Tick_ADDR, sithTrackThing_Tick);
    hook_function(sithTrackThing_LoadPathParams_ADDR, sithTrackThing_LoadPathParams);
    hook_function(sithTrackThing_BlockedIdk_ADDR, sithTrackThing_BlockedIdk);
    hook_function(sithTrackThing_StoppedMoving_ADDR, sithTrackThing_StoppedMoving);
    hook_function(sithTrackThing_Stop_ADDR, sithTrackThing_Stop);
    hook_function(sithTrackThing_PathMovePause_ADDR, sithTrackThing_PathMovePause);
    hook_function(sithTrackThing_PathMoveResume_ADDR, sithTrackThing_PathMoveResume);
    hook_function(sithTrackThing_idkpathmove_ADDR, sithTrackThing_idkpathmove);
    
    // jkPlayer
    hook_function(jkPlayer_LoadAutosave_ADDR, jkPlayer_LoadAutosave);
    hook_function(jkPlayer_LoadSave_ADDR, jkPlayer_LoadSave);
    hook_function(jkPlayer_Startup_ADDR, jkPlayer_Startup);
    hook_function(jkPlayer_Shutdown_ADDR, jkPlayer_Shutdown);
    hook_function(jkPlayer_Open_ADDR, jkPlayer_Open);
    hook_function(jkPlayer_Close_ADDR, jkPlayer_Close);
    hook_function(jkPlayer_InitSaber_ADDR, jkPlayer_InitSaber);
    hook_function(jkPlayer_InitThings_ADDR, jkPlayer_InitThings);
    hook_function(jkPlayer_nullsub_1_ADDR, jkPlayer_nullsub_1);
    hook_function(jkPlayer_CreateConf_ADDR, jkPlayer_CreateConf);
    hook_function(jkPlayer_WriteConf_ADDR, jkPlayer_WriteConf);
    hook_function(jkPlayer_ReadConf_ADDR, jkPlayer_ReadConf);
    hook_function(jkPlayer_SetPovModel_ADDR, jkPlayer_SetPovModel);
    hook_function(jkPlayer_DrawPov_ADDR, jkPlayer_DrawPov);
    hook_function(jkPlayer_renderSaberWeaponMesh_ADDR, jkPlayer_renderSaberWeaponMesh);
    hook_function(jkPlayer_renderSaberTwinkle_ADDR, jkPlayer_renderSaberTwinkle);
    hook_function(jkPlayer_SetWaggle_ADDR, jkPlayer_SetWaggle);
    hook_function(jkPlayer_VerifyWcharName_ADDR, jkPlayer_VerifyWcharName);
    hook_function(jkPlayer_VerifyCharName_ADDR, jkPlayer_VerifyCharName);
    hook_function(jkPlayer_SetMpcInfo_ADDR, jkPlayer_SetMpcInfo);
    hook_function(jkPlayer_SetPlayerName_ADDR, jkPlayer_SetPlayerName);
    hook_function(jkPlayer_GetMpcInfo_ADDR, jkPlayer_GetMpcInfo);
    hook_function(jkPlayer_SetChoice_ADDR, jkPlayer_SetChoice);
    hook_function(jkPlayer_GetChoice_ADDR, jkPlayer_GetChoice);
    hook_function(jkPlayer_CalcAlignment_ADDR, jkPlayer_CalcAlignment);
    hook_function(jkPlayer_MpcInitBins_ADDR, jkPlayer_MpcInitBins);
    hook_function(jkPlayer_MPCParse_ADDR, jkPlayer_MPCParse);
    hook_function(jkPlayer_MPCWrite_ADDR, jkPlayer_MPCWrite);
    hook_function(jkPlayer_MPCBinWrite_ADDR, jkPlayer_MPCBinWrite);
    hook_function(jkPlayer_MPCBinRead_ADDR, jkPlayer_MPCBinRead);
    hook_function(jkPlayer_InitForceBins_ADDR, jkPlayer_InitForceBins);
    hook_function(jkPlayer_GetAlignment_ADDR, jkPlayer_GetAlignment);
    hook_function(jkPlayer_SetAccessiblePowers_ADDR, jkPlayer_SetAccessiblePowers);
    hook_function(jkPlayer_ResetPowers_ADDR, jkPlayer_ResetPowers);
    hook_function(jkPlayer_WriteConfSwap_ADDR, jkPlayer_WriteConfSwap);
    hook_function(jkPlayer_WriteCutsceneConf_ADDR, jkPlayer_WriteCutsceneConf);
    hook_function(jkPlayer_ReadCutsceneConf_ADDR, jkPlayer_ReadCutsceneConf);
    hook_function(jkPlayer_FixStars_ADDR, jkPlayer_FixStars);
    hook_function(jkPlayer_CalcStarsAlign_ADDR, jkPlayer_CalcStarsAlign);
    hook_function(jkPlayer_SetProtectionDeadlysight_ADDR, jkPlayer_SetProtectionDeadlysight);
    hook_function(jkPlayer_DisallowOtherSide_ADDR, jkPlayer_DisallowOtherSide);
    hook_function(jkPlayer_WriteOptionsConf_ADDR, jkPlayer_WriteOptionsConf);
    hook_function(jkPlayer_ReadOptionsConf_ADDR, jkPlayer_ReadOptionsConf);
    hook_function(jkPlayer_GetJediRank_ADDR, jkPlayer_GetJediRank);
    hook_function(jkPlayer_SetRank_ADDR, jkPlayer_SetRank);
    
    // jkSaber
    hook_function(jkSaber_Startup_ADDR, jkSaber_Startup);
    hook_function(jkSaber_Shutdown_ADDR, jkSaber_Shutdown);
    hook_function(jkSaber_InitializeSaberInfo_ADDR, jkSaber_InitializeSaberInfo);
    hook_function(jkSaber_PolylineRand_ADDR, jkSaber_PolylineRand);
    hook_function(jkSaber_Draw_ADDR, jkSaber_Draw);
    hook_function(jkSaber_UpdateLength_ADDR, jkSaber_UpdateLength);
    hook_function(jkSaber_UpdateCollision_ADDR, jkSaber_UpdateCollision);
    hook_function(jkDSS_Load_ADDR, jkDSS_Load);
    hook_function(jkDSS_player_thingsidkfunc_ADDR, jkDSS_player_thingsidkfunc);
    hook_function(jkSaber_Enable_ADDR, jkSaber_Enable);
    hook_function(jkDSS_playerconfig_idksync_ADDR, jkDSS_playerconfig_idksync);
    hook_function(jkDSS_SendSetSaberInfo2_ADDR, jkDSS_SendSetSaberInfo2);
    hook_function(jkDSS_SendSetSaberInfo_ADDR, jkDSS_SendSetSaberInfo);
    hook_function(jkDSS_Sendx32_ADDR, jkDSS_Sendx32);
    hook_function(jkDSS_ProcessSetSaberInfo_ADDR, jkDSS_ProcessSetSaberInfo);
    hook_function(jkDSS_ProcessSetSaberInfo2_ADDR, jkDSS_ProcessSetSaberInfo2);
    hook_function(jkDSS_Processx32_ADDR, jkDSS_Processx32);
    hook_function(jkDSS_Processx36_setwaggle_ADDR, jkDSS_Processx36_setwaggle);
    hook_function(jkDSS_ProcessHudTarget_ADDR, jkDSS_ProcessHudTarget);
    
    // jkSmack
    hook_function(jkSmack_Startup_ADDR, jkSmack_Startup);
    hook_function(jkSmack_Shutdown_ADDR, jkSmack_Shutdown);
    hook_function(jkSmack_GetCurrentGuiState_ADDR, jkSmack_GetCurrentGuiState);
    hook_function(jkSmack_SmackPlay_ADDR, jkSmack_SmackPlay);
    
    // jkGame
    hook_function(jkGame_SetDefaultSettings_ADDR, jkGame_SetDefaultSettings);
    hook_function(jkGame_ForceRefresh_ADDR, jkGame_ForceRefresh);
    hook_function(jkGame_Update_ADDR, jkGame_Update);
    hook_function(jkGame_cam_idk_maybe_ADDR, jkGame_PrecalcViewSizes);
    hook_function(jkGame_ScreensizeIncrease_ADDR, jkGame_ScreensizeIncrease);
    hook_function(jkGame_ScreensizeDecrease_ADDR, jkGame_ScreensizeDecrease);
    hook_function(jkGame_Gamma_ADDR, jkGame_Gamma);
    hook_function(jkGame_ddraw_idk_palettes_ADDR, jkGame_ddraw_idk_palettes);
    hook_function(jkGame_nullsub_36_ADDR, jkGame_nullsub_36);
    hook_function(jkGame_Startup_ADDR, jkGame_Startup);
    hook_function(jkGame_Shutdown_ADDR, jkGame_Shutdown);
    hook_function(jkGame_ParseSection_ADDR, jkGame_ParseSection);
    
    // jkGob
    hook_function(jkGob_Startup_ADDR, jkGob_Startup);
    hook_function(jkGob_Shutdown_ADDR, jkGob_Shutdown);
    
    // jkRes
    hook_function(jkRes_Startup_ADDR, jkRes_Startup);
    hook_function(jkRes_HookHS_ADDR, jkRes_HookHS);
    hook_function(jkRes_UnhookHS_ADDR, jkRes_UnhookHS);
    hook_function(jkRes_FileExists_ADDR, jkRes_FileExists);
    hook_function(jkRes_ReadKey_ADDR, jkRes_ReadKey);
    hook_function(jkRes_LoadNew_ADDR, jkRes_LoadNew);
    hook_function(jkRes_FileOpen_ADDR, jkRes_FileOpen);
    hook_function(jkRes_FileClose_ADDR, jkRes_FileClose);
    hook_function(jkRes_FileRead_ADDR, jkRes_FileRead);
    hook_function(jkRes_FileWrite_ADDR, jkRes_FileWrite);
    hook_function(jkRes_FileGets_ADDR, jkRes_FileGets);
    hook_function(jkRes_FileGetws_ADDR, jkRes_FileGetws);
    hook_function(jkRes_FileSize_ADDR, jkRes_FileSize);
    
    // jkStrings
    hook_function(jkStrings_Startup_ADDR, jkStrings_Startup);
    hook_function(jkStrings_Shutdown_ADDR, jkStrings_Shutdown);
    hook_function(jkStrings_GetUniString_ADDR, jkStrings_GetUniString);
    hook_function(jkStrings_GetUniStringWithFallback_ADDR, jkStrings_GetUniStringWithFallback);
    hook_function(jkStrings_unused_sub_40B490_ADDR, jkStrings_unused_sub_40B490);
    
    // jkControl
    hook_function(jkControl_Startup_ADDR, jkControl_Startup);
    hook_function(jkControl_Shutdown_ADDR, jkControl_Shutdown);
    hook_function(jkControl_HandleHudKeys_ADDR, jkControl_HandleHudKeys);
    
    // Main
    hook_function(Main_Startup_ADDR, Main_Startup);
    
    // sithCollision
#if 0
    hook_function(sithCollision_Startup_ADDR, sithCollision_Startup);
    hook_function(sithCollision_AddCollisionHandler_ADDR, sithCollision_AddCollisionHandler);
    hook_function(sithCollision_PopStack_ADDR, sithCollision_PopStack);
    hook_function(sithCollision_SearchForCollisions_ADDR, sithCollision_SearchForCollisions);
    hook_function(sithCollision_DecreaseStackLevel_ADDR, sithCollision_DecreaseStackLevel);
    hook_function(sithCollision_RotateThing_ADDR, sithCollision_RotateThing);
    hook_function(sithCollision_MoveThing_ADDR, sithCollision_MoveThing);
    hook_function(sithCollision_HandleThingHitSurface_ADDR, sithCollision_HandleThingHitSurface);
    hook_function(sithCollision_ThingCollisionHandler_ADDR, sithCollision_ThingCollisionHandler);
    hook_function(sithCollision_CollideHurt_ADDR, sithCollision_CollideHurt);
    hook_function(sithCollision_HasLOS_ADDR, sithCollision_HasLOS);
    hook_function(sithCollision_ParticleAndActorCollisionHandler_ADDR, sithCollision_ParticleAndActorCollisionHandler);
    hook_function(sithCollision_sub_4E6FB0_ADDR, sithCollision_RaycastFromCamera);
    hook_function(sithCollision_sub_4E7310_ADDR, sithCollision_RaycastSector);
    hook_function(sithCollision_sub_4E73F0_ADDR, sithCollision_CheckPathClear);
#endif
    
    // sithActor
    hook_function(sithActor_SetDifficulty_ADDR, sithActor_SetDifficulty);
    hook_function(sithActor_SurfaceCollisionHandler_ADDR, sithActor_SurfaceCollisionHandler);
    hook_function(sithActor_SetHeadPYR_ADDR, sithActor_SetHeadPYR);
    hook_function(sithActor_ActorCollisionHandler_ADDR, sithActor_ActorCollisionHandler);
    hook_function(sithActor_Update_ADDR, sithActor_Update);
    hook_function(sithActor_DestroyCorpse_ADDR, sithActor_DestroyCorpse);
    
    // sithItem
    hook_function(sithItem_PlayerCollisionHandler_ADDR, sithItem_PlayerCollisionHandler);
    hook_function(sithItem_Initialize_ADDR, sithItem_Initialize);
    hook_function(sithItem_SetItemTaken_ADDR, sithItem_SetItemTaken);
    hook_function(sithItem_DestroyItem_ADDR, sithItem_DestroyItem);
    hook_function(sithItem_ParseArg_ADDR, sithItem_ParseArg);
    hook_function(sithItem_ParseArg_ADDR, sithItem_ParseArg);
    
    // sithMap
    hook_function(sithMap_Startup_ADDR, sithMap_Startup);
    hook_function(sithMap_Shutdown_ADDR, sithMap_Shutdown);
    
    // sithEvent
    hook_function(sithEvent_Startup_ADDR, sithEvent_Startup);
    hook_function(sithEvent_Shutdown_ADDR, sithEvent_Shutdown);
    hook_function(sithEvent_Open_ADDR, sithEvent_Open);
    hook_function(sithEvent_Close_ADDR, sithEvent_Close);
    hook_function(sithEvent_Reset_ADDR, sithEvent_Reset);
    hook_function(sithEvent_CreateEvent_ADDR, sithEvent_CreateEvent);
    hook_function(sithEvent_FreeEvent_ADDR, sithEvent_FreeEvent);
    hook_function(sithEvent_RegisterTask_ADDR, sithEvent_RegisterTask);
    hook_function(sithEvent_Process_ADDR, sithEvent_Process);
    
#if 0
    // sithKeyFrame
    hook_function(sithKeyFrame_Load_ADDR, sithKeyFrame_Load);
    hook_function(sithKeyFrame_GetByIdx_ADDR, sithKeyFrame_GetByIdx);
    hook_function(sithKeyFrame_LoadEntry_ADDR, sithKeyFrame_LoadEntry);
    hook_function(sithKeyFrame_New_ADDR, sithKeyFrame_New);
    hook_function(sithKeyFrame_Free_ADDR, sithKeyFrame_Free);
#endif
    
    // sithSprite
    hook_function(sithSprite_Startup_ADDR, sithSprite_Startup);
    hook_function(sithSprite_Shutdown_ADDR, sithSprite_Shutdown);
    hook_function(sithSprite_ReadStaticSpritesListText_ADDR, sithSprite_ReadStaticSpritesListText);
    hook_function(sithSprite_FreeWorldSprites_ADDR, sithSprite_FreeWorldSprites);
    hook_function(sithSprite_Load_ADDR, sithSprite_Load);
    hook_function(sithSprite_AllocWorldSprites_ADDR, sithSprite_AllocWorldSprites);
    
    // sithMapView
    hook_function(sithOverlayMap_Startup_ADDR, sithOverlayMap_Startup);
    hook_function(sithOverlayMap_Close_ADDR, sithOverlayMap_Close);
    hook_function(sithOverlayMap_ToggleMap_ADDR, sithOverlayMap_ToggleMap);
    hook_function(sithOverlayMap_ZoomIn_ADDR, sithOverlayMap_ZoomIn);
    hook_function(sithOverlayMap_ZoomOut_ADDR, sithOverlayMap_ZoomOut);
    // sithOverlayMap_Draw
    // sithOverlayMap_DrawSectors
    // sithOverlayMap_DrawSector
    hook_function(sithOverlayMap_CanDrawSurfaceEdge_ADDR, sithOverlayMap_CanDrawSurfaceEdge);
    
    // sithMaterial
    hook_function(sithMaterial_Startup_ADDR, sithMaterial_Startup);
    hook_function(sithMaterial_Shutdown_ADDR, sithMaterial_Shutdown);
    hook_function(sithMaterial_FreeWorldMaterials_ADDR, sithMaterial_FreeWorldMaterials);
    hook_function(sithMaterial_ReadMaterialsListText_ADDR, sithMaterial_ReadMaterialsListText);
    hook_function(sithMaterial_Load_ADDR, sithMaterial_Load);
    hook_function(sithMaterial_GetMaterialByIndex_ADDR, sithMaterial_GetMaterialByIndex);
    hook_function(sithMaterial_GetMemorySize_ADDR, sithMaterial_GetMemorySize);
    hook_function(sithMaterial_AllocWorldMaterials_ADDR, sithMaterial_AllocWorldMaterials);
    hook_function(sithMaterial_UnloadAll_ADDR, sithMaterial_UnloadAll);
    
    // sithParticle
    hook_function(sithParticle_Startup_ADDR, sithParticle_Startup);
    hook_function(sithParticle_Shutdown_ADDR, sithParticle_Shutdown);
    hook_function(sithParticle_Load_ADDR, sithParticle_Load);
    hook_function(sithParticle_AllocWorldParticles_ADDR, sithParticle_AllocWorldParticles);
    hook_function(sithParticle_ParseArg_ADDR, sithParticle_ParseArg);
    hook_function(sithParticle_Update_ADDR, sithParticle_Update);
    hook_function(sithParticle_Initalize_ADDR, sithParticle_Initalize);
    hook_function(sithParticle_DestroyParticle_ADDR, sithParticle_DestroyParticle);
    hook_function(sithParticle_Free_ADDR, sithParticle_Free);
    hook_function(sithParticle_FreeWorldParticles_ADDR, sithParticle_FreeWorldParticles);
    
#if 0
    // sithPuppet
    hook_function(sithPuppet_Free_ADDR, sithPuppet_Free);
    hook_function(sithPuppet_PlayMode_ADDR, sithPuppet_PlayMode);
    hook_function(sithPuppet_PlayKey_ADDR, sithPuppet_PlayKey);
    hook_function(sithPuppet_DefaultCallback_ADDR, sithPuppet_DefaultCallback);
    hook_function(sithPuppet_StopKey_ADDR, sithPuppet_StopKey);
    hook_function(sithPuppet_SetArmedMode_ADDR, sithPuppet_SetArmedMode);
#endif

    // sithRender
    hook_function(sithRender_Startup_ADDR, sithRender_Startup);
    hook_function(sithRender_Open_ADDR, sithRender_Open);
    hook_function(sithRender_Close_ADDR, sithRender_Close);
    hook_function(sithRender_Shutdown_ADDR, sithRender_Shutdown);
    hook_function(sithRender_SetRenderFlags_ADDR, sithRender_SetRenderFlags);
    hook_function(sithRender_GetRenderFlags_ADDR, sithRender_GetRenderFlags);
    hook_function(sithRender_EnableIRMode_ADDR, sithRender_EnableIRMode);
    hook_function(sithRender_DisableIRMode_ADDR, sithRender_DisableIRMode);
    hook_function(sithRender_SetGeoMode_ADDR, sithRender_SetGeoMode);
    hook_function(sithRender_SetLightingMode_ADDR, sithRender_SetLightingMode);
    hook_function(sithRender_SetTexMode_ADDR, sithRender_SetTexMode);
    hook_function(sithRender_SetPalette_ADDR, sithRender_SetPalette);
    hook_function(sithRender_Draw_ADDR, sithRender_Draw);
    //hook_function(sithRender_BuildVisibleSectorList_ADDR, sithRender_BuildVisibleSectorList);
    hook_function(sithRender_RenderSectors_ADDR, sithRender_RenderSectors);
    hook_function(sithRender_BuildVisibleSectorsThingList_ADDR, sithRender_BuildVisibleSectorsThingList);
    hook_function(sithRender_BuildSectorThingList_ADDR, sithRender_BuildSectorThingList);
    hook_function(sithRender_BuildDynamicLights_ADDR, sithRender_BuildDynamicLights);
    hook_function(sithRender_RenderThings_ADDR, sithRender_RenderThings);
    hook_function(sithRender_RenderThing_ADDR, sithRender_RenderThing);
    hook_function(sithRender_RenderAlphaAdjoins_ADDR, sithRender_RenderAlphaAdjoins);
    hook_function(sithRender_SetExtraThingRenderFunc_ADDR, sithRender_SetExtraThingRenderFunc);
    
    // sithSave
    hook_function(sithGamesave_Setidk_ADDR, sithGamesave_Setidk);
    hook_function(sithGamesave_GetProfilePath_ADDR, sithGamesave_GetProfilePath);
    hook_function(sithGamesave_Restore_ADDR, sithGamesave_Restore);
    hook_function(sithGamesave_RestoreFile_ADDR, sithGamesave_RestoreFile);
    hook_function(sithGamesave_Save_ADDR, sithGamesave_Save);
    hook_function(sithGamesave_Process_ADDR, sithGamesave_Process);

    // sithSound
    hook_function(sithSound_Startup_ADDR, sithSound_Startup);
    hook_function(sithSound_Shutdown_ADDR, sithSound_Shutdown);
    hook_function(sithSound_ReadSoundsListText_ADDR, sithSound_ReadSoundsListText);
    hook_function(sithSound_FreeWorldSounds_ADDR, sithSound_FreeWorldSounds);
    hook_function(sithSound_New_ADDR, sithSound_New);
    hook_function(sithSound_Load_ADDR, sithSound_Load);
    hook_function(sithSound_GetFromIdx_ADDR, sithSound_GetFromIdx);
    hook_function(sithSound_LoadFileData_ADDR, sithSound_LoadFileData);
    hook_function(sithSound_UnloadData_ADDR, sithSound_UnloadData);
    hook_function(sithSound_LoadData_ADDR, sithSound_LoadData);
    //hook_function(sithSound_StopAll_ADDR, sithSound_StopAll); // TODO: not yet decompiled
    hook_function(sithSound_InitFromPath_ADDR, sithSound_InitFromPath);
    
    // sithSoundClass
    hook_function(sithSoundClass_Startup_ADDR, sithSoundClass_Startup);
    hook_function(sithSoundClass_Shutdown_ADDR, sithSoundClass_Shutdown);
    hook_function(sithSoundClass_ReadSoundClassesListText_ADDR, sithSoundClass_ReadSoundClassesListText);
    hook_function(sithSoundClass_Load_ADDR, sithSoundClass_Load);
    hook_function(sithSoundClass_LoadEntry_ADDR, sithSoundClass_LoadEntry);
    hook_function(sithSoundClass_PlayModeFirst_ADDR, sithSoundClass_PlayModeFirst);
    hook_function(sithSoundClass_PlayMode_ADDR, sithSoundClass_PlayMode);
    hook_function(sithSoundClass_PlayModeFirstEx_ADDR, sithSoundClass_PlayModeFirstEx);
    hook_function(sithSoundClass_StopMode_ADDR, sithSoundClass_StopMode);
    hook_function(sithSoundClass_FreeWorldSoundClasses_ADDR, sithSoundClass_FreeWorldSoundClasses);
    hook_function(sithSoundClass_SetThingClass_ADDR, sithSoundClass_SetThingClass);
    
    // sithSoundMixer
    hook_function(sithSoundMixer_Startup_ADDR, sithSoundMixer_Startup);
    hook_function(sithSoundMixer_Shutdown_ADDR, sithSoundMixer_Shutdown);
    hook_function(sithSoundMixer_PlaySong_ADDR, sithSoundMixer_PlaySong);
    hook_function(sithSoundMixer_StopSong_ADDR, sithSoundMixer_StopSong);
    hook_function(sithSoundMixer_UpdateMusicVolume_ADDR, sithSoundMixer_UpdateMusicVolume);
    hook_function(sithSoundMixer_SetMusicVol_ADDR, sithSoundMixer_SetMusicVol);
    hook_function(sithSoundMixer_ResumeMusic_ADDR, sithSoundMixer_ResumeMusic);
    hook_function(sithSoundMixer_Open_ADDR, sithSoundMixer_Open);
    hook_function(sithSoundMixer_Close_ADDR, sithSoundMixer_Close);
    hook_function(sithSoundMixer_ClearAll_ADDR, sithSoundMixer_ClearAll);
    hook_function(sithSoundMixer_StopAll_ADDR, sithSoundMixer_StopAll);
    hook_function(sithSoundMixer_ResumeAll_ADDR, sithSoundMixer_ResumeAll);
    hook_function(sithSoundMixer_PlayingSoundFromSound_ADDR, sithSoundMixer_PlayingSoundFromSound);
    hook_function(sithSoundMixer_PlaySound_ADDR, sithSoundMixer_PlaySound);
    hook_function(sithSoundMixer_PlaySoundPos_ADDR, sithSoundMixer_PlaySoundPos);
    hook_function(sithSoundMixer_PlaySoundThing_ADDR, sithSoundMixer_PlaySoundThing);
    hook_function(sithSoundMixer_SetPitch_ADDR, sithSoundMixer_SetPitch);
    hook_function(sithSoundMixer_FreeThing_ADDR, sithSoundMixer_FreeThing);
    hook_function(sithSoundMixer_SetSectorAmbientSound_ADDR, sithSoundMixer_SetSectorAmbientSound);
    hook_function(sithSoundMixer_SetVelocity_ADDR, sithSoundMixer_SetVelocity);
    
    // sithAI
    hook_function(sithAI_Startup_ADDR, sithAI_Startup);
    hook_function(sithAI_Shutdown_ADDR, sithAI_Shutdown);
    hook_function(sithAI_Create_ADDR, sithAI_Create);
    hook_function(sithAI_Free_ADDR, sithAI_Free);
    hook_function(sithAI_RegisterInstinct_ADDR, sithAI_RegisterInstinct);
    hook_function(sithAI_FindInstinct_ADDR, sithAI_FindInstinct);
    hook_function(sithAI_AIList_ADDR, sithAI_AIList);
    hook_function(sithAI_AIStatus_ADDR, sithAI_AIStatus);
    hook_function(sithAI_ParseArg_ADDR, sithAI_ParseArg);
    hook_function(sithAI_CreateAIFramesFomMarker_ADDR, sithAI_CreateAIFramesFomMarker);
    hook_function(sithAI_Tick_ADDR, sithAI_Tick);
    hook_function(sithAI_SetLookFrame_ADDR, sithAI_SetLookFrame);
    hook_function(sithAI_SetMoveThing_ADDR, sithAI_SetMoveThing);
    hook_function(sithAI_Jump_ADDR, sithAI_Jump);
    hook_function(sithAI_RandomFireVector_ADDR, sithAI_RandomFireVector);
    hook_function(sithAI_sub_4EAD60_ADDR, sithAI_sub_4EAD60);
    hook_function(sithAI_CanDetectSightThing_ADDR, sithAI_CanDetectSightThing);
    hook_function(sithAI_CheckSightThing_ADDR, sithAI_CheckSightThing);
    hook_function(sithAI_sub_4EAF40_ADDR, sithAI_sub_4EAF40);
    hook_function(sithAI_FireWeapon_ADDR, sithAI_FireWeapon);
    hook_function(sithAI_sub_4EB300_ADDR, sithAI_sub_4EB300);
    hook_function(sithAI_CanWalk_ExplicitSector_ADDR, sithAI_CanWalk_ExplicitSector);
    hook_function(sithAI_sub_4EA630_ADDR, sithAI_sub_4EA630);
    hook_function(sithAI_FirstThingInView_ADDR, sithAI_FirstThingInView);
    hook_function(sithAI_GetThingsInView_ADDR, sithAI_GetThingsInView);
    hook_function(sithAI_CanWalk_ADDR, sithAI_CanWalk);
    hook_function(sithAI_idk_msgarrived_target_ADDR, sithAI_idk_msgarrived_target);
    hook_function(sithAI_RandomRotationVector_ADDR, sithAI_RandomRotationVector);
    hook_function(sithAI_sub_4EB860_ADDR, sithAI_sub_4EB860);

    // sithAIClass
    hook_function(sithAIClass_Startup_ADDR, sithAIClass_Startup);
    hook_function(sithAIClass_Shutdown_ADDR, sithAIClass_Shutdown);
    hook_function(sithAIClass_ReadStaticAIClassesListText_ADDR, sithAIClass_ReadStaticAIClassesListText);
    hook_function(sithAIClass_AllocWorldAIClasses_ADDR, sithAIClass_AllocWorldAIClasses);
    hook_function(sithAIClass_FreeWorldAIClasses_ADDR, sithAIClass_FreeWorldAIClasses);
    hook_function(sithAIClass_Load_ADDR, sithAIClass_Load);
    hook_function(sithAIClass_LoadEntry_ADDR, sithAIClass_LoadEntry);
    
    // sithAICmd
    hook_function(sithAICmd_Startup_ADDR, sithAICmd_Startup);
    hook_function(sithAICmd_Follow_ADDR, sithAICmd_Follow);
    hook_function(sithAICmd_CircleStrafe_ADDR, sithAICmd_CircleStrafe);
    hook_function(sithAICmd_Crouch_ADDR, sithAICmd_Crouch);
    hook_function(sithAICmd_BlindFire_ADDR, sithAICmd_BlindFire);
    hook_function(sithAICmd_LobFire_ADDR, sithAICmd_LobFire);
    hook_function(sithAICmd_PrimaryFire_ADDR, sithAICmd_PrimaryFire);
    hook_function(sithAICmd_TurretFire_ADDR, sithAICmd_TurretFire);
    hook_function(sithAICmd_Listen_ADDR, sithAICmd_Listen);
    hook_function(sithAICmd_LookForTarget_ADDR, sithAICmd_LookForTarget);
    hook_function(sithAICmd_OpenDoors_ADDR, sithAICmd_OpenDoors);
    hook_function(sithAICmd_Jump_ADDR, sithAICmd_Jump);
    hook_function(sithAICmd_Flee_ADDR, sithAICmd_Flee);
    hook_function(sithAICmd_Withdraw_ADDR, sithAICmd_Withdraw);
    hook_function(sithAICmd_Dodge_ADDR, sithAICmd_Dodge);
    hook_function(sithAICmd_RandomTurn_ADDR, sithAICmd_RandomTurn);
    hook_function(sithAICmd_Roam_ADDR, sithAICmd_Roam);
    hook_function(sithAICmd_SenseDanger_ADDR, sithAICmd_SenseDanger);
    hook_function(sithAICmd_HitAndRun_ADDR, sithAICmd_HitAndRun);
    hook_function(sithAICmd_Retreat_ADDR, sithAICmd_Retreat);
    hook_function(sithAICmd_ReturnHome_ADDR, sithAICmd_ReturnHome);
    hook_function(sithAICmd_Talk_ADDR, sithAICmd_Talk);
    
    // jkAI
    hook_function(jkAI_Startup_ADDR, jkAI_Startup);
    hook_function(jkAI_SaberFighting_ADDR, jkAI_SaberFighting);
    hook_function(jkAI_SpecialAttack_ADDR, jkAI_SpecialAttack);
    hook_function(jkAI_ForcePowers_ADDR, jkAI_ForcePowers);
    hook_function(jkAI_SaberMove_ADDR, jkAI_SaberMove);

    // jkGUIRend
    hook_function(jkGuiRend_CopyVBuffer_ADDR, jkGuiRend_CopyVBuffer);
    hook_function(jkGuiRend_SetPalette_ADDR, jkGuiRend_SetPalette);
    hook_function(jkGuiRend_DrawRect_ADDR, jkGuiRend_DrawRect);
    hook_function(jkGuiRend_UpdateDrawMenu_ADDR, jkGuiRend_UpdateDrawMenu);
    hook_function(jkGuiRend_Paint_ADDR, jkGuiRend_Paint);
    hook_function(jkGuiRend_ElementSetClickShortcutScancode_ADDR, jkGuiRend_ElementSetClickShortcutScancode);
    hook_function(jkGuiRend_MenuSetReturnKeyShortcutElement_ADDR, jkGuiRend_MenuSetReturnKeyShortcutElement);
    hook_function(jkGuiRend_MenuSetEscapeKeyShortcutElement_ADDR, jkGuiRend_MenuSetEscapeKeyShortcutElement);
    hook_function(jkGuiRend_DisplayAndReturnClicked_ADDR, jkGuiRend_DisplayAndReturnClicked);
    hook_function(jkGuiRend_sub_50FAD0_ADDR, jkGuiRend_sub_50FAD0);
    hook_function(jkGuiRend_gui_sets_handler_framebufs_ADDR, jkGuiRend_gui_sets_handler_framebufs);
    hook_function(jkGuiRend_Menuidk_ADDR, jkGuiRend_Menuidk);
    hook_function(jkGuiRend_sub_50FDB0_ADDR, jkGuiRend_sub_50FDB0);
    hook_function(jkGuiRend_Startup_ADDR, jkGuiRend_Startup);
    hook_function(jkGuiRend_Shutdown_ADDR, jkGuiRend_Shutdown);
    hook_function(jkGuiRend_Open_ADDR, jkGuiRend_Open);
    hook_function(jkGuiRend_Close_ADDR, jkGuiRend_Close);
    hook_function(jkGuiRend_MenuGetClickableById_ADDR, jkGuiRend_MenuGetClickableById);
    //hook_function();
    hook_function(jkGuiRend_SetCursorVisible_ADDR, jkGuiRend_SetCursorVisible);
    hook_function(jkGuiRend_UpdateCursor_ADDR, jkGuiRend_UpdateCursor);
    hook_function(jkGuiRend_UpdateSurface_ADDR, jkGuiRend_UpdateSurface);
    hook_function(jkGuiRend_DrawAndFlip_ADDR, jkGuiRend_DrawAndFlip);
    hook_function(jkGuiRend_Invalidate_ADDR, jkGuiRend_Invalidate);
    hook_function(jkGuiRend_DarrayNewStr_ADDR, jkGuiRend_DarrayNewStr);
    hook_function(jkGuiRend_DarrayReallocStr_ADDR, jkGuiRend_DarrayReallocStr);
    hook_function(jkGuiRend_AddStringEntry_ADDR, jkGuiRend_AddStringEntry);
    hook_function(jkGuiRend_SetClickableString_ADDR, jkGuiRend_SetClickableString);
    hook_function(jkGuiRend_GetString_ADDR, jkGuiRend_GetString);
    hook_function(jkGuiRend_GetId_ADDR, jkGuiRend_GetId);
    hook_function(jkGuiRend_GetStringEntry_ADDR, jkGuiRend_GetStringEntry);
    hook_function(jkGuiRend_DarrayFree_ADDR, jkGuiRend_DarrayFree);
    hook_function(jkGuiRend_DarrayFreeEntry_ADDR, jkGuiRend_DarrayFreeEntry);
    hook_function(jkGuiRend_sub_5103E0_ADDR, jkGuiRend_sub_5103E0);
    hook_function(jkGuiRend_ElementHasHoverSound_ADDR, jkGuiRend_ElementHasHoverSound);
    hook_function(jkGuiRend_UpdateAndDrawClickable_ADDR, jkGuiRend_UpdateAndDrawClickable);
    hook_function(jkGuiRend_InvokeEvent_ADDR, jkGuiRend_InvokeEvent);
    hook_function(jkGuiRend_InvokeClicked_ADDR, jkGuiRend_InvokeClicked);
    hook_function(jkGuiRend_PlayClickSound_ADDR, jkGuiRend_PlayClickSound);
    hook_function(jkGuiRend_RenderFocused_ADDR, jkGuiRend_RenderFocused);
    //hook_function(jkGuiRend_RenderIdk2_ADDR, jkGuiRend_RenderIdk2); // TODO: renamed to jkGuiRend_RenderIdk2_alt, needs _ADDR
    //hook_function(jkGuiRend_RenderAll_ADDR, jkGuiRend_RenderAll); // TODO: not yet decompiled
    hook_function(jkGuiRend_ClickableMouseover_ADDR, jkGuiRend_ClickableMouseover);
    hook_function(jkGuiRend_MouseMovedCallback_ADDR, jkGuiRend_MouseMovedCallback);
    hook_function(jkGuiRend_SetVisibleAndDraw_ADDR, jkGuiRend_SetVisibleAndDraw);
    hook_function(jkGuiRend_ClickableHover_ADDR, jkGuiRend_ClickableHover);
    hook_function(jkGuiRend_sub_510C60_ADDR, jkGuiRend_sub_510C60);
    hook_function(jkGuiRend_ClickSound_ADDR, jkGuiRend_ClickSound);
    hook_function(jkGuiRend_HoverOn_ADDR, jkGuiRend_HoverOn);
    hook_function(jkGuiRend_ListBoxEventHandler_ADDR, jkGuiRend_ListBoxEventHandler);
    hook_function(jkGuiRend_ListBoxDraw_ADDR, jkGuiRend_ListBoxDraw);
    hook_function(jkGuiRend_CheckBoxDraw_ADDR, jkGuiRend_CheckBoxDraw);
    hook_function(jkGuiRend_DrawClickableAndUpdatebool_ADDR, jkGuiRend_DrawClickableAndUpdatebool);
    hook_function(jkGuiRend_WindowHandler_ADDR, jkGuiRend_WindowHandler);
    hook_function(jkGuiRend_UpdateMouse_ADDR, jkGuiRend_UpdateMouse);
    hook_function(jkGuiRend_FlipAndDraw_ADDR, jkGuiRend_FlipAndDraw);
    hook_function(jkGuiRend_GetMousePos_ADDR, jkGuiRend_GetMousePos);
    hook_function(jkGuiRend_ResetMouseLatestMs_ADDR, jkGuiRend_ResetMouseLatestMs);
    hook_function(jkGuiRend_InvalidateGdi_ADDR, jkGuiRend_InvalidateGdi);
    hook_function(jkGuiRend_SliderEventHandler_ADDR, jkGuiRend_SliderEventHandler);
    hook_function(jkGuiRend_SliderDraw_ADDR, jkGuiRend_SliderDraw);
    hook_function(jkGuiRend_TextBoxEventHandler_ADDR, jkGuiRend_TextBoxEventHandler);
    hook_function(jkGuiRend_TextBoxDraw_ADDR, jkGuiRend_TextBoxDraw);
    hook_function(jkGuiRend_TextDraw_ADDR, jkGuiRend_TextDraw);
    hook_function(jkGuiRend_PicButtonEventHandler_ADDR, jkGuiRend_PicButtonEventHandler);
    hook_function(jkGuiRend_PicButtonDraw_ADDR, jkGuiRend_PicButtonDraw);
    hook_function(jkGuiRend_TextButtonEventHandler_ADDR, jkGuiRend_TextButtonEventHandler);
    hook_function(jkGuiRend_TextButtonDraw_ADDR, jkGuiRend_TextButtonDraw);
    
    // jkGUI
    hook_function(jkGui_InitMenu_ADDR, jkGui_InitMenu);
    hook_function(jkGui_MessageBeep_ADDR, jkGui_MessageBeep);
    hook_function(jkGui_Startup_ADDR, jkGui_Startup);
    hook_function(jkGui_Shutdown_ADDR, jkGui_Shutdown);
    hook_function(jkGui_SetModeMenu_ADDR, jkGui_SetModeMenu);
    hook_function(jkGui_SetModeGame_ADDR, jkGui_SetModeGame);
    hook_function(jkGui_sub_412E20_ADDR, jkGui_sub_412E20);
    hook_function(jkGui_copies_string_ADDR, jkGui_copies_string);
    hook_function(jkGui_sub_412EC0_ADDR, jkGui_sub_412EC0);
    hook_function(jkGui_sub_412ED0_ADDR, jkGui_sub_412ED0);
    
    // jkGUIForce
    hook_function(jkGuiForce_ChoiceRemoveStar_ADDR, jkGuiForce_ChoiceRemoveStar);
    hook_function(jkGuiForce_ChoiceRemoveStars_ADDR, jkGuiForce_ChoiceRemoveStars);
    hook_function(jkGuiForce_ForceStarsDraw_ADDR, jkGuiForce_ForceStarsDraw);
    hook_function(jkGuiForce_ExtraClick_ADDR, jkGuiForce_ExtraClick);
    hook_function(jkGuiForce_ButtonClick_ADDR, jkGuiForce_ButtonClick);
    hook_function(jkGuiForce_ButtonClick_ADDR, jkGuiForce_ButtonClick);
    hook_function(jkGuiForce_ResetClick_ADDR, jkGuiForce_ResetClick);
    hook_function(jkGuiForce_Show_ADDR, jkGuiForce_Show);
    hook_function(jkGuiForce_Startup_ADDR, jkGuiForce_Startup);
    hook_function(jkGuiForce_Shutdown_ADDR, jkGuiForce_Shutdown);
    hook_function(jkGuiForce_UpdateViewForRank_ADDR, jkGuiForce_UpdateViewForRank);
    hook_function(jkGuiForce_DarkLightHoverDraw_ADDR, jkGuiForce_DarkLightHoverDraw);
    
    // jkGUIGeneral
    hook_function(jkGuiGeneral_Startup_ADDR, jkGuiGeneral_Startup);
    hook_function(jkGuiGeneral_Shutdown_ADDR, jkGuiGeneral_Shutdown);
    hook_function(jkGuiGeneral_Show_ADDR, jkGuiGeneral_Show);
    
    // jkGUIMain
    hook_function(jkGuiMain_Show_ADDR, jkGuiMain_Show);
    hook_function(jkGuiMain_ShowCutscenes_ADDR, jkGuiMain_ShowCutscenes);
    hook_function(jkGuiMain_Startup_ADDR, jkGuiMain_Startup);
    hook_function(jkGuiMain_Shutdown_ADDR, jkGuiMain_Shutdown);
    hook_function(jkGuiMain_PopulateCutscenes_ADDR, jkGuiMain_PopulateCutscenes);
    hook_function(jkGuiMain_FreeCutscenes_ADDR, jkGuiMain_FreeCutscenes);
    
    // jkGUIEsc
    hook_function(jkGuiEsc_Startup_ADDR, jkGuiEsc_Startup);
    hook_function(jkGuiEsc_Shutdown_ADDR, jkGuiEsc_Shutdown);
    hook_function(jkGuiEsc_Show_ADDR, jkGuiEsc_Show);
    
    // jkGUIDecision
    hook_function(jkGuiDecision_Startup_ADDR, jkGuiDecision_Startup);
    hook_function(jkGuiDecision_Shutdown_ADDR, jkGuiDecision_Shutdown);
    hook_function(jkGuiDecision_Show_ADDR, jkGuiDecision_Show);
    
    // jkGUISaveLoad
    hook_function(jkGuiSaveLoad_ListClick_ADDR, jkGuiSaveLoad_ListClick);
    hook_function(jkGuiSaveLoad_PopulateInfo_ADDR, jkGuiSaveLoad_PopulateInfo);
    hook_function(jkGuiSaveLoad_DeleteOnClick_ADDR, jkGuiSaveLoad_DeleteOnClick);
    hook_function(jkGuiSaveLoad_PopulateList_ADDR, jkGuiSaveLoad_PopulateList);
    hook_function(jkGuiSaveLoad_SaveSort_ADDR, jkGuiSaveLoad_SaveSort);
    hook_function(jkGuiSaveLoad_Show_ADDR, jkGuiSaveLoad_Show);
    hook_function(jkGuiSaveLoad_PopulateInfoInit_ADDR, jkGuiSaveLoad_PopulateInfoInit);
    hook_function(jkGuiSaveLoad_Startup_ADDR, jkGuiSaveLoad_Startup);
    hook_function(jkGuiSaveLoad_Shutdown_ADDR, jkGuiSaveLoad_Shutdown);
    
    // jkGUISingleplayer
    hook_function(jkGuiSingleplayer_Startup_ADDR, jkGuiSingleplayer_Startup);
    hook_function(jkGuiSingleplayer_Shutdown_ADDR, jkGuiSingleplayer_Shutdown);
    hook_function(jkGuiSingleplayer_Show_ADDR, jkGuiSingleplayer_Show);
    hook_function(jkGuiSingleplayer_EnumEpisodes_ADDR, jkGuiSingleplayer_EnumEpisodes);
    hook_function(jkGuiSingleplayer_sub_41AA30_ADDR, jkGuiSingleplayer_sub_41AA30);
    hook_function(jkGuiSingleplayer_sub_41AC70_ADDR, jkGuiSingleplayer_sub_41AC70);
    hook_function(jkGuiSingleplayer_sub_41AD00_ADDR, jkGuiSingleplayer_sub_41AD00);
    
    // jkGUISingleTally
    hook_function(jkGuiSingleTally_Show_ADDR, jkGuiSingleTally_Show);
    hook_function(jkGuiSingleTally_Startup_ADDR, jkGuiSingleTally_Startup);
    
    // jkGUIControlOptions
    hook_function(jkGuiControlOptions_Startup_ADDR, jkGuiControlOptions_Startup);
    hook_function(jkGuiControlOptions_Shutdown_ADDR, jkGuiControlOptions_Shutdown);
    hook_function(jkGuiControlOptions_Show_ADDR, jkGuiControlOptions_Show);
    
    // jkGUISetup
    hook_function(jkGuiSetup_sub_412EF0_ADDR, jkGuiSetup_sub_412EF0);
    hook_function(jkGuiSetup_Startup_ADDR, jkGuiSetup_Startup);
    hook_function(jkGuiSetup_Shutdown_ADDR, jkGuiSetup_Shutdown);
    hook_function(jkGuiSetup_Show_ADDR, jkGuiSetup_Show);
    
    // jkGUIGameplay
    hook_function(jkGuiGameplay_Startup_ADDR, jkGuiGameplay_Startup);
    hook_function(jkGuiGameplay_Shutdown_ADDR, jkGuiGameplay_Shutdown);
    hook_function(jkGuiGameplay_Show_ADDR, jkGuiGameplay_Show);
    
    // jkGUITitle
    hook_function(jkGuiTitle_Startup_ADDR, jkGuiTitle_Startup);
    hook_function(jkGuiTitle_Shutdown_ADDR, jkGuiTitle_Shutdown);
    hook_function(jkGuiTitle_sub_4189A0_ADDR, jkGuiTitle_sub_4189A0);
    hook_function(jkGuiTitle_quicksave_related_func1_ADDR, jkGuiTitle_quicksave_related_func1);
    hook_function(jkGuiTitle_UnkDraw_ADDR, jkGuiTitle_UnkDraw);
    hook_function(jkGuiTitle_WorldLoadCallback_ADDR, jkGuiTitle_WorldLoadCallback);
    hook_function(jkGuiTitle_ShowLoadingStatic_ADDR, jkGuiTitle_ShowLoadingStatic);
    hook_function(jkGuiTitle_ShowLoading_ADDR, jkGuiTitle_ShowLoading);
    hook_function(jkGuiTitle_LoadingFinalize_ADDR, jkGuiTitle_LoadingFinalize);
    
    // jkGUISound
    hook_function(jkGuiSound_Startup_ADDR, jkGuiSound_Startup);
    hook_function(jkGuiSound_Shutdown_ADDR, jkGuiSound_Shutdown);
    hook_function(jkGuiSound_Show_ADDR, jkGuiSound_Show);
    
    // jkGUIObjectives
    hook_function(jkGuiObjectives_CustomRender_ADDR, jkGuiObjectives_CustomRender);
    hook_function(jkGuiObjectives_Show_ADDR, jkGuiObjectives_Show);
    hook_function(jkGuiObjectives_Startup_ADDR, jkGuiObjectives_Startup);
    hook_function(jkGuiObjectives_Shutdown_ADDR, jkGuiObjectives_Shutdown);
    
    // jkGUIDialog
    hook_function(jkGuiDialog_Startup_ADDR, jkGuiDialog_Startup);
    hook_function(jkGuiDialog_Shutdown_ADDR, jkGuiDialog_Shutdown);
    hook_function(jkGuiDialog_OkCancelDialog_ADDR, jkGuiDialog_OkCancelDialog);
    hook_function(jkGuiDialog_ErrorDialog_ADDR, jkGuiDialog_ErrorDialog);
    hook_function(jkGuiDialog_YesNoDialog_ADDR, jkGuiDialog_YesNoDialog);
    
    // jkGUIMultiplayer
    hook_function(jkGuiMultiplayer_Startup_ADDR, jkGuiMultiplayer_Startup);
    hook_function(jkGuiMultiplayer_Shutdown_ADDR, jkGuiMultiplayer_Shutdown);
    hook_function(jkGuiMultiplayer_Show_ADDR, jkGuiMultiplayer_Show);

    // jkGUIBuildMulti
    hook_function(jkGuiBuildMulti_StartupEditCharacter_ADDR, jkGuiBuildMulti_StartupEditCharacter);
    hook_function(jkGuiBuildMulti_ShutdownEditCharacter_ADDR, jkGuiBuildMulti_ShutdownEditCharacter);
    hook_function(jkGuiBuildMulti_ModelLoader_ADDR, jkGuiBuildMulti_ModelLoader);
    hook_function(jkGuiBuildMulti_MatLoader_ADDR, jkGuiBuildMulti_MatLoader);
    hook_function(jkGuiBuildMulti_KeyframeLoader_ADDR, jkGuiBuildMulti_KeyframeLoader);
    hook_function(jkGuiBuildMulti_CloseRender_ADDR, jkGuiBuildMulti_CloseRender);
    hook_function(jkGuiBuildMulti_ThingInit_ADDR, jkGuiBuildMulti_ThingInit);
    hook_function(jkGuiBuildMulti_ThingCleanup_ADDR, jkGuiBuildMulti_ThingCleanup);
    hook_function(jkGuiBuildMulti_ShowEditCharacter_ADDR, jkGuiBuildMulti_ShowEditCharacter);
    hook_function(jkGuiBuildMulti_DisplayModel_ADDR, jkGuiBuildMulti_DisplayModel);
    hook_function(jkGuiBuildMulti_ModelDrawer_ADDR, jkGuiBuildMulti_ModelDrawer);
    hook_function(jkGuiBuildMulti_SaberDrawer_ADDR, jkGuiBuildMulti_SaberDrawer);
    hook_function(jkGuiBuildMulti_sub_41A120_ADDR, jkGuiBuildMulti_sub_41A120);
    hook_function(jkGuiBuildMulti_SaberButtonClicked_ADDR, jkGuiBuildMulti_SaberButtonClicked);
    hook_function(jkGuiBuildMulti_Startup_ADDR, jkGuiBuildMulti_Startup);
    hook_function(jkGuiBuildMulti_Shutdown_ADDR, jkGuiBuildMulti_Shutdown);
    hook_function(jkGuiBuildMulti_Load_ADDR, jkGuiBuildMulti_Load);
    hook_function(jkGuiBuildMulti_Show_ADDR, jkGuiBuildMulti_Show);
    hook_function(jkGuiBuildMulti_Show2_ADDR, jkGuiBuildMulti_Show2);
    hook_function(jkGuiBuildMulti_ShowNewCharacter_ADDR, jkGuiBuildMulti_ShowNewCharacter);
    hook_function(jkGuiBuildMulti_sub_41D000_ADDR, jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler);
    hook_function(jkGuiBuildMulti_ShowLoad_ADDR, jkGuiBuildMulti_ShowLoad);
    hook_function(jkGuiBuildMulti_sub_41D680_ADDR, jkGuiBuildMulti_sub_41D680);
    hook_function(jkGuiBuildMulti_sub_41D830_ADDR, jkGuiBuildMulti_sub_41D830);

    // jkGUIMultiTally
    hook_function(jkGuiMultiTally_Show_ADDR, jkGuiMultiTally_Show);
    hook_function(jkGuiMultiTally_SortPlayerScore_ADDR, jkGuiMultiTally_SortPlayerScore);
    hook_function(jkGuiMultiTally_Startup_ADDR, jkGuiMultiTally_Startup);
    hook_function(jkGuiMultiTally_Shutdown_ADDR, jkGuiMultiTally_Shutdown);
    hook_function(jkGuiMultiTally_ShowTeamScores_ADDR, jkGuiMultiTally_ShowTeamScores);
    hook_function(jkGuiMultiTally_SortTeamScore_ADDR, jkGuiMultiTally_SortTeamScore);
    hook_function(jkGuiMultiTally_sub_4188B0_ADDR, jkGuiMultiTally_sub_4188B0);
    
    // Darray
    hook_function(Darray_New_ADDR, Darray_New);
    hook_function(Darray_Free_ADDR, Darray_Free);
    hook_function(Darray_NewEntry_ADDR, Darray_NewEntry);
    hook_function(Darray_GetIndex_ADDR, Darray_GetIndex);
    hook_function(Darray_ClearAll_ADDR, Darray_ClearAll);
    hook_function(Darray_sub_520CB0_ADDR, Darray_sub_520CB0);
    
    // sithConsole
    hook_function(sithConsole_Startup_ADDR, sithConsole_Startup);
    hook_function(sithConsole_Shutdown_ADDR, sithConsole_Shutdown);
    hook_function(sithConsole_Open_ADDR, sithConsole_Open);
    hook_function(sithConsole_Close_ADDR, sithConsole_Close);
    hook_function(sithConsole_PrintString_ADDR, sithConsole_PrintString);
    hook_function(sithConsole_PrintWString_ADDR, sithConsole_PrintWString);
    hook_function(sithConsole_ExeCommand_ADDR, sithConsole_ExeCommand);
    hook_function(sithConsole_sub_4DA100_ADDR, sithConsole_sub_4DA100);
    hook_function(sithConsole_Flush_ADDR, sithConsole_Flush);
    hook_function(sithConsole_RegisterCommand_ADDR, sithConsole_RegisterCommand);
    hook_function(sithConsole_RegisterPrintFunctions_ADDR, sithConsole_RegisterPrintFunctions);
    hook_function(sithConsole_Help_ADDR, sithConsole_Help);
    hook_function(sithConsole_AlertSound_ADDR, sithConsole_AlertSound);

    // sithCommand
    hook_function(sithCommand_Startup_ADDR, sithCommand_Startup);
    hook_function(sithCommand_Tick_ADDR, sithCommand_Tick);
    hook_function(sithCommand_Session_ADDR, sithCommand_Session);
    hook_function(sithCommand_DebugMode_ADDR, sithCommand_DebugMode);
    hook_function(sithCommand_CogTrace_ADDR, sithCommand_CogTrace);
    hook_function(sithCommand_CogPause_ADDR, sithCommand_CogPause);
    hook_function(sithCommand_CogList_ADDR, sithCommand_CogList);
    hook_function(sithCommand_Fly_ADDR, sithCommand_Fly);
    hook_function(sithCommand_Memory_ADDR, sithCommand_Memory);
    hook_function(sithCommand_DynamicMemory_ADDR, sithCommand_DynamicMemory);
    hook_function(sithCommand_MemoryDump_ADDR, sithCommand_MemoryDump);
    hook_function(sithCommand_MatList_ADDR, sithCommand_MatList);
    hook_function(sithCommand_Coords_ADDR, sithCommand_Coords);
    hook_function(sithCommand_Warp_ADDR, sithCommand_Warp);
    hook_function(sithCommand_Activate_ADDR, sithCommand_Activate);
    hook_function(sithCommand_Jump_ADDR, sithCommand_Jump);
    hook_function(sithCommand_Players_ADDR, sithCommand_Players);
    hook_function(sithCommand_PingPlayer_ADDR, sithCommand_PingPlayer);
    hook_function(sithCommand_Kick_ADDR, sithCommand_Kick);
    hook_function(sithCommand_CompareMatInfos_ADDR, sithCommand_CompareMatInfos);

    //hook_function(Darray_sub_520CB0_ADDR, Darray_sub_520CB0);
    // test saber time
    //*(flex_t*)0x5220C4 = 0.01f;
    
    //hook_function();
    
#ifdef LINUX
    hook_function(Window_ShowCursorUnwindowed_ADDR, Window_ShowCursorUnwindowed);
    //hook_function(Window_DefaultHandler_ADDR, Window_DefaultHandler);
    hook_function(Window_MessageLoop_ADDR, Window_MessageLoop);
    hook_function(Window_msg_main_handler_ADDR, Window_msg_main_handler);
    //hook_function(sithControl_GetAxis_ADDR, sithControl_GetAxis); // TODO: not yet decompiled
    //hook_function(sithControl_ReadAxisStuff_ADDR, sithControl_ReadAxisStuff); // TODO: not yet decompiled
    hook_function(sithControl_GetKey_ADDR, sithControl_GetKey);

    hook_function(stdControl_Open_ADDR, stdControl_Open);
    hook_function(stdControl_Close_ADDR, stdControl_Close);
    hook_function(stdControl_Flush_ADDR, stdControl_Flush);
    hook_function(stdControl_ToggleCursor_ADDR, stdControl_ToggleCursor);
    hook_function(stdControl_ShowCursor_ADDR, stdControl_ShowCursor);
    hook_function(stdControl_ReadControls_ADDR, stdControl_ReadControls);
    hook_function(stdControl_FinishRead_ADDR, stdControl_FinishRead);
    hook_function(stdControl_ReadAxis_ADDR, stdControl_ReadAxis);
    //hook_function(sithControl_GetAxis2_ADDR, sithControl_GetAxis2); // TODO: not yet decompiled
    
    hook_function(stdDisplay_Startup_ADDR, stdDisplay_Startup);
    hook_function(stdDisplay_VBufferFill_ADDR, stdDisplay_VBufferFill);
    hook_function(stdDisplay_VBufferCopy_ADDR, stdDisplay_VBufferCopy);
    hook_function(stdDisplay_SetMasterPalette_ADDR, stdDisplay_SetMasterPalette);
    hook_function(stdDisplay_DDrawGdiSurfaceFlip_ADDR, stdDisplay_DDrawGdiSurfaceFlip);
    hook_function(stdDisplay_ddraw_waitforvblank_ADDR, stdDisplay_ddraw_waitforvblank);
    hook_function(stdDisplay_ClearRect_ADDR, stdDisplay_ClearRect);
    hook_function(stdDisplay_SetMode_ADDR, stdDisplay_SetMode);
    hook_function(stdDisplay_FindClosestMode_ADDR, stdDisplay_FindClosestMode);
    hook_function(stdDisplay_FindClosestDevice_ADDR, stdDisplay_FindClosestDevice);
    hook_function(stdDisplay_Open_ADDR, stdDisplay_Open);
    hook_function(stdDisplay_Close_ADDR, stdDisplay_Close);
    hook_function(stdDisplay_VBufferNew_ADDR, stdDisplay_VBufferNew);
    hook_function(stdDisplay_VBufferLock_ADDR, stdDisplay_VBufferLock);
    hook_function(stdDisplay_VBufferUnlock_ADDR, stdDisplay_VBufferUnlock);
    hook_function(stdDisplay_VBufferSetColorKey_ADDR, stdDisplay_VBufferSetColorKey);
    hook_function(stdDisplay_VBufferFree_ADDR, stdDisplay_VBufferFree);
    hook_function(stdDisplay_RestoreDisplayMode_ADDR, stdDisplay_RestoreDisplayMode);
    hook_function(stdDisplay_VBufferConvertColorFormat_ADDR, stdDisplay_VBufferConvertColorFormat);
    
    hook_function(stdPlatform_GetTimeMsec_ADDR, stdPlatform_GetTimeMsec);
    
    hook_function(sithControl_Close_ADDR, sithControl_Close);
    
    hook_function(Video_SwitchToGDI_ADDR, Video_SwitchToGDI);
    
    hook_function(stdFileUtil_Deltree_ADDR, stdFileUtil_Deltree);
    
    hook_function(stdSound_Startup_ADDR, stdSound_Startup);
    hook_function(stdSound_Shutdown_ADDR, stdSound_Shutdown);
    hook_function(stdSound_SetMenuVolume_ADDR, stdSound_SetMenuVolume);
    hook_function(stdSound_BufferCreate_ADDR, stdSound_BufferCreate);
    hook_function(stdSound_BufferSetData_ADDR, stdSound_BufferSetData);
    hook_function(stdSound_BufferUnlock_ADDR, stdSound_BufferUnlock);
    hook_function(stdSound_BufferPlay_ADDR, stdSound_BufferPlay);
    hook_function(stdSound_BufferStop_ADDR, stdSound_BufferStop);
    hook_function(stdSound_BufferReset_ADDR, stdSound_BufferReset);
    hook_function(stdSound_BufferDuplicate_ADDR, stdSound_BufferDuplicate);
    hook_function(stdSound_SetPositionOrientation_ADDR, stdSound_SetPositionOrientation);
    hook_function(stdSound_SetPosition_ADDR, stdSound_SetPosition);
    hook_function(stdSound_SetVelocity_ADDR, stdSound_SetVelocity);
    hook_function(stdSound_IsPlaying_ADDR, stdSound_IsPlaying);
    
    hook_function(sithSoundMixer_StopAll_ADDR, sithSoundMixer_StopAll);
    hook_function(sithSoundMixer_ResumeAll_ADDR, sithSoundMixer_ResumeAll);
    hook_function(sithSoundMixer_StopSong_ADDR, sithSoundMixer_StopSong);
    hook_function(sithSoundMixer_PlaySong_ADDR, sithSoundMixer_PlaySong);
    hook_function(sithSoundMixer_SetMusicVol_ADDR, sithSoundMixer_SetMusicVol);
    
    hook_function(stdComm_OpenConnection_ADDR, stdComm_OpenConnection);
    hook_function(stdComm_CloseConnection_ADDR, stdComm_CloseConnection);
    hook_function(stdComm_Open_ADDR, stdComm_Open);

    //hook_function_inv(sithSurface_Startup_ADDR, sithSurface_Startup);
    //hook_function_inv(sithSurface_Shutdown_ADDR, sithSurface_Shutdown);
    //hook_function_inv(sithSurface_Open_ADDR, sithSurface_Open);
    //hook_function_inv(sithSurface_ValidateWorldSurfaces_ADDR, sithSurface_ValidateWorldSurfaces);
    //hook_function_inv(sithSurface_ReadSurfacesListText_ADDR, sithSurface_ReadSurfacesListText);
    //hook_function_inv(sithSurface_ValidateSurfacePointer_ADDR, sithSurface_ValidateSurfacePointer);
    //hook_function_inv(sithSurface_HideSectorAdjoin_ADDR, sithSurface_HideSectorAdjoin);
    //hook_function_inv(sithSurface_ShowSectorAdjoin_ADDR, sithSurface_ShowSectorAdjoin);
    //hook_function_inv(sithSurface_SurfaceAnim_ADDR, sithSurface_SurfaceAnim);
    //hook_function_inv(sithSurface_Startup2_ADDR, sithSurface_Startup2);
    //hook_function_inv(sithSurface_Startup3_ADDR, sithSurface_Startup3);
    //hook_function_inv(sithSurface_SetSectorLight_ADDR, sithSurface_SetSectorLight);
    //hook_function_inv(sithSurface_FreeWorldSurfaces_ADDR, sithSurface_FreeWorldSurfaces);
    //hook_function_inv(sithSurface_Tick_ADDR, sithSurface_Tick);
    //hook_function_inv(sithSurface_ScrollSky_ADDR, sithSurface_ScrollSky);
    //hook_function_inv(sithSurface_StopAnim_ADDR, sithSurface_StopAnim);
    //hook_function_inv(sithSurface_GetSurfaceAnim_ADDR, sithSurface_GetSurfaceAnim);
    //hook_function_inv(sithSurface_SurfaceLightAnim_ADDR, sithSurface_SurfaceLightAnim);
    //hook_function_inv(sithSurface_SlideWall_ADDR, sithSurface_SlideWall);
    //hook_function_inv(sithSurface_MaterialAnim_ADDR, sithSurface_MaterialAnim);
    //hook_function_inv(sithSurface_DetachThing_ADDR, sithSurface_DetachThing);
    //hook_function_inv(sithSurface_GetCenterPoint_ADDR, sithSurface_GetCenterPoint);
    //hook_function_inv(sithSurface_SlideHorizonSky_ADDR, sithSurface_SlideHorizonSky);
    //hook_function_inv(sithSurface_sub_4F00A0_ADDR, sithSurface_sub_4F00A0);
    //hook_function_inv(sithSurface_SetThingLight_ADDR, sithSurface_SetThingLight);
    //hook_function_inv(sithSurface_HandleThingImpact_ADDR, sithSurface_HandleThingImpact);
    //hook_function_inv(sithSurface_GetRdSurface_ADDR, sithSurface_GetRdSurface);

#if 0
    hook_function_inv(sithIntersect_IsSphereInSector_ADDR, sithIntersect_IsSphereInSector);
    hook_function_inv(sithIntersect_sub_5080D0_ADDR, sithIntersect_sub_5080D0);
    hook_function_inv(sithIntersect_sub_508540_ADDR, sithIntersect_sub_508540);
    hook_function_inv(sithIntersect_CheckSphereFaceIntersectionEx_ADDR, sithIntersect_CheckSphereFaceIntersectionEx);
    hook_function_inv(sithIntersect_CheckSphereHit_ADDR, sithIntersect_CheckSphereHit); // regressed
    hook_function_inv(sithIntersect_TestSphereFaceHit_ADDR, sithIntersect_TestSphereFaceHit);
    hook_function_inv(sithIntersect_CheckSphereFaceIntersection_ADDR, sithIntersect_CheckSphereFaceIntersection);
    hook_function_inv(sithIntersect_CheckSphereMeshIntersection_ADDR, sithIntersect_CheckSphereMeshIntersection);
    hook_function_inv(sithIntersect_CheckSphereFaceHitVerticesIntersection_ADDR, sithIntersect_CheckSphereFaceHitVerticesIntersection);
#endif

#if 0
    hook_function_inv(sithCollision_Startup_ADDR, sithCollision_Startup);
    hook_function_inv(sithCollision_Shutdown_ADDR, sithCollision_Shutdown);
    hook_function_inv(sithCollision_AddCollisionHandler_ADDR, sithCollision_AddCollisionHandler);
    hook_function_inv(sithCollision_AddSurfaceCollisionHandler_ADDR, sithCollision_AddSurfaceCollisionHandler);
    hook_function_inv(sithCollision_PopStack_ADDR, sithCollision_PopStack);
    hook_function_inv(sithCollision_SearchForCollisions_ADDR, sithCollision_SearchForCollisions);
    hook_function_inv(sithCollision_DecreaseStackLevel_ADDR, sithCollision_DecreaseStackLevel);
    hook_function_inv(sithCollision_FindSectorInRadius_ADDR, sithCollision_FindSectorInRadius);
    hook_function_inv(sithCollision_FallHurt_ADDR, sithCollision_FallHurt);
    hook_function_inv(sithCollision_RotateThing_ADDR, sithCollision_RotateThing);*/
    hook_function_inv(sithCollision_MoveThing_ADDR, sithCollision_MoveThing);
    hook_function_inv(sithCollision_HandleThingHitSurface_ADDR, sithCollision_HandleThingHitSurface);
    hook_function_inv(sithCollision_ThingCollisionHandler_ADDR, sithCollision_ThingCollisionHandler);
    hook_function_inv(sithCollision_CollideHurt_ADDR, sithCollision_CollideHurt);
    hook_function_inv(sithCollision_HasLOS_ADDR, sithCollision_HasLOS);
    hook_function_inv(sithCollision_sub_4E77A0_ADDR, sithCollision_sub_4E77A0);
    hook_function_inv(sithCollision_ParticleAndActorCollisionHandler_ADDR, sithCollision_ParticleAndActorCollisionHandler);
#endif

#if 0
    hook_function_inv(rdPuppet_New_ADDR, rdPuppet_New);
    hook_function_inv(rdPuppet_Free_ADDR, rdPuppet_Free);
    hook_function_inv(rdPuppet_BuildJointMatrices_ADDR, rdPuppet_BuildJointMatrices);
    hook_function_inv(rdPuppet_ResetTrack_ADDR, rdPuppet_ResetTrack);
    hook_function_inv(rdPuppet_UpdateTracks_ADDR, rdPuppet_UpdateTracks);
    hook_function_inv(rdPuppet_AddTrack_ADDR, rdPuppet_AddTrack);
    hook_function_inv(rdPuppet_SetCallback_ADDR, rdPuppet_SetCallback);
    hook_function_inv(rdPuppet_FadeInTrack_ADDR, rdPuppet_FadeInTrack);
    hook_function_inv(rdPuppet_AdvanceTrack_ADDR, rdPuppet_AdvanceTrack);
    hook_function_inv(rdPuppet_FadeOutTrack_ADDR, rdPuppet_FadeOutTrack);
    hook_function_inv(rdPuppet_SetTrackSpeed_ADDR, rdPuppet_SetTrackSpeed);
    hook_function_inv(rdPuppet_SetStatus_ADDR, rdPuppet_SetStatus);
    hook_function_inv(rdPuppet_PlayTrack_ADDR, rdPuppet_PlayTrack);
    hook_function_inv(rdPuppet_unk_ADDR, rdPuppet_unk);
    hook_function_inv(rdPuppet_RemoveTrack_ADDR, rdPuppet_RemoveTrack);
#endif

#if 0
    hook_function_inv(sithDSS_SendSyncSurface_ADDR, sithDSS_SendSyncSurface);
    hook_function_inv(sithDSS_ProcessSyncSurface_ADDR, sithDSS_ProcessSyncSurface);
    hook_function_inv(sithDSS_SendSyncSector_ADDR, sithDSS_SendSyncSector);
    hook_function_inv(sithDSS_ProcessSyncSector_ADDR, sithDSS_ProcessSyncSector);
// syncsectoralt
    hook_function_inv(sithDSS_SendSyncAI_ADDR, sithDSS_SendSyncAI);
    hook_function_inv(sithDSS_ProcessSyncAI_ADDR, sithDSS_ProcessSyncAI);
    hook_function_inv(sithDSS_SendSyncItemDesc_ADDR, sithDSS_SendSyncItemDesc);
    hook_function_inv(sithDSS_ProcessSyncItemDesc_ADDR, sithDSS_ProcessSyncItemDesc);
    hook_function_inv(sithDSS_SendStopAnim_ADDR, sithDSS_SendStopAnim);
    hook_function_inv(sithDSS_ProcessStopAnim_ADDR, sithDSS_ProcessStopAnim);
    hook_function_inv(sithDSS_PuppetStatus_ADDR, sithDSS_PuppetStatus);
    hook_function_inv(sithDSS_ProcessPuppetStatus_ADDR, sithDSS_ProcessPuppetStatus);
    hook_function_inv(sithDSS_SendSyncTimers_ADDR, sithDSS_SendSyncTimers);
    hook_function_inv(sithDSS_ProcessSyncTimers_ADDR, sithDSS_ProcessSyncTimers);
    hook_function_inv(sithDSS_SendSyncPalEffects_ADDR, sithDSS_SendSyncPalEffects);
    hook_function_inv(sithDSS_ProcessSyncPalEffects_ADDR, sithDSS_ProcessSyncPalEffects);
    hook_function_inv(sithDSS_SyncCameras_ADDR, sithDSS_SyncCameras);
    hook_function_inv(sithDSS_ProcessSyncCameras_ADDR, sithDSS_ProcessSyncCameras);
    hook_function_inv(sithDSS_SyncGameState_ADDR, sithDSS_SyncGameState);
    hook_function_inv(sithDSS_ProcessSyncGameState_ADDR, sithDSS_ProcessSyncGameState);
    
    hook_function_inv(sithDSSThing_SendSyncThingFull_ADDR, sithDSSThing_SendSyncThingFull);
    hook_function_inv(sithDSSThing_SendPlaySoundPos_ADDR, sithDSSThing_SendPlaySoundPos);
    hook_function_inv(sithDSSThing_ProcessSyncThingFull_ADDR, sithDSSThing_ProcessSyncThingFull);
    hook_function_inv(sithDSSThing_ProcessPlaySoundPos_ADDR, sithDSSThing_ProcessPlaySoundPos);
    hook_function_inv(sithDSSThing_Attachment_ADDR, sithDSSThing_Attachment);
    
    hook_function_inv(sithPuppet_Startup_ADDR, sithPuppet_Startup);
    hook_function_inv(sithPuppet_New_ADDR, sithPuppet_New);
    hook_function_inv(sithPuppet_Free_ADDR, sithPuppet_Free);
    hook_function_inv(sithPuppet_SetMoveMode_ADDR, sithPuppet_SetMoveMode);
    hook_function_inv(sithPuppet_PlayMode_ADDR, sithPuppet_PlayMode);
    hook_function_inv(sithPuppet_PlayKey_ADDR, sithPuppet_PlayKey);
    hook_function_inv(sithPuppet_ResetTrack_ADDR, sithPuppet_ResetTrack);
    hook_function_inv(sithPuppet_UpdatePuppet_ADDR, sithPuppet_UpdatePuppet);
    hook_function_inv(sithPuppet_UpdateThingMove_ADDR, sithPuppet_UpdateThingMove);
    hook_function_inv(sithPuppet_sub_4E4A20_ADDR, sithPuppet_sub_4E4A20);
    hook_function_inv(sithPuppet_DefaultCallback_ADDR, sithPuppet_DefaultCallback);
    hook_function_inv(sithPuppet_StopKey_ADDR, sithPuppet_StopKey);
    hook_function_inv(sithPuppet_SetArmedMode_ADDR, sithPuppet_SetArmedMode);
#endif

#if 0
    hook_function_inv(sithKeyFrame_Load_ADDR, sithKeyFrame_Load);
    hook_function_inv(sithKeyFrame_GetByIdx_ADDR, sithKeyFrame_GetByIdx);
    hook_function_inv(sithKeyFrame_LoadEntry_ADDR, sithKeyFrame_LoadEntry);
    hook_function_inv(sithKeyFrame_New_ADDR, sithKeyFrame_New);
    hook_function_inv(sithKeyFrame_Free_ADDR, sithKeyFrame_Free);
    
    hook_function_inv(rdKeyframe_RegisterLoader_ADDR, rdKeyframe_RegisterLoader);
    hook_function_inv(rdKeyframe_RegisterUnloader_ADDR, rdKeyframe_RegisterUnloader);
    hook_function_inv(rdKeyframe_NewEntry_ADDR, rdKeyframe_NewEntry);
    hook_function_inv(rdKeyframe_Load_ADDR, rdKeyframe_Load);
    hook_function_inv(rdKeyframe_LoadEntry_ADDR, rdKeyframe_LoadEntry);
    hook_function_inv(rdKeyframe_Write_ADDR, rdKeyframe_Write);
    hook_function_inv(rdKeyframe_Free_ADDR, rdKeyframe_Free);
    hook_function_inv(rdKeyframe_FreeEntry_ADDR, rdKeyframe_FreeEntry);
#endif
#endif

    // ========================================
    // ========================================

#endif // !NO_JK_MMAP
}
#endif // WIN64_STANDALONE
