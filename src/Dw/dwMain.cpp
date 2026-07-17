// DroidWorks app-layer core.
//
// Ghidra source: dwMain part 1 (0x410d60-0x411550) — dwCompleteMovie, the
// error/fatal-UI HostServices hooks, the dw-core/dwPlayer dwString static
// ctors; and dw part 2 (0x419bd0-0x41c0ef) — the MASTER boot dw_Startup /
// dw_Shutdown, the material-recolor cache, items.inv parse, dwMain_MainLoopTick
// and the dwApp boot dwSegment (vtbl dwApp_vtbl @0x51ee40).
//
// LANGUAGE: this file is C++ (was dwMain.c). dwMain parts 1 & 2 are verifiably
// C++ in the binary (MSVC EH frames / ExceptionList around dwString /
// dwStringTable / dwList / dwConfFile / dwGuiQuickView object locals; dwApp /
// dwCompleteMovie / dwMaterialCache are classes with ctor/dtor pairs). The DW
// object model (dwString / dwStringTable / dwList) is C++-only with NO C API —
// dwList.h even #errors if included from C — so the boot flow (global.txt string
// table, the *.PLS / *.MIS enumerate-and-parse loops, dwPlayer_basePath) cannot
// be written in C. Converting to .cpp also resolves the pre-existing linkage
// mismatch on dwGuiOptions_New / dwCompleteMovie_New (dwGuiInGame.cpp declares
// them as C++-mangled functions). All symbols that C files / extern "C"
// consumers reference keep C linkage via the extern "C" blocks below.

#include "Dw/dwMain.h"

#include "Dw/dwRect.h"
#include "Dw/dwInits.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwCursor.h"
#include "Dw/dwMovie.h"
#include "Dw/dwWidget.h"
#include "Dw/dwSegment.h"
#include "Dw/dwColormap.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h" // dwDisplay_pScreenImage->desc (full-screen present rect)
#include "Dw/dwImageDraw.h"
#include "Dw/dwFont.h"
#include "Dw/dwControlPanel.h"
#include "Dw/dwPart.h"
#include "Dw/dwPlayer.h"
#include "Dw/dwCog.h"
#include "Dw/dwCamera.h"
#include "Dw/dwLaser.h"
#include "Dw/dwDroidStats.h"
#include "Dw/dwWorkshop.h"
#include "Dw/dwWorkshopDroidEditor.h"
#include "Dw/dwGuiMission.h"
#include "Dw/dwGuiOptions.h"
#include "Dw/dwGuiCredits.h"
#include "Dw/dwEnding.h"
#include "Dw/dwSith.h"
#include "Dw/dwSound.h"
#include "Dw/dwString.h"
#include "Dw/dwStringTable.h"
#include "Dw/dwList.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwMission.h"
#include "stdPlatform.h"
#include "globals.h" // pHS, g_should_exit

extern "C" {
#include "General/stdHashtbl.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h"
#include "Engine/rdColormap.h"
}

// ------------------------------------------------------------------
// dw-core globals (formerly dwMain.c placeholders — now the real owners).
//
// Kept in an extern "C" block so the many extern "C" consumers across the DW
// layer resolve to unmangled symbols (global-scope variables are unmangled in
// C++ regardless, but this makes the linkage explicit).
extern "C" {

// The DW host-services pointer. Binary global dw_hostServices @0x53d988 is the
// DW app's OWN inline copy of HostServices; here we alias the engine's shared
// pHS (set in dwMain_Startup). See report note.
HostServices* dwMain_pHS = NULL;

// The three dw-core lists are the raw circular-list SENTINEL nodes (consumers
// iterate `for (n = list->pNext; n != list; n = n->pNext)` and wrap them as
// `(dwList*)&dwCore_pXxx`). Sentinels are created once in dwMain_Startup; the
// blueprint/mission contents are filled by dw_Startup and freed by dw_Shutdown.
dwListNode* dwCore_pBlueprintList = NULL; // @0x53d964: *.PLS blueprints (dwPart*)
dwListNode* dwCore_pMissionList   = NULL; // @0x53d95c: *.MIS missions (dwMission*)
dwListNode* dwCore_pWorkspaceNodes = NULL; // @0x53d984: workspace droid (dwPartNode*)

// @0x53d958 — global.txt localized-string table (dwGuiScreen_LocalizeString).
dwStringTable* dwCore_pGlobalStrings = NULL;
// @0x53d954 — the selected mission record (first parsed *.MIS at boot).
dwMission* dwCore_pCurrentMission = NULL;
// @0x53e854 — 0 = dirty-rect draws (faithful default); 1 = full redraw.
uint8_t dwMain_bFullRedraw = 0;

} // extern "C"

// Persistent dw-core dwStrings currently OWNED by dwInits.cpp (the binary
// attributes dwCore_workspaceName @0x53d978 + dwCore_currentRefFile @0x53d968
// to the dw-core static ctors in this unit — see report; kept in dwInits.cpp
// for now to avoid a cross-file edit). dwPlayer_name comes from dwPlayer.h.
extern dwString dwCore_workspaceName;
extern dwString dwCore_currentRefFile;

// dw_bStarted @0x53e8xx — set once dwSith/MaterialCache/dwFont bring-up
// succeeds inside dw_Startup; gates dw_Shutdown teardown.
static char dw_bStarted = 0;

// ==================================================================
//  Material-recolor cache (dw part 2, 0x41b870-0x41bfff)
//
//  DroidWorks droid-part team-color painting cache. struct 0x187c: a colormap
//  (textures.cmp), an enable flag, a 0x209-slot round-robin entry table
//  {refCount, rdMaterial* pColorVariant, rdMaterial* pBaseMaterial}, a
//  round-robin cursor and a name->entry hash. Registered as the rdMaterial
//  loader/unloader so every part material loads through here.
// ==================================================================

struct dwMaterialCacheEntry
{
    int refCount;               // 0x00
    rdMaterial* pColorVariant;  // 0x04: the "<name>COLOR.mat" recolor-source variant
    rdMaterial* pBaseMaterial;  // 0x08: the plain material
};

struct dwMaterialCache
{
    rdColormap* pColormap;                 // 0x00: textures.cmp
    uint8_t bEnabled;                      // 0x04 (3 bytes pad -> entries @0x08)
    dwMaterialCacheEntry entries[0x209];   // 0x08
    uint32_t currentIndex;                 // 0x1874: round-robin cursor
    tHashTable* pByName;                   // 0x1878
}; // sizeof 0x187c

// @dwMain_pMaterialCache — the cache singleton (NULL until dw_Startup).
static dwMaterialCache* dwMain_pMaterialCache = NULL;

// @0x41bd80 (dwMain_MaterialCache_GetRecolored) — return the material a caller
// should use for an entry.
static rdMaterial* dwMain_MaterialCache_GetRecolored(dwMaterialCache* pCache, dwMaterialCacheEntry* pEntry)
{
    // TODO(dw-decomp): the enabled + has-variant path rebuilds a fresh
    // per-texel team-color-remapped copy of pBaseMaterial each call (Ghidra
    // @41bd80: allocs a material, rdMaterial_LoadEntry, then remaps every
    // texel through pCache->pColormap + pColorVariant via the DW-binary
    // texture lock/unlock helpers stdDisplay_FUN_004fdf70/fdfc0). That texel
    // loop depends on DW-binary rdMaterial/rdTexture struct offsets that need
    // per-field verification against the repo's rd structs — deferred. We
    // return the cached variant (or base), so parts render with their base
    // texture (untinted), matching the documented P4 fallback behavior.
    if (!pCache->bEnabled || pEntry->pColorVariant == NULL)
    {
        if (pEntry->pColorVariant != NULL)
            return pEntry->pColorVariant;
        return pEntry->pBaseMaterial;
    }
    return pEntry->pColorVariant; // (see TODO: should be a fresh recolored copy)
}

// @0x41bd60 (dwMain_MaterialCache_Find) — name -> entry.
static dwMaterialCacheEntry* dwMain_MaterialCache_Find(dwMaterialCache* pCache, const char* pName)
{
    return (dwMaterialCacheEntry*)stdHashtbl_Find(pCache->pByName, pName);
}

// @0x41ba60 (dwMain_MaterialCache_Load) — the rdMaterial loader hook. Miss ->
// round-robin free slot, rdMaterial_LoadEntry (fallback dflt.mat), build the
// "<name>COLOR.mat" variant, hash-add keyed by the stored material name.
static rdMaterial* dwMain_MaterialCache_Load(dwMaterialCache* pCache, const char* pName, int a3, int a4)
{
    // Key on the filename part only (binary: dwString_FindFilename).
    char* pKey = (char*)pName;
    dwString_FindFilename(&pKey);

    dwMaterialCacheEntry* pEntry = dwMain_MaterialCache_Find(pCache, pKey);
    if (pEntry != NULL)
    {
        pEntry->refCount++;
        return dwMain_MaterialCache_GetRecolored(pCache, pEntry);
    }

    // Find the next free slot round-robin from currentIndex.
    uint32_t idx = pCache->currentIndex;
    do
    {
        idx = (idx + 1) % 0x209;
        if (idx == pCache->currentIndex)
            break;
    } while (pCache->entries[idx].pBaseMaterial != NULL);

    pEntry = &pCache->entries[idx];
    if (pEntry->pBaseMaterial != NULL)
    {
        jk_printf("DROIDWORKS MATERIAL CACHE FULL!\n");
        // (binary reuses the hash-hit path here — but there was no hit, so the
        //  slot stays full; return nothing usable)
        return NULL;
    }

    // Load the base material (with dflt.mat fallback).
    pEntry->pBaseMaterial = (rdMaterial*)dwMain_pHS->alloc(sizeof(rdMaterial));
    if (pEntry->pBaseMaterial != NULL &&
        rdMaterial_LoadEntry(pKey, pEntry->pBaseMaterial, a3, a4) == 0)
    {
        dwMain_pHS->free(pEntry->pBaseMaterial);
        pEntry->pBaseMaterial = NULL;
    }
    if (pEntry->pBaseMaterial == NULL)
    {
        pEntry->pBaseMaterial = (rdMaterial*)dwMain_pHS->alloc(sizeof(rdMaterial));
        if (pEntry->pBaseMaterial != NULL)
        {
            if (rdMaterial_LoadEntry((char*)"dflt.mat", pEntry->pBaseMaterial, a3, a4) == 0)
            {
                dwMain_pHS->free(pEntry->pBaseMaterial);
                pEntry->pBaseMaterial = NULL;
            }
            else
            {
                _strncpy(pEntry->pBaseMaterial->mat_fpath, pKey, 0x1f);
                pEntry->pBaseMaterial->mat_fpath[0x1f] = 0;
            }
        }
        if (pEntry->pBaseMaterial == NULL)
            return NULL;
    }

    // Build the "<name>COLOR.mat" recolor-source variant name and load it.
    char aVariant[64];
    _strncpy(aVariant, pKey, sizeof(aVariant) - 1);
    aVariant[sizeof(aVariant) - 1] = 0;
    char* pExt = aVariant;
    dwString_FindExtension(&pExt);
    _strcpy(pExt, "COLOR.mat");

    pEntry->pColorVariant = (rdMaterial*)dwMain_pHS->alloc(sizeof(rdMaterial));
    if (pEntry->pColorVariant != NULL &&
        rdMaterial_LoadEntry(aVariant, pEntry->pColorVariant, a3, a4) == 0)
    {
        dwMain_pHS->free(pEntry->pColorVariant);
        pEntry->pColorVariant = NULL;
    }

    pCache->currentIndex = idx;
    stdHashtbl_Add(pCache->pByName, pEntry->pBaseMaterial->mat_fpath, pEntry);

    pEntry->refCount++;
    return dwMain_MaterialCache_GetRecolored(pCache, pEntry);
}

// @0x41bcb0 (dwMain_MaterialCache_Unload) — the rdMaterial unloader hook.
static void dwMain_MaterialCache_Unload(dwMaterialCache* pCache, rdMaterial* pMaterial)
{
    dwMaterialCacheEntry* pEntry = dwMain_MaterialCache_Find(pCache, pMaterial->mat_fpath);
    if (pEntry == NULL)
        return;

    // A recolored copy that is neither the variant nor the base is caller-owned.
    if (pMaterial != pEntry->pColorVariant && pMaterial != pEntry->pBaseMaterial)
    {
        rdMaterial_FreeEntry(pMaterial);
        dwMain_pHS->free(pMaterial);
    }

    if (--pEntry->refCount == 0)
    {
        stdHashtbl_Remove(pCache->pByName, pEntry->pBaseMaterial->mat_fpath);
        if (pEntry->pBaseMaterial != NULL)
        {
            rdMaterial_FreeEntry(pEntry->pBaseMaterial);
            dwMain_pHS->free(pEntry->pBaseMaterial);
            pEntry->pBaseMaterial = NULL;
        }
        if (pEntry->pColorVariant != NULL)
        {
            rdMaterial_FreeEntry(pEntry->pColorVariant);
            dwMain_pHS->free(pEntry->pColorVariant);
            pEntry->pColorVariant = NULL;
        }
    }
}

// The registered loader/unloader function-pointer callbacks. Kept as VARIABLES
// (consumers extern them as `rdMaterialLoader_t dwMain_MaterialLoaderCb`), each
// pointing at a thin dispatch onto the singleton. @0x41b870 / @0x41b890.
static rdMaterial* dwMain_MaterialCache_LoaderFn(const char* pName, int a2, int a3)
{
    return dwMain_MaterialCache_Load(dwMain_pMaterialCache, pName, a2, a3);
}
static int dwMain_MaterialCache_UnloaderFn(rdMaterial* pMaterial)
{
    dwMain_MaterialCache_Unload(dwMain_pMaterialCache, pMaterial);
    return 0;
}

extern "C" {
rdMaterialLoader_t   dwMain_MaterialLoaderCb   = &dwMain_MaterialCache_LoaderFn;
rdMaterialUnloader_t dwMain_MaterialUnloaderCb = &dwMain_MaterialCache_UnloaderFn;
}

// @0x41b970 (dwMain_MaterialCache_Ctor)
static void dwMain_MaterialCache_Ctor(dwMaterialCache* pCache)
{
    pCache->pColormap = NULL;
    pCache->bEnabled = 1;
    for (int i = 0; i < 0x209; i++)
    {
        pCache->entries[i].refCount = 0;
        pCache->entries[i].pColorVariant = NULL;
        pCache->entries[i].pBaseMaterial = NULL;
    }
    pCache->currentIndex = 0;
    pCache->pByName = stdHashtbl_New(0x209);
    pCache->pColormap = rdColormap_Load((char*)"textures.cmp");
}

// @0x41b9c0 (dwMain_MaterialCache_Dtor)
static void dwMain_MaterialCache_Dtor(dwMaterialCache* pCache)
{
    for (int i = 0; i < 0x209; i++)
    {
        if (pCache->entries[i].pBaseMaterial != NULL)
        {
            rdMaterial_FreeEntry(pCache->entries[i].pBaseMaterial);
            dwMain_pHS->free(pCache->entries[i].pBaseMaterial);
        }
        if (pCache->entries[i].pColorVariant != NULL)
        {
            rdMaterial_FreeEntry(pCache->entries[i].pColorVariant);
            dwMain_pHS->free(pCache->entries[i].pColorVariant);
        }
    }
    if (pCache->pByName != NULL)
        stdHashtbl_Free(pCache->pByName);
    if (pCache->pColormap != NULL)
        rdColormap_Free(pCache->pColormap);
}

// @0x41b8b0 (dwMain_MaterialCache_Startup)
static int dwMain_MaterialCache_Startup(void)
{
    dwMain_pMaterialCache = (dwMaterialCache*)dwMain_pHS->alloc(sizeof(dwMaterialCache));
    if (dwMain_pMaterialCache != NULL)
        dwMain_MaterialCache_Ctor(dwMain_pMaterialCache);

    if (dwMain_pMaterialCache != NULL)
    {
        rdMaterial_RegisterLoader(dwMain_MaterialLoaderCb);
        rdMaterial_RegisterUnloader(dwMain_MaterialUnloaderCb);
    }
    return dwMain_pMaterialCache != NULL;
}

// @0x41b930 (dwMain_MaterialCache_Shutdown)
static void dwMain_MaterialCache_Shutdown(void)
{
    rdMaterial_RegisterLoader(NULL);
    rdMaterial_RegisterUnloader(NULL);
    if (dwMain_pMaterialCache != NULL)
    {
        dwMain_MaterialCache_Dtor(dwMain_pMaterialCache);
        dwMain_pHS->free(dwMain_pMaterialCache);
    }
    dwMain_pMaterialCache = NULL;
}

// @0x41ba40 / @0x41ba50 — the runtime enable/disable (dwPart tinting) — C shims.
extern "C" void dwMain_MaterialCache_Enable(void)
{
    if (dwMain_pMaterialCache != NULL)
        dwMain_pMaterialCache->bEnabled = 1;
}
extern "C" void dwMain_MaterialCache_Disable(void)
{
    if (dwMain_pMaterialCache != NULL)
        dwMain_pMaterialCache->bEnabled = 0;
}

// @0x41bf70 (dwMain_MaterialCache_RecolorMasked) — paint a masked region of a
// part material with a team color.
extern "C" void dwMain_MaterialCache_RecolorMasked(rdMaterial* pMaterial, int matchColor, int newColor)
{
    // TODO(dw-decomp): the faithful body (@41bf70) locks the material's texture
    // surfaces and remaps every texel whose mask-texture value == matchColor to
    // the colormap-shaded newColor. It depends on the DW-binary rdMaterial /
    // rdTexture struct offsets + stdDisplay_FUN_004fdf70/fdfc0 texel lock
    // helpers (same deferral as GetRecolored). No-op = parts keep their base
    // texture (untinted), which is the documented acceptable fallback.
    (void)pMaterial; (void)matchColor; (void)newColor;
}

// ==================================================================
//  Error / fatal-UI HostServices hooks (dwMain part 1, 0x411160-0x411430)
//
//  Translated for completeness. NOT installed by default: in OpenJKDF2 the DW
//  layer aliases the ENGINE's shared HostServices (dwMain_pHS == pHS), so
//  hooking its alloc/fileOpen slots would affect the whole engine; the engine
//  already owns error handling. The CD-insert retry and MessageBoxA are Win32
//  specific and irrelevant to the extracted-file OpenJKDF2 flow. See report.
// ==================================================================

static dwStringTable* dwMain_pErrorStrings = NULL;
static char dwMain_bAborting = 0;

// @0x411360 (dwMain_ShowErrorBox) — binary: MessageBoxA "Fatal Error".
static void dwMain_ShowErrorBox(const char* pMsg)
{
    // Note: Win32 MessageBoxA -> portable print (no modal UI in OpenJKDF2).
    const char* pTitle = "Fatal Error";
    if (dwMain_pErrorStrings != NULL)
    {
        dwString* pVal = dwMain_pErrorStrings->Find("ERROR_TITLE");
        if (pVal != NULL)
            pTitle = pVal->pBuffer;
    }
    jk_printf("DroidWorks [%s]: %s\n", pTitle, pMsg);
}

// @0x4111e0 (dwMain_FreeErrorStrings)
static void dwMain_FreeErrorStrings(void)
{
    if (dwMain_pErrorStrings != NULL)
    {
        delete dwMain_pErrorStrings;
        dwMain_pErrorStrings = NULL;
    }
}

// @0x41b6a0 (dwMain_ShutdownSubsystems) — the fatal-exit teardown.
static void dwMain_ShutdownSubsystems(void)
{
    dwSegment_Shutdown();
    // Note: dwAnim_SmushShutdown (SMUSH cluster, P8) + the dwGob critical
    // section DeleteCriticalSection are omitted (Win32 / not yet ported).
    stdSound_Shutdown();
    dwDisplay_Shutdown();
    dwMain_FreeErrorStrings();
    inits_Shutdown();
}

// @0x411210 (dwMain_FatalExit)
static void dwMain_FatalExit(void)
{
    if (dwMain_bAborting == 0)
    {
        dwMain_bAborting = 1;
        dwMain_ShutdownSubsystems();
    }
    abort();
}

// @0x411160 (dwMain_InstallErrorHandlers) — loads errors.txt; the binary also
// swapped HostServices alloc(+0x20)/fileOpen(+0x30) for AllocOrDie /
// OpenFileOrPromptCD wrappers (omitted here — shared engine pHS, see banner).
static int dwMain_InstallErrorHandlers(void)
{
    dwMain_pErrorStrings = new dwStringTable("errors.txt");
    return 1;
}

// @0x411230 (dwMain_AllocOrDie) — translated; not wired (see banner).
[[maybe_unused]] static void* dwMain_AllocOrDie(int size)
{
    void* p = dwMain_pHS->alloc(size);
    if (p == NULL)
    {
        const char* pMsg = "There is not enough memory to run Droidworks. The program will now exit.";
        if (dwMain_pErrorStrings != NULL)
        {
            dwString* pVal = dwMain_pErrorStrings->Find("OUT_OF_MEMORY");
            if (pVal != NULL)
                pMsg = pVal->pBuffer;
        }
        dwMain_ShowErrorBox(pMsg);
        dwMain_FatalExit();
    }
    return p;
}

// ==================================================================
//  Inventory types — items.inv (dw part 2, 0x41a8c0 / 0x41a9b0)
// ==================================================================

// @0x41a8c0 (dw_ParseInventoryTypes) — parses items.inv into the DW-forked
// sithInventory type table.
extern "C" void dw_ParseInventoryTypes(void)
{
    // TODO(dw-decomp): the faithful body needs the DW-forked sithInventory
    // subsystem (sithInventory_RegisterType / sithInventory_g_aTypes /
    // SithInventoryType + dw_LoadInventoryCog), which is NOT in the repo yet
    // (part of the P8 sith-engine diff). Stubbed until then — no inventory
    // types register, so tool/inventory verbs have no descriptors.
    jk_printf("dw_ParseInventoryTypes: stub (needs sithInventory, P8)\n");
}

// @0x41a9b0 (dw_FreeInventoryIcons)
extern "C" void dw_FreeInventoryIcons(void)
{
    // (see dw_ParseInventoryTypes — nothing to free while stubbed)
}

// ==================================================================
//  dwCompleteMovie — end-of-mission win movie (dwMain part 1, 0x410d60)
// ==================================================================

// dwCompleteMovie_New(idx) — pushed by dwGuiInGame_EndMission on a win.
// C linkage: dwGuiInGame.cpp declares it inside its extern "C" block.
extern "C" dwSegment* dwCompleteMovie_New(int idx)
{
    // TODO(dw-decomp): the faithful dwCompleteMovie (@410d60) is a dwMovie
    // subclass that plays one of 3 end-of-mission .san clips (name table I
    // could not read out of the binary data section) AND overlays a rendered
    // droid snapshot (dwGuiQuickView -> stdBitmapRle2). SMUSH playback is
    // stubbed engine-wide (movies finish immediately -> RequestAdvance), so a
    // plain dwMovie is a functional stand-in; the .san names below are guesses
    // and the droid-snapshot overlay is dropped. Verify the names against the
    // binary data at the dwCompleteMovie ctor's string table if the overlay is
    // ever restored.
    static const char* aNames[3] = { "complet0.san", "complet1.san", "complet2.san" };
    if (idx < 0 || idx > 2)
        idx = 0;
    return new dwMovie(aNames[idx]);
}

// ==================================================================
//  Kept placeholders (NOT P7 — owners elsewhere)
// ==================================================================

// owner: dwGuiOptions — the options SCREEN factory. dw_Startup does NOT use it
// (it pushes the enter-seg), but dwGuiInGame_EndMission's FINAL path does
// (dwSegment_Push(dwGuiOptions_New(0))). Left as a link placeholder; belongs in
// dwGuiOptions.cpp as a `new dwGuiOptions(0)` factory (report).
// C linkage: dwGuiInGame.cpp declares it inside its extern "C" block.
extern "C" dwSegment* dwGuiOptions_New(int index) { (void)index; return NULL; }

// owner: dwCog part 1 (P8) — the 34-verb registration table. C linkage
// (consumed by dwSith.c, a C file).
extern "C" void dwCog_RegisterVerbs(void)
{
    jk_printf("TODO(dw-decomp): dwCog_RegisterVerbs stub (owner dwCog part 1 P8)\n");
}
// owner: P8 sith-engine diff audit — DW-forked sith internals (no repo twin).
// C linkage: dwGuiInGame.cpp declares them inside its extern "C" block.
extern "C" void sithCamera_sub_44B190(void) {}   // DW cam-slot-7 setup
extern "C" void sithControl_FUN_00456da0(void) {} // DW control-fn registration

extern "C" {
// owner: P8 sith-engine diff audit — DW-forked engine globals with no repo
// twin (cosmetic/gameplay state reached only once a mission is running).
uint8_t* DAT_006478f8 = NULL;                                // stdDisplay current video-mode record
int _DAT_006915f0 = 0, _DAT_00691528 = 0, _DAT_0069158c = 0; // DW sith control latches
float _DAT_0069a658 = 0.0f;                                  // DW inventory battery-capacity global
int DAT_0054518c = 0, DAT_00545190 = 0, DAT_00545194 = 0, DAT_005b7200 = 0, DAT_00546880 = 0; // render counters
uint32_t DAT_0053e810 = 0, DAT_0053e814 = 0;                 // DW load-progress bar bounds
float _DAT_00528698 = 0.0f, _DAT_0052869c = 0.0f, _DAT_005286c0 = 0.0f, _DAT_005286d4 = 0.0f;  // chatter timing
const char* PTR_s_GHCA009_wav_00528688[] = { 0 };            // ambient chatter wav tables (unrecovered)
const char* PTR_s_GHCA006_wav_00528678[] = { 0 };
const char* PTR_s_GHCA058_wav_005286c8[] = { 0 };
const char* PTR_s_GHCA048_wav_005286a8[] = { 0 };
} // extern "C"

// ==================================================================
//  dw_Startup / dw_Shutdown — the MASTER game init (dw part 2, 0x419bd0)
// ==================================================================

// @0x419bd0 (dw_Startup) — the Activate slot of the dwApp boot dwSegment.
//
// ⭐ THE HANG FIX: this stages the dwWorkshop singleton on the segment stack
// (BOTTOM) UNDER the intro/options enter-seg. dwGuiOptions case 0xc does
// dwSegment_PushAndAdvance(wstart.san) expecting the workshop already staged;
// the old boot shortcut never staged it, so loading a profile underflowed the
// segment stack ("Popped off the segment stack!"). Boot stack bottom->top =
// [dwWorkshop, intro-or-options-enter-seg], then RequestAdvance.
static bool dw_Startup(void)
{
    jk_printf("Initializing DroidWorks...\n");

    if (!dwSith_Startup(dwMain_pHS))
        return dw_bStarted != 0;
    if (!dwMain_MaterialCache_Startup())
        return dw_bStarted != 0;
    if (!dwFont_Startup())
        return dw_bStarted != 0;

    dw_bStarted = 1;

    // Note: the binary seeds the CRT rng from getTimerTick here (FUN_00507f20).
    // Omitted — no _srand in the repo; the random-droid generator still works
    // unseeded. (Report.)

    // Sound manager (spawns the worker thread; deferred out of dwMain_Startup).
    dwSound_Startup();

    // global.txt localized-string table.
    dwCore_pGlobalStrings = new dwStringTable("global.txt");

    // dwPlayer_basePath = (installPath || workingDir) + PLAYER_DIR + '\'.
    dwPlayer_basePath.AssignString(&dwCore_installPath);
    if (dwPlayer_basePath.length == 0)
        dwPlayer_basePath.AssignString(&dwCore_workingDir);
    if (dwCore_pGlobalStrings != NULL)
    {
        dwString* pPlayerDir = dwCore_pGlobalStrings->Find("PLAYER_DIR");
        if (pPlayerDir != NULL && pPlayerDir->pBuffer != NULL)
            dwPlayer_basePath.Append(pPlayerDir->pBuffer, pPlayerDir->length);
    }
    if (dwPlayer_basePath.pBuffer != NULL)
        stdFileUtil_MkDir(dwPlayer_basePath.pBuffer);
    dwPlayer_basePath.Append("\\", 1);

    // Binary gates this on a 16bpp video mode (DAT_006478f8+0x20 == 0x10);
    // load it unconditionally (colormap load is mode-agnostic in our display).
    dwColormap_Load((char*)"workshop2.cmp");

    dwControlPanel_Startup();

    // ---- enumerate *.PLS -> dwPart blueprints -----------------------------
    int nBlueprints = 0;
    {
        dwList files;
        inits_EnumFilesByExt("PLS", &files);
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel; pNode = pNode->pNext)
        {
            dwString* pFilename = (dwString*)pNode->pData;
            dwConfFile conf;
            dwConfFile_Open(&conf, pFilename->pBuffer);
            while (!conf.bEof)
            {
                char* pTok;
                do
                {
                    if (conf.bEof)
                        break;
                    dwConfFile_ReadLine(&conf);
                    pTok = dwConfFile_NextToken(&conf);
                } while (!dwString_Equals(pTok, "PART"));
                if (conf.bEof)
                    break;

                // dwPart(conf) parses one record until END_PART.
                dwPart* pPart = new dwPart(&conf);
                dwList* pList = (dwList*)&dwCore_pBlueprintList;
                pList->InsertAfter(pList->pSentinel->pPrev, pPart);
                nBlueprints++;
            }
            dwConfFile_Close(&conf);
        }
        // free the enumerated filename strings + the list nodes/sentinel.
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel;)
        {
            dwListNode* pNext = pNode->pNext;
            delete (dwString*)pNode->pData;
            pNode = pNext;
        }
        files.Free();
    }

    // build the name -> blueprint hash.
    dwPart_hashBlueprints = stdHashtbl_New((nBlueprints * 3) >> 1);
    if (dwPart_hashBlueprints != NULL)
    {
        for (dwListNode* pNode = dwCore_pBlueprintList->pNext;
             pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
        {
            dwPart* pPart = (dwPart*)pNode->pData;
            stdHashtbl_Add(dwPart_hashBlueprints, pPart->name.pBuffer, pPart);
        }
    }

    // ---- enumerate *.MIS -> dwMission records -----------------------------
    {
        dwList files;
        inits_EnumFilesByExt("MIS", &files);
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel; pNode = pNode->pNext)
        {
            dwString* pFilename = (dwString*)pNode->pData;
            dwConfFile conf;
            dwConfFile_Open(&conf, pFilename->pBuffer);
            while (!conf.bEof)
            {
                char* pTok;
                do
                {
                    if (conf.bEof)
                        break;
                    dwConfFile_ReadLine(&conf);
                    pTok = dwConfFile_NextToken(&conf);
                } while (!dwString_Equals(pTok, "BEGIN"));
                if (conf.bEof)
                    break;

                dwMission* pMission = dwMission_New(&conf); // alloc 0x8c + ParseInfo
                dwList* pList = (dwList*)&dwCore_pMissionList;
                pList->InsertAfter(pList->pSentinel->pPrev, pMission);
                if (dwCore_pCurrentMission == NULL)
                    dwCore_pCurrentMission = pMission;
            }
            dwConfFile_Close(&conf);
        }
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel;)
        {
            dwListNode* pNext = pNode->pNext;
            delete (dwString*)pNode->pData;
            pNode = pNext;
        }
        files.Free();
    }

    // ---- stage the segment stack ------------------------------------------
    // 1) the dwWorkshop singleton (bottom) — the load-profile-hang fix.
    dwWorkshop_CreateSingleton();
    if (dwWorkshop_pSingleton != NULL)
        dwSegment_Push(static_cast<dwSegment*>(dwWorkshop_pSingleton));

    // 2) intro sequencer (no profiles) OR options enter-seg (sign-in), on top.
    {
        dwList profiles;
        dwPlayer_EnumProfiles(&profiles);
        bool bHasProfiles = (profiles.pSentinel->pNext != profiles.pSentinel);

        dwSegment* pEnter;
        if (!bHasProfiles)
            pEnter = new dwGuiIntroSeg();
        else
            pEnter = new dwGuiOptionsEnterSeg(2); // binary: screenIndex 2 (sign-in)
        dwSegment_Push(pEnter);

        for (dwListNode* pNode = profiles.pSentinel->pNext; pNode != profiles.pSentinel;)
        {
            dwListNode* pNext = pNode->pNext;
            delete (dwString*)pNode->pData;
            pNode = pNext;
        }
        profiles.Free();
    }

    dwSegment_RequestAdvance();

    // Binary here draws a loading fill + Present (cosmetic clear before the
    // first screen paints). Present the current (opening.cmp) surface so the
    // window is not stale until the next tick paints the enter-seg.
    // Note: dwDisplay_AddDirtyRect dereferences its rect (no NULL "whole
    // screen" shorthand) — pass the real full-screen rect from the screen image.
    if (dwDisplay_pScreenImage)
    {
        dwRect full;
        full.left = 0;
        full.top = 0;
        full.right = (int16_t)dwDisplay_pScreenImage->desc.width;
        full.bottom = (int16_t)dwDisplay_pScreenImage->desc.height;
        dwDisplay_AddDirtyRect(&full);
    }
    dwDisplay_Present();

    return dw_bStarted != 0;
}

// @0x41a7d0 (dw_Shutdown) — the Destroy slot of the dwApp boot dwSegment.
static void dw_Shutdown(void)
{
    jk_printf("Shutting Down DroidWorks...\n");

    dwPlayer_SavePlr();

    if (dwSound_pManager != NULL)
        dwSound_Shutdown();

    // Free the mission records.
    if (dwCore_pMissionList != NULL)
    {
        for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList;)
        {
            dwListNode* pNext = pNode->pNext;
            if (pNode->pData != NULL)
                dwMission_Delete((dwMission*)pNode->pData); // FreeInfo + free
            pNode = pNext;
        }
        ((dwList*)&dwCore_pMissionList)->Free();
        dwCore_pMissionList = NULL;
    }
    dwCore_pCurrentMission = NULL;

    if (dwPart_hashBlueprints != NULL)
    {
        stdHashtbl_Free(dwPart_hashBlueprints);
        dwPart_hashBlueprints = NULL;
    }

    // Free any workspace droid nodes.
    if (dwCore_pWorkspaceNodes != NULL)
    {
        for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext; pNode != dwCore_pWorkspaceNodes;)
        {
            dwListNode* pNext = pNode->pNext;
            if (pNode->pData != NULL)
                delete (dwPartNode*)pNode->pData;
            pNode = pNext;
        }
        ((dwList*)&dwCore_pWorkspaceNodes)->Free();
        dwCore_pWorkspaceNodes = NULL;
    }

    // Free the blueprints.
    if (dwCore_pBlueprintList != NULL)
    {
        for (dwListNode* pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList;)
        {
            dwListNode* pNext = pNode->pNext;
            if (pNode->pData != NULL)
                delete (dwPart*)pNode->pData;
            pNode = pNext;
        }
        ((dwList*)&dwCore_pBlueprintList)->Free();
        dwCore_pBlueprintList = NULL;
    }

    if (dwCore_pGlobalStrings != NULL)
    {
        delete dwCore_pGlobalStrings;
        dwCore_pGlobalStrings = NULL;
    }

    // The dw-core / dwPlayer persistent dwStrings (owned by dwInits.cpp for now;
    // see report — binary attributes dwCore_workspaceName/currentRefFile here).
    dwCore_workspaceName.Free();
    dwPlayer_name.Free();
    dwCore_currentRefFile.Free();

    if (dw_bStarted)
    {
        dwFont_Shutdown();
        dwMain_MaterialCache_Shutdown();
        // Note: rd_FUN_0047eae0 (renderer texture-cache flush) + dwSith_Shutdown.
        dwSith_Shutdown();
    }
}

// Note: the binary modeled dw_Startup/dw_Shutdown as the Activate/Destroy slots
// of a persistent dwApp ROOT segment (vtbl dwApp_vtbl @0x51ee40) that stays at
// the bottom of the stack for the whole app lifetime. In OpenJKDF2, dwMain_
// BootFlow calls dw_Startup directly and dwMain_Shutdown calls dw_Shutdown at
// app exit — so no throwaway boot segment is needed (one would self-destruct
// right after advancing and tear the engine down mid-boot).

// ==================================================================
//  Startup / Shutdown / per-frame tick (OpenJKDF2 seams)
// ==================================================================

static int dwMain_bInitted = 0;
// The boot flow (dwMain_BootFlow) sets this after pushing the dwApp boot
// segment + RequestAdvance. Until then dwMain_GuiAdvance must NOT tick the
// (empty) segment stack.
static int dwMain_bBooted = 0;

// Create a fresh empty circular-list sentinel (dwList allocates + self-links
// one; dwList has no dtor, so the sentinel outlives the local handle).
static dwListNode* dwMain_NewSentinel(void)
{
    dwList l;
    return l.pSentinel;
}

extern "C" int dwMain_Startup()
{
    // Statics reset (soft-reset loop rule).
    dwMain_bInitted = 0;
    dwMain_bBooted = 0;
    dw_bStarted = 0;
    dwMain_bAborting = 0;
    dwMain_pMaterialCache = NULL;
    dwMain_pErrorStrings = NULL;
    dwCore_pGlobalStrings = NULL;
    dwCore_pCurrentMission = NULL;
    dwMain_bFullRedraw = 0;
    dwMain_MaterialLoaderCb = &dwMain_MaterialCache_LoaderFn;
    dwMain_MaterialUnloaderCb = &dwMain_MaterialCache_UnloaderFn;
    dwMain_pHS = pHS; // alias the engine HostServices (binary: dw_hostServices copy)

    // Empty dw-core list sentinels (dw_Startup fills, dw_Shutdown clears).
    if (dwCore_pBlueprintList == NULL)  dwCore_pBlueprintList  = dwMain_NewSentinel();
    if (dwCore_pMissionList == NULL)    dwCore_pMissionList    = dwMain_NewSentinel();
    if (dwCore_pWorkspaceNodes == NULL) dwCore_pWorkspaceNodes = dwMain_NewSentinel();

    stdPlatform_Printf("OpenJKDF2: %s — DroidWorks app layer\n", __func__);

    // DW VFS (dwGob + inits hooked fileOpen) — first thing the binary does.
    inits_Startup(pHS);

    // CRT-static-ctor replacements + module static resets (must precede any
    // dwDisplay_Open; ran before WinMain in the binary).
    dwDisplay_Startup();
    dwCursor_Startup();
    dwMovie_Startup();
    dwWidget_Startup();
    dwSegment_Startup();
    dwColormap_Startup();
    dwControlPanel_Startup(); // dw_aPartSlotColors fill (also re-run in dw_Startup)
    dwPart_Startup();
    dwPlayer_Startup();
    dwCog_Startup();
    dwCamera_Startup();
    dwLaser_Startup();
    dwDroidStats_Startup();
    dwWorkshop_Startup();
    dwWorkshopDroidEditor_Startup();
    dwGuiMission_Startup();
    dwGuiOptions_Startup();
    dwGuiCredits_Startup();
    dwEnding_Startup();
    // Note: dwFont_Startup / dwSound_Startup / dwSith_Startup /
    // dwMain_MaterialCache_Startup are part of the dw_Startup boot flow, not the
    // static-ctor reset — they run there.

    dwMain_bInitted = 1;
    return 1;
}

extern "C" void dwMain_Shutdown()
{
    if (!dwMain_bInitted)
        return;

    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    if (dwMain_bBooted && dw_bStarted)
        dw_Shutdown(); // mirrors dwApp_Destroy -> dw_Shutdown

    dwSegment_Shutdown();
    dwSegment_FreePlaylist(); // header rule: before the next dwSegment_Startup
    dwFont_Shutdown();
    dwMain_FreeErrorStrings();
    inits_Shutdown();
    dwMain_bInitted = 0;
    dwMain_bBooted = 0;
}

// Added (P7): the DroidWorks app boot flow — the OpenJKDF2 mapping of the
// binary's StartOpeningCutscenes @0x41b530. The engine's Main_Startup already
// brought up the SDL window + stdDisplay, the renderer (rdStartup), the VFS
// (inits_Startup, via dwMain_Startup) and stdSound — so this does the
// DW-specific bring-up (dwImage null vtable, DW display surface, palette, arm
// the segment loop) and then pushes the dwApp boot dwSegment whose Activate =
// dw_Startup (which stages the workshop + intro/options enter-seg).
//
// Runs lazily on the FIRST dwMain_GuiAdvance tick: by then the engine main loop
// + Window draw handlers are live, which dwDisplay_Present's flip needs.
static void dwMain_BootFlow(void)
{
    // Set first so a mid-boot failure can't respin the flow every frame.
    dwMain_bBooted = 1;

    // dwImage null-vtable (HostServices print stubs) — StartOpeningCutscenes step.
    dwImage_InitNullVtable(dwMain_pHS);

    // errors.txt (translated; not installed as HostServices hooks — see banner).
    dwMain_InstallErrorHandlers();

    // Bring up the DW display over the engine Video buffers + boot colormap.
    if (!dwDisplay_Open((char*)"opening.cmp"))
        stdPlatform_Printf("OpenJKDF2: dwMain_BootFlow — dwDisplay_Open(\"opening.cmp\") failed\n");
    dwColormap_SetDisplayPalette((void*)(intptr_t)dw_settingBrightness);

    // Arm the segment loop keep-running flag (StartOpeningCutscenes did this
    // before pushing any segment).
    dwSegment_SignalQuit();

    // Build dwPlayer_basePath minimally now so profile enumeration works even
    // before dw_Startup rebuilds it from global.txt PLAYER_DIR.
    dwPlayer_SetupBasePath("Player");

    // Run the master boot directly (dw_Startup itself stages the workshop +
    // intro/options enter-seg onto the segment stack and RequestAdvances).
    // Note: the binary modeled dw_Startup as the Activate slot of a persistent
    // dwApp ROOT segment kept at the bottom of the stack (destroyed only at app
    // exit -> dw_Shutdown). Pushing it as a normal segment here made it a
    // ONE-SHOT that got released right after advancing — running dw_Shutdown
    // (full engine teardown) immediately after boot. Calling dw_Startup directly
    // avoids that: dw_Shutdown now runs only from dwMain_Shutdown at app exit.
    // The binary also pushed the droids.san / LLLogo.san opening movies on top;
    // they are SMUSH-stubbed (finish immediately) and cosmetic — dropped.
    dw_Startup();

    stdPlatform_Printf("OpenJKDF2: dwMain_BootFlow — DW display up, dw_Startup ran (workshop + enter-seg staged)\n");
}

// @0x41b6d0 (dwMain_MainLoopTick) — tick the segment stack once; a false return
// means quit was requested (binary DestroyWindow -> here g_should_exit).
static void dwMain_MainLoopTick(void)
{
    if (!dwSegment_Tick())
        g_should_exit = 1;
}

extern "C" void dwMain_GuiAdvance()
{
    // The engine's outer Window/SDL loop calls jkMain_GuiAdvance -> here once
    // per frame (REPLACING DroidWorks' own WinMain message pump). Input pumping
    // + the SDL event loop are owned by the engine; this only advances the DW
    // segment/present pipeline.
    if (!dwMain_bBooted)
    {
        dwMain_BootFlow(); // opens the DW display + pushes the dwApp boot segment
        return;            // next frame begins ticking the segment stack
    }

    dwMain_MainLoopTick();
}
