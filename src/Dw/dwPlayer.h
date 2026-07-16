#ifndef _DWPLAYER_H
#define _DWPLAYER_H

// dwPlayer — player PROFILE persistence (.plr files).
// DroidWorks.exe unit range: 0x429180-0x429c8f (the dwGuiQuickView /
// dwGuiDroidPreview widget classes sharing the range are P6, dwGuiQuickView.c).
//
// A profile is a subdirectory <basePath>\<name>\ holding <name>.plr — a
// dwConfFile (keyword\tvalue) with sections NAME / BRIGHTNESS / SCREEN_SIZE /
// MUSIC_VOLUME / SOUND_VOLUME / SHOW_TEXT / STATS / TOPIC / PARTS (owned
// blueprints) / MISSIONS (unlocked\trank\tdone) / WORKSPACE (the assembled
// droid, .drd-format via dwGuiWidgets_Write/ReadDroidFile).
//
// Implemented in dwPlayer.cpp (compiled as C++: the binary unit has MSVC EH
// frames around its dwString/dwConfFile locals), but the whole surface keeps
// C linkage — dw_Startup/dw_Shutdown (dwMain, C) drive it. dwString/dwList
// cross the C boundary as opaque pointers only.

#include "Dw/dwTypes.h"
#include "Dw/dwString.h" // dual-language: class for C++, opaque typedef for C

#ifdef __cplusplus
#include "Dw/dwList.h"
#else
typedef struct dwList dwList; // C view: opaque forward decl (dwList.h is C++-only)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---- unit-owned globals -----------------------------------------------------

// Current profile name / the profiles root dir (trailing '\', built by
// dw_Startup from install/working path + PLAYER_DIR) / the current profile's
// directory (basePath + name + '\'). dwString values — opaque to C.
extern dwString dwPlayer_name;       // @0x53d900
extern dwString dwPlayer_basePath;   // @0x53d8f0
extern dwString dwPlayer_profileDir; // @0x53d930

// Shared settings (.plr-persisted; also poked by dwGuiOptions/dwGuiInGame).
// Defaults match the binary's .data initializers.
extern uint8_t dw_settingShowText;    // @0x527d50: SHOW_TEXT (default 1)
extern uint32_t dw_settingBrightness; // @0x527d54: BRIGHTNESS gamma index (default 4)
extern uint32_t dw_viewSizePct;       // @0x527d58: SCREEN_SIZE — HUD 3D-viewport size % (default 100)
extern uint32_t dw_settingMusicVol;   // @0x527d5c: MUSIC_VOLUME 0-100 (default 50)
extern uint32_t dw_settingSoundVol;   // @0x527d60: SOUND_VOLUME 0-100 (default 60)

// Mission-progress/stats bitmask (.plr STATS key; unnamed @0x53d9f8 in the
// binary — read by dwGuiStatus and poked by the MST3K cheat in dwGuiScreen).
extern uint32_t dwPlayer_statsFlags;  // @0x53d9f8

// ---- API ----------------------------------------------------------------------

// Module statics reset (no binary counterpart — the globals above were
// CRT-static-ctor'd / .data-initialized; needed for the soft-reset loop).
void dwPlayer_Startup(void);

// mkdir <basePath>\<pName> (via inits_MakeDir, ext "PLR" -> player base
// path), then set name/profileDir and write a fresh .plr. @429180
void dwPlayer_CreateProfile(const char* pName);

// Recursive rmdir of <basePath>\<pName> (inits_RemoveDirTree). @4291e0
void dwPlayer_DeleteProfile(const char* pName);

// Read <pName>.plr (resolved into the profile dir by the hooked VFS open):
// sets name/profileDir, applies the settings (brightness -> display palette,
// music/sound volumes), loads stats/topic, marks owned blueprints on
// dwCore_pBlueprintList, unlocked/rank/done on dwCore_pMissionList, and
// rebuilds the workspace droid via dwGuiWidgets_ReadDroidFile. @429200
void dwPlayer_LoadPlr(const char* pName);

// Write <name>.plr (no-op when no profile name is set). @4296d0
void dwPlayer_SavePlr(void);

// Enumerate profile subdirs of basePath into pOutList (dwList of heap
// dwString*), then drop any entry lacking <name>\<name>.plr. @429950
void dwPlayer_EnumProfiles(dwList* pOutList);

#ifdef __cplusplus
}
#endif

#endif // _DWPLAYER_H
