#ifndef _RDCACHE_H
#define _RDCACHE_H

#define rdCache_Startup_ADDR (0x0043AD60)
#define rdCache_AdvanceFrame_ADDR (0x0043AD70)
#define rdCache_FinishFrame_ADDR (0x0043AD80)
#define rdCache_Reset_ADDR (0x0043AD90)
#define rdCache_ClearFrameCounters_ADDR (0x0043ADD0)
#define rdCache_GetProcEntry_ADDR (0x0043ADE0)
#define rdCache_Flush_ADDR (0x0043AE70)
#define rdCache_AddProcFace_ADDR (0x0043AF90)
#define rdCache_SendFaceListToHardware_ADDR (0x0043B1C0	000010F7)
#define rdCache_ResetRenderList_ADDR (0x0043C2C0)
#define rdCache_DrawRenderList_ADDR (0x0043C2E0)
#define rdCache_TriCompare_ADDR (0x0043C380)
#define rdCache_DrawFaceN_ADDR (0x0043C3C0)
#define rdCache_DrawFaceZ_ADDR (0x0043CED0)
#define rdCache_DrawFaceUser_ADDR (0x0043D9E0)
#define rdCache_ProcFaceCompare_ADDR (0x0043E170)

static int (*rdCache_Startup)(void) = rdCache_Startup_ADDR;
static void (*rdCache_ClearFrameCounters)(void) = rdCache_ClearFrameCounters_ADDR;
static void (*rdCache_AdvanceFrame)(void) = rdCache_AdvanceFrame_ADDR;
static void (*rdCache_Flush)(void) = rdCache_Flush_ADDR;
static void (*rdCache_FinishFrame)(void) = rdCache_FinishFrame_ADDR;

#endif // _RDCACHE_H
