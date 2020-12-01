#ifndef _JKRES_H
#define _JKRES_H

#define jkRes_Startup_ADDR (0x0040E360)
#define jkRes_Shutdown_ADDR (0x0040E490)
#define jkRes_New_ADDR (0x0040E560)
#define jkRes_LoadGob_ADDR (0x0040E5B0)
#define jkRes_LoadCd_ADDR (0x0040E980)
#define jkRes_HookHS_ADDR (0x0040EA30)
#define jkRes_UnhookHS_ADDR (0x0040EAA0)
#define jkRes_FileExists_ADDR (0x0040EB20)
#define jkRes_LoadCD_ADDR (0x0040EBB0)
#define jkRes_ReadKey_ADDR (0x0040F110)
#define jkRes_LoadNew_ADDR (0x0040F190)
#define jkRes_NewGob_ADDR (0x0040F360)
#define jkRes_FileOpen_ADDR (0x0040F4C0)
#define jkRes_FileClose_ADDR (0x0040F6B0)
#define jkRes_FileRead_ADDR (0x0040F710)
#define jkRes_FileWrite_ADDR (0x0040F770)
#define jkRes_FileGets_ADDR (0x0040F7B0)
#define jkRes_FileGetws_ADDR (0x0040F810)
#define jkRes_FEof_ADDR (0x0040F870)
#define jkRes_FTell_ADDR (0x0040F8B0)
#define jkRes_FSeek_ADDR (0x0040F8F0)
#define jkRes_FileSize_ADDR (0x0040F950)
#define jkRes_FilePrintf_ADDR (0x0040F970)

#define jkRes_pHS (*(common_functions**)0x00555C68)
#define jkRes_episodeGobName ((char*)0x00555C70)
#define jkRes_curDir ((char*)0x00555C90)

static void (*jkRes_LoadGob)(char *a1) = (void*)jkRes_LoadGob_ADDR;

#endif // _JKRES_H
