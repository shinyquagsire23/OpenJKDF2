#ifndef _JKGUIMULTITALLY_H
#define _JKGUIMULTITALLY_H

#include "types.h"

#define jkGuiMultiTally_Show_ADDR (0x00418070)
#define jkGuiMultiTally_SortPlayerScore_ADDR (0x004185A0)
#define jkGuiMultiTally_Initialize_ADDR (0x00418640)
#define jkGuiMultiTally_Shutdown_ADDR (0x00418680)
#define jkGuiMultiTally_ShowTeamScores_ADDR (0x00418690)
#define jkGuiMultiTally_SortTeamScore_ADDR (0x00418870)
#define jkGuiMultiTally_sub_4188B0_ADDR (0x004188B0)

int jkGuiMultiTally_Show(int a1);
int jkGuiMultiTally_SortPlayerScore(const sithPlayerInfo *pA, const sithPlayerInfo *pB);
void jkGuiMultiTally_Initialize();
void jkGuiMultiTally_Shutdown();
int jkGuiMultiTally_ShowTeamScores(int a1);
int jkGuiMultiTally_SortTeamScore(const void* a, const void* b);
void jkGuiMultiTally_sub_4188B0(jkGuiMenu *pMenu);

//static int (*jkGuiMultiTally_ShowTeamScores)(int) = (void*)jkGuiMultiTally_ShowTeamScores_ADDR;

//static int (*jkGuiMultiTally_Show)() = (void*)jkGuiMultiTally_Show_ADDR;
//static int (*jkGuiMultiTally_Initialize)() = (void*)jkGuiMultiTally_Initialize_ADDR;

#endif // _JKGUIMULTITALLY_H
