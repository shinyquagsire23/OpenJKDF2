#ifndef _JKGUIMULTITALLY_H
#define _JKGUIMULTITALLY_H

#define jkGuiMultiTally_Show_ADDR (0x00418070)
#define jkGuiMultiTally_SortPlayerScore_ADDR (0x004185A0)
#define jkGuiMultiTally_Initialize_ADDR (0x00418640)
#define jkGuiMultiTally_Shutdown_ADDR (0x00418680)
#define jkGuiMultiTally_ShowMenu3_ADDR (0x00418690)
#define jkGuiMultiTally_Sortidk_ADDR (0x00418870)
#define jkGuiMultiTally_sub_4188B0_ADDR (0x004188B0)

static int (*jkGuiMultiTally_Show)() = (void*)jkGuiMultiTally_Show_ADDR;
static int (*jkGuiMultiTally_Initialize)() = (void*)jkGuiMultiTally_Initialize_ADDR;

#endif // _JKGUIMULTITALLY_H
