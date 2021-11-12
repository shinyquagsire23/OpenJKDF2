#ifndef _JKGUIBUILDMULTI_H
#define _JKGUIBUILDMULTI_H

#define jkGuiBuildMulti_InitializeEditCharacter_ADDR (0x00418ED0)
#define jkGuiBuildMulti_ShutdownEditCharacter_ADDR (0x00418EF0)
#define jkGuiBuildMulti_ModelLoader_ADDR (0x00418F00)
#define jkGuiBuildMulti_MatLoader_ADDR (0x00418F60)
#define jkGuiBuildMulti_KeyframeLoader_ADDR (0x00418FE0)
#define jkGuiBuildMulti_sub_419030_ADDR (0x00419030)
#define jkGuiBuildMulti_ThingInstancer_ADDR (0x004190F0)
#define jkGuiBuildMulti_sub_4191E0_ADDR (0x004191E0)
#define jkGuiBuildMulti_ShowEditCharacter_ADDR (0x00419230)
#define jkGuiBuildMulti_DisplayModel_ADDR (0x00419AE0)
#define jkGuiBuildMulti_sub_419DB0_ADDR (0x00419DB0)
#define jkGuiBuildMulti_sub_41A0A0_ADDR (0x0041A0A0)
#define jkGuiBuildMulti_sub_41A120_ADDR (0x0041A120)
#define jkGuiBuildMulti_sub_41A140_ADDR (0x0041A140)

#define jkGuiBuildMulti_Initialize_ADDR (0x0041C5E0)
#define jkGuiBuildMulti_Shutdown_ADDR (0x0041C630)
#define jkGuiBuildMulti_Load_ADDR (0x0041C640)
#define jkGuiBuildMulti_Show_ADDR (0x0041C700)
#define jkGuiBuildMulti_Show2_ADDR (0x0041CAA0)
#define jkGuiBuildMulti_ShowNewCharacter_ADDR (0x0041CCB0)
#define jkGuiBuildMulti_sub_41D000_ADDR (0x0041D000)
#define jkGuiBuildMulti_ShowLoad_ADDR (0x0041D0E0)
#define jkGuiBuildMulti_sub_41D680_ADDR (0x0041D680)
#define jkGuiBuildMulti_sub_41D830_ADDR (0x0041D830)

static int (*jkGuiBuildMulti_InitializeEditCharacter)() = (void*)jkGuiBuildMulti_InitializeEditCharacter_ADDR;

static int (*jkGuiBuildMulti_Initialize)() = (void*)jkGuiBuildMulti_Initialize_ADDR;
static void (*jkGuiBuildMulti_Shutdown)() = (void*)jkGuiBuildMulti_Shutdown_ADDR;
static int (*jkGuiBuildMulti_ShowLoad)(jkPlayerMpcInfo *a1, char *a2, char *a3, int a4, int a5) = (void*)jkGuiBuildMulti_ShowLoad_ADDR;
static int (*jkGuiBuildMulti_Show)() = (void*)jkGuiBuildMulti_Show_ADDR;

#endif // _JKGUIBUILDMULTI_H
