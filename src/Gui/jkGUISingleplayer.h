#ifndef _JKGUISINGLEPLAYER_H
#define _JKGUISINGLEPLAYER_H

#include "types.h"

#define jkGuiSingleplayer_Startup_ADDR (0x0041A440)
#define jkGuiSingleplayer_Shutdown_ADDR (0x0041A490)
#define jkGuiSingleplayer_Show_ADDR (0x0041A4A0)
#define jkGuiSingleplayer_EnumEpisodes_ADDR (0x0041A9B0)
#define jkGuiSingleplayer_sub_41AA30_ADDR (0x0041AA30)
#define jkGuiSingleplayer_sub_41AC70_ADDR (0x0041AC70)
#define jkGuiSingleplayer_sub_41AD00_ADDR (0x0041AD00)

void jkGuiSingleplayer_Startup();
void jkGuiSingleplayer_Shutdown();
int jkGuiSingleplayer_Show();
int jkGuiSingleplayer_EnumEpisodes(Darray *array, jkGuiElement *element, int a3, jkEpisodeTypeFlags_t typeMask);
void jkGuiSingleplayer_sub_41AA30(Darray *array, jkGuiElement *element, int a3, char *episodeDir, int a5, int a6, int a7, jkEpisodeEntry* a8);
void jkGuiSingleplayer_sub_41AC70(Darray *array, jkGuiElement *element, int idx);
int jkGuiSingleplayer_sub_41AD00(Darray *array);

//static void (*jkGuiSingleplayer_sub_41AA30)(Darray *array, jkGuiElement *element, int a3, char *episodeDir, int a5, int a6, int a7, int a8) = (void*)jkGuiSingleplayer_sub_41AA30_ADDR;

#endif // _JKGUISINGLEPLAYER_H
