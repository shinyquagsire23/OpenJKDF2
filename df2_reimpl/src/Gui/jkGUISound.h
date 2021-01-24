#ifndef _JKGUI_SOUND_H
#define _JKGUI_SOUND_H

#define jkGuiSound_Initialize_ADDR (0x00410D70)
#define jkGuiSound_Shutdown_ADDR (0x00410E30)
#define jkGuiSound_Show_ADDR (0x00410E70)

void jkGuiSound_Initialize();
void jkGuiSound_Shutdown();
int jkGuiSound_Show();

#define jkGuiSound_sfxVolume (*(float*)0x00547DD0)
#define jkGuiSound_numChannels (*(int*)0x0054A680)
#define jkGuiSound_bLowResSound (*(int*)0x00563700)
#define jkGuiSound_b3DSound (*(int*)0x00563704)
#define jkGuiSound_b3DSound_2 (*(int*)0x00563708)
#define jkGuiSound_b3DSound_3 (*(int*)0x0056370C)
#define jkGuiSound_musicVolume (*(float*)0x0086077C)

#endif // _JKGUI_SOUND_H
