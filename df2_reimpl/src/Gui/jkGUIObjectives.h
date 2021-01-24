#ifndef _JKGUIOBJECTIVES_H
#define _JKGUIOBJECTIVES_H

#include "types.h"

#define jkGuiObjectives_CustomRender_ADDR (0x00417B00)
#define jkGuiObjectives_Show_ADDR (0x00417CE0)
#define jkGuiObjectives_Initialize_ADDR (0x00417E00)
#define jkGuiObjectives_Shutdown_ADDR (0x00417E20)

void jkGuiObjectives_CustomRender(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4);
int jkGuiObjectives_Show();
void jkGuiObjectives_Initialize();
void jkGuiObjectives_Shutdown();

#endif // _JKGUIOBJECTIVES_H
