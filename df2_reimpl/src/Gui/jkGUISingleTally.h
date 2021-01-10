#ifndef _JKGUI_SINGLETALLY_H
#define _JKGUI_SINGLETALLY_H

#define jkGuiSingleTally_Show_ADDR (0x00417E30)
#define jkGuiSingleTally_Initialize_ADDR (0x00417FC0)
#define jkGuiSingleTally_Shutdown_ADDR (0x00417FF0)
#define jkGuiSingleTally_ForceStarsRender_ADDR (0x00418000)

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct stdVBuffer stdVBuffer;

int jkGuiSingleTally_Show();
void jkGuiSingleTally_Initialize();
void jkGuiSingleTally_Shutdown();
void jkGuiSingleTally_ForceStarsRender(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int d);

#define jkGuiSingleTally_foStars (*(stdBitmap**)0x00556880)

#endif // _JKGUI_SINGLETALLY_H
