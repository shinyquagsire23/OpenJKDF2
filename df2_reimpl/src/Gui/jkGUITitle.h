#ifndef _JKGUITITLE_H
#define _JKGUITITLE_H

#include "types.h"

#define jkGuiTitle_Initialize_ADDR (0x00418960)
#define jkGuiTitle_Shutdown_ADDR (0x00418990)
#define jkGuiTitle_sub_4189A0_ADDR (0x004189A0)
#define jkGuiTitle_quicksave_related_func1_ADDR (0x004189D0)
#define jkGuiTitle_UnkDraw_ADDR (0x00418AA0)
#define jkGuiTitle_LoadBarDraw_ADDR (0x00418B90)
#define jkGuiTitle_WorldLoadCallback_ADDR (0x00418C60)
#define jkGuiTitle_ShowLoadingStatic_ADDR (0x00418CF0)
#define jkGuiTitle_ShowLoading_ADDR (0x00418D80)
#define jkGuiTitle_LoadingFinalize_ADDR (0x00418EB0)

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct stdVBuffer stdVBuffer;
typedef struct stdStrTable stdStrTable;

void jkGuiTitle_Initialize();
void jkGuiTitle_Shutdown();
char jkGuiTitle_sub_4189A0(char *a1);
wchar_t* jkGuiTitle_quicksave_related_func1(stdStrTable *strTable, char *jkl_fname);
void jkGuiTitle_UnkDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4);
void jkGuiTitle_LoadBarDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4);
void jkGuiTitle_WorldLoadCallback(float percentage);
void jkGuiTitle_ShowLoadingStatic();
void jkGuiTitle_ShowLoading(char *a1, wchar_t *a2);
void jkGuiTitle_LoadingFinalize();

static int (*jkGuiTitle_UnkDraw_)(jkGuiElement *a1, jkGuiMenu *a2, stdVBuffer *a3, int a4) = (void*)jkGuiTitle_UnkDraw_ADDR;
static int (*jkGuiTitle_LoadBarDraw_)(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4) = (void*)jkGuiTitle_LoadBarDraw_ADDR;

#define jkGuiTitle_verMinor    (*(int*)0x00552884)
#define jkGuiTitle_verMajor    (*(int*)0x00525030)
#define jkGuiTitle_verRevision (*(int*)0x00525034)
#define jkGuiTitle_aTexts ((jkGuiStringEntry*)0x005568E0)
#define jkGuiTitle_whichLoading (*(int*)0x00556980)

#endif // _JKGUITITLE_H
