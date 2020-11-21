#ifndef _JKGUITITLE_H
#define _JKGUITITLE_H

#define jkGuiTitle_Initialize_ADDR (0x00418960)
#define jkGuiTitle_Shutdown_ADDR (0x00418990)
#define jkGuiTitle_sub_4189A0_ADDR (0x004189A0)
#define jkGuiTitle_quicksave_related_func1_ADDR (0x004189D0)
#define jkGuiTitle_sub_418AA0_ADDR (0x00418AA0)
#define jkGuiTitle_sub_418B90_ADDR (0x00418B90)
#define jkGuiTitle_WorldLoadCallback_ADDR (0x00418C60)
#define jkGuiTitle_sub_418CF0_ADDR (0x00418CF0)
#define jkGuiTitle_gui_level_texts_ADDR (0x00418D80)
#define jkGuiTitle_sub_418EB0_ADDR (0x00418EB0)

typedef struct stdStrTable stdStrTable;

static wchar_t* (*jkGuiTitle_quicksave_related_func1)(stdStrTable *a1, char *jkl_fname) = (void*)jkGuiTitle_quicksave_related_func1_ADDR;

#endif // _JKGUITITLE_H
