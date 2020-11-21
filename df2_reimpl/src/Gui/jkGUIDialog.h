#ifndef _JKGUIDIALOG_H
#define _JKGUIDIALOG_H

#define jkGuiDialog_Initialize_ADDR (0x004168D0)
#define jkGuiDialog_Shutdown_ADDR (0x004168F0)
#define jkGuiDialog_sub_416900_ADDR (0x00416900)
#define jkGuiDialog_OkCancelDialog_ADDR (0x00416970)
#define jkGuiDialog_ErrorDialog_ADDR (0x00416A90)
#define jkGuiDialog_YesNoDialog_ADDR (0x00416BA0)

static int (*jkGuiDialog_YesNoDialog)(wchar_t* a1, wchar_t* a2) = (void*)jkGuiDialog_YesNoDialog_ADDR;

#endif // _JKGUIDIALOG_H
