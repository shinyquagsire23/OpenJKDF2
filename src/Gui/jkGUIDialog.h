#ifndef _JKGUIDIALOG_H
#define _JKGUIDIALOG_H

#include "types.h"

#define jkGuiDialog_Startup_ADDR (0x004168D0)
#define jkGuiDialog_Shutdown_ADDR (0x004168F0)
#define jkGuiDialog_sub_416900_ADDR (0x00416900)
#define jkGuiDialog_OkCancelDialog_ADDR (0x00416970)
#define jkGuiDialog_ErrorDialog_ADDR (0x00416A90)
#define jkGuiDialog_YesNoDialog_ADDR (0x00416BA0)

void jkGuiDialog_Startup();
void jkGuiDialog_Shutdown();

int jkGuiDialog_OkCancelDialog(wchar_t *stringA, wchar_t *stringB);
void jkGuiDialog_ErrorDialog(wchar_t *stringA, wchar_t *stringB);
int jkGuiDialog_YesNoDialog(wchar_t *stringA, wchar_t *stringB);

#endif // _JKGUIDIALOG_H
