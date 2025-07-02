#ifndef _JKQUAKECONSOLE_H
#define _JKQUAKECONSOLE_H

#include "types.h"
#include "globals.h"

void jkQuakeConsole_Startup();
void jkQuakeConsole_Shutdown();
void jkQuakeConsole_Render();
void jkQuakeConsole_ExecuteCommand(const char* pCmd);
void jkQuakeConsole_SendInput(WPARAM wParam, int bIsChar);
int jkQuakeConsole_WmHandler(HWND a1, UINT msg, WPARAM wParam, HWND a4, LRESULT *a5);
void jkQuakeConsole_PrintLine(const char* pLine);
void jkQuakeConsole_RecordHistory(const char* pLine);

extern int jkQuakeConsole_bOpen;

#endif // _JKQUAKECONSOLE_H
