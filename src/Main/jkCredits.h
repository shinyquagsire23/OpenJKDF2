#ifndef _JKCREDITS_H
#define _JKCREDITS_H

#include "types.h"
#include "globals.h"

#define jkCredits_Initialize_ADDR (0x004216C0)
#define jkCredits_Shutdown_ADDR (0x00421710)
#define jkCredits_Show_ADDR (0x00421760)
#define jkCredits_Skip_ADDR (0x00421AC0)
#define jkCredits_Tick_ADDR (0x00421B50)
#define jkCredits_Handler_ADDR (0x00421F60)

void jkCredits_Initialize(char *fpath);
void jkCredits_Shutdown();
int jkCredits_Show();
int jkCredits_Tick();
int jkCredits_Skip();
int jkCredits_Handler(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5);

//static int (*jkCredits_Show)() = (void*)jkCredits_Show_ADDR;
//static void (*jkCredits_Skip)() = (void*)jkCredits_Skip_ADDR;
//static int (*jkCredits_Tick)() = (void*)jkCredits_Tick_ADDR;

//static void (*jkCredits_Initialize)() = (void*)jkCredits_Initialize_ADDR;

#endif // _JKCREDITS_H
