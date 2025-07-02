#ifndef _SITHCONTROL_H
#define _SITHCONTROL_H

#include "types.h"
#include "globals.h"

#define sithControl_Startup_ADDR (0x004D6840)
#define sithControl_Shutdown_ADDR (0x004D6880)
#define sithControl_Open_ADDR (0x004D68B0)
#define sithControl_Close_ADDR (0x004D68D0)
#define sithControl_IsOpen_ADDR (0x004D6900)
#define sithControl_sub_4D6910_ADDR (0x004D6910)
#define sithControl_sub_4D6930_ADDR (0x004D6930)
#define sithControl_MapFunc_ADDR (0x004D6940)
#define sithControl_MapAxisFunc_ADDR (0x004D6A30)
#define sithControl_ShiftFuncKeyinfo_ADDR (0x004D6B60)
#define sithControl_input_map_idk_ADDR (0x004D6BC0)
#define sithControl_AddInputHandler_ADDR (0x004D6C50)
#define sithControl_Tick_ADDR (0x004D6C70)
#define sithControl_GetAxis2_ADDR (0x004D6D70)
#define sithControl_ReadAxisStuff_ADDR (0x004D6EB0)
#define sithControl_GetAxis_ADDR (0x004D6F80)
#define sithControl_ReadFunctionMap_ADDR (0x004D7010)
#define sithControl_ReadControls_ADDR (0x004D70A0)
#define sithControl_FinishRead_ADDR (0x004D70B0)
#define sithControl_InputInit_ADDR (0x004D70C0)
#define sithControl_sub_4D7350_ADDR (0x004D7350)
#define sithControl_JoyInputInit_ADDR (0x004D73E0)
#define sithControl_sub_4D7670_ADDR (0x004D7670)
#define sithControl_WriteConf_ADDR (0x004D78E0)
#define sithControl_ReadConf_ADDR (0x004D79A0)
#define sithControl_sub_4D7C30_ADDR (0x004D7C30)
#define sithControl_InitFuncToControlType_ADDR (0x004D7C50)
#define sithControl_MapDefaults_ADDR (0x004D7D40)
#define sithControl_EnumBindings_ADDR (0x004D82C0)
#define sithControl_HandlePlayer_ADDR (0x004D8520)
#define sithControl_PlayerMovement_ADDR (0x004D8A00)
#define sithControl_FreeCam_ADDR (0x004D8C90)
#define sithControl_PlayerLook_ADDR (0x004D8F40)

int sithControl_Startup();
int sithControl_Shutdown();
int sithControl_IsOpen();
int sithControl_Open();
void sithControl_Close();
void sithControl_InitFuncToControlType();
void sithControl_Tick(flex_t deltaSecs, int deltaMs);
void sithControl_AddInputHandler(sithControl_handler_t a1);
int sithControl_HandlePlayer(sithThing *player_, flex_t a2);
void sithControl_PlayerLook(sithThing *player, flex_t deltaSecs);
void sithControl_PlayerMovement(sithThing *player);
void sithControl_FreeCam(sithThing *player);

stdControlKeyInfoEntry* sithControl_MapFunc(int funcIdx, int keyNum, int flags);
stdControlKeyInfoEntry* sithControl_MapAxisFunc(int funcIdx, int dxKeyNum, uint32_t flags);
void sithControl_ShiftFuncKeyinfo(int funcIdx, unsigned int idx);
void sithControl_MapFuncToDxKey(int funcIdx, int dxKeyNum);
int sithControl_ReadConf();
int sithControl_WriteConf();

void sithControl_ReadControls();
void sithControl_FinishRead();
void sithControl_MapDefaults();
void sithControl_InputInit();
flex_t sithControl_GetAxis2(int axisNum);
flex_t sithControl_ReadAxisStuff(int funcIdx);
flex_t sithControl_GetAxis(int funcIdx);
int sithControl_ReadFunctionMap(int func, int* out);

void sithControl_sub_4D6930(int a);
stdControlKeyInfo* sithControl_EnumBindings(sithControlEnumFunc_t pfEnumFunction, int a2, int a3, int a4, Darray *a5);
void sithControl_sub_4D7670();
void sithControl_sub_4D7350();
void sithControl_JoyInputInit();

//static stdControlKeyInfo* (*sithControl_EnumBindings)(sithControlEnumFunc_t func, int a2, int a3, int a4, int a5) = (void*)sithControl_EnumBindings_ADDR;
//static void (*sithControl_sub_4D7670)() = (void*)sithControl_sub_4D7670_ADDR;
//static int (*sithControl_HandlePlayer)(sithThing *a1, flex_t a2) = (void*)sithControl_HandlePlayer_ADDR;

//static int (*sithControl_IsOpen)() = (void*)sithControl_IsOpen_ADDR;
//static int (*sithControl_Close)() = (void*)sithControl_Close_ADDR;
//static int (*sithControl_Open)() = (void*)sithControl_Open_ADDR;

//static void (*sithControl_PlayerLook)(sithThing *player, flex_t a3) = (void*)sithControl_PlayerLook_ADDR;
//static void (*sithControl_PlayerMovement)(sithThing *player) = (void*)sithControl_PlayerMovement_ADDR;
//static int (*sithControl_FreeCam)(sithThing *player) = (void*)sithControl_FreeCam_ADDR;

#endif // _SITHCONTROL_H
