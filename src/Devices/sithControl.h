#ifndef _SITHCONTROL_H
#define _SITHCONTROL_H

#include "types.h"
#include "globals.h"

#define sithControl_Startup_ADDR (0x004D6840)
#define sithControl_Shutdown_ADDR (0x004D6880)
#define sithControl_Open_ADDR (0x004D68B0)
#define sithControl_Close_ADDR (0x004D68D0)
#define sithControl_IsOpen_ADDR (0x004D6900)
#define sithControl_RegisterAxisFunction_ADDR (0x004D6910)
#define sithControl_RegisterKeyFunction_ADDR (0x004D6930)
#define sithControl_BindControl_ADDR (0x004D6940)
#define sithControl_BindAxis_ADDR (0x004D6A30)
#define sithControl_UnbindFunctionIndex_ADDR (0x004D6B60)
#define sithControl_input_map_idk_ADDR (0x004D6BC0)
#define sithControl_RegisterControlCallback_ADDR (0x004D6C50)
#define sithControl_Update_ADDR (0x004D6C70)
#define sithControl_GetKeyAsAxisNormalized_ADDR (0x004D6D70)
#define sithControl_GetKeyAsAxis_ADDR (0x004D6EB0)
#define sithControl_GetAxisNonTimeCorrected_ADDR (0x004D6F80)
#define sithControl_GetKey_ADDR (0x004D7010)
#define sithControl_ReadControls_ADDR (0x004D70A0)
#define sithControl_FinishRead_ADDR (0x004D70B0)
#define sithControl_DefaultInit_ADDR (0x004D70C0)
#define sithControl_RebindKeyboard_ADDR (0x004D7350)
#define sithControl_RebindJoystick_ADDR (0x004D73E0)
#define sithControl_RebindMouse_ADDR (0x004D7670)
#define sithControl_WriteConf_ADDR (0x004D78E0)
#define sithControl_ReadConf_ADDR (0x004D79A0)
#define sithControl_sub_4D7C30_ADDR (0x004D7C30)
#define sithControl_RegisterControlFunctions_ADDR (0x004D7C50)
#define sithControl_RegisterKeyboardBindings_ADDR (0x004D7D40)
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
void sithControl_RegisterAxisFunction(int functionId, uint32_t flag);
void sithControl_Reset();
void sithControl_RegisterControlFunctions();
void sithControl_Update(flex_t secDeltaTime, int msecDeltaTime);
void sithControl_RegisterControlCallback(sithControl_handler_t pfCallback);
MATH_FUNC int sithControl_HandlePlayer(SithThing *player_, flex_t a2);
MATH_FUNC void sithControl_PlayerLook(SithThing *player, flex_t deltaSecs);
MATH_FUNC void sithControl_PlayerMovement(SithThing *player);
MATH_FUNC void sithControl_PlayerMovementMots(SithThing *player);
MATH_FUNC void sithControl_FreeCam(SithThing *player);

stdControlKeyInfoEntry* sithControl_BindControl(int functionId, int controlId, int flags);
stdControlKeyInfoEntry* sithControl_BindAxis(int functionId, int axis, uint32_t flags);
// Added: DroidWorks in-mission control bindings (binary sithControl_FUN_00456da0);
// installed per-mission by dwGuiInGame::StartMission. No-op outside DW.
void sithControl_FUN_00456da0(void);
void sithControl_UnbindFunctionIndex(int funcId, unsigned int bindIndex);
void sithControl_UnbindControl(int flags, int controlId);
int sithControl_ReadConf();
int sithControl_WriteConf();

void sithControl_ReadControls();
void sithControl_FinishRead();
void sithControl_RegisterKeyboardBindings();
void sithControl_DefaultInit();
MATH_FUNC flex_t sithControl_GetKeyAsAxisNormalized(int axisId);
MATH_FUNC flex_t sithControl_GetKeyAsAxis(int axisId);
MATH_FUNC flex_t sithControl_GetAxis(int axisId);
int sithControl_GetKey(int func, int* out);

void sithControl_RegisterKeyFunction(int a);
stdControlKeyInfo* sithControl_EnumBindings(sithControlEnumFunc_t pfFunc, int a2, int a3, int a4, Darray *a5);
void sithControl_RegisterMouseBindings(); // Added
void sithControl_RebindMouse();
void sithControl_RebindKeyboard();
void sithControl_RebindJoystick();

void sithControl_MapDefaultsJoystick();

#ifdef QOL_IMPROVEMENTS
void sithControl_SetLastSelected(int which);
int sithControl_GetLastSelected();
#endif // QOL_IMPROVEMENTS

//static stdControlKeyInfo* (*sithControl_EnumBindings)(sithControlEnumFunc_t func, int a2, int a3, int a4, int a5) = (void*)sithControl_EnumBindings_ADDR;
//static void (*sithControl_RebindMouse)() = (void*)sithControl_RebindMouse_ADDR;
//static int (*sithControl_HandlePlayer)(SithThing *a1, flex_t a2) = (void*)sithControl_HandlePlayer_ADDR;

//static int (*sithControl_IsOpen)() = (void*)sithControl_IsOpen_ADDR;
//static int (*sithControl_Close)() = (void*)sithControl_Close_ADDR;
//static int (*sithControl_Open)() = (void*)sithControl_Open_ADDR;

//static void (*sithControl_PlayerLook)(SithThing *player, flex_t a3) = (void*)sithControl_PlayerLook_ADDR;
//static void (*sithControl_PlayerMovement)(SithThing *player) = (void*)sithControl_PlayerMovement_ADDR;
//static int (*sithControl_FreeCam)(SithThing *player) = (void*)sithControl_FreeCam_ADDR;

#endif // _SITHCONTROL_H
