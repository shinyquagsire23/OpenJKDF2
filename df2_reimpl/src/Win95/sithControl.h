#ifndef _WIN95SITHCONTROL_H
#define _WIN95SITHCONTROL_H

#define sithControl_Initialize_ADDR (0x004D6840)
#define sithControl_Shutdown_ADDR (0x004D6880)
#define sithControl_Open_ADDR (0x004D68B0)
#define sithControl_Close_ADDR (0x004D68D0)
#define sithControl_IsOpen_ADDR (0x004D6900)
#define sithControl_sub_4D6910_ADDR (0x004D6910)
#define sithControl_sub_4D6930_ADDR (0x004D6930)
#define sithControl_MapFunc_ADDR (0x004D6940)
#define sithControl_sub_4D6A30_ADDR (0x004D6A30)
#define sithControl_sub_4D6B60_ADDR (0x004D6B60)
#define sithControl_input_map_idk_ADDR (0x004D6BC0)
#define sithControl_AddInputHandler_ADDR (0x004D6C50)
#define sithControl_Tick_ADDR (0x004D6C70)
#define sithControl_ReadAxisStuff_ADDR (0x004D6EB0)
#define sithControl_GetAxis_ADDR (0x004D6F80)
#define sithControl_ReadFunctionMap_ADDR (0x004D7010)
#define sithControl_ReadControls_ADDR (0x004D70A0)
#define sithControl_FinishRead_ADDR (0x004D70B0)
#define sithControl_InputInit_ADDR (0x004D70C0)
#define sithControl_sub_4D7350_ADDR (0x004D7350)
#define sithControl_sub_4D73E0_ADDR (0x004D73E0)
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

static void (*sithControl_InputInit)() = (void*)sithControl_InputInit_ADDR;
static int (*sithControl_IsOpen)() = (void*)sithControl_IsOpen_ADDR;
static int (*sithControl_Close)() = (void*)sithControl_Close_ADDR;
static int (*sithControl_WriteConf)() = (void*)sithControl_WriteConf_ADDR;
static int (*sithControl_Open)() = (void*)sithControl_Open_ADDR;
static int (*sithControl_ReadConf)() = (void*)sithControl_ReadConf_ADDR;

#endif // _WIN95SITHCONTROL_H
