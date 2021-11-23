#ifndef _SITHCONTROL_H
#define _SITHCONTROL_H

#include "types.h"
#include "globals.h"

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

enum INPUT_FUNC
{
    INPUT_FUNC_FORWARD = 0,
    INPUT_FUNC_TURN = 1,
    INPUT_FUNC_SLIDE = 2,
    INPUT_FUNC_SLIDETOGGLE = 3,
    INPUT_FUNC_JUMP = 4,
    INPUT_FUNC_DUCK = 5,
    INPUT_FUNC_FAST = 6,
    INPUT_FUNC_SLOW = 7,
    INPUT_FUNC_PITCH = 8,
    INPUT_FUNC_CENTER = 9,
    INPUT_FUNC_FIRE1 = 10,
    INPUT_FUNC_FIRE2 = 11,
    INPUT_FUNC_ACTIVATE = 12,
    INPUT_FUNC_SELECT1 = 13,
    INPUT_FUNC_SELECT2 = 14,
    INPUT_FUNC_SELECT3 = 15,
    INPUT_FUNC_SELECT4 = 16,
    INPUT_FUNC_SELECT5 = 17,
    INPUT_FUNC_SELECT6 = 18,
    INPUT_FUNC_SELECT7 = 19,
    INPUT_FUNC_SELECT8 = 20,
    INPUT_FUNC_SELECT9 = 21,
    INPUT_FUNC_SELECT0 = 22,
    INPUT_FUNC_GAMESAVE = 23,
    INPUT_FUNC_DEBUG = 24,
    INPUT_FUNC_NEXTINV = 25,
    INPUT_FUNC_PREVINV = 26,
    INPUT_FUNC_USEINV = 27,
    INPUT_FUNC_NEXTWEAPON = 28,
    INPUT_FUNC_PREVWEAPON = 29,
    INPUT_FUNC_NEXTSKILL = 30,
    INPUT_FUNC_PREVSKILL = 31,
    INPUT_FUNC_USESKILL = 32,
    INPUT_FUNC_MAP = 33,
    INPUT_FUNC_INCREASE = 34,
    INPUT_FUNC_DECREASE = 35,
    INPUT_FUNC_MLOOK = 36,
    INPUT_FUNC_CAMERAMODE = 37,
    INPUT_FUNC_TALK = 38,
    INPUT_FUNC_GAMMA = 39,
    INPUT_FUNC_SCREENSHOT = 40,
    INPUT_FUNC_TALLY = 41,
    INPUT_FUNC_ACTIVATE0 = 42,
    INPUT_FUNC_ACTIVATE1 = 43,
    INPUT_FUNC_ACTIVATE2 = 44,
    INPUT_FUNC_ACTIVATE3 = 45,
    INPUT_FUNC_ACTIVATE4 = 46,
    INPUT_FUNC_ACTIVATE5 = 47,
    INPUT_FUNC_ACTIVATE6 = 48,
    INPUT_FUNC_ACTIVATE7 = 49,
    INPUT_FUNC_ACTIVATE8 = 50,
    INPUT_FUNC_ACTIVATE9 = 51,
    INPUT_FUNC_ACTIVATE10 = 52,
    INPUT_FUNC_ACTIVATE11 = 53,
    INPUT_FUNC_ACTIVATE12 = 54,
    INPUT_FUNC_ACTIVATE13 = 55,
    INPUT_FUNC_ACTIVATE14 = 56,
    INPUT_FUNC_ACTIVATE15 = 57,
    INPUT_FUNC_ACTIVATE16 = 58,
    INPUT_FUNC_ACTIVATE17 = 59,
    INPUT_FUNC_ACTIVATE18 = 60,
    INPUT_FUNC_ACTIVATE19 = 61,
    INPUT_FUNC_ACTIVATE20 = 62,
    INPUT_FUNC_ACTIVATE21 = 63,
    INPUT_FUNC_ACTIVATE22 = 64,
    INPUT_FUNC_ACTIVATE23 = 65,
    INPUT_FUNC_ACTIVATE24 = 66,
    INPUT_FUNC_ACTIVATE25 = 67,
    INPUT_FUNC_ACTIVATE26 = 68,
    INPUT_FUNC_ACTIVATE27 = 69,
    INPUT_FUNC_ACTIVATE28 = 70,
    INPUT_FUNC_ACTIVATE29 = 71,
    INPUT_FUNC_ACTIVATE30 = 72,
    INPUT_FUNC_ACTIVATE31 = 73,
    INPUT_FUNC_MAX = 74,
};

int sithControl_IsOpen();
int sithControl_Open();
void sithControl_Close();
void sithControl_Tick(float deltaSecs, int deltaMs);
void sithControl_AddInputHandler(sithControl_handler_t a1);
int sithControl_HandlePlayer(sithThing *player_, float a2);
void sithControl_PlayerLook(sithThing *player, float deltaSecs);
void sithControl_PlayerMovement(sithThing *player);
void sithControl_FreeCam(sithThing *player);


static void (*sithControl_MapFunc)(int funcIdx, int a2, int a3) = (void*)sithControl_MapFunc_ADDR;
//static int (*sithControl_HandlePlayer)(sithThing *a1, float a2) = (void*)sithControl_HandlePlayer_ADDR;

//static int (*sithControl_IsOpen)() = (void*)sithControl_IsOpen_ADDR;
//static int (*sithControl_Close)() = (void*)sithControl_Close_ADDR;
//static int (*sithControl_Open)() = (void*)sithControl_Open_ADDR;

//static void (*sithControl_PlayerLook)(sithThing *player, float a3) = (void*)sithControl_PlayerLook_ADDR;
//static void (*sithControl_PlayerMovement)(sithThing *player) = (void*)sithControl_PlayerMovement_ADDR;
//static int (*sithControl_FreeCam)(sithThing *player) = (void*)sithControl_FreeCam_ADDR;

#ifdef SDL2_RENDER
int sithControl_Initialize();
void sithControl_InputInit();
int sithControl_ReadFunctionMap(int func, int* out);
float sithControl_GetAxis(int num);
float sithControl_ReadAxisStuff(int num);
int sithControl_ReadConf();
int sithControl_WriteConf();
void sithControl_sub_4D6930(int a);
#else
static int (*sithControl_Initialize)() = (void*)sithControl_Initialize_ADDR;
static void (*sithControl_InputInit)() = (void*)sithControl_InputInit_ADDR;
static int (*sithControl_ReadFunctionMap)(int func, int* out) = (void*)sithControl_ReadFunctionMap_ADDR;
static float (*sithControl_GetAxis)(int num) = (void*)sithControl_GetAxis_ADDR;
static float (*sithControl_ReadAxisStuff)(int num) = (void*)sithControl_ReadAxisStuff_ADDR;
static int (*sithControl_ReadConf)() = (void*)sithControl_ReadConf_ADDR;
static int (*sithControl_WriteConf)() = (void*)sithControl_WriteConf_ADDR;
static void (*sithControl_sub_4D6930)(int a) = (void*)sithControl_sub_4D6930_ADDR;
#endif

#endif // _SITHCONTROL_H
