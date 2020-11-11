#ifndef _SITHRENDER_H
#define _SITHRENDER_H

#define sithRender_Startup_ADDR (0x004C6180)
#define sithRender_Open_ADDR (0x004C61C0)
#define sithRender_Close_ADDR (0x004C6250)
#define sithRender_Shutdown_ADDR (0x004C6260)
#define sithRender_SetSomeRenderflag_ADDR (0x004C6270)
#define sithRender_GetSomeRenderFlag_ADDR (0x004C6280)
#define sithRender_EnableIRMode_ADDR (0x004C6290)
#define sithRender_DisableIRMode_ADDR (0x004C6320)
#define sithRender_SetVar1_ADDR (0x004C6330)
#define sithRender_SetVar2_ADDR (0x004C6340)
#define sithRender_SetVar3_ADDR (0x004C6350)
#define sithRender_SetPalette_ADDR (0x004C6360)
#define sithRender_sub_4C63B0_ADDR (0x004C63B0)
#define sithRender_idksighted_ADDR (0x004C6650)
#define sithRender_mesh_func_5_ADDR (0x004C6C40)
#define sithRender_sub_4C76B0_ADDR (0x004C76B0)
#define sithRender_sub_4C7720_ADDR (0x004C7720)
#define sithRender_weird_jkl_sqrt_idk_ADDR (0x004C79A0)
#define sithRender_RenderWorld_ADDR (0x004C7BE0)
#define sithRender_RenderPov_ADDR (0x004C8070)
#define sithRender_mesh_func_6_ADDR (0x004C8220)
#define sithRender_SetRenderWeaponHandle_ADDR (0x004C8600)

static void (*sithRender_EnableIRMode)(float a1, float a2) = (void*)sithRender_EnableIRMode_ADDR;
static void (*sithRender_DisableIRMode)() = (void*)sithRender_DisableIRMode_ADDR;

#endif // _SITHRENDER_H
