#include "sithAICmd.h"

#include "sithAI.h"

#define sithAICmd_Follow ((void*)sithAICmd_Follow_ADDR)
#define sithAICmd_CircleStrafe ((void*)sithAICmd_CircleStrafe_ADDR)
#define sithAICmd_Crouch ((void*)sithAICmd_Crouch_ADDR)
#define sithAICmd_BlindFire ((void*)sithAICmd_BlindFire_ADDR)
#define sithAICmd_LobFire ((void*)sithAICmd_LobFire_ADDR)
#define sithAICmd_PrimaryFire ((void*)sithAICmd_PrimaryFire_ADDR)
#define sithAICmd_TurretFire ((void*)sithAICmd_TurretFire_ADDR)
#define sithAICmd_Listen ((void*)sithAICmd_Listen_ADDR)
#define sithAICmd_LookForTarget ((void*)sithAICmd_LookForTarget_ADDR)
#define sithAICmd_OpenDoors ((void*)sithAICmd_OpenDoors_ADDR)
#define sithAICmd_Jump ((void*)sithAICmd_Jump_ADDR)
#define sithAICmd_Flee ((void*)sithAICmd_Flee_ADDR)
#define sithAICmd_Withdraw ((void*)sithAICmd_Withdraw_ADDR)
#define sithAICmd_Dodge ((void*)sithAICmd_Dodge_ADDR)
#define sithAICmd_RandomTurn ((void*)sithAICmd_RandomTurn_ADDR)
#define sithAICmd_Roam ((void*)sithAICmd_Roam_ADDR)
#define sithAICmd_SenseDanger ((void*)sithAICmd_SenseDanger_ADDR)
#define sithAICmd_HitAndRun ((void*)sithAICmd_HitAndRun_ADDR)
#define sithAICmd_Retreat ((void*)sithAICmd_Retreat_ADDR)
#define sithAICmd_ReturnHome ((void*)sithAICmd_ReturnHome_ADDR)
#define sithAICmd_Talk ((void*)sithAICmd_Talk_ADDR)

void sithAICmd_Startup()
{
    sithAI_RegisterCommand("listen", sithAICmd_Listen, 0, 0, 7);
    sithAI_RegisterCommand("lookfortarget", sithAICmd_LookForTarget, 0x204, 0, 0);
    sithAI_RegisterCommand("primaryfire", sithAICmd_PrimaryFire, 2, 0, 0x100);
    sithAI_RegisterCommand("follow", sithAICmd_Follow, 2, 0x800, 0xE00);
    sithAI_RegisterCommand("turretfire", sithAICmd_TurretFire, 2, 0x800, 0x100);
    sithAI_RegisterCommand("opendoors", sithAICmd_OpenDoors, 2, 0, 0);
    sithAI_RegisterCommand("jump", sithAICmd_Jump, 0, 0, 0x604);
    sithAI_RegisterCommand("randomturn", sithAICmd_RandomTurn, 4, 0, 0);
    sithAI_RegisterCommand("roam", sithAICmd_Roam, 4, 0, 0);
    sithAI_RegisterCommand("flee", sithAICmd_Flee, 0x800, 0, 0xF05);
    sithAI_RegisterCommand("sensedanger", sithAICmd_SenseDanger, 4, 0x800, 7);
    sithAI_RegisterCommand("hitandrun", sithAICmd_HitAndRun, 0xC00, 0, 0);
    sithAI_RegisterCommand("retreat", sithAICmd_Retreat, 2, 0x800, 0);
    sithAI_RegisterCommand("circlestrafe", sithAICmd_CircleStrafe, 2, 0x800, 0);
    sithAI_RegisterCommand("blindfire", sithAICmd_BlindFire, 2, 0xC00, 0);
    sithAI_RegisterCommand("returnhome", sithAICmd_ReturnHome, 0, 0, 0x900);
    sithAI_RegisterCommand("lobfire", sithAICmd_LobFire, 2, 0, 0x100);
    sithAI_RegisterCommand("talk", sithAICmd_Talk, 0xFFFF, 0, 0);
    sithAI_RegisterCommand("crouch", sithAICmd_Crouch, 2, 0, 0x100);
    sithAI_RegisterCommand("withdraw", sithAICmd_Withdraw, 0x800, 0, 0xF05);
    sithAI_RegisterCommand("dodge", sithAICmd_Dodge, 0, 0, 0x1003);
}
