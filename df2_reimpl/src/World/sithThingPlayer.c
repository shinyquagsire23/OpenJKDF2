#include "sithThingPlayer.h"

#include "Cog/sithCog.h"

int sithThingPlayer_cogMsg_SendSendTrigger(sithCog *a1, int a2, int a3, int a4, int a5, int a6, int a7, float a8_, float a8, float a9, float a10, int a11)
{
    int v12; // edi
    sithThing *v13; // eax
    sithThing *v14; // eax
    
    NETMSG_START;

    NETMSG_PUSHU32(a7);
    v12 = 1;
    NETMSG_PUSHU16(a1 ? a1->selfCog : -1);
    NETMSG_PUSHU8(a3);
    NETMSG_PUSHU8(a5);

    if ( a3 == 3 && (v13 = sithThing_GetThingByIdx(a4)) != 0 ) {
        NETMSG_PUSHU32(v13->thing_id);
    }
    else {
        NETMSG_PUSHU32(a4);
    }

    if ( a5 == 3 && (v14 = sithThing_GetThingByIdx(a6)) != 0 ) {
        NETMSG_PUSHU32(v14->thing_id);
    }
    else {
        NETMSG_PUSHU32(a6);
    }

    NETMSG_PUSHU16(a2 & 0xFF);
    
    NETMSG_PUSHF32(a8_);
    NETMSG_PUSHF32(a8);
    NETMSG_PUSHF32(a9);
    NETMSG_PUSHF32(a10);
    
    NETMSG_END(COGMSG_SENDTRIGGER);

    if ( a2 == SITH_MESSAGE_TOUCHED )
        v12 = 0;
    return sithCogVm_SendMsgToPlayer(&g_netMsgTmp, a11, 1, v12);
}
