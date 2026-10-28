/* Adapted from andreipemberton, original contribution 5fa4644d03080fef69d7137eaa2c8f295c47bd63;
 * source snapshot 6fa54630a123485d8c7b602c47992613a1f397b5. */
/* Original synthetic fixture for the complete production Take and SetItemTaken.
 * Transport and COG callbacks are stubs; RNG is deterministic. This verifies
 * host lifecycle decisions, not the engine ABI or joined-peer synchronization. */

#include <stdlib.h>
#define assert(condition) do { if (!(condition)) { fprintf(stderr, "FAIL takeitem line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)
#include <stdio.h>
#include <string.h>
#define JKM_PARAMS 1
enum { DSS_TAKEITEM1=1, DSS_TAKEITEM2=2, DSS_DESTROYTHING=3,
       SITH_THING_ITEM=4, SITH_TF_DISABLED=1, SITH_TF_DESTROYED=2, SITH_TF_10=4,
       SITH_COLLIDE_NONE=0, SITH_COLLIDE_SPHERE=1,
       SITH_ITEM_RESPAWN_SP=1, SITH_ITEM_RESPAWN_MP=2, SITH_MESSAGE_TAKEN=5 };
typedef double flex_t;
typedef struct SithThing {
    int guid, type, flags, collide, msecLifeLeft;
    struct { int flags; double secRespawnInterval, respawnFactor; } itemParams;
} SithThing;
typedef struct SithMessage {
    int pktData[2];
    struct { int flag_maybe, cogMsgId, msg_size, idx; } netMsg;
} SithMessage;
static SithMessage sithComm_netMsgTmp, last_sent;
static SithThing item, actor, unknown;
static SithThing *sithPlayer_g_pLocalPlayerThing;
static int Main_bMotsCompat, sithNet_isMulti, sithNet_isServer, sithNet_serverNetId;
static int jkPlayer_maxPlayers, playerThingIdx;
static struct { int flags; } jkPlayer_playerInfos[2];
static int sent_count, sent_target, sent_stream, sent_flags, taken_messages, destroyed_count;
void sithDSSThing_Take(SithThing *, SithThing *, int);
void sithItem_SetItemTaken(SithThing *, SithThing *, int);
static SithThing *sithThing_GetGuidThing(int guid) {
    return guid == item.guid ? &item : guid == actor.guid ? &actor : NULL;
}
static void sithComm_SendMsgToPlayer(SithMessage *msg, int target, int stream, int flags) {
    sent_count++; last_sent=*msg; sent_target=target; sent_stream=stream; sent_flags=flags;
}
static void sithCog_ThingSendMessage(SithThing *value, SithThing *source, int message) {
    assert(value == &item && source == &actor && message == SITH_MESSAGE_TAKEN);
    taken_messages++;
}
static void sithThing_DestroyThing(SithThing *value) { assert(value == &item); destroyed_count++; }
static double _frand(void) { return 0.25; }
static void reset(void) {
    memset(&sithComm_netMsgTmp,0,sizeof(sithComm_netMsgTmp)); memset(&last_sent,0,sizeof(last_sent));
    memset(&item,0,sizeof(item)); memset(&actor,0,sizeof(actor)); memset(&unknown,0,sizeof(unknown));
    item.guid=101; item.type=SITH_THING_ITEM; item.collide=SITH_COLLIDE_SPHERE;
    item.itemParams.flags=SITH_ITEM_RESPAWN_MP; item.itemParams.secRespawnInterval=30.0;
    item.itemParams.respawnFactor=1.0; actor.guid=202; unknown.guid=999;
    sithPlayer_g_pLocalPlayerThing=&actor; Main_bMotsCompat=1; sithNet_isMulti=1;
    sithNet_isServer=1; sithNet_serverNetId=777; jkPlayer_maxPlayers=2; playerThingIdx=0;
    sent_count=sent_target=sent_stream=sent_flags=taken_messages=destroyed_count=0;
}

#include "actual_takeitem.inc"
#include "actual_setitemtaken.inc"

int main(void) {
    reset(); sithDSSThing_Take(&item,NULL,255);
    assert(sent_count==1 && last_sent.netMsg.cogMsgId==DSS_TAKEITEM2);
    assert(sent_target==-1 && sent_stream==1 && sent_flags==1 && last_sent.pktData[1]==-1);
    assert((item.flags&SITH_TF_DISABLED) && item.msecLifeLeft==30000 && taken_messages==0);
    puts("host MotS sentinel: acknowledgement and actual respawn scheduling passed");
    reset(); Main_bMotsCompat=0; sithDSSThing_Take(&item,NULL,255);
    assert(sent_count==0 && item.flags==0 && item.msecLifeLeft==0);
    puts("host JK sentinel: rejection preserved");
    reset(); sithDSSThing_Take(&item,&unknown,255);
    assert(sent_count==0 && item.flags==0 && item.msecLifeLeft==0);
    puts("unknown non-sentinel actor GUID: rejection preserved");
    for (int mode=0; mode<=1; mode++) {
        reset(); Main_bMotsCompat=mode; sithDSSThing_Take(&item,&actor,42);
        assert(sent_count==1 && last_sent.netMsg.cogMsgId==DSS_TAKEITEM2 && last_sent.pktData[1]==actor.guid);
        assert((item.flags&SITH_TF_DISABLED) && item.msecLifeLeft==30000 && taken_messages==1);
    }
    puts("valid actor: JK and MotS acknowledgement/effects preserved");
    reset(); sithNet_isServer=0; sithDSSThing_Take(&item,NULL,42);
    assert(sent_count==1 && last_sent.netMsg.cogMsgId==DSS_TAKEITEM1 && last_sent.pktData[1]==-1);
    assert(sent_target==777 && sent_stream==42 && sent_flags==1 && item.flags==0 && item.msecLifeLeft==0);
    puts("client forwarding: unchanged request and no premature respawn scheduling");
    for (int flags=SITH_TF_DISABLED; flags<=SITH_TF_DESTROYED; flags++) {
        reset(); item.flags=flags; sithDSSThing_Take(&item,NULL,255);
        assert(sent_count==0 && item.msecLifeLeft==0);
    }
    reset(); item.type=123; sithDSSThing_Take(&item,NULL,255);
    assert(sent_count==0 && item.flags==0 && item.msecLifeLeft==0);
    puts("disabled/destroyed/non-item guards: preserved");
    reset(); sithItem_SetItemTaken(&item,NULL,0);
    assert(sent_count==1 && last_sent.netMsg.cogMsgId==DSS_TAKEITEM2 && item.msecLifeLeft==30000);
    assert((item.flags&SITH_TF_DISABLED) && item.collide==SITH_COLLIDE_NONE);
    puts("actual native SetItemTaken entry: end-to-end sentinel acknowledgement and respawn scheduling passed");
    return 0;
}
