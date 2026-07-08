#include "sithDSS.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Cog/sithCog.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "Devices/sithSoundMixer.h"
#include "Engine/sithPuppet.h"
#include "World/sithMaterial.h"
#include "Engine/sithKeyFrame.h"
#include "Dss/sithMulti.h"
#include "Gameplay/sithEvent.h"
#include "Devices/sithComm.h"
#include "World/jkPlayer.h"

#include "jk.h"

const char* sithDSS_IdToStr(int id)
{
    const char* strs[DSS_MAX] = 
    {
        "UNK_0",
        "DSS_THINGPOS",
        "DSS_CHAT",
        "DSS_SECTORFLAGS",
        "DSS_FIREPROJECTILE",
        "DSS_DEATH",
        "DSS_DAMAGE",
        "DSS_SETTHINGMODEL",
        "DSS_SENDTRIGGER",
        "DSS_PLAYKEY",
        "DSS_PLAYSOUND",
        "DSS_SYNCTHING",
        "DSS_THINGFULLDESC",
        "DSS_SYNCCOG",
        "DSS_SURFACESTATUS",
        "DSS_AISTATUS",
        "DSS_INVENTORY",
        "DSS_SURFACE",
        "DSS_SECTORSTATUS",
        "DSS_PLAYKEYMODE",
        "DSS_PATHMOVE",
        "DSS_SYNCPUPPET",
        "DSS_SYNCTHINGATTACHMENT",
        "DSS_SYNCEVENTS",
        "DSS_SYNCCAMERAS",
        "DSS_TAKEITEM1",
        "DSS_TAKEITEM2",
        "DSS_STOPKEY",
        "DSS_STOPSOUND",
        "DSS_CREATETHING",
        "DSS_SYNCPALEFFECTS",
        "DSS_ID_1F",
        "DSS_LEAVEJOIN",
        "DSS_WELCOME",
        "DSS_JOINREQUEST",
        "DSS_DESTROYTHING",
        "DSS_JOINING",
        "DSS_PLAYSOUNDMODE",
        "DSS_PING",
        "DSS_PINGREPLY",
        "DSS_RESET",
        "DSS_ENUMPLAYERS",
        "DSS_QUIT",
        "DSS_ID_2B",
        "DSS_MOTS_NEW_1",
        "DSS_MOTS_NEW_2",
        "DSS_ID_2E",
        "DSS_ID_2F",
        "DSS_JKENABLESABER",
        "DSS_SABERINFO3",
        "DSS_ID_32",
        "DSS_ID_33",
        "DSS_ID_34",
        "DSS_HUDTARGET",
        "DSS_ID_36",
        "DSS_JKPRINTUNISTRING",
        "DSS_ENDLEVEL",
        "DSS_SABERINFO1",
        "DSS_SABERINFO2",
        "DSS_JKSETWEAPONMESH",
        "DSS_SETTEAM",
        "DSS_61",
        "DSS_62",
        "DSS_63",
        "DSS_64",
        "DSS_MAX",
    };
    if (id < 0) return "UNK_TOOSMAll";
    if (id > DSS_MAX) {
        return "UNK_TOOLARGE";
    }
    return strs[id];
}

void sithDSS_SurfaceStatus(SithSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(surface->index);
    NETMSG_PUSHU32(surface->flags);
    if ( surface->surfaceInfo.face.material ) {
        NETMSG_PUSHS32(surface->surfaceInfo.face.material->id);
    }
    else {
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHS16(surface->surfaceInfo.face.wallCel);
    NETMSG_PUSHVEC2(surface->surfaceInfo.face.clipIdk);
    NETMSG_PUSHF32(surface->surfaceInfo.face.extraLight);
    NETMSG_PUSHU32(surface->surfaceInfo.face.type);
    NETMSG_PUSHU32(surface->surfaceInfo.face.geometryMode);
    NETMSG_PUSHU32(surface->surfaceInfo.face.lightingMode);
    NETMSG_PUSHU32(surface->surfaceInfo.face.textureMode);
    if ( surface->pAdjoin )
    {
        NETMSG_PUSHU32(surface->pAdjoin->flags);
    }
    
    NETMSG_END(DSS_SURFACESTATUS);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessSurfaceStatus(SithMessage *msg)
{
    uint32_t v1; // eax
    SithSurface *surface; // edi
    int32_t v4; // ecx
    
    NETMSG_IN_START(msg);

    v1 = NETMSG_POPS16();
    if ( v1 >= sithWorld_g_pCurrentWorld->numSurfaces )
        return 0;

    surface = &sithWorld_g_pCurrentWorld->surfaces[v1];

    surface->flags = NETMSG_POPU32();
    surface->surfaceInfo.face.material = sithMaterial_GetMaterialByIndex(NETMSG_POPS32());

    v4 = NETMSG_POPS16();
    if ( v4 == -1 || !surface->surfaceInfo.face.material || v4 >= surface->surfaceInfo.face.material->num_texinfo )
        surface->surfaceInfo.face.wallCel = -1;
    else
        surface->surfaceInfo.face.wallCel = v4;

    surface->surfaceInfo.face.clipIdk = NETMSG_POPVEC2();
    surface->surfaceInfo.face.extraLight = NETMSG_POPF32();
    surface->surfaceInfo.face.type = NETMSG_POPU32();
    surface->surfaceInfo.face.geometryMode = (rdGeoMode_t)NETMSG_POPU32();
    surface->surfaceInfo.face.lightingMode = (rdLightMode_t)NETMSG_POPU32();
    surface->surfaceInfo.face.textureMode = (rdTexMode_t)NETMSG_POPU32();

    if ( surface->pAdjoin )
        surface->pAdjoin->flags = NETMSG_POPU32();

    return 1;
}

void sithDSS_SectorStatus(SithSector *sector, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sector->id);
    NETMSG_PUSHS16(((intptr_t)sector->colormap - (intptr_t)sithWorld_g_pCurrentWorld->colormaps) / sizeof(rdColormap));
    NETMSG_PUSHU32(sector->flags);
    NETMSG_PUSHF32(sector->ambientLight);
    NETMSG_PUSHF32(sector->extraLight);
    
    if (sector->flags & SITH_SECTOR_USETHRUST)
    {
        NETMSG_PUSHVEC3(sector->thrust);
    }
    NETMSG_PUSHVEC3(sector->tint);
    
    NETMSG_END(DSS_SECTORSTATUS);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessSectorStatus(SithMessage *msg)
{
    uint32_t idx; // eax
    SithSector *sector; // edi
    uint32_t colormapIdx = 0; // eax
    int oldSectorFlags = 0;

    NETMSG_IN_START(msg);

    idx = NETMSG_POPS16();
    if ( idx >= sithWorld_g_pCurrentWorld->numSectors )
        return 0;
    sector = &sithWorld_g_pCurrentWorld->aSectors[idx];
    //sector->id = idx; // Not in original?

    colormapIdx = NETMSG_POPS16();
    if ( colormapIdx >= sithWorld_g_pCurrentWorld->numColormaps )
        return 0;
    sector->colormap = &sithWorld_g_pCurrentWorld->colormaps[colormapIdx];

    oldSectorFlags = sector->flags;
    sector->flags = NETMSG_POPU32();

    // TODO: untangle this
    if (!(sector->flags & SITH_SECTOR_ADJOINSOFF))
    {
        if ( (oldSectorFlags & SITH_SECTOR_ADJOINSOFF) == 0 )
            goto LABEL_11;
LABEL_9:
        if ( (sector->flags & SITH_SECTOR_ADJOINSOFF) == 0 )
            sithSector_ShowSectorAdjoins(sector);
    }
    else {
        if (oldSectorFlags & SITH_SECTOR_ADJOINSOFF)
            goto LABEL_9;
        sithSector_HideSectorAdjoins(sector);
    }
LABEL_11:

    sector->ambientLight = NETMSG_POPF32();
    sector->extraLight = NETMSG_POPF32();

    if (sector->flags & SITH_SECTOR_USETHRUST)
    {
        sector->thrust = NETMSG_POPVEC3();
    }
    else
    {
        rdVector_Zero3(&sector->thrust);
    }

    sector->tint = NETMSG_POPVEC3();

    return 1;
}

void sithDSS_SectorFlags(SithSector *pSector, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(pSector->id);
    NETMSG_PUSHU32(pSector->flags);
    NETMSG_END(DSS_SECTORFLAGS);

    if (!(pSector->flags & SITH_SECTOR_ADJOINSOFF))
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
    else
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 0);
}

int sithDSS_ProcessSectorFlags(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    int idx = NETMSG_POPS16();

    SithSector* pSector = sithSector_GetPtrFromIdx(idx);
    if ( pSector )
    {
        int oldFlags = pSector->flags;
        pSector->flags = NETMSG_POPU32();
        if (pSector->flags & SITH_SECTOR_ADJOINSOFF)
        {
            if (!(oldFlags & SITH_SECTOR_ADJOINSOFF))
            {
                sithSector_HideSectorAdjoins(pSector);
                return 1;
            }
        }
        else if (!(oldFlags & SITH_SECTOR_ADJOINSOFF))
        {
            return 1;
        }

        if (!(pSector->flags & SITH_SECTOR_ADJOINSOFF))
            sithSector_ShowSectorAdjoins(pSector);

        return 1;
    }
    return 0;
}

void sithDSS_AIStatus(SithAIControlBlock *actor, int sendto_id, int idx)
{    
    NETMSG_START;

    NETMSG_PUSHS16(actor->thing->idx);
    NETMSG_PUSHS16((int16_t)(((intptr_t)actor->pClass - (intptr_t)sithWorld_g_pCurrentWorld->aAIClasses) / sizeof(SithAIClass)));
    NETMSG_PUSHU32(actor->flags);
    NETMSG_PUSHU32(actor->nextUpdate);
    if ( actor->pMoveThing ) {
        NETMSG_PUSHS16(actor->pMoveThing->idx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->movepos);
    NETMSG_PUSHVEC3(actor->field_23C);
    NETMSG_PUSHU32(actor->field_248);
    if ( actor->pDistractor ) {
        NETMSG_PUSHS16(actor->pDistractor->idx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->field_1D4);
    NETMSG_PUSHVEC3(actor->field_1F8);
    NETMSG_PUSHU32(actor->field_204);
    NETMSG_PUSHF32(actor->moveSpeed);

    if (actor->flags & SITHAI_MODE_MOVING)
    {
        NETMSG_PUSHVEC3(actor->movePos);
    }
    if (actor->flags & SITHAI_MODE_TURNING)
    {
        NETMSG_PUSHVEC3(actor->goalLVec);
    }
    if (actor->flags & SITHAI_MODE_FLEEING)
    {
        if ( actor->pFleeFromThing) {
            NETMSG_PUSHS16(actor->pFleeFromThing->idx);
        }
        else {
            NETMSG_PUSHS16(-1);
        }
    }
    NETMSG_PUSHVEC3(actor->position);
    NETMSG_PUSHVEC3(actor->orient);
    for (int i = 0; i < actor->numInstincts; i++)
    {
        NETMSG_PUSHU32(actor->aInstinctStates[i].nextUpdate);
        NETMSG_PUSHF32(actor->aInstinctStates[i].param0);
        NETMSG_PUSHF32(actor->aInstinctStates[i].param1);
        NETMSG_PUSHF32(actor->aInstinctStates[i].param2);
        NETMSG_PUSHF32(actor->aInstinctStates[i].param3);
    }
    NETMSG_PUSHU32(actor->field_288);
    NETMSG_PUSHU32(actor->field_28C);
    NETMSG_PUSHU32(actor->loadedFrames);
    for (int i = 0; i < actor->loadedFrames; i++)
    {
        NETMSG_PUSHVEC3(actor->aFrames[i]);
    }
    
    NETMSG_END(DSS_AISTATUS);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, idx, 1);
}

int sithDSS_ProcessAIStatus(SithMessage *msg)
{
    SithThing *thing;
    SithAIControlBlock *actor;
    
    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIndex(NETMSG_POPS16());
    if ( !thing )
        return 0;
    if ( thing->controlType != SITH_CT_AI )
        return 0;
    actor = thing->actor;
    if ( !actor )
        return 0;
    
    int16_t idx = NETMSG_POPS16();
    if ( idx >= sithWorld_g_pCurrentWorld->numAIClasses )
        return 0;

    actor->pClass = &sithWorld_g_pCurrentWorld->aAIClasses[idx];
    actor->numInstincts = sithWorld_g_pCurrentWorld->aAIClasses[idx].numEntries;
    actor->flags = NETMSG_POPU32();
    actor->nextUpdate = NETMSG_POPU32();
    actor->pMoveThing = sithThing_GetThingByIndex(NETMSG_POPS16());
    actor->field_224 = 0; // interesting?
    
    actor->movepos = NETMSG_POPVEC3();
    actor->field_23C = NETMSG_POPVEC3();
    actor->field_248 = NETMSG_POPU32();

    actor->pDistractor = sithThing_GetThingByIndex(NETMSG_POPS16());
    
    actor->field_1D4 = NETMSG_POPVEC3();
    actor->field_1E0 = 0; // interesting?
    actor->field_1F8 = NETMSG_POPVEC3();
    actor->field_204 = NETMSG_POPU32();
    actor->moveSpeed = NETMSG_POPF32();

    if (actor->flags & SITHAI_MODE_MOVING)
    {
        actor->movePos = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAI_MODE_TURNING)
    {
        actor->goalLVec = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAI_MODE_FLEEING)
    {
        actor->pFleeFromThing = sithThing_GetThingByIndex(NETMSG_POPS16());
    }
    actor->position = NETMSG_POPVEC3();
    actor->orient = NETMSG_POPVEC3();

    for (int i = 0; i < actor->numInstincts; i++)
    {
        actor->aInstinctStates[i].nextUpdate = NETMSG_POPU32();
        actor->aInstinctStates[i].param0 = NETMSG_POPF32();
        actor->aInstinctStates[i].param1 = NETMSG_POPF32();
        actor->aInstinctStates[i].param2 = NETMSG_POPF32();
        actor->aInstinctStates[i].param3 = NETMSG_POPF32();
    }
    
    actor->field_288 = NETMSG_POPU32();
    actor->field_28C = NETMSG_POPU32();
    actor->loadedFrames = NETMSG_POPU32();
    
    if ( actor->loadedFrames)
    {
        actor->aFrames = (rdVector3 *)SITH_ALLOC(sizeof(rdVector3) * actor->loadedFrames);
        actor->sizeFrames = actor->loadedFrames;
        if ( actor->aFrames )
        {
            for (int i = 0; i < actor->loadedFrames; i++)
            {
                actor->aFrames[i] = NETMSG_POPVEC3();
            }
            return 1;
        }
    }
    else
    {
        actor->sizeFrames = 0;
        actor->loadedFrames = 0;
        actor->aFrames = NULL; // Added
    }
    return 1;
}

void sithDSS_Inventory(SithThing *thing, int binIdx, int sendto_id, int mpFlags)
{
    if ( thing->type == SITH_THING_PLAYER || thing->type == SITH_THING_ACTOR )
    {
        SithPlayer* v5 = thing->actorParams.pPlayer;
        if ( v5 )
        {
            NETMSG_START;
        
            NETMSG_PUSHS16(thing->idx);
            NETMSG_PUSHS16(binIdx);
            NETMSG_PUSHF32(v5->aItems[binIdx].amount);
            NETMSG_PUSHU32(v5->aItems[binIdx].state);
            NETMSG_PUSHU32(v5->aItems[binIdx].field_4);
            NETMSG_PUSHF32(v5->aItems[binIdx].activatedTimeSecs);
            NETMSG_PUSHF32(v5->aItems[binIdx].activationDelaySecs);
            NETMSG_PUSHF32(v5->aItems[binIdx].binWait);
            
            NETMSG_END(DSS_INVENTORY);
            
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
        }
    }
}

int sithDSS_ProcessInventory(SithMessage *msg)
{
    int idx; // edx
    SithThing *thing; // ecx
    SithPlayer *playerInfo; // edx
    int binIdx; // ecx
    SithInventoryItem *aItems; // ecx
    
    NETMSG_IN_START(msg);

    idx = NETMSG_POPS16();
    if ( idx < 0 )
        return 0;
    if ( idx >= sithWorld_g_pCurrentWorld->numThingsLoaded )
        return 0;

    thing = &sithWorld_g_pCurrentWorld->aThings[idx];
    if ( thing->type != SITH_THING_ACTOR && thing->type != SITH_THING_PLAYER )
        return 0;

    playerInfo = thing->actorParams.pPlayer;
    if ( !playerInfo )
        return 0;

    binIdx = NETMSG_POPS16();
    if ( binIdx < 0 || binIdx >= 200 )
        return 0;

    aItems = &playerInfo->aItems[binIdx];
    aItems->amount = NETMSG_POPF32();
    aItems->state = NETMSG_POPU32();
    aItems->field_4 = NETMSG_POPU32();
    aItems->activatedTimeSecs = NETMSG_POPF32();
    aItems->activationDelaySecs = NETMSG_POPF32();
    aItems->binWait = NETMSG_POPF32();

    //printf("%x %f\n", binIdx, aItems->amount);

    // Added: idk if this is necessary
    sithInventory_g_aTypes[binIdx].flags |= SITHINVENTORY_TYPE_REGISTERED;

    return 1;
}

void sithDSS_AnimStatus(rdSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(surface->index);
    NETMSG_PUSHU32(surface->flags);
    if (surface->flags & 0xC0000)
    {
        NETMSG_PUSHS32(surface->parent_thing->idx);
        NETMSG_PUSHU32(surface->signature);
    }
    if (surface->flags & 0x20000)
        NETMSG_PUSHU32(surface->sithSurfaceParent->index);
    if (surface->flags & 0x100000)
    {
        NETMSG_PUSHVEC3(surface->field_24);
        NETMSG_PUSHVEC2(surface->scrollVector);
    }
    if (surface->flags & 0x200000)
    {
        NETMSG_PUSHU32(surface->field_30);
        NETMSG_PUSHU32(surface->field_34);
        NETMSG_PUSHU32(surface->wallCel);
    }
    if (surface->flags & 0x400000)
    {
        NETMSG_PUSHF32(surface->field_44);
        NETMSG_PUSHF32(surface->field_48);
        NETMSG_PUSHF32(surface->field_40);
        NETMSG_PUSHF32(surface->field_3C);
    }
    if (surface->flags & 0x10000)
        NETMSG_PUSHS32(surface->material->id);
    if (surface->flags & 0x2000000)
        NETMSG_PUSHS32(surface->sector->id);
    
    NETMSG_END(DSS_SURFACE);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessAnimStatus(SithMessage *msg)
{
    rdSurface *rdsurface; // edi
    rdSurface *surface; // eax
    int v7; // eax

    NETMSG_IN_START(msg);

    int idx = NETMSG_POPS32();
    rdsurface = sithSurface_GetByIdx(idx);
    if (!rdsurface) {
        rdsurface = sithSurface_Alloc();
    }

    if (!rdsurface)
    {
        return 0;
    }


    rdsurface->flags = NETMSG_POPU32();
    if (!rdsurface->flags )
    {
        sithSurface_StopAnim(rdsurface);
        return 1;
    }
    
    if (rdsurface->flags & 0xC0000)
    {
        rdsurface->parent_thing = sithThing_GetThingByIndex(NETMSG_POPS32());
        if ( rdsurface->parent_thing && rdsurface->parent_thing->renderData.type == RD_THING_SPRITE3 )
            rdsurface->material = rdsurface->parent_thing->renderData.sprite3->face.material;
        rdsurface->signature = NETMSG_POPU32();
    }

    if (rdsurface->flags & 0x20000)
    {
        v7 = NETMSG_POPS32();
        if ( v7 >= 0 && v7 < sithWorld_g_pCurrentWorld->numSurfaces )
        {
            rdsurface->sithSurfaceParent = &sithWorld_g_pCurrentWorld->surfaces[v7];
            rdsurface->material = sithWorld_g_pCurrentWorld->surfaces[v7].surfaceInfo.face.material;
        }
    }

    if (rdsurface->flags & 0x100000)
    {
        rdsurface->field_24 = NETMSG_POPVEC3();
        rdsurface->scrollVector = NETMSG_POPVEC2();
    }

    if (rdsurface->flags & 0x200000)
    {
        rdsurface->field_30 = NETMSG_POPU32();
        rdsurface->field_34 = NETMSG_POPU32();
        rdsurface->wallCel = NETMSG_POPU32();
    }

    if (rdsurface->flags & 0x400000)
    {
        rdsurface->field_44 = NETMSG_POPF32();
        rdsurface->field_48 = NETMSG_POPF32();
        rdsurface->field_40 = NETMSG_POPF32();
        rdsurface->field_3C = NETMSG_POPF32();
    }

    if (rdsurface->flags & 0x10000)
    {
        rdsurface->material = sithMaterial_GetMaterialByIndex(NETMSG_POPS32());
    }

    if (rdsurface->flags & 0x2000000)
        rdsurface->sector = sithSector_GetPtrFromIdx(NETMSG_POPS32());

    return 1;
}

void sithDSS_SyncTaskEvents(SithEvent *timer, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU32(timer->msecEventTime - sithTime_g_msecGameTime);
    NETMSG_PUSHU32(timer->params.idx);
    NETMSG_PUSHU32(timer->params.timerIdx);
    NETMSG_PUSHF32(timer->params.field_10);
    NETMSG_PUSHF32(timer->params.field_14);
    NETMSG_PUSHS16(timer->taskNum);
    
    NETMSG_END(DSS_SYNCEVENTS);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessSyncTaskEvents(SithMessage *msg)
{
    int deltaMs;
    int16_t field_4;
    SithEventParams info;

    NETMSG_IN_START(msg);

    deltaMs = NETMSG_POPU32();
    info.idx = NETMSG_POPU32();
    info.timerIdx = NETMSG_POPU32();
    info.field_10 = NETMSG_POPF32();
    info.field_14 = NETMSG_POPF32();
    field_4 = NETMSG_POPS16();
    sithEvent_CreateEvent(field_4, &info, deltaMs);
    return 1;
}

void sithDSS_SendSyncPalEffects(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(stdPalEffects_numEffectRequests);
    NETMSG_PUSHU8(stdPalEffects_state.field_4);
    NETMSG_PUSHU8(stdPalEffects_state.field_8);
    
    NETMSG_PUSHU8(stdPalEffects_state.field_C);
    NETMSG_PUSHU8(stdPalEffects_state.field_10);
    
    stdPalEffectRequest* iter = &stdPalEffects_aEffects[0];
    for (int i = 0; i < 32; i++)
    {
        NETMSG_PUSHU16(iter->isValid);
        if ( iter->isValid )
        {
            uint16_t v5 = 0;
            if ( iter->effect.filter.x )
                v5 |= 1;
            if ( iter->effect.filter.y )
                v5 |= 2u;
            if ( iter->effect.filter.z )
                v5 |= 4u;

            NETMSG_PUSHU16(v5);
            NETMSG_PUSHVEC3(iter->effect.tint);
            NETMSG_PUSHVEC3I(iter->effect.add)
            NETMSG_PUSHF32(iter->effect.fade);
            NETMSG_PUSHS16(iter->idx);
        }
        ++iter;
    }
    
    NETMSG_END(DSS_SYNCPALEFFECTS);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessSyncPalEffects(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    stdPalEffects_numEffectRequests = NETMSG_POPS16();
    stdPalEffects_state.field_4 = NETMSG_POPU8();
    stdPalEffects_state.field_8 = NETMSG_POPU8();
    stdPalEffects_state.field_C = NETMSG_POPU8();
    stdPalEffects_state.field_10 = NETMSG_POPU8();
    
    stdPalEffectRequest* iter = &stdPalEffects_aEffects[0];
    for (int i = 0; i < 32; i++)
    {
        iter->isValid = NETMSG_POPS16();
        if ( iter->isValid )
        {
            uint16_t v5 = NETMSG_POPU16();
            if ( v5 & 1 )
                iter->effect.filter.x = 1;
            if ( v5 & 2 )
                iter->effect.filter.y = 1;
            if ( v5 & 4 )
                iter->effect.filter.z = 1;

            iter->effect.tint = NETMSG_POPVEC3();
            iter->effect.add = NETMSG_POPVEC3I();
            iter->effect.fade = NETMSG_POPF32();
            iter->idx = NETMSG_POPS16();
        }
        ++iter;
    }
    
    stdPalEffects_RefreshPalette();
    return 1;
}

void sithDSS_SyncCameras(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sithCamera_g_pCurCamera - sithCamera_g_aCameras);
    NETMSG_PUSHU32(sithCamera_g_bCurCameraSet);
    NETMSG_PUSHU32(sithCamera_g_curCycleCamNum);
    NETMSG_PUSHVEC3(sithCamera_g_vecCameraPosOffset);
    NETMSG_PUSHVEC3(sithCamera_g_vecCameraAngleOffset);
    NETMSG_PUSHF32(sithCamera_g_cameraPosDelta);
    NETMSG_PUSHF32(sithCamera_g_cameraAngleDelta);

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        if ( sithCamera_g_aCameras[i].pPrimaryFocusThing ) {
            NETMSG_PUSHS32(sithCamera_g_aCameras[i].pPrimaryFocusThing->idx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if ( sithCamera_g_aCameras[i].pSecondaryFocusThing ) {
            NETMSG_PUSHS32(sithCamera_g_aCameras[i].pSecondaryFocusThing->idx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if (Main_bMotsCompat) {
#ifndef QOL_IMPROVEMENTS
            if (!sithCamera_g_aCameras[i].rdCamera.canvas || !sithCamera_g_aCameras[i].bZoomed) {
                NETMSG_PUSHF32(sithCamera_g_aCameras[i].rdCamera.fov); //fVar1 = (ADJ(ppsVar5)->rdCamera).fov;
            }
            else {
                NETMSG_PUSHF32(sithCamera_g_aCameras[i].zoomFov);
                //fVar1 = ADJ(ppsVar5)->zoomFov;
            }
#else
            NETMSG_PUSHF32(sithCamera_g_aCameras[i].fov);
#endif
            
        }
        else {
            NETMSG_PUSHF32(sithCamera_g_aCameras[i].fov);
        }
        
    }

    NETMSG_PUSHU16(sithPlayer_g_pLocalPlayer->palEffectsIdx1);
    NETMSG_PUSHU16(sithPlayer_g_pLocalPlayer->palEffectsIdx2);
    
    NETMSG_END(DSS_SYNCCAMERAS);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

// MOTS altered
int sithDSS_ProcessSyncCameras(SithMessage *msg)
{
    NETMSG_IN_START(msg);
    
    sithCamera_g_pCurCamera = &sithCamera_g_aCameras[NETMSG_POPS16()];
    sithCamera_g_bCurCameraSet = NETMSG_POPU32();
    sithCamera_g_curCycleCamNum = NETMSG_POPU32();
    sithCamera_g_vecCameraPosOffset = NETMSG_POPVEC3();
    sithCamera_g_vecCameraAngleOffset = NETMSG_POPVEC3();
    sithCamera_g_cameraPosDelta = NETMSG_POPF32();
    sithCamera_g_cameraAngleDelta = NETMSG_POPF32();

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        // Added: shifted around the -1 checks
        int primaryIdx = NETMSG_POPS32();
        int secondaryIdx = NETMSG_POPS32();
        sithCamera_g_aCameras[i].pPrimaryFocusThing = sithThing_GetThingByIndex(primaryIdx);
        if (!sithCamera_g_aCameras[i].pPrimaryFocusThing && primaryIdx != -1) return 0;

        sithCamera_g_aCameras[i].pSecondaryFocusThing = sithThing_GetThingByIndex(secondaryIdx);
        if (!sithCamera_g_aCameras[i].pSecondaryFocusThing && secondaryIdx != -1) return 0;

        sithCamera_g_aCameras[i].fov = NETMSG_POPF32();

        // MOTS added
        if (Main_bMotsCompat) {
#ifndef QOL_IMPROVEMENTS
            if ((sithCamera_g_aCameras[i].fov < 5.0) || (179.0 < sithCamera_g_aCameras[i].fov)) {
                sithCamera_g_aCameras[i].fov = 90.0;
            }
#else
            if ((sithCamera_g_aCameras[i].fov < 5.0) || (179.0 < sithCamera_g_aCameras[i].fov)) {
                sithCamera_g_aCameras[i].fov = jkPlayer_fov;
            }
#endif

            rdCamera_SetFOV(&sithCamera_g_aCameras[i].rdCamera, sithCamera_g_aCameras[i].fov);
            sithCamera_g_aCameras[i].bZoomed = 0;
            sithCamera_g_aCameras[i].zoomFov = sithCamera_g_aCameras[i].fov;
#ifdef QOL_IMPROVEMENTS
            sithCamera_g_aCameras[i].zoomFov = 1.0;
            sithCamera_g_aCameras[i].zoomScale = 1.0;
            sithCamera_g_aCameras[i].invZoomScale = 1.0;
            sithCamera_g_aCameras[i].zoomScaleOrig = 1.0;
#endif
        }
    }

    sithPlayer_g_pLocalPlayer->palEffectsIdx1 = NETMSG_POPU16();
    sithPlayer_g_pLocalPlayer->palEffectsIdx2 = NETMSG_POPU16();

    return 1;
}

// MOTS altered
void sithDSS_SyncGameState(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(sithCog_g_pMasterCog ? sithCog_g_pMasterCog->idx : -1);
    if (Main_bMotsCompat) {
        NETMSG_PUSHS32(sithCog_pActionCog ? sithCog_pActionCog->idx : -1);
        NETMSG_PUSHS32(sithCog_actionCogIdk);
    }

    for (int i = 0; i < 2; i++)
    {
        NETMSG_PUSHF32(sithWeapon_a8BD030[i]);
        NETMSG_PUSHF32(sithWeapon_8BD0A0[i]);
    }
    NETMSG_PUSHF32(sithWeapon_8BD060);
    NETMSG_PUSHF32(sithWeapon_LastFireTimeSecs);
    NETMSG_PUSHF32(sithWeapon_fireWait);
    NETMSG_PUSHF32(sithWeapon_secMountWait);
    NETMSG_PUSHS32(sithWeapon_8BD05C);
    NETMSG_PUSHF32(sithWeapon_fireRate);
    NETMSG_PUSHU32(sithWeapon_CurWeaponMode);
    NETMSG_PUSHU32(sithWeapon_8BD024);
    NETMSG_PUSHU32(sithPlayer_g_pLocalPlayer->curItemID);
    NETMSG_PUSHU32(sithPlayer_g_pLocalPlayer->curWeaponID);
    NETMSG_PUSHU32(sithPlayer_g_pLocalPlayer->curPower);

    for (int i = 0; i < ((sithComm_version == 0x7D6) ? 32 : 20); i++)
    {
        NETMSG_PUSHU32(sithInventory_powerKeybinds[i].idk);
    }

    NETMSG_PUSHU32(sithInventory_g_bSendDeactivateMessage);
    NETMSG_PUSHU32(sithInventory_bUnkPower);
    NETMSG_PUSHU32(sithInventory_g_bInitInventory);
    NETMSG_PUSHU32(sithInventory_8339EC);
    NETMSG_PUSHU32(sithInventory_bRendIsHidden);
    NETMSG_PUSHU32(sithInventory_8339F4);
    NETMSG_PUSHU32(sithRender_lightingIRMode);
    NETMSG_PUSHF32(sithRender_f_83198C);
    NETMSG_PUSHF32(sithRender_f_831990);
    NETMSG_PUSHU32(sithRender_bResetCameraAspect);
    NETMSG_PUSHU8(sithSoundMixer_bPlayingMci);
    NETMSG_PUSHF32(sithSoundMixer_musicVolume);

    if ( sithSoundMixer_bPlayingMci )
    {
        NETMSG_PUSHU8(sithSoundMixer_dword_835FCC);
        NETMSG_PUSHU8(sithSoundMixer_trackFrom);
        NETMSG_PUSHU8(sithSoundMixer_trackTo);
    }

    // MoTS AI misc
    if (Main_bMotsCompat) {
        for (int i = 0; i < 10; i++) 
        {
            NETMSG_PUSHS32(sithAI_aAlignments[i].bValid);
            NETMSG_PUSHS32(sithAI_aAlignments[i].field_4);
            NETMSG_PUSHF32(sithAI_aAlignments[i].field_8);
        }
    }
    
    NETMSG_END(DSS_ID_1F);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

// MOTS altered
int sithDSS_ProcessSyncGameState(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    sithCog_g_pMasterCog = sithCog_GetCogByIndex(NETMSG_POPS32());
    if (Main_bMotsCompat) {
        sithCog_pActionCog = sithCog_GetCogByIndex(NETMSG_POPS32());
        sithCog_actionCogIdk = NETMSG_POPS32();
    }

    for (int i = 0; i < 2; i++)
    {
        sithWeapon_a8BD030[i] = NETMSG_POPF32();
        sithWeapon_8BD0A0[i] = NETMSG_POPF32();
    }
    sithWeapon_8BD060 = NETMSG_POPF32();
    sithWeapon_LastFireTimeSecs = NETMSG_POPF32();
    sithWeapon_fireWait = NETMSG_POPF32();
    sithWeapon_secMountWait = NETMSG_POPF32();
    sithWeapon_8BD05C = NETMSG_POPS32();
    sithWeapon_fireRate = NETMSG_POPF32();
    sithWeapon_CurWeaponMode = NETMSG_POPU32();
    sithWeapon_8BD024 = NETMSG_POPU32();
    sithPlayer_g_pLocalPlayer->curItemID = NETMSG_POPU32();
    sithPlayer_g_pLocalPlayer->curWeaponID = NETMSG_POPU32();
    sithPlayer_g_pLocalPlayer->curPower = NETMSG_POPU32();

    for (int i = 0; i < ((sithComm_version == 0x7D6) ? 32 : 20); i++)
    {
        sithInventory_powerKeybinds[i].idk = NETMSG_POPU32();
    }

    sithInventory_g_bSendDeactivateMessage = NETMSG_POPU32();
    sithInventory_bUnkPower = NETMSG_POPU32();
    sithInventory_g_bInitInventory = NETMSG_POPU32();
    sithInventory_8339EC = NETMSG_POPU32();
    sithInventory_bRendIsHidden = NETMSG_POPU32();
    sithInventory_8339F4 = NETMSG_POPU32();
    sithRender_lightingIRMode = NETMSG_POPU32();
    sithRender_f_83198C = NETMSG_POPF32();
    sithRender_f_831990 = NETMSG_POPF32();
    sithRender_bResetCameraAspect = NETMSG_POPU32();
    sithSoundMixer_bPlayingMci = NETMSG_POPU8();

    sithSoundMixer_SetMusicVol(NETMSG_POPF32());
    if ( sithSoundMixer_bPlayingMci )
    {
        sithSoundMixer_dword_835FCC = NETMSG_POPU8();
        sithSoundMixer_trackFrom = NETMSG_POPU8();
        sithSoundMixer_trackTo = NETMSG_POPU8();
        sithSoundMixer_ResumeMusic(1);
    }

    // MoTS AI misc
    if (Main_bMotsCompat) {
        for (int i = 0; i < 10; i++) 
        {
            sithAI_aAlignments[i].bValid = NETMSG_POPS32();
            sithAI_aAlignments[i].field_4 = NETMSG_POPS32();
            sithAI_aAlignments[i].field_8 = NETMSG_POPF32();
        }
    }
    
    return 1;
}

void sithDSS_PuppetStatus(SithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    rdPuppet* puppet = thing->renderData.puppet;

    NETMSG_PUSHS32(thing->idx);
    for (int i = 0; i < 4; i++)
    {           
        NETMSG_PUSHU32(puppet->tracks[i].status);
        if ( puppet->tracks[i].status )
        {
            NETMSG_PUSHS32(puppet->tracks[i].keyframe->id);
            NETMSG_PUSHS32(puppet->tracks[i].field_4);
            NETMSG_PUSHS16(puppet->tracks[i].lowPri);
            NETMSG_PUSHS16(puppet->tracks[i].highPri);
            NETMSG_PUSHF32(puppet->tracks[i].speed);
            NETMSG_PUSHF32(puppet->tracks[i].playSpeed);
            NETMSG_PUSHF32(puppet->tracks[i].field_120);
            NETMSG_PUSHF32(puppet->tracks[i].field_124);
        }
    }
    if ( thing->puppet )
    {
        NETMSG_PUSHS32(thing->puppet->otherTrack);
        NETMSG_PUSHS16(thing->puppet->field_0);
        NETMSG_PUSHS16(thing->puppet->field_4);
    }
    
    NETMSG_END(DSS_SYNCPUPPET);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_ProcessPuppetStatus(SithMessage *msg)
{
    SithThing *thing; // eax
    rdPuppet *rdpuppet; // edi

    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIndex(NETMSG_POPS32());

    if ( !thing )
        return 0;

    if ( !thing->pPuppetClass )
        return 0;

    if ( !thing->puppet )
        return 0;

    rdpuppet = thing->renderData.puppet;
    if ( !rdpuppet )
        return 0;

    rdPuppet_NewEntry(rdpuppet, &thing->renderData);

    for (int i = 0; i < 4; i++)
    {
        rdpuppet->tracks[i].status = NETMSG_POPU32();
        if ( rdpuppet->tracks[i].status )
        {
            int idx = NETMSG_POPS32();
            rdpuppet->tracks[i].keyframe = sithKeyFrame_GetByIdx(idx);
            //if (rdpuppet->tracks[i].keyframe)
            //    rdpuppet->tracks[i].keyframe->id = idx;
            rdpuppet->tracks[i].field_4 = NETMSG_POPS32();
            rdpuppet->tracks[i].lowPri = (int)NETMSG_POPS16();
            rdpuppet->tracks[i].highPri = (int)NETMSG_POPS16();
            rdpuppet->tracks[i].speed = NETMSG_POPF32();
            rdpuppet->tracks[i].playSpeed = NETMSG_POPF32();
            rdpuppet->tracks[i].field_120 = NETMSG_POPF32();
            rdpuppet->tracks[i].field_124 = NETMSG_POPF32();

            // Added: Fix lingering animations?
            if ( rdpuppet->tracks[i].status & 8) {
                rdPuppet_FadeOutTrack(rdpuppet, i, rdpuppet->tracks[i].speed);
            }
            else if ( rdpuppet->tracks[i].status & 4) {
                int tmp = rdpuppet->tracks[i].status; // TODO idk if this is needed but idk
                rdPuppet_FadeInTrack(rdpuppet, i, rdpuppet->tracks[i].speed);
                rdpuppet->tracks[i].status = tmp;
            }
        }
        else // Added
        {
            _memset(&rdpuppet->tracks[i], 0, sizeof(rdpuppet->tracks[i]));
        }
    }

    if ( thing->puppet )
    {
        thing->puppet->otherTrack = NETMSG_POPS32();
        
        sithPuppet_SetArmedMode(thing, NETMSG_POPS16());
        sithPuppet_SetMoveMode(thing, NETMSG_POPS16());
    }
    return 1;
}
