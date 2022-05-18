#include "sithDSS.h"

#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Cog/sithCog.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithKeyFrame.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithAdjoin.h"

#include "jk.h"

void sithDSS_SendSyncSurface(sithSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(surface->field_0);
    NETMSG_PUSHU32(surface->surfaceFlags);
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
    if ( surface->adjoin )
    {
        NETMSG_PUSHU32(surface->adjoin->flags);
    }
    
    NETMSG_END(COGMSG_SYNCSURFACE);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncSurface(sithCogMsg *msg)
{
    unsigned int v1; // eax
    sithSurface *surface; // edi
    signed int v4; // ecx
    
    NETMSG_IN_START(msg);

    v1 = NETMSG_POPS16();
    if ( v1 >= sithWorld_pCurrentWorld->numSurfaces )
        return 0;

    surface = &sithWorld_pCurrentWorld->surfaces[v1];

    surface->surfaceFlags = NETMSG_POPU32();
    surface->surfaceInfo.face.material = sithMaterial_GetByIdx(NETMSG_POPS32());;

    v4 = NETMSG_POPS16();
    if ( v4 == -1 || !surface->surfaceInfo.face.material || v4 >= surface->surfaceInfo.face.material->num_texinfo )
        surface->surfaceInfo.face.wallCel = -1;
    else
        surface->surfaceInfo.face.wallCel = v4;

    surface->surfaceInfo.face.clipIdk = NETMSG_POPVEC2();
    surface->surfaceInfo.face.extraLight = NETMSG_POPF32();
    surface->surfaceInfo.face.type = NETMSG_POPU32();
    surface->surfaceInfo.face.geometryMode = NETMSG_POPU32();
    surface->surfaceInfo.face.lightingMode = NETMSG_POPU32();
    surface->surfaceInfo.face.textureMode = NETMSG_POPU32();

    if ( surface->adjoin )
        surface->adjoin->flags = NETMSG_POPU32();

    return 1;
}

void sithDSS_SendSyncSector(sithSector *sector, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sector->id);
    NETMSG_PUSHS16(((intptr_t)sector->colormap - (intptr_t)sithWorld_pCurrentWorld->colormaps) / sizeof(rdColormap));
    NETMSG_PUSHU32(sector->flags);
    NETMSG_PUSHF32(sector->ambientLight);
    NETMSG_PUSHF32(sector->extraLight);
    
    if (sector->flags & SITH_SECTOR_HASTHRUST)
    {
        NETMSG_PUSHVEC3(sector->thrust);
    }
    NETMSG_PUSHVEC3(sector->tint);
    
    NETMSG_END(COGMSG_SYNCSECTOR);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncSector(sithCogMsg *msg)
{
    uint32_t idx; // eax
    sithSector *sector; // edi
    uint32_t colormapIdx = 0; // eax
    int oldSectorFlags = 0;

    NETMSG_IN_START(msg);

    idx = NETMSG_POPS16();
    if ( idx >= sithWorld_pCurrentWorld->numSectors )
        return 0;
    sector = &sithWorld_pCurrentWorld->sectors[idx];
    sector->id = idx; // Not in original?

    colormapIdx = NETMSG_POPS16();
    if ( colormapIdx >= sithWorld_pCurrentWorld->numColormaps )
        return 0;
    sector->colormap = &sithWorld_pCurrentWorld->colormaps[colormapIdx];

    oldSectorFlags = sector->flags;
    sector->flags = NETMSG_POPU32();

    // TODO: untangle this
    if (!(sector->flags & SITH_SECTOR_80))
    {
        if ( (oldSectorFlags & SITH_SECTOR_80) == 0 )
            goto LABEL_11;
LABEL_9:
        if ( (sector->flags & SITH_SECTOR_80) == 0 )
            sithSector_SetAdjoins(sector);
        goto LABEL_11;
    }
    if (oldSectorFlags & SITH_SECTOR_80)
        goto LABEL_9;
    sithSector_UnsetAdjoins(sector);
LABEL_11:

    sector->ambientLight = NETMSG_POPF32();
    sector->extraLight = NETMSG_POPF32();

    if (sector->flags & SITH_SECTOR_HASTHRUST)
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

void sithDSS_SendSyncSectorAlt(sithSector *pSector, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(pSector->id);
    NETMSG_PUSHU32(pSector->flags);
    NETMSG_END(COGMSG_SYNCSECTORALT);

    if (!(pSector->flags & SITH_SECTOR_80))
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
    else
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 0);
}

int sithDSS_HandleSyncSectorAlt(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    int idx = NETMSG_POPS16();

    sithSector* pSector = sithSector_GetPtrFromIdx(idx);
    if ( pSector )
    {
        int oldFlags = pSector->flags;
        pSector->flags = NETMSG_POPU32();
        if (pSector->flags & SITH_SECTOR_80)
        {
            if (!(oldFlags & SITH_SECTOR_80))
            {
                sithSector_UnsetAdjoins(pSector);
                return 1;
            }
        }
        else if (!(oldFlags & SITH_SECTOR_80))
        {
            return 1;
        }

        if (!(pSector->flags & SITH_SECTOR_80))
            sithSector_SetAdjoins(pSector);

        return 1;
    }
    return 0;
}

void sithDSS_SendSyncAI(sithActor *actor, int sendto_id, int idx)
{    
    NETMSG_START;

    NETMSG_PUSHS16(actor->thing->thingIdx);
    NETMSG_PUSHS16((int16_t)(((intptr_t)actor->aiclass - (intptr_t)sithWorld_pCurrentWorld->aiclasses) / sizeof(sithAIClass)));
    NETMSG_PUSHU32(actor->flags);
    NETMSG_PUSHU32(actor->nextUpdate);
    if ( actor->thingidk ) {
        NETMSG_PUSHS16(actor->thingidk->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->movepos);
    NETMSG_PUSHVEC3(actor->field_23C);
    NETMSG_PUSHU32(actor->field_248);
    if ( actor->field_1D0 ) {
        NETMSG_PUSHS16(actor->field_1D0->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->field_1D4);
    NETMSG_PUSHVEC3(actor->field_1F8);
    NETMSG_PUSHU32(actor->field_204);
    NETMSG_PUSHF32(actor->moveSpeed);

    if (actor->flags & SITHAIFLAGS_MOVING_TO_DEST)
    {
        NETMSG_PUSHVEC3(actor->movePos);
    }
    if (actor->flags & SITHAIFLAGS_TURNING_TO_DEST)
    {
        NETMSG_PUSHVEC3(actor->lookVector);
    }
    if (actor->flags & SITHAIFLAGS_FLEEING)
    {
        if ( actor->field_1C0 ) {
            NETMSG_PUSHS16(actor->field_1C0->thingIdx);
        }
        else {
            NETMSG_PUSHS16(-1);
        }
    }
    NETMSG_PUSHVEC3(actor->position);
    NETMSG_PUSHVEC3(actor->lookOrientation);
    for (int i = 0; i < actor->numAIClassEntries; i++)
    {
        NETMSG_PUSHU32(actor->instincts[i].nextUpdate);
        NETMSG_PUSHF32(actor->instincts[i].param0);
        NETMSG_PUSHF32(actor->instincts[i].param1);
        NETMSG_PUSHF32(actor->instincts[i].param2);
        NETMSG_PUSHF32(actor->instincts[i].param3);
    }
    NETMSG_PUSHU32(actor->field_288);
    NETMSG_PUSHU32(actor->field_28C);
    NETMSG_PUSHU32(actor->loadedFrames);
    for (int i = 0; i < actor->loadedFrames; i++)
    {
        NETMSG_PUSHVEC3(actor->framesAlloc[i]);
    }
    
    NETMSG_END(COGMSG_SYNCAI);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, idx, 1);
}

int sithDSS_HandleSyncAI(sithCogMsg *msg)
{
    sithThing *thing;
    sithActor *actor;
    
    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIdx(NETMSG_POPS16());
    if ( !thing )
        return 0;
    if ( thing->thingtype != SITH_THING_ACTOR )
        return 0;
    actor = thing->actor;
    if ( !actor )
        return 0;
    
    int16_t idx = NETMSG_POPS16();
    if ( idx >= sithWorld_pCurrentWorld->numAIClassesLoaded )
        return 0;

    actor->aiclass = &sithWorld_pCurrentWorld->aiclasses[idx];
    actor->numAIClassEntries = sithWorld_pCurrentWorld->aiclasses[idx].numEntries;
    actor->flags = NETMSG_POPU32();
    actor->nextUpdate = NETMSG_POPU32();
    actor->thingidk = sithThing_GetThingByIdx(NETMSG_POPS16());
    actor->field_224 = 0; // interesting?
    
    actor->movepos = NETMSG_POPVEC3();
    actor->field_23C = NETMSG_POPVEC3();
    actor->field_248 = NETMSG_POPU32();

    actor->field_1D0 = sithThing_GetThingByIdx(NETMSG_POPS16());
    
    actor->field_1D4 = NETMSG_POPVEC3();
    actor->field_1E0 = 0; // interesting?
    actor->field_1F8 = NETMSG_POPVEC3();
    actor->field_204 = NETMSG_POPU32();
    actor->moveSpeed = NETMSG_POPF32();

    if (actor->flags & SITHAIFLAGS_MOVING_TO_DEST)
    {
        actor->movePos = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAIFLAGS_TURNING_TO_DEST)
    {
        actor->lookVector = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAIFLAGS_FLEEING)
    {
        actor->field_1C0 = sithThing_GetThingByIdx(NETMSG_POPS16());
    }
    actor->position = NETMSG_POPVEC3();
    actor->lookOrientation = NETMSG_POPVEC3();

    for (int i = 0; i < actor->numAIClassEntries; i++)
    {
        actor->instincts[i].nextUpdate = NETMSG_POPU32();
        actor->instincts[i].param0 = NETMSG_POPF32();
        actor->instincts[i].param1 = NETMSG_POPF32();
        actor->instincts[i].param2 = NETMSG_POPF32();
        actor->instincts[i].param3 = NETMSG_POPF32();
    }
    
    actor->field_288 = NETMSG_POPU32();
    actor->field_28C = NETMSG_POPU32();
    actor->loadedFrames = NETMSG_POPU32();
    
    if ( actor->loadedFrames)
    {
        actor->framesAlloc = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * actor->loadedFrames);
        actor->numFrames = actor->loadedFrames;
        if ( actor->framesAlloc )
        {
            for (int i = 0; i < actor->loadedFrames; i++)
            {
                actor->framesAlloc[i] = NETMSG_POPVEC3();
            }
            return 1;
        }
    }
    else
    {
        actor->numFrames = 0;
        actor->loadedFrames = 0;
        actor->framesAlloc = NULL; // Added
    }
    return 1;
}

void sithDSS_SendSyncItemDesc(sithThing *thing, int binIdx, int sendto_id, int mpFlags)
{
    if ( thing->type == SITH_THING_PLAYER || thing->type == SITH_THING_ACTOR )
    {
        sithPlayerInfo* v5 = thing->actorParams.playerinfo;
        if ( v5 )
        {
            NETMSG_START;
        
            NETMSG_PUSHS16(thing->thingIdx);
            NETMSG_PUSHS16(binIdx);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].ammoAmt);
            NETMSG_PUSHU32(v5->iteminfo[binIdx].state);
            NETMSG_PUSHU32(v5->iteminfo[binIdx].field_4);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].activatedTimeSecs);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].activationDelaySecs);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].binWait);
            
            NETMSG_END(COGMSG_SYNCITEMDESC);
            
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
        }
    }
}

int sithDSS_HandleSyncItemDesc(sithCogMsg *msg)
{
    int thingIdx; // edx
    sithThing *thing; // ecx
    sithPlayerInfo *playerInfo; // edx
    int binIdx; // ecx
    sithItemInfo *iteminfo; // ecx
    
    NETMSG_IN_START(msg);

    thingIdx = NETMSG_POPS16();
    if ( thingIdx < 0 )
        return 0;
    if ( thingIdx >= sithWorld_pCurrentWorld->numThingsLoaded )
        return 0;

    thing = &sithWorld_pCurrentWorld->things[thingIdx];
    if ( thing->type != SITH_THING_ACTOR && thing->type != SITH_THING_PLAYER )
        return 0;

    playerInfo = thing->actorParams.playerinfo;
    if ( !playerInfo )
        return 0;

    binIdx = NETMSG_POPS16();
    if ( binIdx < 0 || binIdx >= 200 )
        return 0;

    iteminfo = &playerInfo->iteminfo[binIdx];
    iteminfo->ammoAmt = NETMSG_POPF32();
    iteminfo->state = NETMSG_POPU32();
    iteminfo->field_4 = NETMSG_POPU32();
    iteminfo->activatedTimeSecs = NETMSG_POPF32();
    iteminfo->activationDelaySecs = NETMSG_POPF32();
    iteminfo->binWait = NETMSG_POPF32();

    // Added: idk if this is necessary
    sithInventory_aDescriptors[binIdx].flags |= ITEMINFO_VALID;

    return 1;
}

void sithDSS_SendStopAnim(rdSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(surface->index);
    NETMSG_PUSHU32(surface->flags);
    if (surface->flags & 0xC0000)
    {
        NETMSG_PUSHS32(surface->parent_thing->thingIdx);
        NETMSG_PUSHU32(surface->signature);
    }
    if (surface->flags & 0x20000)
        NETMSG_PUSHU32(surface->sithSurfaceParent->field_0);
    if (surface->flags & 0x100000)
    {
        NETMSG_PUSHVEC3(surface->field_24);
        NETMSG_PUSHVEC2(surface->field_1C);
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
    
    NETMSG_END(COGMSG_STOPANIM);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleStopAnim(sithCogMsg *msg)
{
    rdSurface *rdsurface; // edi
    rdSurface *surface; // eax
    int v7; // eax

    NETMSG_IN_START(msg);

    rdsurface = sithSurface_GetByIdx(NETMSG_POPS32());
    if ( rdsurface || (surface = sithSurface_Alloc(), (rdsurface = surface) != 0) )
    {
        rdsurface->flags = NETMSG_POPU32();
        if (!rdsurface->flags )
        {
            sithSurface_StopAnim(rdsurface);
            return 1;
        }
        
        if (rdsurface->flags & 0xC0000)
        {
            rdsurface->parent_thing = sithThing_GetThingByIdx(NETMSG_POPS32());
            if ( rdsurface->parent_thing && rdsurface->parent_thing->rdthing.type == RD_THINGTYPE_SPRITE3 )
                rdsurface->material = rdsurface->parent_thing->rdthing.sprite3->face.material;
            rdsurface->signature = NETMSG_POPU32();
        }

        if (rdsurface->flags & 0x20000)
        {
            v7 = NETMSG_POPS32();
            if ( v7 >= 0 && v7 < sithWorld_pCurrentWorld->numSurfaces )
            {
                rdsurface->sithSurfaceParent = &sithWorld_pCurrentWorld->surfaces[v7];
                rdsurface->material = sithWorld_pCurrentWorld->surfaces[v7].surfaceInfo.face.material;
            }
        }

        if (rdsurface->flags & 0x100000)
        {
            rdsurface->field_24 = NETMSG_POPVEC3();
            rdsurface->field_1C = NETMSG_POPVEC2();
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
            rdsurface->material = sithMaterial_GetByIdx(NETMSG_POPS32());
        }

        if (rdsurface->flags & 0x2000000)
            rdsurface->sector = sithSector_GetPtrFromIdx(NETMSG_POPS32());

        return 1;
    }
    return 0;
}

void sithDSS_SendSyncEvents(sithEvent *timer, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU32(timer->endMs - sithTime_curMs);
    NETMSG_PUSHU32(timer->timerInfo.cogIdx);
    NETMSG_PUSHU32(timer->timerInfo.timerIdx);
    NETMSG_PUSHF32(timer->timerInfo.field_10);
    NETMSG_PUSHF32(timer->timerInfo.field_14);
    NETMSG_PUSHS16(timer->taskNum);
    
    NETMSG_END(COGMSG_SYNCEVENTS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncEvents(sithCogMsg *msg)
{
    int deltaMs;
    int16_t field_4;
    sithEventInfo info;

    NETMSG_IN_START(msg);

    deltaMs = NETMSG_POPU32();
    info.cogIdx = NETMSG_POPU32();
    info.timerIdx = NETMSG_POPU32();
    info.field_10 = NETMSG_POPF32();
    info.field_14 = NETMSG_POPF32();
    field_4 = NETMSG_POPS16();
    sithEvent_Set(field_4, &info, deltaMs);
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
    
    NETMSG_END(COGMSG_SYNCPALEFFECTS);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncPalEffects(sithCogMsg *msg)
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

void sithDSS_SendSyncCameras(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sithCamera_currentCamera - sithCamera_cameras);
    NETMSG_PUSHU32(sithCamera_dword_8EE5A0);
    NETMSG_PUSHU32(sithCamera_curCameraIdx);
    NETMSG_PUSHVEC3(sithCamera_povShakeVector1);
    NETMSG_PUSHVEC3(sithCamera_povShakeVector2);
    NETMSG_PUSHF32(sithCamera_povShakeF1);
    NETMSG_PUSHF32(sithCamera_povShakeF2);

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        if ( sithCamera_cameras[i].primaryFocus ) {
            NETMSG_PUSHS32(sithCamera_cameras[i].primaryFocus->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if ( sithCamera_cameras[i].secondaryFocus ) {
            NETMSG_PUSHS32(sithCamera_cameras[i].secondaryFocus->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        NETMSG_PUSHF32(sithCamera_cameras[i].fov);
    }

    NETMSG_PUSHU16(g_selfPlayerInfo->palEffectsIdx1);
    NETMSG_PUSHU16(g_selfPlayerInfo->palEffectsIdx2);
    
    NETMSG_END(COGMSG_SYNCCAMERAS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncCameras(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);
    
    sithCamera_currentCamera = &sithCamera_cameras[NETMSG_POPS16()];
    sithCamera_dword_8EE5A0 = NETMSG_POPU32();
    sithCamera_curCameraIdx = NETMSG_POPU32();
    sithCamera_povShakeVector1 = NETMSG_POPVEC3();
    sithCamera_povShakeVector2 = NETMSG_POPVEC3();
    sithCamera_povShakeF1 = NETMSG_POPF32();
    sithCamera_povShakeF2 = NETMSG_POPF32();

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        // Added: shifted around the -1 checks
        int primaryIdx = NETMSG_POPS32();
        int secondaryIdx = NETMSG_POPS32();
        sithCamera_cameras[i].primaryFocus = sithThing_GetThingByIdx(primaryIdx);
        if (!sithCamera_cameras[i].primaryFocus && primaryIdx != -1) return 0;

        sithCamera_cameras[i].secondaryFocus = sithThing_GetThingByIdx(secondaryIdx);
        if (!sithCamera_cameras[i].secondaryFocus && secondaryIdx != -1) return 0;

        sithCamera_cameras[i].fov = NETMSG_POPF32();
    }

    g_selfPlayerInfo->palEffectsIdx1 = NETMSG_POPU16();
    g_selfPlayerInfo->palEffectsIdx2 = NETMSG_POPU16();

    return 1;
}

void sithDSS_SendMisc(int sendto_id, int mpFlags)
{
    NETMSG_START;

    if ( sithCog_masterCog ) {
        NETMSG_PUSHS32(sithCog_masterCog->selfCog);
    }
    else {
        NETMSG_PUSHS32(-1);
    }

    for (int i = 0; i < 2; i++)
    {
        NETMSG_PUSHF32(sithWeapon_a8BD030[i]);
        NETMSG_PUSHF32(sithWeapon_8BD0A0[i]);
    }
    NETMSG_PUSHF32(sithWeapon_8BD05C[1]);
    NETMSG_PUSHF32(sithWeapon_LastFireTimeSecs);
    NETMSG_PUSHF32(sithWeapon_fireWait);
    NETMSG_PUSHF32(sithWeapon_mountWait);
    NETMSG_PUSHF32(sithWeapon_8BD05C[0]);
    NETMSG_PUSHF32(sithWeapon_fireRate);
    NETMSG_PUSHU32(sithWeapon_CurWeaponMode);
    NETMSG_PUSHU32(sithWeapon_8BD024);
    NETMSG_PUSHU32(g_selfPlayerInfo->curItem);
    NETMSG_PUSHU32(g_selfPlayerInfo->curWeapon);
    NETMSG_PUSHU32(g_selfPlayerInfo->curPower);

    for (int i = 0; i < 20; i++)
    {
        NETMSG_PUSHU32(sithInventory_powerKeybinds[i].idk);
    }

    NETMSG_PUSHU32(sithInventory_bUnk);
    NETMSG_PUSHU32(sithInventory_bUnkPower);
    NETMSG_PUSHU32(sithInventory_549FA0);
    NETMSG_PUSHU32(sithInventory_8339EC);
    NETMSG_PUSHU32(sithInventory_bRendIsHidden);
    NETMSG_PUSHU32(sithInventory_8339F4);
    NETMSG_PUSHU32(sithRender_lightingIRMode);
    NETMSG_PUSHF32(sithRender_f_83198C);
    NETMSG_PUSHF32(sithRender_f_831990);
    NETMSG_PUSHU32(sithRender_needsAspectReset);
    NETMSG_PUSHU8(sithSoundSys_bPlayingMci);
    NETMSG_PUSHF32(sithSoundSys_musicVolume);

    if ( sithSoundSys_bPlayingMci )
    {
        NETMSG_PUSHU8(sithSoundSys_dword_835FCC);
        NETMSG_PUSHU8(sithSoundSys_trackFrom);
        NETMSG_PUSHU8(sithSoundSys_trackTo);
    }
    
    NETMSG_END(COGMSG_ID_1F);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleMisc(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithCog_masterCog = sithCog_GetByIdx(NETMSG_POPS32());

    for (int i = 0; i < 2; i++)
    {
        sithWeapon_a8BD030[i] = NETMSG_POPF32();
        sithWeapon_8BD0A0[i] = NETMSG_POPF32();
    }
    sithWeapon_8BD05C[1] = NETMSG_POPF32();
    sithWeapon_LastFireTimeSecs = NETMSG_POPF32();
    sithWeapon_fireWait = NETMSG_POPF32();
    sithWeapon_mountWait = NETMSG_POPF32();
    sithWeapon_8BD05C[0] = NETMSG_POPF32();
    sithWeapon_fireRate = NETMSG_POPF32();
    sithWeapon_CurWeaponMode = NETMSG_POPU32();
    sithWeapon_8BD024 = NETMSG_POPU32();
    g_selfPlayerInfo->curItem = NETMSG_POPU32();
    g_selfPlayerInfo->curWeapon = NETMSG_POPU32();
    g_selfPlayerInfo->curPower = NETMSG_POPU32();

    for (int i = 0; i < 20; i++)
    {
        sithInventory_powerKeybinds[i].idk = NETMSG_POPU32();
    }

    sithInventory_bUnk = NETMSG_POPU32();
    sithInventory_bUnkPower = NETMSG_POPU32();
    sithInventory_549FA0 = NETMSG_POPU32();
    sithInventory_8339EC = NETMSG_POPU32();
    sithInventory_bRendIsHidden = NETMSG_POPU32();
    sithInventory_8339F4 = NETMSG_POPU32();
    sithRender_lightingIRMode = NETMSG_POPU32();
    sithRender_f_83198C = NETMSG_POPF32();
    sithRender_f_831990 = NETMSG_POPF32();
    sithRender_needsAspectReset = NETMSG_POPU32();
    sithSoundSys_bPlayingMci = NETMSG_POPU8();

    sithSoundSys_SetMusicVol(NETMSG_POPF32());
    if ( sithSoundSys_bPlayingMci )
    {
        sithSoundSys_dword_835FCC = NETMSG_POPU8();
        sithSoundSys_trackFrom = NETMSG_POPU8();
        sithSoundSys_trackTo = NETMSG_POPU8();
        sithSoundSys_ResumeMusic(1);
    }

    return 1;
}

void sithDSS_SendSyncPuppet(sithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    rdPuppet* puppet = thing->rdthing.puppet;

    NETMSG_PUSHS32(thing->thingIdx);
    for (int i = 0; i < 4; i++)
    {
        // HACK HACK HACK weird animation glitches on savefile load -- only for player?
        if (thing == g_localPlayerThing) {
            NETMSG_PUSHU32(0);
            continue;
        }
                
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
    
    NETMSG_END(COGMSG_SYNCPUPPET);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSS_HandleSyncPuppet(sithCogMsg *msg)
{
    sithThing *thing; // eax
    rdPuppet *rdpuppet; // edi

    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIdx(NETMSG_POPS32());

    if ( !thing )
        return 0;

    if ( !thing->animclass )
        return 0;

    if ( !thing->puppet )
        return 0;

    rdpuppet = thing->rdthing.puppet;
    if ( !rdpuppet )
        return 0;

    rdPuppet_RemoveTrack(rdpuppet, &thing->rdthing);

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
            
            // HACK HACK HACK weird animation glitches on savefile load -- only for player?
            if (thing == g_localPlayerThing)
                _memset(&rdpuppet->tracks[i], 0, sizeof(rdpuppet->tracks[i]));
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
        sithPuppet_sub_4E4760(thing, NETMSG_POPS16());
    }
    return 1;
}
