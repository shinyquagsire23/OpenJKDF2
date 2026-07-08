#include "sithWeapon.h"

#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "World/sithSurface.h"
#include "World/sithTemplate.h"
#include "Gameplay/sithTime.h"
#include "Devices/sithControl.h"
#include "Engine/sithCamera.h"
#include "AI/sithAI.h"
#include "AI/sithAIAwareness.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSoundClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithPhysics.h"
#include "Cog/sithCog.h"
#include "stdPlatform.h"
#include "Main/jkGame.h"
#include "Main/Main.h"
#include "Devices/sithConsole.h"
#include "Dss/sithDSSThing.h"
#include "General/stdMath.h"
#include "jk.h"

// MOTS added
int sithWeapon_mots_5a3258 = -1;
int sithWeapon_motsAConv[10] = {
    10, 11, 2, 3, 4, 5, 6, 7, 8, 9
};

void sithWeapon_InitDefaults()
{
    sithWeapon_bAutoPickup = 1;
    sithWeapon_bAutoSwitch = 3;
    sithWeapon_bAutoReload = 0;
    sithWeapon_bMultiAutoPickup = 15;
    sithWeapon_bMultiplayerAutoSwitch = 3;
    sithWeapon_bMultiAutoReload = 3;
    sithWeapon_bAutoAim = 1;
    g_flt_8BD040 = 0.0;
    g_flt_8BD044 = 5.0;
    g_flt_8BD048 = 10.0;
    g_flt_8BD04C = 30.0;
    g_flt_8BD050 = 1.5;
    g_flt_8BD054 = 0.5;
    g_flt_8BD058 = 2.0;
}

void sithWeapon_Startup()
{
    sithWeapon_InitDefaults();
}

void sithWeapon_Update(SithThing* pThing, flex_t secDeltaTime)
{
    SITH_ASSERTREL(pThing); // Added: from OpenJones3D
    sithWeaponFlags_t flags = pThing->weaponParams.flags;
    if (flags & SITH_WF_INSTANT_IMPACT) // shooting walls?
    {
        sithWeapon_HandleImpact(pThing);
    }
    else if (flags & SITH_WF_10000)
    {
        sithWeapon_sub_4D3920(pThing);
    }
    else
    {
        if (flags & SITH_WF_DAMAGE_DECAY 
            && pThing->weaponParams.damage > (flex_d_t)pThing->weaponParams.minDamage)
        {
            flex_t v3 = pThing->weaponParams.damage - pThing->weaponParams.rate * secDeltaTime;
            pThing->weaponParams.damage = v3;
            // no idea if this is even correct but it makes sense?
            // c0 | c3, https://c9x.me/x86/html/file_module_x86_id_87.html
            if (v3 <= 0.0)
                v3 = pThing->weaponParams.minDamage;
            pThing->weaponParams.damage = v3;
        }
        if ( (flags & SITH_WF_DECAYEMITSOUNDAWARENESSEVENT) != 0 && (((uint8_t)jkPlayer_currentTickIdx + (pThing->idx & 0xFF)) & 7) == 0 )
            sithAIAwareness_CreateTransmittingEvent(pThing->sector, &pThing->position, 2, 2.0, pThing);
    }
}

// MOTS altered: don't affect cog aThings?
void sithWeapon_HandleImpact(SithThing *pWeapon)
{
    flex_t damage; // ecx
    rdVector3 *weaponPos; // edx
    SithSector *sector; // ebx
    SithCollision *searchRes; // edi
    SithThing *damageReceiver; // eax
    SithThing *pExplosionTemplate; // eax
    SithThing *trailThing; // eax
    flex_d_t v19; // st7
    flex_t moveSize; // [esp-8h] [ebp-40h]
    flex_t damage_; // [esp+10h] [ebp-28h]
    rdVector3 weaponPos_; // [esp+14h] [ebp-24h] BYREF
    rdVector3 tmp; // [esp+20h] [ebp-18h] BYREF
    rdVector3 tmp2; // [esp+2Ch] [ebp-Ch] BYREF
    flex_t size; // [esp+3Ch] [ebp+4h]

    damage = pWeapon->weaponParams.damage;
    weaponPos = &pWeapon->orient.lvec;
    size = pWeapon->weaponParams.size;
    damage_ = damage;
    sector = pWeapon->sector;
    rdVector_Copy3(&weaponPos_, weaponPos);
    moveSize = pWeapon->moveSize;
    sithCollision_SearchForCollisions(sector, pWeapon, &pWeapon->position, &weaponPos_, pWeapon->weaponParams.range, moveSize, 0);
    searchRes = sithCollision_PopStack();
    if ( searchRes )
    {
        while ( 1 )
        {
            if ( (pWeapon->weaponParams.flags & SITH_WF_OBJECT_TRAIL) != 0
              && pWeapon->weaponParams.trailThing
              && size < (flex_d_t)searchRes->distance )
            {
                do
                {
                    rdVector_Copy3(&tmp, &pWeapon->position);
                    rdVector_ScaleAdd3Acc(&tmp, &weaponPos_, size);
                    sithThing_CreateThingAtPos(pWeapon->weaponParams.trailThing, &tmp, &pWeapon->orient, sector, 0);
                    size += pWeapon->weaponParams.size;
                }
                while ( size < searchRes->distance );
            }
            if ( (searchRes->type & SITHCOLLISION_ADJOINCROSS) == 0 )
                break;
            sector = searchRes->surface->pAdjoin->sector;
            searchRes = sithCollision_PopStack();
            if ( !searchRes )
                goto LABEL_20;
        }
        if ( (pWeapon->weaponParams.flags & SITH_WF_DAMAGE_DECAY) != 0 )
        {
            damage_ = damage_ - pWeapon->weaponParams.rate * searchRes->distance;
            if ( pWeapon->weaponParams.minDamage > (flex_d_t)damage_ )
                damage_ = pWeapon->weaponParams.minDamage;
        }
        if (searchRes->type & SITHCOLLISION_THING)
        {
            sithThing_DamageThing(searchRes->pThingCollided, pWeapon, damage_, pWeapon->weaponParams.damageType);
            if ( pWeapon->weaponParams.force != 0.0 )
            {
                damageReceiver = searchRes->pThingCollided;
                if ( damageReceiver->moveType == SITH_MT_PHYSICS && MOTS_ONLY_FLAG(damageReceiver->type != SITH_THING_COG))
                {
                    rdVector_Scale3(&tmp2, &weaponPos_, pWeapon->weaponParams.force);
                    sithPhysics_ApplyForce(damageReceiver, &tmp2);
                }
            }
        }
        else if ( (searchRes->type & SITHCOLLISION_WORLD) != 0 )
        {
            sithSurface_HandleThingImpact(searchRes->surface, pWeapon, damage_, pWeapon->weaponParams.damageType);
        }
        if ( pWeapon->weaponParams.pExplosionTemplate )
        {
            rdVector_Copy3(&tmp2, &pWeapon->position);
            rdVector_ScaleAdd3Acc(&tmp2, &weaponPos_, searchRes->distance);
            sithThing_CreateThingAtPos(pWeapon->weaponParams.pExplosionTemplate, &tmp2, &rdroid_identMatrix34, sector, 0);
        }
    }

LABEL_20:
    sithCollision_DecreaseStackLevel();
    if ( !searchRes
      && (pWeapon->weaponParams.flags & SITH_WF_OBJECT_TRAIL) != 0
      && pWeapon->weaponParams.trailThing
      && size < (flex_d_t)pWeapon->weaponParams.range )
    {
        do
        {
            rdVector_Copy3(&tmp, &pWeapon->position);
            rdVector_ScaleAdd3Acc(&tmp, &weaponPos_, size);
            sithThing_CreateThingAtPos(pWeapon->weaponParams.trailThing, &tmp, &pWeapon->orient, sector, 0);
            size += pWeapon->weaponParams.size;
        }
        while ( size < pWeapon->weaponParams.range );
    }
    sithThing_DestroyThing(pWeapon);
}

void sithWeapon_sub_4D3920(SithThing *weapon)
{
    flex_t size; // eax
    flex_t elementSize__; // edx
    SithCollision *searchRes; // ebp
    flex_d_t v5; // st6
    flex_d_t v6; // st5
    flex_d_t v7; // st7
    flex_d_t v8; // st7
    flex_d_t v9; // st6
    flex_d_t v10; // st5
    flex_d_t v11; // st7
    uint8_t v17; // c0
    uint8_t v18; // c3
    flex_d_t v19; // st6
    flex_d_t normAng; // st7
    SithSector *sectorLook; // eax
    flex_d_t v22; // st7
    SithThing *receiveThing; // eax
    flex_d_t v24; // st7
    flex_d_t v25; // st6
    SithThing *pExplosionTemplate; // eax
    flex_d_t v27; // st6
    flex_d_t v29; // st6
    flex_d_t v30; // st5
    flex_d_t v31; // st7
    flex_d_t v32; // st7
    flex_d_t v33; // st6
    flex_d_t v34; // st5
    flex_d_t v35; // st7
    flex_d_t v36; // rtt
    flex_d_t v37; // st5
    flex_d_t v38; // st7
    flex_d_t v40; // st6
    uint8_t v41; // c0
    uint8_t v42; // c3
    flex_d_t v43; // st6
    flex_d_t v44; // st7
    SithSector *sectorLook_; // eax
    flex_t range; // [esp-Ch] [ebp-CCh]
    flex_t moveSize; // [esp-8h] [ebp-C8h]
    flex_t elementSize_; // [esp+14h] [ebp-ACh]
    flex_t v49; // [esp+14h] [ebp-ACh]
    flex_t v50; // [esp+18h] [ebp-A8h]
    flex_t v51; // [esp+18h] [ebp-A8h]
    rdVector3 lookOrient; // [esp+1Ch] [ebp-A4h] BYREF
    rdVector3 weaponPos; // [esp+28h] [ebp-98h] BYREF
    rdVector3 a1a; // [esp+34h] [ebp-8Ch] BYREF
    flex_t amount; // [esp+40h] [ebp-80h]
    rdVector3 vertex_out; // [esp+44h] [ebp-7Ch] BYREF
    SithSector *sector; // [esp+50h] [ebp-70h]
    rdVector3 a3; // [esp+54h] [ebp-6Ch] BYREF
    rdVector3 rot; // [esp+60h] [ebp-60h] BYREF
    rdVector3 tmp; // [esp+6Ch] [ebp-54h] BYREF
    rdVector3 tmp2; // [esp+78h] [ebp-48h] BYREF
    rdVector3 vertex; // [esp+84h] [ebp-3Ch] BYREF
    rdMatrix34 camera; // [esp+90h] [ebp-30h] BYREF

    amount = weapon->weaponParams.damage;
    size = weapon->weaponParams.size;
    rdVector_Copy3(&lookOrient, &weapon->orient.lvec);
    rdVector_Copy3(&weaponPos, &weapon->position);
    moveSize = weapon->moveSize;
    range = weapon->weaponParams.range;
    elementSize_ = size;
    sector = weapon->sector;
    sithCollision_SearchForCollisions(sector, weapon, &weapon->position, &lookOrient, range, moveSize, 0);
    elementSize__ = weapon->weaponParams.size;
    _memcpy(&camera, &weapon->orient, sizeof(camera));
    vertex.x = 0.0;
    vertex.y = elementSize__;
    vertex.z = 0.0;
    searchRes = sithCollision_PopStack();
    if ( searchRes )
    {
        while ( 1 )
        {
            if ( (weapon->weaponParams.flags & SITH_WF_OBJECT_TRAIL) != 0
              && weapon->weaponParams.trailThing
              && elementSize_ < (flex_d_t)searchRes->distance )
            {
                do
                {
                    rdVector_Sub3(&vertex_out, &weaponPos, &weapon->position);
                    elementSize_ = rdVector_Dot3(&vertex_out, &lookOrient);
                    if ( elementSize_ > searchRes->distance )
                        break;
                    rdVector_Copy3(&a3, &weapon->position);
                    rdVector_ScaleAdd3Acc(&a3, &lookOrient, elementSize_);
                    rdVector_Sub3(&a1a, &a3, &weaponPos);
                    if (rdVector_Len3(&a1a) <= weapon->weaponParams.trailCylRadius)
                    {
                        rot.x = _frand()
                              * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                              - weapon->weaponParams.trainRandAngle;
                        rot.y = _frand()
                              * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                              - weapon->weaponParams.trainRandAngle;
                        rot.z = _frand()
                              * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                              - weapon->weaponParams.trainRandAngle;
                        rdMatrix_PreRotate34(&camera, &rot);
                        if ( camera.lvec.x * lookOrient.x + camera.lvec.y * lookOrient.y + camera.lvec.z * lookOrient.z < 0.0 )
                            _memcpy(&camera, &weapon->orient, sizeof(camera));
                    }
                    else
                    {
                        rdVector_Sub3(&a1a, &a3, &weaponPos);
                        rdVector_Normalize3Acc(&a1a);
                        
                        v19 = _frand() * 0.5;
                        rdVector_Scale3Acc(&a1a, v19);
                        v50 = 1.0 - v19;
                        
                        rdVector_Copy3(&tmp, &a1a);
                        rdVector_ScaleAdd3Acc(&tmp, &lookOrient, v50);
                        rdVector_Normalize3Acc(&tmp);
                        rdVector_ExtractAngle(&tmp, &rot);
                        rdMatrix_BuildRotate34(&camera, &rot);
                    }
                    sectorLook = sithCollision_FindSectorInRadius(sector, &a3, &weaponPos, 0.0);
                    sithThing_CreateThingAtPos(weapon->weaponParams.trailThing, &weaponPos, &camera, sectorLook, 0);
                    rdMatrix_TransformPoint34(&vertex_out, &vertex, &camera);
                    rdVector_Add3Acc(&weaponPos, &vertex_out);
                }
                while ( elementSize_ < (flex_d_t)searchRes->distance );
            }
            if ( (searchRes->type & SITHCOLLISION_ADJOINCROSS) == 0 )
                break;
            sector = searchRes->surface->pAdjoin->sector;
            searchRes = sithCollision_PopStack();
            if ( !searchRes )
                goto LABEL_25;
        }
        if ( (weapon->weaponParams.flags & SITH_WF_DAMAGE_DECAY) != 0 )
        {
            v22 = weapon->weaponParams.minDamage;
            amount = amount - searchRes->distance * weapon->weaponParams.rate;
            if ( v22 > amount )
                amount = weapon->weaponParams.minDamage;
        }
        if ( (searchRes->type & SITHCOLLISION_THING) != 0 )
        {
            sithThing_DamageThing(searchRes->pThingCollided, weapon, amount, weapon->weaponParams.damageType);
            if ( weapon->weaponParams.force != 0.0 )
            {
                receiveThing = searchRes->pThingCollided;
                if ( receiveThing->moveType == SITH_MT_PHYSICS )
                {
                    tmp2.x = weapon->weaponParams.force * lookOrient.x;
                    tmp2.y = weapon->weaponParams.force * lookOrient.y;
                    tmp2.z = weapon->weaponParams.force * lookOrient.z;
                    sithPhysics_ApplyForce(receiveThing, &tmp2);
                }
            }
        }
        else if ( (searchRes->type & SITHCOLLISION_WORLD) != 0 )
        {
            sithSurface_HandleThingImpact(searchRes->surface, weapon, amount, weapon->weaponParams.damageType);
        }
        pExplosionTemplate = weapon->weaponParams.pExplosionTemplate;
        if ( pExplosionTemplate )
        {
            tmp2.x = searchRes->distance * lookOrient.x + weapon->position.x;
            tmp2.y = searchRes->distance * lookOrient.y + weapon->position.y;
            tmp2.z = searchRes->distance * lookOrient.z + weapon->position.z;
            sithThing_CreateThingAtPos(pExplosionTemplate, &tmp2, &rdroid_identMatrix34, sector, 0);
        }
    }
LABEL_25:
    sithCollision_DecreaseStackLevel();
    if ( !searchRes
      && (weapon->weaponParams.flags & SITH_WF_OBJECT_TRAIL) != 0
      && weapon->weaponParams.trailThing
      && elementSize_ < (flex_d_t)weapon->weaponParams.range )
    {
        do
        {
            rdVector_Sub3(&vertex_out, &weaponPos, &weapon->position);
            v32 = rdVector_Dot3(&vertex_out, &lookOrient);
            if ( v32 > weapon->weaponParams.range )
                break;

            a3.x = v32 * lookOrient.x + weapon->position.x;
            a3.y = v32 * lookOrient.y + weapon->position.y;
            a3.z = v32 * lookOrient.z + weapon->position.z;
            rdVector_Sub3(&a1a, &a3, &weaponPos);
            if (rdVector_Len3(&a1a) <= weapon->weaponParams.trailCylRadius)
            {
                rot.x = _frand() * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                      - weapon->weaponParams.trainRandAngle;
                rot.y = _frand() * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                      - weapon->weaponParams.trainRandAngle;
                rot.z = _frand() * (weapon->weaponParams.trainRandAngle + weapon->weaponParams.trainRandAngle)
                      - weapon->weaponParams.trainRandAngle;
                rdMatrix_PreRotate34(&camera, &rot);
                if ( camera.lvec.x * lookOrient.x + camera.lvec.y * lookOrient.y + camera.lvec.z * lookOrient.z < 0.0 )
                    _memcpy(&camera, &weapon->orient, sizeof(camera));
            }
            else
            {
                rdVector_Sub3(&a1a, &a3, &weaponPos);
                rdVector_Normalize3Acc(&a1a);
                v43 = _frand() * 0.5;
                rdVector_Scale3Acc(&a1a, v43);
                v51 = 1.0 - v43;
                rdVector_Copy3(&tmp, &a1a);
                rdVector_ScaleAdd3Acc(&tmp, &lookOrient, v51);
                rdVector_Normalize3Acc(&tmp);
                rdVector_ExtractAngle(&tmp, &rot);
                rdMatrix_BuildRotate34(&camera, &rot);
            }
            sectorLook_ = sithCollision_FindSectorInRadius(sector, &a3, &weaponPos, 0.0);
            sithThing_CreateThingAtPos(weapon->weaponParams.trailThing, &weaponPos, &camera, sectorLook_, 0);
            rdMatrix_TransformPoint34(&vertex_out, &vertex, &camera);
            rdVector_Add3Acc(&weaponPos, &vertex_out);
        }
        while ( v32 < (flex_d_t)weapon->weaponParams.range );
    }
    sithThing_DestroyThing(weapon);
}

int sithWeapon_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum)
{
    int tmp;

    switch ( adjNum )
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(pArg->value, "%x", &tmp) != 1 )
                return 1;
            pThing->weaponParams.flags = (sithWeaponFlags_t)tmp;
            return 1;

        case THINGPARAM_DAMAGE:
            pThing->weaponParams.damage = _atof(pArg->value);
            return 1;

        case SITHTHING_ARG_MINDAMAGE:
            pThing->weaponParams.minDamage = _atof(pArg->value);
            return 1;

        case THINGPARAM_DAMAGECLASS:
            if ( _sscanf(pArg->value, "%x", &tmp) == 1 )
            {
                pThing->weaponParams.damageType = tmp;
            }
            return 1;
        case THINGPARAM_EXPLODE:
            pThing->weaponParams.pExplosionTemplate = sithTemplate_GetTemplate(pArg->value);
            return 1;

        case THINGPARAM_FORCE:
            pThing->weaponParams.force = _atof(pArg->value);
            return 1;

        case THINGPARAM_RANGE:
            pThing->weaponParams.range = _atof(pArg->value);
            return 1;

        case THINGPARAM_RATE:
            pThing->weaponParams.rate = _atof(pArg->value);
            return 1;

        case THINGPARAM_ELEMENTSIZE:
            pThing->weaponParams.size = _atof(pArg->value);
            return 1;

        case THINGPARAM_TRAILTHING:
            pThing->weaponParams.trailThing = sithTemplate_GetTemplate(pArg->value);
            return 1;

        case THINGPARAM_TRAILCYLRADIUS:
            pThing->weaponParams.trailCylRadius = _atof(pArg->value);
            return 1;

        case THINGPARAM_TRAINRANDANGLE:
            pThing->weaponParams.trainRandAngle = _atof(pArg->value);
            return 1;

        case THINGPARAM_FLESHHIT:
            pThing->weaponParams.fleshHitTemplate = sithTemplate_GetTemplate(pArg->value);
            return 1;

        default:
            return 0;
    }
}

// Mots added: unused
SithThing* sithWeapon_FireMots(SithThing *weapon, SithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, flex_t scale, int16_t scaleFlags, flex_t a9, int extra)
{
    SithThing *spawned; // esi

    if ( fireSound )
        sithAIAwareness_CreateTransmittingEvent(weapon->sector, &weapon->position, 1, 4.0, weapon);

    spawned = sithWeapon_WeaponFireProjectile(weapon, projectile, fireOffset, aimError, fireSound, anim, scale, scaleFlags, a9, 0);

    if ( spawned && sithMessage_g_outputstream )
        sithDSSThing_Fire(weapon, projectile, fireOffset, aimError, fireSound, anim, scale, scaleFlags, a9, spawned->guid, -1, 255, extra);

    return spawned;
}

SithThing* sithWeapon_WeaponFire(SithThing *pShooter, SithThing *pProjectileTemplate, rdVector3 *pFireDir, rdVector3 *pFirePos, sithSound *hFireSnd, int submode, flex_t extra, int16_t projectileFlags, flex_t secDeltaTime)
{
    SithThing *spawned; // esi

    SITH_ASSERTREL(pShooter); // Added: from OpenJones3D
    if ( hFireSnd )
        sithAIAwareness_CreateTransmittingEvent(pShooter->sector, &pShooter->position, 1, 4.0, pShooter);

    spawned = sithWeapon_WeaponFireProjectile(pShooter, pProjectileTemplate, pFireDir, pFirePos, hFireSnd, submode, extra, projectileFlags, secDeltaTime, 0);

    if ( spawned && sithMessage_g_outputstream )
        sithDSSThing_Fire(pShooter, pProjectileTemplate, pFireDir, pFirePos, hFireSnd, submode, extra, projectileFlags, secDeltaTime, spawned->guid, -1, 255, 0);

    return spawned;
}

SithThing* sithWeapon_WeaponFireProjectile(SithThing *pShooter, SithThing *pProjectileTemplate, rdVector3 *pFireDir, rdVector3 *pFirePos, sithSound *hFireSnd, int submode, flex_t scale, char flags, flex_t secDeltaTime, int extra)
{
    SithThing *v9; // esi
    flex_d_t v17; // st7
    flex_d_t v18; // st7
    SithCollision *v19; // ebx
    SithThing *v20; // ebx
    rdVector3 a1; // [esp+10h] [ebp-48h] BYREF
    rdVector3 a5a; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 a3a; // [esp+28h] [ebp-30h] BYREF
    flex_t a6a; // [esp+74h] [ebp+1Ch]
    flex_t a6c; // [esp+74h] [ebp+1Ch]
    flex_t a6; // [esp+74h] [ebp+1Ch]

    //return sithWeapon_FireProjectile_0_(pMeshCollided, projectileTemplate, fireOffset, aimError, fireSound, anim, scale, scaleFlags, a9);

    v9 = 0;
    if ( !pShooter || !pFireDir )
    {
        SITHLOG_ERROR("Bad arguments passed.\n"); // Added: from OpenJones3D
        return 0;
    }

    if ( pProjectileTemplate )
    {
        rdMatrix_BuildFromLook34(&a3a, pFireDir);

        flex_t fVar3, fVar2;
        if (Main_bMotsCompat) {
            fVar3 = pProjectileTemplate->physicsParams.vel.z;
            fVar2 = stdMath_ArcTan1(pProjectileTemplate->physicsParams.vel.y,fVar3);
            rdMatrix_ExtractAngles34(&a3a,&a5a);
            a5a.x = -fVar2 + a5a.x;
            if (a5a.x < 0.0) {
                a5a.x = -a5a.x;
            }
            if (a5a.x > 80.0) {
                pProjectileTemplate->physicsParams.vel.z = 0;
            }
        }
        v9 = sithThing_CreateThingAtPos(pProjectileTemplate, &pShooter->position, &a3a, pShooter->sector, pShooter);
        if (Main_bMotsCompat) {
            pProjectileTemplate->physicsParams.vel.z = fVar3;
        }

        if (!v9 )
            return 0;

        if (Main_bMotsCompat) {
            a5a.x = (flex_t)extra; // FLEXTODO
            a5a.y = 0.0;
            v9->userval = (flex_t)extra; // FLEXTODO
        }

        if ((flags & 1) && v9->moveType == SITH_MT_PHYSICS) // Added: physics check
        {
            rdVector_Scale3Acc(&v9->physicsParams.vel, scale);
        }
        if (flags & 2)
            v9->weaponParams.damage *= scale;
        if (flags & 4)
            v9->weaponParams.damage *= scale;
        if (flags & 8)
            v9->weaponParams.unk8 *= scale;
        rdVector_Sub3(&a1, pFirePos, &pShooter->position);
        if (!rdVector_IsZero3(&a1))
        {
            a6a = rdVector_Normalize3Acc(&a1);
            sithCollision_MoveThing(v9, &a1, a6a, 0);
        }
        if ( secDeltaTime > 0.02 )
        {
            sithPhysics_UpdateThing(v9, secDeltaTime);
            v17 = rdVector_Normalize3(&a5a, &v9->physicsParams.deltaVelocity);
            if ( v17 > 0.0 )
            {
                a6c = v17;
                sithCollision_MoveThing(v9, &a5a, a6c, v9->physicsParams.flags);
            }
        }

        // TODO Co-op
        if ( !sithNet_isMulti && jkPlayer_setDiff && pShooter == sithPlayer_g_pLocalPlayerThing && (v9->weaponParams.flags & SITH_WF_EMITAITARGETEDEVENT) != 0 )
        {
            v18 = rdVector_Normalize3(&a5a, &v9->physicsParams.vel) * 3.0;
            a6 = v18 >= 5.0 ? (flex_t)5.0 : (flex_t)v18; // FLEXTODO
            sithCollision_SearchForCollisions(v9->sector, v9, &v9->position, &a5a, a6, 0.0, RAYCAST_2);
            v19 = sithCollision_PopStack();
            sithCollision_DecreaseStackLevel();
            if (v19 && v19->type & SITHCOLLISION_THING)
            {
                v20 = v19->pThingCollided;
                if ( v20->controlType == SITH_CT_AI )
                    sithAI_EmitEvent(v20->actor, SITHAI_MODE_SLEEPING, (intptr_t)v9); // aaaaaaaaa undefined
            }
        }
        goto LABEL_31;
    }

LABEL_31:
    if ( hFireSnd ) {
        sithSoundMixer_PlaySoundThing(hFireSnd, pShooter, 1.0, 1.0, 4.0, SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_HIGHPRIO);
    }
    if ( submode >= 0 )
    {
        if ( pShooter->pPuppetClass ) {
            sithPuppet_PlayMode(pShooter, submode, 0);
        }
    }

    return v9;
}

void sithWeapon_DamageWeapon(SithThing *pThing, SithThing* pPurpetrator, flex_t damage)
{
    unsigned int v3; // eax
    
    // TODO: ??? why is timeLeft unused

    if ( (pThing->weaponParams.flags & SITH_WF_DAMAGEDESTROY) != 0 && damage > 1.0 )
    {
        if ( !pThing->msecLifeLeft || pThing->msecLifeLeft > 250 )
            pThing->msecLifeLeft = 250;
    }
}

// MOTS altered
// TODO: I think there's some inlining happening in here
int sithWeapon_ThingCollisionHandler(SithThing *pWeapon, SithThing *pThing, SithCollision *pCollision, int a5)
{
    int v4; // eax
    int result; // eax
    flex_d_t v8; // st7
    flex_d_t v11; // st6
    flex_d_t v12; // st4
    flex_d_t v13; // st7
    flex_d_t v14; // st7

    // MoTS added
    if (MOTS_ONLY_FLAG(pThing->type == SITH_THING_ITEM && !(pThing->itemParams.flags & SITH_ITEM_10))) {
        return 0;
    }

    // Make the mines go Beep Beep Beep before exploding
    if (pWeapon->weaponParams.flags & SITH_WF_PROXIMITY)
    {
        // MoTS added
        if (MOTS_ONLY_FLAG(pThing->type == SITH_THING_COG && a5)) {
            return 0;
        }
        pWeapon->weaponParams.flags &= ~SITH_WF_PROXIMITY;
        pWeapon->weaponParams.flags |= SITH_WF_EXPLODE;
        pWeapon->collideSize = 0.0;
        pWeapon->msecLifeLeft = 550;
        sithSoundClass_PlayModeFirst(pWeapon, SITH_SC_ACTIVATE);
        return 0;
    }

    int bFlagsHadWfImpactSoundFxEarlier = pWeapon->weaponParams.flags & SITH_WF_IMPACTSOUND;
    if ( pWeapon->weaponParams.flags & SITH_WF_IMPACTSOUND && pThing->flags & SITH_TF_4
      || pThing->type == SITH_THING_COG && pWeapon->weaponParams.flags & SITH_WF_SURFACERICOCHET && pWeapon->weaponParams.numRicochets < 2 )
    {
        if ( pWeapon->weaponParams.numRicochets++ < MAX_DEFLECTION_BOUNCES )
        {
            rdVector3 v31 = pWeapon->physicsParams.vel;
            result = sithCollision_ThingCollisionHandler(pWeapon, pThing, pCollision, 0);
            if ( result )
            {
                v8 = rdVector_Dot3(&pCollision->hitNorm, &v31) * -2.0;
                if ( a5 )
                    v8 = -v8;

                rdVector_Copy3(&pWeapon->physicsParams.vel, &v31);
                rdVector_ScaleAdd3Acc(&pWeapon->physicsParams.vel, &pCollision->hitNorm, v8);

                rdVector3 tmp;
                rdVector_Normalize3(&tmp, &pWeapon->physicsParams.vel);
                rdMatrix_BuildFromLook34(&pWeapon->orient, &tmp);

                sithSoundClass_PlayModeRandom(pWeapon, SITH_SC_DEFLECTED);
                pWeapon->weaponParams.flags &= ~SITH_WF_NOSHOOTERDAMAGE;
                result = 1;
            }
            return result;
        }
    }
    if ( pThing->type != SITH_THING_ACTOR && pThing->type != SITH_THING_PLAYER )
    {
        // MoTS added
        if (MOTS_ONLY_FLAG(pThing->type == SITH_THING_COG && a5)) {
            return 0;
        }

        if (pWeapon->weaponParams.damage != 0.0) {
            sithThing_DamageThing(pThing, pWeapon, pWeapon->weaponParams.damage, pWeapon->weaponParams.damageType);
        }

        if (pWeapon->weaponParams.flags & SITH_WF_FACEHITEXPLODE)
        {
            sithWeapon_CreateWeaponExplosion(pWeapon, pWeapon->weaponParams.pExplosionTemplate);
            return 1;
        }
        if (!(pWeapon->weaponParams.flags & SITH_WF_ATTACHFACE)) {
            return sithCollision_ThingCollisionHandler(pWeapon, pThing, pCollision, a5);
        }
        sithPhysics_ResetThingMovement(pWeapon);
        sithSoundClass_StopMode(pWeapon, SITH_PF_USEGRAVITY);
        sithSoundClass_PlayModeFirst(pWeapon, SITH_SC_HITHARD);
        pWeapon->moveSize = 0.0;
        sithThing_AttachThingToThing(pWeapon, pThing);
        sithPhysics_SetThingLook(pWeapon, &pCollision->hitNorm, 0.0);
        
        pWeapon->attach_flags |= SITH_ATTACH_NOMOVE;
        pWeapon->physicsParams.flags |= SITH_PF_USEGRAVITY;
        return 1;
    }
    if (pThing->weaponParams.flags & SITH_WF_INSTANT_IMPACT
      && bFlagsHadWfImpactSoundFxEarlier
      && !(pThing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED))
      && (pThing != sithPlayer_g_pLocalPlayerThing || sithTime_g_secGameTime >= (flex_d_t)sithWeapon_fireWait)
      && sithActor_thing_anim_blocked(pWeapon, pThing, pCollision) )
    {
        return 1;
    }
    if ( pWeapon->weaponParams.damage == 0.0 && !(pWeapon->weaponParams.flags & (SITH_WF_ATTACHTHING | SITH_WF_THINGHITEXPLODE)))
        return 0;

    if (sithCollision_ThingCollisionHandler(pWeapon, pThing, pCollision, a5))
    {
        if (pWeapon->weaponParams.damage != 0.0) {
            sithThing_DamageThing(pThing, pWeapon, pWeapon->weaponParams.damage, pWeapon->weaponParams.damageType);
        }
        if (pWeapon->weaponParams.flags & SITH_WF_THINGHITEXPLODE)
        {
            // Proximity mines did the Beep Beep Beep, time to explode
            if (pThing->weaponParams.flags & SITH_WF_EXPLODE)
            {
                sithWeapon_CreateWeaponExplosion(pWeapon, pWeapon->weaponParams.pExplosionTemplate);
                return 1;
            }

            // Gun splat spawning
            sithWeapon_CreateWeaponExplosion(pWeapon, pWeapon->weaponParams.fleshHitTemplate);
            return 1;
        }
        if (!(pWeapon->weaponParams.flags & SITH_WF_ATTACHTHING))
            return 1;
        sithPhysics_ResetThingMovement(pWeapon);
        sithThing_AttachThingToThing(pWeapon, pThing);

        pWeapon->attach_flags |= SITH_ATTACH_NOMOVE;
        pWeapon->physicsParams.flags |= SITH_PF_USEGRAVITY;
        return 1;
    }
    return 0;
}

// MoTS altered: floor hit explode
int sithWeapon_SurfaceCollisionHandler(SithThing *pThing, SithSurface *pSurf, SithCollision *pStack)
{
    int result; // eax
    rdMaterial *v4; // eax
    const char *v5; // eax
    int v6; // ecx
    int flags; // eax
    int v9; // eax
    char v10; // bl
    int v11; // eax

    SITH_ASSERTREL(pThing->type == SITH_THING_WEAPON); // Added: from OpenJones3D
    if ( pThing->moveType != SITH_MT_PHYSICS )
        return 0;
    if ( (g_debugmodeFlags & DEBUGFLAG_PRINT_HITS) != 0 )
    {
        v4 = pSurf->surfaceInfo.face.material;
        if ( v4 )
            v5 = v4->mat_fpath;
        else
            v5 = "none";
        _sprintf(std_g_genBuffer, "Weapon hit surface %d, sector %d, material '%s'.\n", pSurf->index, pSurf->pSector->id, v5);
        sithConsole_PrintString(std_g_genBuffer);
    }
    v6 = pSurf->flags;
    if (v6 & (SITH_SURFACE_CEILING_SKY|SITH_SURFACE_HORIZON_SKY)) {
        sithThing_DestroyThing(pThing);
        return 1;
    }
    flags = pThing->weaponParams.flags;
    if ( ((flags & SITH_WF_IMPACTSOUND) != 0 && (v6 & SITH_SURFACE_MAGSEALED) != 0 || (flags & SITH_WF_SURFACERICOCHET) != 0 && pThing->weaponParams.numRicochets < 2u)
      && (++pThing->weaponParams.numRicochets < MAX_DEFLECTION_BOUNCES) )
    {
        pThing->physicsParams.flags |= SITH_PF_SURFACEBOUNCE;
        sithCollision_HandleThingHitSurface(pThing, pSurf, pStack);
        if ( (pThing->physicsParams.flags & SITH_PF_SURFACEBOUNCE) == 0 )
        {
            pThing->physicsParams.flags &= ~SITH_PF_SURFACEBOUNCE;
        }
        rdVector_Normalize3(&pThing->orient.lvec, &pThing->physicsParams.vel);
        pThing->orient.rvec.x = (pThing->orient.lvec.y * 1.0) - (pThing->orient.lvec.z * 0.0);
        pThing->orient.rvec.y = (pThing->orient.lvec.z * 0.0) - (pThing->orient.lvec.x * 1.0);
        pThing->orient.rvec.z = (pThing->orient.lvec.x * 0.0) - (pThing->orient.lvec.y * 0.0);
        rdVector_Normalize3Acc(&pThing->orient.rvec);
        pThing->orient.uvec.x = (pThing->orient.rvec.y * pThing->orient.lvec.z) - (pThing->orient.rvec.z * pThing->orient.lvec.y);
        pThing->orient.uvec.y = (pThing->orient.rvec.z * pThing->orient.lvec.x) - (pThing->orient.lvec.z * pThing->orient.rvec.x);
        pThing->orient.uvec.z = (pThing->orient.lvec.y * pThing->orient.rvec.x) - (pThing->orient.rvec.y * pThing->orient.lvec.x);
        pThing->weaponParams.flags &= ~SITH_WF_NOSHOOTERDAMAGE;
        
        sithSoundClass_PlayModeRandom(pThing, SITH_SC_DEFLECTED);
        result = 1;
    }
    else
    {
        if ( pThing->weaponParams.damage != 0.0 )
            sithSurface_HandleThingImpact(pSurf, pThing, pThing->weaponParams.damage, pThing->weaponParams.damageType);

        // MOTS added: floor explode?
        if (pThing->weaponParams.flags & SITH_WF_FACEHITEXPLODE || MOTS_ONLY_FLAG(pThing->weaponParams.flags & SITH_WF_ACTORKILLDESTROY && pSurf->flags & SITH_SURFACE_FLOOR))
        {
            sithWeapon_CreateWeaponExplosion(pThing, pThing->weaponParams.pExplosionTemplate);
            return 1;
        }
        if ( (pThing->weaponParams.flags & SITH_WF_ATTACHFACE) == 0 )
        {
            result = sithCollision_HandleThingHitSurface(pThing, pSurf, pStack);
        }
        else
        {
            sithCollision_HandleThingHitSurface(pThing, pSurf, pStack);
            sithPhysics_ResetThingMovement(pThing);
            sithSoundClass_StopMode(pThing, SITH_SC_CREATE);
            pThing->moveSize = 0.0;
            sithThing_AttachThingToSurface(pThing, pSurf, 0);
            sithPhysics_SetThingLook(pThing, &pSurf->surfaceInfo.face.normal, 0.0);
            pThing->physicsParams.flags |= SITH_PF_NOTHRUST;
            result = 1;
        }
    }
    return result;
}

void sithWeapon_DestroyWeapon(SithThing *pWeapon)
{
    SITH_ASSERTREL(pWeapon && (pWeapon->type == SITH_THING_WEAPON)); // Added: from OpenJones3D
    // This gets called for thermal detonators and prox mines when they run out of lifetime
    if (pWeapon->weaponParams.flags & SITH_WF_EXPLODE)
    {
        sithWeapon_CreateWeaponExplosion(pWeapon, pWeapon->weaponParams.pExplosionTemplate);
    }
    else
    {
        sithThing_DestroyThing(pWeapon);
    }
}

void sithWeapon_CreateWeaponExplosion(SithThing *pWeapon, SithThing *pExplosionTemplate)
{
    if (pExplosionTemplate)
    {
        SithThing* player = sithThing_GetThingParent(pWeapon);
        SithThing* spawned = sithThing_CreateThingAtPos(pExplosionTemplate, &pWeapon->position, &rdroid_identMatrix34, pWeapon->sector, player);
        if (spawned)
        {
            // Added: second comparison, co-op
            if (player == sithPlayer_g_pLocalPlayerThing || player->type == SITH_THING_PLAYER) {
                sithAIAwareness_CreateTransmittingEvent(spawned->sector, &spawned->position, 0, 2.0, player);
            }
            if (pWeapon->flags & SITH_TF_INVULN)
            {
                spawned->flags |= SITH_TF_INVULN;
            }
        }
    }
    sithThing_DestroyThing(pWeapon);
}

void sithWeapon_StartupEntry()
{
    sithWeapon_8BD0A0[0] = -1.0;
    sithWeapon_a8BD030[0] = 0;
    sithWeapon_8BD0A0[1] = -1.0;
    sithWeapon_8BD060 = -1.0;
    sithWeapon_LastFireTimeSecs = -1.0;
    sithWeapon_fireWait = -1.0;
    sithWeapon_fireRate = -1.0;
    sithWeapon_a8BD030[1] = 0;
    sithWeapon_secMountWait = 0.0;
    sithWeapon_8BD05C = 0;
    sithWeapon_CurWeaponMode = -1;
    sithWeapon_8BD024 = -1;
}

void sithWeapon_ShutdownEntry()
{
    ;
}

// MOTS altered
int sithWeapon_SelectWeapon(SithThing *pThing, int typeId, int a3)
{
    int v4; // edi
    sithCog *v5; // edx
    int v7; // ebp
    int v9; // esi
    int v10; // edi
    int v11; // eax
    int v12; // eax
    SithInventoryType *v13; // ebp
    int v15; // esi
    int v18; // [esp-18h] [ebp-28h]
    int playera; // [esp+14h] [ebp+4h]

    //printf("%x\n", sithWeapon_8BD024);

    v4 = sithInventory_GetCurrentWeapon(pThing);
    if ( typeId == v4 || sithInventory_GetInventory(pThing, typeId) == 0.0 || !sithInventory_IsInventoryAvailable(pThing, typeId) || sithWeapon_8BD024 != -1 )
        return 0;
    v5 = sithInventory_GetType(typeId)->cog;
    if ( v5 )
    {
        v7 = 0;
        v9 = sithWeapon_bAutoSwitch & 2;
        v10 = sithWeapon_bMultiplayerAutoSwitch & 2;
        
        sithWeapon_bAutoSwitch &= ~2;
        
        sithWeapon_bMultiplayerAutoSwitch &= ~2u;
        if ( sithCog_SendMessageEx(v5, SITH_MESSAGE_AUTOSELECT, SENDERTYPE_SYSTEM, -1, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0) < 0.0 )
            v7 = 1;
        if ( v9 )
        {
            sithWeapon_bAutoSwitch |= 2;
        }
        if ( v10 )
        {
            sithWeapon_bMultiplayerAutoSwitch |= 2;
        }
        if (v7)
            return 0;
    }

    v13 = sithInventory_GetType(v4);
    if ( v13 && v13->cog ) // Added: v13 nullptr check
    {
        //printf("Send deselect %x\n", v4);
        sithCog_SendMessage(v13->cog, SITH_MESSAGE_DESELECTED, SENDERTYPE_SYSTEM, sithWeapon_8BD024, SENDERTYPE_THING, pThing->idx, 0);
        for (int i = 0; i < 2; i++)
        {
            if (sithWeapon_8BD0A0[i] != -1.0 ) {
                sithCog_SendMessage(v13->cog, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, i, SENDERTYPE_THING, pThing->idx, 0);
            }
        }
    }

    sithWeapon_8BD024 = typeId;
    sithWeapon_senderIndex = a3 != 0;

    // MoTS added
    if (Main_bMotsCompat) {
        sithWeapon_mots_5a3258 = sithInventory_SelectWeaponPrior(typeId);
    }

    return 1;
}

void sithWeapon_SetMountWait(SithThing *a1, flex32_t secWait)
{
    sithWeapon_secMountWait = secWait + sithTime_g_secGameTime;
}

void sithWeapon_SetFireWait(SithThing *pThing, flex32_t waitTime)
{
    if ( waitTime == -1.0 )
    {
        sithWeapon_fireWait = -1.0;
        sithWeapon_fireRate = -1.0;
    }
    else
    {
        sithWeapon_fireRate = waitTime;
        sithWeapon_fireWait = waitTime + sithTime_g_secGameTime;
    }
}

void sithWeapon_UpdateActorWeaponState(SithThing *pThing)
{
    SithInventoryType *v1; // eax
    int v3; // eax
    SithInventoryType *v4; // eax
    int v6; // eax
    SithInventoryType *v7; // eax
    int v9; // [esp-18h] [ebp-1Ch]

    //printf("%x %x %f %f %f\n", sithWeapon_8BD024, sithWeapon_8BD05C, sithWeapon_secMountWait, sithWeapon_fireWait, sithTime_g_secGameTime);

    if ( sithWeapon_8BD024 == -1 || sithTime_g_secGameTime < (flex_d_t)sithWeapon_secMountWait )
    {
        // aaaaaaaaaaa ????? wtf is going on here
        if ( sithWeapon_8BD05C == 1 && sithTime_g_secGameTime >= (flex_d_t)sithWeapon_secMountWait )
        {
            v3 = sithInventory_GetCurrentWeapon(pThing);
            v4 = sithInventory_GetType(v3);
            if ( v4 && (v4->flags & ITEMINFO_WEAPON) != 0 && sithWeapon_CurWeaponMode != -1 ) // Added: nullptr check
            {
                if ( v4->cog )
                    sithCog_SendMessage(v4->cog, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, sithWeapon_CurWeaponMode, SENDERTYPE_THING, pThing->idx, 0);
            }
            sithWeapon_8BD05C = 0;
        }
        else if ( sithWeapon_CurWeaponMode != -1 && sithWeapon_fireRate > 0.0 && sithTime_g_secGameTime >= (flex_d_t)sithWeapon_fireWait )
        {
            v6 = sithInventory_GetCurrentWeapon(pThing);
            v7 = sithInventory_GetType(v6);
            if ( v7 && (v7->flags & ITEMINFO_WEAPON) && v7->cog ) // Added: nullptr check
            {
                v9 = pThing->idx;
                sithWeapon_fireWait = sithWeapon_fireRate + sithTime_g_secGameTime;
                sithCog_SendMessageEx(v7->cog, SITH_MESSAGE_FIRE, SENDERTYPE_SYSTEM, sithWeapon_CurWeaponMode, SENDERTYPE_THING, v9, 0, 0.0, 0.0, 0.0, 0.0);
            }
        }
    }
    else
    {
        v1 = sithInventory_GetType(sithWeapon_8BD024);
        if ( v1 && (v1->flags & ITEMINFO_WEAPON) && v1->cog && sithWeapon_8BD024 != -1) // Added: nullptr check
        {
            sithWeapon_LastFireTimeSecs = -1.0;
            sithCog_SendMessage(v1->cog, SITH_MESSAGE_SELECTED, SENDERTYPE_SYSTEM, sithWeapon_senderIndex, SENDERTYPE_THING, pThing->idx, 0);
            sithWeapon_8BD05C = 1;
        }
        sithWeapon_8BD024 = -1;
    }
}

void sithWeapon_ActivateWeapon(SithThing *pThing, sithCog *pCog, flex_t waitTime, int mode)
{
    sithWeapon_fireRate = waitTime;
    sithWeapon_CurWeaponMode = mode;
    sithWeapon_8BD0A0[mode] = sithTime_g_secGameTime;

    if (sithWeapon_fireRate <= 0.0)
        sithWeapon_fireWait = -1.0;

    if ( sithWeapon_fireWait != -1.0 && sithTime_g_secGameTime >= (flex_d_t)sithWeapon_fireWait )
    {
        if ( mode != -1 )
            sithCog_SendMessageEx(pCog, SITH_MESSAGE_FIRE, 1, mode, 3, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0);
        sithWeapon_fireWait = sithWeapon_fireRate + sithTime_g_secGameTime;
    }
}

flex_t sithWeapon_DeactivateWeapon(SithThing *pThing, sithCog *cogCtx, int mode)
{
    int v3; // edx
    flex_t result; // st7

    // Added: bounds check
    if (mode < 0 || mode >= 2)
        return 0.0;

    v3 = 0;
    if (sithWeapon_8BD0A0[mode] == -1.0 )
        result = 0.0;
    else
        result = sithTime_g_secGameTime - sithWeapon_8BD0A0[mode];

    sithWeapon_8BD0A0[mode] = -1.0;
    if ( sithWeapon_fireRate > 0.0 )
        sithWeapon_secMountWait = sithWeapon_fireRate + sithTime_g_secGameTime;
    sithWeapon_LastFireTimeSecs = -1.0;
    sithWeapon_fireRate = 0.0;
    for (int i = 0; i < 2; i++)
    {
        if ( sithWeapon_a8BD030[i] == 1 )
            v3 = 1;
    }

    if ( !v3 )
        sithWeapon_CurWeaponMode = -1;
    return result;
}

int sithWeapon_AutoSelect(SithThing *player, int weapIdx)
{
    int v7; // [esp+10h] [ebp-4h]
    flex_t a1a; // [esp+18h] [ebp+4h]

    sithInventory_GetCurrentWeapon(player);
    v7 = -1;
    a1a = -1.0;
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryType* desc =  &sithInventory_g_aTypes[i];
        if (desc->flags & ITEMINFO_WEAPON)
        {
            if (desc->cog)
            {
                flex_t v5 = sithCog_SendMessageEx(desc->cog, SITH_MESSAGE_AUTOSELECT, SENDERTYPE_SYSTEM, weapIdx, SENDERTYPE_THING, player->idx, 0, 0.0, 0.0, 0.0, 0.0);
                if ( v5 > a1a )
                {
                    a1a = v5;
                    v7 = i;
                }
            }
        }
    }
    return v7;
}

// MOTS altered TODO?
int sithWeapon_ProcessWeaponControls(SithThing *pThing, flex_t secDeltaTime)
{
    flex_t *v3; // edi
    int v4; // eax
    sithCog *v5; // eax
    int inputFunc; // edi
    int v11; // edi
    SithInventoryType *v12; // eax
    signed int v14; // eax
    int v15; // edi
    SithInventoryType *v16; // eax
    SithInventoryType *v17; // eax
    int v18; // eax
    SithInventoryType *v19; // ebx
    int v20; // eax
    int v21; // ebp
    int v22; // edi
    sithCog *v23; // eax
    sithCog *v24; // eax
    int v25; // [esp+10h] [ebp-8h]
    int v26; // [esp+14h] [ebp-4h]
    int readInput;
    
    //return sithWeapon_HandleWeaponKeys_(player, a2);

    if ( pThing->type != SITH_THING_PLAYER || (pThing->flags & SITH_TF_DEAD) != 0 )
        return 0;

    if ( (pThing->weaponParams.flags & SITH_WF_EMITAITARGETEDEVENT) == 0 )
    {
        if ( sithTime_g_secGameTime < sithWeapon_secMountWait )
            return 0;

        inputFunc = INPUT_FUNC_SELECT1;
        while ( 1 )
        {
            sithControl_GetKey(inputFunc, &readInput);
            if ( readInput && sithThing_MotsTick(7,0,inputFunc))
            {
                if (!Main_bMotsCompat) {
                    if ( sithWeapon_SelectWeapon(pThing, sithInventory_SelectWeaponFollowing(inputFunc - INPUT_FUNC_ACTIVATE), 0) )
                        break;
                }
                else {
                    flex_t fVar7 = 0.0;
                    int iVar2 = sithInventory_GetCurrentWeapon(pThing);
                    int iVar5 = inputFunc + -0xc;
                    if ((iVar5 % 10 != sithWeapon_mots_5a3258 % 10) && ((iVar5 < 0xb && (sithWeapon_motsAConv[iVar5 % 10] != iVar5)))) {
                        iVar5 = sithWeapon_motsAConv[iVar5 % 10];
                    }
                    int iVar4 = sithInventory_SelectWeaponFollowing(iVar5);
                    if (iVar4 == iVar2) {
                        if (iVar5 < 0xb) {
                            iVar5 = iVar5 + 10;
                        }
                    }
                    else if ((iVar5 < 0xb) && ((fVar7 = sithInventory_GetInventory(pThing,iVar4), fVar7 == 0.0 || (iVar2 = sithInventory_IsInventoryAvailable(pThing,iVar4), iVar2 == 0))))
                    {
                        iVar5 = iVar5 + 10;
                    }

                    iVar2 = sithInventory_SelectWeaponFollowing(iVar5);
                    sithWeapon_motsAConv[iVar5 % 10] = iVar5;
                    iVar2 = sithWeapon_SelectWeapon(pThing,iVar2,0);
                    if (iVar2 == 0) {
                        if (iVar5 < 0xb) {
                            iVar5 = iVar5 + 10;
                        }
                        else {
                            iVar5 = iVar5 + -10;
                        }
                        iVar2 = sithInventory_SelectWeaponFollowing(iVar5);
                        sithWeapon_motsAConv[iVar5 % 10] = iVar5;
                        iVar5 = sithWeapon_SelectWeapon(pThing,iVar2,0);
                        if (iVar5 != 0) {
                            return 0;
                        }
                    }
                }
            }

            if ( ++inputFunc <= INPUT_FUNC_SELECT0 )
                continue;

            sithControl_GetKey(INPUT_FUNC_NEXTWEAPON, &readInput);
            while (readInput--)
            {
                if (sithThing_MotsTick(7,1,1.0)) {
                    sithWeapon_SelectNextWeapon(pThing);
                }
            }

            sithControl_GetKey(INPUT_FUNC_PREVWEAPON, &readInput);
            while (readInput--)
            {
                if (sithThing_MotsTick(7,1,-1.0)) {
                    sithWeapon_SelectPreviousWeapon(pThing);
                }
            }

            if ( sithWeapon_8BD024 != -1 )
                return 0;

            v18 = sithInventory_GetCurrentWeapon(pThing);
            v19 = sithInventory_GetType(v18);
            v20 = INPUT_FUNC_FIRE2;
            v26 = INPUT_FUNC_FIRE2;
            v25 = 1;
            v21 = 0;
            while ( 1 )
            {
                v22 = v20 - 10;
                if ( sithControl_GetKey(v20, &readInput) )
                {
                    if (sithThing_MotsTick(3, 0, (flex_t)v22) && !sithWeapon_a8BD030[v25]) // MOTS added // FLEXTODO
                    {
                        sithWeapon_a8BD030[v25] = 1;
                        v23 = v19->cog;
                        if ( v23 )
                        {
                            if (sithWeapon_a8BD030[v21]) {
                                sithCog_SendMessage(v23, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, 1 - v22, SENDERTYPE_THING, pThing->idx, 0);
                            }
                            sithCog_SendMessage(v19->cog, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, v22, SENDERTYPE_THING, pThing->idx, 0);
                        }
                    }
                }
                else if ( sithWeapon_a8BD030[v25] == 1 )
                {
                    sithWeapon_a8BD030[v25] = 0;
                    v24 = v19->cog;
                    if ( v24 )
                    {
                        sithCog_SendMessage(v24, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, v22, SENDERTYPE_THING, pThing->idx, 0);
                        if (sithWeapon_a8BD030[v21])
                            sithCog_SendMessage(v19->cog, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, 1 - v22, SENDERTYPE_THING, pThing->idx, 0);
                    }
                }
                ++v21;
                --v26;
                --v25;
                if ( v21 > 1 )
                    break;
                v20 = v26;
            }
            return 0;
        }
        return 0;
    }

    for (int v2 = 0; v2 < 2; v2++)
    {
        if (sithWeapon_a8BD030[v2] == 1 )
        {
            sithWeapon_a8BD030[v2] = 0;
            v4 = sithInventory_GetCurrentWeapon(pThing);
            v5 = sithInventory_GetType(v4)->cog;
            if ( v5 ) {
                sithCog_SendMessage(v5, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, v2, SENDERTYPE_THING, pThing->idx, 0);
            }
        }
    }
    return 0;
}

// MOTS altered ??
void sithWeapon_GetAimOrient(rdMatrix34 *pOutOrient, SithThing *pShooter, rdMatrix34 *pStartOrient, rdVector3 *pFireOffset, flex_t autoAimFovX, flex_t autoAimFovZ)
{
    unsigned int v9; // ebp
    unsigned int v10; // ebx
    SithThing **v11; // edi
    SithThing *v12; // eax
    SithThing *v13; // eax
    flex_d_t v15; // st7
    rdVector3 v16; // [esp+0h] [ebp-58h] BYREF
    rdVector3 v17; // [esp+Ch] [ebp-4Ch] BYREF
    SithThing *thingList[16]; // [esp+18h] [ebp-40h] BYREF
    flex_t a3a; // [esp+6Ch] [ebp+14h]
    int a4a; // [esp+70h] [ebp+18h]

    SITH_ASSERTREL(pShooter); // Added: from OpenJones3D
    if ( autoAimFovX == 0.0 && autoAimFovZ == 0.0 )
        return;
    if ( jkPlayer_setDiff == 2 )
    {
        autoAimFovX = autoAimFovX * g_flt_8BD054;
        autoAimFovZ = autoAimFovZ * g_flt_8BD054;
    }
    else if ( !jkPlayer_setDiff )
    {
        autoAimFovX = autoAimFovX * g_flt_8BD050;
        autoAimFovZ = autoAimFovZ * g_flt_8BD050;
    }

    if ( sithCamera_g_pCurCamera - sithCamera_g_aCameras == 1 )
    {
        autoAimFovX = autoAimFovX * g_flt_8BD058;
        autoAimFovZ = autoAimFovZ * g_flt_8BD058;
    }
    _memcpy(pOutOrient, pStartOrient, sizeof(rdMatrix34));
    rdVector_Copy3(&pOutOrient->scale, pFireOffset);
    v9 = sithAI_FirstThingInView(pShooter->sector, pOutOrient, autoAimFovX, autoAimFovZ, 16, thingList, 1028, g_flt_8BD044);
    if ( v9 )
    {
        v10 = 0;
        a4a = -1;
        a3a = -1.0;
        v11 = thingList;
        do
        {
            v12 = *v11;
            if ( *v11 != pShooter && (v12->actorParams.flags & SITH_AF_NOTARGET) == 0 )
            {
                if ( sithCollision_HasLOS(pShooter, v12, 0) )
                {
                    v13 = *v11;
                    rdVector_Sub3(&v16, &v13->position, &pShooter->position);
                    if (rdVector_Len3(&v16) > g_flt_8BD040)
                    {
                        v17 = pOutOrient->lvec;
                        rdVector_Normalize3Acc(&v16);
                        rdVector_Normalize3Acc(&v17);
                        v15 = rdVector_Dot3(&v16, &v17);
                        if ( v15 < 0.0 )
                            v15 = -v15;
                        if ( a4a < 0 || v15 > a3a )
                        {
                            a3a = v15;
                            a4a = v10;
                        }
                    }
                }
            }
            ++v10;
            ++v11;
        }
        while ( v10 < v9 );
        if ( a4a >= 0 ) {
            rdMatrix_LookAt(pOutOrient, pFireOffset, &thingList[a4a]->position, 0.0);
            //jkHud_SetTarget(thingList[a4a]);
        }
    }
}

// MOTS altered ??
SithThing* sithWeapon_FireProjectile(SithThing *pShooter, SithThing *pProjectile, sithSound *hFireSnd, int submode, rdVector3 *pFireOffset, rdVector3 *pAimError, flex_t scale, int16_t flags, flex_t autoAimFovX, flex_t autoAimFovZ, int extra)
{
    int thingType; // eax
    flex_t finalTimeOffset; // esi
    SithThing *pResult; // eax
    rdVector3 fireDir; // [esp+10h] [ebp-6Ch] BYREF
    rdMatrix34 fireOrient; // [esp+1Ch] [ebp-60h] BYREF
    rdMatrix34 senderOrient; // [esp+4Ch] [ebp-30h] BYREF
    flex_t catchupFactor; // [esp+80h] [ebp+4h]
    flex_t catchupTimeOffset; // [esp+90h] [ebp+14h]

    SITH_ASSERTREL(pShooter); // Added: from OpenJones3D
    thingType = pShooter->type;
    _memcpy(&senderOrient, &pShooter->orient, sizeof(senderOrient));
    if ( thingType == SITH_THING_ACTOR || thingType == SITH_THING_PLAYER )
        rdMatrix_PreRotate34(&senderOrient, &pShooter->actorParams.headPYR);
    if ( pFireOffset->x == 0.0 && pFireOffset->y == 0.0 && pFireOffset->z == 0.0 )
    {
        *pFireOffset = pShooter->position;
    }
    else
    {
        rdMatrix_TransformVector34Acc(pFireOffset, &senderOrient);
        rdVector_Add3Acc(pFireOffset, &pShooter->position);
    }

    if ( (sithWeapon_bAutoAim & 1) != 0 && (flags & 0x20) != 0 && (!sithNet_isMulti || (flags & 0x40) != 0) )
        sithWeapon_GetAimOrient(&fireOrient, pShooter, &senderOrient, pFireOffset, autoAimFovX, autoAimFovZ);
    else
        _memcpy(&fireOrient, &senderOrient, sizeof(fireOrient));
    if ( pAimError->x != 0.0 || pAimError->y != 0.0 || pAimError->z != 0.0 )
        rdMatrix_PreRotate34(&fireOrient, pAimError);
    fireDir = fireOrient.lvec;
    if ( (flags & 0x10) == 0 )
    {
        sithWeapon_LastFireTimeSecs = -1.0;
        finalTimeOffset = 0.0;
    }
    else
    {
        catchupFactor = 1.0;
        if ( sithWeapon_LastFireTimeSecs != -1.0 && sithWeapon_fireRate > 0.0 )
            catchupFactor = (sithTime_g_secGameTime - sithWeapon_LastFireTimeSecs) / sithWeapon_fireRate - 1.0;
        sithWeapon_LastFireTimeSecs = sithTime_g_secGameTime;
        if ( catchupFactor > 1.0 )
        {
            do
            {
                catchupFactor -= 1.0;
                catchupTimeOffset = catchupFactor * sithWeapon_fireRate;
                finalTimeOffset = catchupTimeOffset;
                SithThing *pFired = sithWeapon_WeaponFireProjectile(pShooter, pProjectile, &fireDir, pFireOffset, 0, submode, scale, flags, catchupTimeOffset, extra);
                if ( pFired && sithMessage_g_outputstream )
                    sithDSSThing_Fire(pShooter, pProjectile, &fireDir, pFireOffset, 0, submode, scale, flags, catchupTimeOffset, pFired->guid, -1, 255, extra);
            }
            while ( catchupFactor > 1.0 );
        }
        else
        {
            finalTimeOffset = 0.0;
        }
    }
    if ( hFireSnd )
        sithAIAwareness_CreateTransmittingEvent(pShooter->sector, &pShooter->position, 1, 4.0, pShooter);
    pResult = sithWeapon_WeaponFireProjectile(pShooter, pProjectile, &fireDir, pFireOffset, hFireSnd, submode, scale, flags, finalTimeOffset, extra);
    if ( pResult && sithMessage_g_outputstream )
    {
        sithDSSThing_Fire(
            pShooter,
            pProjectile,
            &fireDir,
            pFireOffset,
            hFireSnd,
            submode,
            scale,
            flags,
            finalTimeOffset,
            pResult->guid,
            -1,
            255,
            extra);
    }
    return pResult;
}

flex_t sithWeapon_GetPriority(SithThing *player, int binIdx, int mode)
{
    flex_d_t result; // st7
    sithCog *cog; // eax

    result = -1.0;
    if ( (sithInventory_g_aTypes[binIdx].flags & ITEMINFO_WEAPON) != 0 )
    {
        cog = sithInventory_g_aTypes[binIdx].cog;
        if ( cog )
            result = sithCog_SendMessageEx(cog, SITH_MESSAGE_AUTOSELECT, SENDERTYPE_SYSTEM, mode, SENDERTYPE_THING, player->idx, 0, 0.0, 0.0, 0.0, 0.0);
    }
    return result;
}

int sithWeapon_GetCurWeaponMode()
{
    return sithWeapon_CurWeaponMode;
}

void sithWeapon_SyncPuppet(SithThing *player)
{
    int weapon; // eax
    SithInventoryType *itemDesc; // eax
    sithCog *cog; // eax

    weapon = sithInventory_GetCurrentWeapon(player);
    itemDesc = sithInventory_GetType(weapon);
    if ( (itemDesc->flags & ITEMINFO_WEAPON) != 0 )
    {
        cog = itemDesc->cog;
        if ( cog )
        {
            if ( sithWeapon_CurWeaponMode != -1 ) {
                sithCog_SendMessage(cog, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, sithWeapon_CurWeaponMode, SENDERTYPE_THING, player->idx, 0);
            }
        }
    }
}

int sithWeapon_WriteConf()
{
    return stdConffile_Printf("autoPickup %d\n", sithWeapon_bAutoPickup)
        && stdConffile_Printf("autoSwitch %d\n", sithWeapon_bAutoSwitch)
        && stdConffile_Printf("autoReload %d\n", sithWeapon_bAutoReload)
        && stdConffile_Printf("multiAutoPickup %d\n", sithWeapon_bMultiAutoPickup)
        && stdConffile_Printf("multiAutoSwitch %d\n", sithWeapon_bMultiplayerAutoSwitch)
        && stdConffile_Printf("multiAutoReload %d\n", sithWeapon_bMultiAutoReload)
        && stdConffile_Printf("autoAim %d\n", sithWeapon_bAutoAim);
}

int sithWeapon_ReadConf()
{
    return stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "autopickup")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bAutoPickup) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "autoswitch")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bAutoSwitch) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "autoreload")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bAutoReload) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "multiautopickup")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bMultiAutoPickup) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "multiautoswitch")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bMultiplayerAutoSwitch) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "multiautoreload")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bMultiAutoReload) == 1
        && stdConffile_ReadArgs()
        && stdConffile_g_entry.numArgs
        && !_strcmp(stdConffile_g_entry.aArgs[0].key, "autoaim")
        && _sscanf(stdConffile_g_entry.aArgs[1].value, "%d", &sithWeapon_bAutoAim) == 1;
}

// TODO these functions are interesting
void sithWeapon_SelectNextWeapon(SithThing* pThing)
{
    SITH_ASSERTREL(pThing); // Added: from OpenJones3D
    if (Main_bMotsCompat) {
        int iVar1;
        int binIdx;
        int iVar2;
        SithInventoryType *psVar3;
        flex_t fVar4;
        
        iVar1 = sithInventory_GetCurrentWeapon(pThing);
        iVar1 = sithInventory_SelectWeaponPrior(iVar1);
        do {
            do {
                do {
                    if (iVar1 == 0x14) {
                        iVar1 = 1;
                    }
                    else if (iVar1 < 0xb) {
                        iVar1 = iVar1 + 10;
                    }
                    else {
                        iVar1 = iVar1 + -9;
                    }
                    binIdx = sithInventory_SelectWeaponFollowing(iVar1);
                    if (binIdx == -1) {
                        iVar1 = 0;
                        binIdx = sithInventory_SelectWeaponFollowing(0);
                    }
                    fVar4 = sithInventory_GetInventory(pThing,binIdx);
                } while (fVar4 == 0.0);
                iVar2 = sithInventory_IsInventoryAvailable(pThing,binIdx);
            } while (iVar2 == 0);
            psVar3 = sithInventory_GetInventoryType(pThing,binIdx);
            fVar4 = sithCog_SendMessageEx(psVar3->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0);
        } while (fVar4 == -1.0);
        sithWeapon_SelectWeapon(pThing,binIdx,0);
    }
    else {
        SithInventoryType *v12; // eax
        SithInventoryType *v13; // eax
        int binIdx = sithInventory_GetCurrentWeapon(pThing);

        int v11 = sithInventory_FindNextTypeID(pThing, binIdx, ITEMINFO_WEAPON);
        if ( v11 == -1 )
            v11 = sithInventory_FindNextTypeID(pThing, 0, ITEMINFO_WEAPON);
        v12 = sithInventory_GetInventoryType(pThing, v11);
        if ( sithCog_SendMessageEx(v12->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0) == -1.0 )
        {
            do
            {
                v11 = sithInventory_FindNextTypeID(pThing, v11, ITEMINFO_WEAPON);
                if ( v11 == -1 )
                    v11 = sithInventory_FindNextTypeID(pThing, 0, ITEMINFO_WEAPON);
                v13 = sithInventory_GetInventoryType(pThing, v11);
            }
            while ( sithCog_SendMessageEx(v13->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0) == -1.0 );
        }
        sithWeapon_SelectWeapon(pThing, v11, 0);
    }
}

void sithWeapon_SelectPreviousWeapon(SithThing* pThing)
{
    SITH_ASSERTREL(pThing); // Added: from OpenJones3D
    if (Main_bMotsCompat) {
        int iVar1;
        int binIdx;
        int iVar2;
        SithInventoryType *psVar3;
        flex_t fVar4;
        
        iVar1 = sithInventory_GetCurrentWeapon(pThing);
        iVar1 = sithInventory_SelectWeaponPrior(iVar1);
        do {
            do {
                do {
                    if (iVar1 == 1) {
                        iVar1 = 0x14;
                    }
                    else if (iVar1 < 0xb) {
                        iVar1 = iVar1 + 9;
                    }
                    else {
                        iVar1 = iVar1 + -10;
                    }
                    binIdx = sithInventory_SelectWeaponFollowing(iVar1);
                    fVar4 = sithInventory_GetInventory(pThing,binIdx);
                } while (fVar4 == 0.0);
                iVar2 = sithInventory_IsInventoryAvailable(pThing,binIdx);
            } while (iVar2 == 0);
            psVar3 = sithInventory_GetInventoryType(pThing,binIdx);
            fVar4 = sithCog_SendMessageEx(psVar3->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0);
        } while (fVar4 == -1.0);
        sithWeapon_SelectWeapon(pThing,binIdx,0);
    }
    else {
        SithInventoryType *v16; // eax
        SithInventoryType *v17; // eax

        int v14 = sithInventory_GetCurrentWeapon(pThing);
                    
        int v15 = sithInventory_FindPreviousTypeID(pThing, v14, ITEMINFO_WEAPON);
        if ( v15 == -1 )
            v15 = sithInventory_FindPreviousTypeID(pThing, 0, ITEMINFO_WEAPON);
        
        v16 = sithInventory_GetInventoryType(pThing, v15);
        if ( sithCog_SendMessageEx(v16->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0) == -1.0 )
        {
            do
            {
                v15 = sithInventory_FindPreviousTypeID(pThing, v15, ITEMINFO_WEAPON);
                if ( v15 == -1 )
                    v15 = sithInventory_FindPreviousTypeID(pThing, 0, ITEMINFO_WEAPON);
                v17 = sithInventory_GetInventoryType(pThing, v15);
            }
            while ( sithCog_SendMessageEx(v17->cog, SITH_MESSAGE_AUTOSELECT, 0, 0, SENDERTYPE_THING, pThing->idx, 0, 0.0, 0.0, 0.0, 0.0) == -1.0 );
        }
        sithWeapon_SelectWeapon(pThing, v15, 0);
    }
}

void sithWeapon_SetFireRate(SithThing *weapon, flex32_t fireRate)
{
    sithWeapon_fireRate = fireRate;
}
