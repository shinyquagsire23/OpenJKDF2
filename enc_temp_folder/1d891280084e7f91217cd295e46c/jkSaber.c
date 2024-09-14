#include "jkSaber.h"

#include "World/jkPlayer.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithAnimClass.h"
#include "World/sithSoundClass.h"
#include "Gameplay/sithTime.h"
#include "World/sithSurface.h"
#include "Engine/sithPuppet.h"
#include "Dss/sithMulti.h"
#include "World/sithTemplate.h"
#include "World/sithModel.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "Main/jkSmack.h"
#include "General/stdString.h"
#include "General/stdMath.h"

#include "jk.h"

#ifdef LIGHTSABER_TRAILS
int jkSaber_trails = 1;
float jkSaber_trailMinVel = 3.0f;
float jkSaber_trailMaxVel = 10.0f;
float jkSaber_trailCutoff = 0.01f;
float jkSaber_trailShutter = 50.0f;
#endif

#ifdef LIGHTSABER_MARKS
extern sithThing* jkSaber_paDecalThings[256];
extern int jkSaber_numDecalThings;
#endif

#define JKSABER_EXTENDTIME (0.3000000)

void jkSaber_InitializeSaberInfo(sithThing *thing, char *material_side_fname, char *material_tip_fname, float base_rad, float tip_rad, float len, sithThing *wall_sparks, sithThing *blood_sparks, sithThing *saber_sparks)
{
    if (!thing) return; // Added: Fix nullptr deref in Mots cutscenes

    float length = 0.0;
    jkPlayerInfo* saberinfo = thing->playerInfo;
    if ( saberinfo->polylineThing.polyline )
    {
        length = saberinfo->polyline.length;
        rdThing_FreeEntry(&saberinfo->polylineThing);
        rdPolyLine_FreeEntry(&saberinfo->polyline);
        saberinfo->polylineThing.polyline = 0;
    }

#ifdef DEBUG_QOL_CHEATS
    if (thing == sithPlayer_pLocalPlayerThing && !sithNet_isMulti) {
        //material_tip_fname = "saberpurple0.mat";
        //material_side_fname = "saberpurple1.mat";
    }
    if (thing == sithPlayer_pLocalPlayerThing) {
        //thing->jkFlags |= JKFLAG_DUALSABERS;
    }
#endif

    rdPolyLine_FreeEntry(&saberinfo->polyline); // Added: fix memleak
    rdPolyLine_NewEntry(&saberinfo->polyline, "Saber", material_side_fname, material_tip_fname, length, base_rad, tip_rad, 4, 0, 0, 0.0);
    rdThing_NewEntry(&saberinfo->polylineThing, thing);
    rdThing_SetPolyline(&saberinfo->polylineThing, &saberinfo->polyline);
#ifdef LIGHTSABER_GLOW
	saberinfo->polyline.tipFace.type |= RD_FF_SCREEN;
	saberinfo->polyline.edgeFace.type |= RD_FF_SCREEN;
#endif
    saberinfo->wall_sparks = wall_sparks;
    saberinfo->blood_sparks = blood_sparks;
    saberinfo->saber_sparks = saber_sparks;
    saberinfo->length = len;

#ifdef LIGHTSABER_GLOW
	rdThing_FreeEntry(&saberinfo->glowSpriteThing);
	rdSprite_FreeEntry(&saberinfo->glowSprite);

	rdSprite_NewEntry(&saberinfo->glowSprite, "SaberGlow", 2, "saberglow.mat", base_rad * 2.0f * 1.5f, base_rad * 2.0f * 1.5f, 4, 0, 0, 0.0, &rdroid_zeroVector3);
	rdThing_NewEntry(&saberinfo->glowSpriteThing, thing);
	rdThing_SetSprite3(&saberinfo->glowSpriteThing, &saberinfo->glowSprite);
#ifdef VERTEX_COLORS
	//saberinfo->glowSpriteThing.color.x = saberinfo->glowSpriteThing.color.y = saberinfo->glowSpriteThing.color.z = 0.3f;
	rdMaterial_GetFillColor(&saberinfo->glowSpriteThing.color, saberinfo->polyline.edgeFace.material, 0);
	//// give the color some kick
	//saberinfo->glowSpriteThing.color.x *= saberinfo->glowSpriteThing.color.x;
	//saberinfo->glowSpriteThing.color.y *= saberinfo->glowSpriteThing.color.y;
	//saberinfo->glowSpriteThing.color.z *= saberinfo->glowSpriteThing.color.z;
#endif
	saberinfo->glowSprite.face.type = RD_FF_ADDITIVE | RD_FF_VERTEX_COLORS;
#endif
}

void jkSaber_PolylineRand(rdThing *thing)
{
    rdPolyLine* line = thing->polyline;
    if ( line )
    {
        if ( !(bShowInvisibleThings & 0xF) )
            line->edgeFace.clipIdk.y = 0.0;
        line->edgeFace.clipIdk.y += (_frand() - 0.8) * 80.0;
    }
}

#ifdef LIGHTSABER_TRAILS
void jkSaber_DrawTrail(rdThing* pThing, jkSaberTrail* pSaberTrail, rdMatrix34* pMatrix)
{
	if(!jkSaber_trails)
		return;

	// clamp the time just in case
	if (pSaberTrail->lastTimeMs > sithTime_curMs)
		pSaberTrail->lastTimeMs = sithTime_curMs;

	rdMatrix34 mat;
	rdMatrix_Multiply34(&mat, &rdCamera_pCurCamera->view_matrix, pMatrix);

	rdVector3 basePos;
	rdMatrix_TransformPoint34(&basePos, &rdroid_zeroVector3, &mat);

	rdVector3 vertex;
	rdVector_Set3(&vertex, 0.0f, pThing->polyline->length, 0.0f);

	rdVector3 tipPos;
	rdMatrix_TransformPoint34(&tipPos, &vertex, &mat);

	int32_t diff = sithTime_curMs - pSaberTrail->lastTimeMs;
	float dt = diff * 0.001f;

	rdVector3 vel;
	rdVector_Sub3(&vel, &tipPos, &pSaberTrail->lastTip);
	rdVector_InvScale3Acc(&vel, dt);

	float len = rdVector_Normalize3Acc(&vel);
	if (len > jkSaber_trailCutoff) // don't bother if it's rly low
	{
		len = stdMath_Clamp(len - jkSaber_trailMinVel, 0.0f, jkSaber_trailMaxVel);
		len *= (1.0f / jkSaber_trailShutter); // scale to desired shutter speed
		rdVector_Scale3Acc(&vel, len);

		//printf("saber trail: len %f, diff %d, diff seconds %f\n", len, diff, (diff * 0.001));

		rdVector3 oldTipPos;
		rdVector_Sub3(&oldTipPos, &tipPos, &vel);

		rdVector3 verts[4];
		rdVector2 uvs[4];

		rdVertexIdxInfo idxInfo;
		idxInfo.numVertices = 4;
		idxInfo.vertices = verts;
		idxInfo.paDynamicLight = 0;
		idxInfo.intensities = 0;

		// Old tip
		{
			float tip_left, tip_bottom, tip_right, tip_top;
			tip_left = oldTipPos.x - pThing->polyline->tipRadius;
			tip_bottom = oldTipPos.z - pThing->polyline->tipRadius;
			tip_right = oldTipPos.x + pThing->polyline->tipRadius;
			tip_top = oldTipPos.z + pThing->polyline->tipRadius;

			// Tip
			{
				verts[0].x = tip_left;
				verts[0].y = oldTipPos.y - -0.001;
				verts[0].z = tip_bottom;
				verts[1].x = tip_right;
				verts[1].y = oldTipPos.y - -0.001;
				verts[1].z = tip_bottom;
				verts[2].x = tip_right;
				verts[2].y = oldTipPos.y - -0.001;
				verts[2].z = tip_top;
				verts[3].x = tip_left;
				verts[3].y = oldTipPos.y - -0.001;
				verts[3].z = tip_top;
				idxInfo.vertices = verts;
				idxInfo.vertexUVs = pThing->polyline->extraUVFaceMaybe;
				pThing->polyline->tipFace.sortId = 0;
				rdPolyLine_DrawFace(pThing, &pThing->polyline->tipFace, verts, &idxInfo);
			}
		}

		// Tip to old tip
		{
			rdVector3 right;
			rdVector_Cross3(&right, &oldTipPos, &tipPos);
			rdVector_Normalize3Acc(&right);

			verts[0].x = tipPos.x + right.x * pThing->polyline->tipRadius;
			verts[0].y = tipPos.y + right.y * pThing->polyline->tipRadius;
			verts[0].z = tipPos.z + right.z * pThing->polyline->tipRadius;

			verts[1].x = tipPos.x + right.x * -pThing->polyline->tipRadius;
			verts[1].y = tipPos.y + right.y * -pThing->polyline->tipRadius;
			verts[1].z = tipPos.z + right.z * -pThing->polyline->tipRadius;

			verts[2].x = oldTipPos.x + right.x * -pThing->polyline->tipRadius;
			verts[2].y = oldTipPos.y + right.y * -pThing->polyline->tipRadius;
			verts[2].z = oldTipPos.z + right.z * -pThing->polyline->tipRadius;

			verts[3].x = oldTipPos.x + right.x * pThing->polyline->tipRadius;
			verts[3].y = oldTipPos.y + right.y * pThing->polyline->tipRadius;
			verts[3].z = oldTipPos.z + right.z * pThing->polyline->tipRadius;
			
			pThing->polyline->edgeFace.sortId = 1;
			idxInfo.vertexUVs = pThing->polyline->extraUVTipMaybe;
			rdPolyLine_DrawFace(pThing, &pThing->polyline->edgeFace, verts, &idxInfo);
		}

		// Old tip to base
		{
			rdVector3 right;
			rdVector_Cross3(&right, &basePos, &oldTipPos);
			rdVector_Normalize3Acc(&right);

			verts[0].x = oldTipPos.x + right.x * pThing->polyline->tipRadius;
			verts[0].y = oldTipPos.y + right.y * pThing->polyline->tipRadius;
			verts[0].z = oldTipPos.z + right.z * pThing->polyline->tipRadius;

			verts[1].x = oldTipPos.x + right.x * -pThing->polyline->tipRadius;
			verts[1].y = oldTipPos.y + right.y * -pThing->polyline->tipRadius;
			verts[1].z = oldTipPos.z + right.z * -pThing->polyline->tipRadius;

			verts[2].x = basePos.x + right.x * -pThing->polyline->baseRadius;
			verts[2].y = basePos.y + right.y * -pThing->polyline->baseRadius;
			verts[2].z = basePos.z + right.z * -pThing->polyline->baseRadius;

			verts[3].x = basePos.x + right.x * pThing->polyline->baseRadius;
			verts[3].y = basePos.y + right.y * pThing->polyline->baseRadius;
			verts[3].z = basePos.z + right.z * pThing->polyline->baseRadius;

			pThing->polyline->edgeFace.sortId = 3;
			idxInfo.vertexUVs = pThing->polyline->extraUVTipMaybe;
			rdPolyLine_DrawFace(pThing, &pThing->polyline->edgeFace, verts, &idxInfo);
		}

		// Core
		{
			rdVector3 right;
			rdVector_Cross3(&right, &basePos, &tipPos);
			rdVector_Normalize3Acc(&right);

			rdVector_Copy3(&verts[0], &tipPos);
			rdVector_Copy3(&verts[1], &oldTipPos);

			rdVector_Copy3(&verts[2], &basePos);
			rdVector_MultAcc3(&verts[2], &right, -pThing->polyline->baseRadius * 0.5);
			
			rdVector_Copy3(&verts[3], &basePos);
			rdVector_MultAcc3(&verts[3], &right, pThing->polyline->baseRadius * 0.5f);

			// use the very center (average) UV to get the center color
			rdVector2 centerUV;
			rdVector_Zero2(&centerUV);
			for (int j = 0; j < 4; ++j)
			{
				rdVector_Add2Acc(&centerUV, &pThing->polyline->extraUVTipMaybe[j]);
			}
			rdVector_Scale2Acc(&centerUV, 0.25f);

			rdVector_Copy2(&uvs[0], &centerUV);
			rdVector_Copy2(&uvs[1], &centerUV);
			rdVector_Copy2(&uvs[2], &centerUV);
			rdVector_Copy2(&uvs[3], &centerUV);

			// the two sided rendering is borked so flip the winding order if needed
			rdVector3 edges[2];
			rdVector_Sub3(&edges[0], &verts[1], &verts[0]);
			rdVector_Sub3(&edges[1], &verts[2], &verts[1]);

			rdVector3 n;
			rdVector_Cross3(&n, &edges[0], &edges[1]);
			if (rdVector_Dot3(&n, &verts[0]) > 0.0f)
			{
				rdVector3 tmp;
				tmp = verts[1];
				verts[1] = verts[0];
				verts[0] = tmp;
			}

			pThing->polyline->edgeFace.sortId = 5;

			idxInfo.vertexUVs = uvs;
			rdPolyLine_DrawFace(pThing, &pThing->polyline->edgeFace, NULL, &idxInfo);
		}
	}
		
	rdVector_Copy3(&pSaberTrail->lastTip, &tipPos);
	pSaberTrail->lastTimeMs = sithTime_curMs;
}
#endif


#ifdef LIGHTSABER_GLOW
// todo: input for different hands
void jkSaber_DrawGlow()
{
	// glow test
	rdVector3 basePos;
	rdMatrix_TransformPoint34(&basePos, &rdroid_zeroVector3, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[5]);

	rdVector3 vertex;
	rdVector_Set3(&vertex, 0.0f, playerThings[playerThingIdx].polyline.length, 0.0f);

	rdVector3 tipPos;
	rdMatrix_TransformPoint34(&tipPos, &vertex, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[5]);

	float randOffset = playerThings[playerThingIdx].polyline.edgeFace.clipIdk.y / 80.0f;

	float rad = playerThings[playerThingIdx].glowSprite.width * 0.5f;
	for (float i = playerThings[playerThingIdx].polyline.length; i > 0; i -= rad)
	{
		float dist = (i / playerThings[playerThingIdx].polyline.length) + randOffset;
		dist -= stdMath_Floor(dist);

		rdVector3 pos;
		rdVector_Lerp3(&pos, &basePos, &tipPos, dist);

		rdMatrix34 mat;
		rdMatrix_BuildTranslate34(&mat, &pos);
		playerThings[playerThingIdx].glowSprite.face.sortId = 0;
		rdSprite_Draw(&playerThings[playerThingIdx].glowSpriteThing, &mat);

		rad *= 0.99;
	}
}
#endif

void jkSaber_Draw(rdMatrix34 *posRotMat)
{
    if ( playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_SABERON
      && playerThings[playerThingIdx].povModel.model3
      && playerThings[playerThingIdx].polylineThing.model3 )
    {
        if ( playerThings[playerThingIdx].povModel.frameTrue != rdroid_frameTrue )
        {
            rdPuppet_BuildJointMatrices(&playerThings[playerThingIdx].povModel, posRotMat);
        }
        jkSaber_PolylineRand(&playerThings[playerThingIdx].polylineThing);
#ifdef LIGHTSABER_GLOW
		jkSaber_DrawGlow();
#endif
        rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[5]); // aaaaa hardcoded K_Rhand
#ifdef LIGHTSABER_TRAILS
		jkSaber_DrawTrail(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].saberTrail[0], &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[5]);
#endif

        // Added: Dual sabers
        if (playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_DUALSABERS)
		{
            rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[2]); // K_Lhand
#ifdef LIGHTSABER_TRAILS
			jkSaber_DrawTrail(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].saberTrail[1], &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[2]);
#endif
		}
    }
}

void jkSaber_UpdateLength(sithThing *thing)
{
    jkPlayerInfo* playerInfo = thing->playerInfo;
    if (!playerInfo )
    {
        thing->jkFlags &= ~JKFLAG_SABERON;
        return;
    }

    if (!(thing->jkFlags & JKFLAG_SABERON)) {
        playerInfo->polyline.length = 0;
        return; // Added: Wanted more logic in jkSaber_UpdateLength
    }

#if 0
    printf("Saber state: ");
    if (thing->jkFlags & JKFLAG_SABERON) {
        printf("ON ");
    }
    if (thing->jkFlags & JKFLAG_SABERDAMAGE) {
        printf("DAMAGE ");
    }
    if (thing->jkFlags & JKFLAG_SABEREXTEND) {
        printf("EXTEND ");
    }
    if (thing->jkFlags & JKFLAG_SABERRETRACT) {
        printf("RETRACT ");
    }
    if (thing->jkFlags & JKFLAG_DUALSABERS) {
        printf("DUALSABERS ");
    }
    if (thing->jkFlags & JKFLAG_SABERFORCEON) {
        printf("FORCEON ");
    }
    printf(" len=%f %f\n", playerInfo->polyline.length, thing->actorParams.timeLeftLengthChange);
#endif

    if (thing->thingflags & SITH_TF_DEAD || thing->type == SITH_THING_CORPSE)
    {
        thing->jkFlags |= JKFLAG_SABERRETRACT;
    }

    // Added: HACK fix a bug where the saber gets stuck extended.
    if ((thing->jkFlags & (JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT)) == (JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT))
    {
        thing->jkFlags &= ~JKFLAG_SABERRETRACT;
        playerInfo->polyline.length = 0;
    }

    if ( thing->jkFlags & JKFLAG_SABEREXTEND)
    {
        float newLength = playerInfo->polyline.length + (sithTime_deltaSeconds * JKSABER_EXTENDTIME);
        float deltaLen = newLength / playerInfo->length;

        thing->jkFlags &= ~JKFLAG_SABERRETRACT;

        playerInfo->polyline.length = newLength;
        thing->actorParams.timeLeftLengthChange = deltaLen * (1.0 - JKSABER_EXTENDTIME);
        if (newLength >= playerInfo->length) // ? verify, IDA crapped out on this comparison
        {
            playerInfo->polyline.length = playerInfo->length;
            thing->actorParams.timeLeftLengthChange = (1.0 - JKSABER_EXTENDTIME);
            thing->jkFlags &= ~(JKFLAG_SABERRETRACT | JKFLAG_SABEREXTEND);
        }
    }
    else if ( thing->jkFlags & JKFLAG_SABERRETRACT )
    {
        float newLength = playerInfo->polyline.length - (sithTime_deltaSeconds * JKSABER_EXTENDTIME);
        float deltaLen = newLength / playerInfo->length;

        thing->jkFlags &= ~JKFLAG_SABEREXTEND;

        playerInfo->polyline.length = newLength;
        thing->actorParams.timeLeftLengthChange = deltaLen * (1.0 - JKSABER_EXTENDTIME);
        if ( newLength <= 0.0 ) // ? verify, IDA crapped out on this comparison
        {
            playerInfo->polyline.length = 0.0;
            thing->jkFlags &= ~(JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT | JKFLAG_SABERON);
            thing->actorParams.timeLeftLengthChange = 0.0;
        }
    }
    else if (thing->jkFlags & JKFLAG_SABERFORCEON) // Used for starting a level with the saber on, ie DF2 lv4
    {
        playerInfo->polyline.length = playerInfo->length;
        thing->actorParams.timeLeftLengthChange = (1.0 - JKSABER_EXTENDTIME);
        thing->jkFlags &= ~(JKFLAG_SABERRETRACT | JKFLAG_SABEREXTEND);
        thing->jkFlags |= JKFLAG_SABERON;

        // Added? I think my RETRACT | EXTEND fix inavertently exposed a bug
        thing->jkFlags &= ~JKFLAG_SABERFORCEON;
    }

    if ( thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP] >= 0 )
    {
        jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP], 0); // MOTS added: last arg
        if ( thing->jkFlags & JKFLAG_DUALSABERS )
        {
            if ( thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP] >= 0 )
                jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP], 1); // MOTS added: last arg
        }
    }
}

// MOTS added: split into its own func
void  jkSaber_UpdateCollision2(sithThing *pPlayerThing,rdVector3 *pSaberPos,rdVector3 *pSaberDir,jkSaberCollide *pCollideInfo)
{
    sithSector *pSector;
    sithCollisionSearchEntry *searchResult;
    sithThing *resultThing;
    rdVector3 local_54;
    rdVector3 local_3c;
    jkPlayerInfo *playerInfo;
    rdMatrix34 tmpMat;
    
    playerInfo = pPlayerThing->playerInfo;
    pSector = sithCollision_GetSectorLookAt(pPlayerThing->sector,&pPlayerThing->position,pSaberPos,0.0);
    if (!pSector) {
        return;
    }
    sithCollision_SearchRadiusForThings(pSector,pPlayerThing,pSaberPos,pSaberDir,pCollideInfo->bladeLength,0.0,0);
    

    sithSector* pSectorIter = pSector;
    while (1) 
    {
        searchResult = sithCollision_NextSearchResult();
        if (!searchResult)
            break;

        if (searchResult->hitType & SITHCOLLISION_ADJOINCROSS)
        {
            pSectorIter = searchResult->surface->adjoin->sector;
        }
        else if (searchResult->hitType & SITHCOLLISION_THING) 
        {
            rdVector_Copy3(&local_54, pSaberPos);
            rdVector_MultAcc3(&local_54, pSaberDir, searchResult->distance);

            resultThing = searchResult->receiver;

            if ( resultThing->type == SITH_THING_ITEM || resultThing->type == SITH_THING_EXPLOSION || resultThing->type == SITH_THING_PARTICLE )
            {
                continue;
            }
            if (resultThing->actorParams.typeflags & SITH_AF_DROID 
                || resultThing->type != SITH_THING_ACTOR && resultThing->type != SITH_THING_PLAYER )
            {
                jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_WALL);
            }
            if ( pCollideInfo->numDamagedThings == 6 )
            {
                break;
            }

            int foundIdx = 0;
            for (foundIdx = 0; foundIdx < pCollideInfo->numDamagedThings; foundIdx++ )
            {
                if ( searchResult->receiver == pCollideInfo->damagedThings[foundIdx] )
                    break;
            }

            if ( foundIdx < pCollideInfo->numDamagedThings )
            {
                break;
            }

            if ( resultThing->type != SITH_THING_ACTOR 
                 && resultThing->type != SITH_THING_PLAYER 
                 || !(resultThing->actorParams.typeflags & SITH_AF_BLEEDS) )
            {
                jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_BLOOD);

                sithThing_Damage(searchResult->receiver, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
                pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
                break;
            }

            // TODO is this a vector func?
            rdVector_Sub3(&local_3c, &local_54, &resultThing->position);
            rdVector_Normalize3Acc(&local_3c);
            rdMatrix_Copy34(&tmpMat, &resultThing->lookOrientation);
            if ( resultThing->type == SITH_THING_ACTOR || resultThing->type == SITH_THING_PLAYER )
                rdMatrix_PreRotate34(&tmpMat, &resultThing->actorParams.eyePYR);
                
            // TODO: is this a vector func?
            rdVector3 v52 = tmpMat.lvec;
            rdVector_Normalize3Acc(&v52);
            if ( rdVector_Dot3(&v52, &local_3c) >= resultThing->actorParams.fov
              && (_frand() < resultThing->actorParams.chance) )
            {
                if (!(pPlayerThing->actorParams.typeflags & SITH_AF_INVISIBLE)) // verify
                {
                    sithSoundClass_PlayModeRandom(pPlayerThing, SITH_SC_DEFLECTED);

                    if ( _frand() >= 0.5 )
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK2, 0);
                    else
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK, 0);

                    jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_SABER);

                    sithCog_SendMessageFromThing(resultThing, 0, SITH_MESSAGE_BLOCKED);
                    pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
                    break;
                }
            }

            jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_BLOOD);

            sithThing_Damage(resultThing, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
            pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
            break;
        }
        else if (searchResult->hitType & SITHCOLLISION_WORLD)
        {
            rdVector_Copy3(&local_54, pSaberPos);
            rdVector_MultAcc3(&local_54, pSaberDir, searchResult->distance - 0.001);
            
            jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_WALL);

            if ( pCollideInfo->numDamagedSurfaces < 6 )
            {
                int surfaceNum = 0;
                for ( surfaceNum = 0; surfaceNum < pCollideInfo->numDamagedSurfaces; surfaceNum++ )
                {
                    if ( searchResult->surface == pCollideInfo->damagedSurfaces[surfaceNum] )
                        break;
                }
                if ( surfaceNum >= pCollideInfo->numDamagedSurfaces )
                {
                    sithSurface_SendDamageToThing(searchResult->surface, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
                    pCollideInfo->damagedSurfaces[pCollideInfo->numDamagedSurfaces++] = searchResult->surface;
                }
            }
            break;
        }
    }
    sithCollision_SearchClose();
}

#ifdef LIGHTSABER_MARKS
// Added: passive (non-damaging) collision effects
void jkSaber_SpawnBurn(jkPlayerInfo* pPlayerInfo, rdVector3* pPos, rdVector3* pHitNormal, sithSector* pSector, int sparkType)
{
	if (sithTime_curMs < pPlayerInfo->lastMarkSpawnMs + 50)
		return;

	// todo: skip these for now until we figure out how best to approach them
	if (sparkType == SPARKTYPE_BLOOD)
	{
		return;
	}
	else if (sparkType == SPARKTYPE_SABER)
	{
		return;
	}

	// if we don't have a last mark, or we made a huge movement, also spawn sparks
	float distSq = 0.0;
	if (!pPlayerInfo->lastSaberMark || (distSq = rdVector_DistSquared3(pPos, &pPlayerInfo->lastSaberMark->position)) > 0.004f)
	{
		jkSaber_SpawnSparks(pPlayerInfo, pPos, pSector, SPARKTYPE_WALL);
	}

	// no decals? fo'get abouuut'it
	if(!jkPlayer_enableDecals)
		return;

	// todo: some way of setting this template param
	sithThing* pTemplate = sithTemplate_GetEntryByName("+sbrmrk");
	if (pTemplate)
	{
		rdMatrix34 axis; // orientation of the decal
		float markLen = 1.0f; // width scale of the decal

		if(pPlayerInfo->lastSaberMark && distSq > 0.0001f)
		{
			// project the positions onto the hit plane
			rdVector3 projPos, lastProjPos;
			rdVector_Project3(&projPos, pPos, pPos, pHitNormal);
			rdVector_Project3(&lastProjPos, &pPlayerInfo->lastSaberMarkPos, pPos, pHitNormal);

			// facing the normal direction
			rdVector_Copy3(&axis.lvec, pHitNormal);
			rdVector_Normalize3Acc(&axis.lvec);
			
			// right vector aligned to the slash direction
			rdVector_Sub3(&axis.rvec, &lastProjPos, &projPos);
			markLen = rdVector_Normalize3Acc(&axis.rvec);
			
			// get the up vector
			rdVector_Cross3(&axis.uvec, &axis.lvec, &axis.rvec);
				
			// place the decal in the middle
			rdVector_Add3(&axis.scale, pPos, &pPlayerInfo->lastSaberMarkPos);
			rdVector_Scale3Acc(&axis.scale, 0.5f);
		}
		else
		{
			// no previous mark, start fresh
			rdMatrix_BuildFromLook34(&axis, pHitNormal);
			rdVector_Copy3(&axis.scale, pPos);
		}


		// make sure we recycle things otherwise we risk running out of them frequently
		int decalIdx = (jkSaber_numDecalThings++ % 256);
		if (jkSaber_paDecalThings[decalIdx])
		{
			sithThing_Destroy(jkSaber_paDecalThings[decalIdx]);
			jkSaber_paDecalThings[decalIdx] = 0;
		}

		sithThing* pSpawned = sithThing_Create(pTemplate, &axis.scale, &axis, pSector, 0);
		if (pSpawned)
		{
			jkSaber_paDecalThings[decalIdx] = pSpawned;

			pSpawned->prev_thing = pPlayerInfo->actorThing;
			pPlayerInfo->lastMarkSpawnMs = sithTime_curMs;
			pSpawned->child_signature = pPlayerInfo->actorThing->signature;

			// adjust the size of the decal (template should be a decal) so it spans the length of the slash
			if(pPlayerInfo->lastSaberMark)
				pSpawned->rdthing.decalScale.x = 1.7f * markLen / pSpawned->rdthing.decal->size.x;

			// if the distance between the 2 points is extremely low gradually scale it up
			// we could do this with the last mark, but we want the sounds and effects to play from the spawned template
			if (pPlayerInfo->lastSaberMark && distSq < 0.0001f)
			{
				pSpawned->rdthing.decalScale.x = min(1.0f + pPlayerInfo->saberCollideInfo.totalCollisionTime, 8.0f);
				pSpawned->rdthing.decalScale.z = min(1.0f + pPlayerInfo->saberCollideInfo.totalCollisionTime, 8.0f);
				pPlayerInfo->saberCollideInfo.totalCollisionTime += sithTime_deltaSeconds;
			}
			else
			{
				pPlayerInfo->saberCollideInfo.totalCollisionTime = 0;
			}

			rdVector_Copy3(&pPlayerInfo->lastSaberMarkPos, pPos);
			pPlayerInfo->lastSaberMark = pSpawned;
		}
	}
}

void jkSaber_UpdateEffectCollision(sithThing* pPlayerThing, rdVector3* pSaberPos, rdVector3* pSaberDir, rdVector3* pSaberLastPos, jkSaberCollide* pCollideInfo)
{
	// clear the damage list so that it updates every frame
	pCollideInfo->numDamagedSurfaces = 0;

	sithSector* pSector;
	sithCollisionSearchEntry* searchResult;
	sithThing* resultThing;
	rdVector3 local_54;
	rdVector3 local_3c;
	jkPlayerInfo* playerInfo;
	rdMatrix34 tmpMat;

	playerInfo = pPlayerThing->playerInfo;
	pSector = sithCollision_GetSectorLookAt(pPlayerThing->sector, &pPlayerThing->position, pSaberPos, 0.0);
	if (!pSector)
	{
		playerInfo->lastSaberMark = 0;
		return;
	}

	float saberLength = !(pPlayerThing->jkFlags & JKFLAG_SABERDAMAGE) ? pPlayerThing->playerInfo->polyline.length : pCollideInfo->bladeLength;
	sithCollision_SearchRadiusForThings(pSector, pPlayerThing, pSaberPos, pSaberDir, saberLength, 0.0, RAYCAST_1); // skipping things for now

	int collisions = 0;
	sithSector* pSectorIter = pSector;
	while (1)
	{
		searchResult = sithCollision_NextSearchResult();
		if (!searchResult)
			break;

		if (searchResult->hitType & SITHCOLLISION_ADJOINCROSS)
		{
			pSectorIter = searchResult->surface->adjoin->sector;
		}
		else if (searchResult->hitType & SITHCOLLISION_WORLD)
		{
			rdVector_Copy3(&local_54, pSaberPos);
			rdVector_MultAcc3(&local_54, pSaberDir, searchResult->distance - 0.001);

			jkSaber_SpawnBurn(playerInfo, &local_54, &searchResult->hitNorm, pSectorIter, SPARKTYPE_WALL);
			++collisions;

			if (pCollideInfo->numDamagedSurfaces < 6)
			{
				int surfaceNum = 0;
				for (surfaceNum = 0; surfaceNum < pCollideInfo->numDamagedSurfaces; surfaceNum++)
				{
					if (searchResult->surface == pCollideInfo->damagedSurfaces[surfaceNum])
						break;
				}
				if (surfaceNum >= pCollideInfo->numDamagedSurfaces)
				{
					sithSurface_SendDamageToThing(searchResult->surface, pPlayerThing, 0.0f, SITH_DAMAGE_SABER);
					pCollideInfo->damagedSurfaces[pCollideInfo->numDamagedSurfaces++] = searchResult->surface;
				}
			}
			break;
		}
	}
	sithCollision_SearchClose();

	if(!collisions)
		playerInfo->lastSaberMark = 0;
}

#endif

// MOTS altered: interpolation and multiple blades
void jkSaber_UpdateCollision(sithThing *player, int joint, int bSecondary)
{
    jkPlayerInfo *playerInfo; // ebx
    rdVector3 a2a;
    rdMatrix34 jointMat;
    rdVector3 jointPos;
    rdMatrix34 matrix;
    rdMatrix34 tmpMat;
    rdMatrix34 local_60;
    rdVector3 lerpSaberDir;
    rdVector3 lerpSaberPos;
    rdVector3 lerpPosDelta;
    rdVector3 lerpDirDelta;
    rdMatrix34 *storeOrientMat;

    playerInfo = player->playerInfo;

    rdMatrix_Copy34(&matrix, &player->lookOrientation);
    rdVector_Copy3(&matrix.scale, &player->position);
    if ( jkSmack_GetCurrentGuiState() == 6 ) {
        rdPuppet_BuildJointMatrices(&player->rdthing, &matrix);
    }

    if ( !rdModel3_GetMeshMatrix(&player->rdthing, &matrix, joint, &jointMat) )
        return;

    rdVector_Copy3(&player->actorParams.saberBladePos, &jointMat.scale);
    rdVector_MultAcc3(&player->actorParams.saberBladePos, &jointMat.lvec, playerInfo->polyline.length);

    if ( player->jkFlags & JKFLAG_40 )
    {
        player->jkFlags &= ~JKFLAG_40;
        playerInfo->saberCollideInfo.numDamagedThings = 0;
        playerInfo->saberCollideInfo.numDamagedSurfaces = 0;
    }

#ifdef LIGHTSABER_MARKS
	// do a collision check with the blade tip to generate effects like saber marks
	rdVector3 lastPosWS;
	rdMatrix_TransformPoint34(&lastPosWS, &playerInfo->saberTrail[bSecondary].lastTip, &rdCamera_camMatrix);
	jkSaber_UpdateEffectCollision(player, &jointMat.scale, &jointMat.lvec, &lastPosWS, &playerInfo->saberCollideInfo);
	playerInfo->saberCollideInfo.numDamagedThings = 0;
	playerInfo->saberCollideInfo.numDamagedSurfaces = 0;
#endif

    if ( !(player->jkFlags & JKFLAG_SABERDAMAGE) )
        return;
    if ( !playerInfo->saberCollideInfo.field_1A4 )
        return;
    
    if (!Main_bMotsCompat) {
        jkSaber_UpdateCollision2(player,&jointMat.scale, &jointMat.lvec, &playerInfo->saberCollideInfo);
        return;
    }
    
    // MOTS added: interpolation at low FPS
    rdVector_Copy3(&jointPos, &jointMat.scale);
    rdVector_Copy3(&a2a, &jointMat.lvec);
    if (sithTime_deltaSeconds > 0.05 && playerInfo->jkmUnk1) 
    {
        storeOrientMat = &playerInfo->jkmSaberUnk1;
        if (bSecondary != 0) {
            storeOrientMat = &playerInfo->jkmSaberUnk2;
        }
        float fVar1 = sithTime_TickHz * 0.05;
        rdMatrix_Copy34(&local_60, storeOrientMat);

        rdVector_Sub3(&lerpPosDelta, &jointMat.scale, &local_60.scale);
        rdVector_Sub3(&lerpDirDelta, &jointMat.lvec, &local_60.lvec);
        float local_b8 = fVar1;
        for (; fVar1 < 1.0; fVar1 = local_b8 + fVar1) {
            rdVector_Copy3(&lerpSaberPos, &local_60.scale);
            rdVector_MultAcc3(&lerpSaberPos, &lerpPosDelta, fVar1);

            rdVector_Copy3(&lerpSaberDir, &local_60.lvec);
            rdVector_MultAcc3(&lerpSaberDir, &lerpDirDelta, fVar1);

            jkSaber_UpdateCollision2(player,&lerpSaberPos,&lerpSaberDir,&playerInfo->saberCollideInfo);
        }
    }
    jkSaber_UpdateCollision2(player,&jointPos,&a2a,&playerInfo->saberCollideInfo);
    storeOrientMat = &playerInfo->jkmSaberUnk1;
    if (bSecondary != 0) {
        storeOrientMat = &playerInfo->jkmSaberUnk2;
    }
    rdMatrix_Copy34(storeOrientMat, &jointMat);
    playerInfo->jkmUnk1 = 1;
}

void jkSaber_SpawnSparks(jkPlayerInfo *pPlayerInfo, rdVector3 *pPos, sithSector *psector, int sparkType)
{
    sithThing *pTemplate; // eax
    sithThing *pSpawned; // eax

    if ( sithTime_curMs < pPlayerInfo->lastSparkSpawnMs + 200 )
        return;

    if ( sparkType == SPARKTYPE_BLOOD )
    {
        pTemplate = pPlayerInfo->blood_sparks;
    }
    else if ( sparkType == SPARKTYPE_SABER )
    {
        pTemplate = pPlayerInfo->saber_sparks;
    }
    else // SPARKTYPE_WALL
    {
        pTemplate = pPlayerInfo->wall_sparks;
    }
    if ( pTemplate )
    {
        pSpawned = sithThing_Create(pTemplate, pPos, &rdroid_identMatrix34, psector, 0);
        if ( pSpawned )
        {
            pSpawned->prev_thing = pPlayerInfo->actorThing;
            pPlayerInfo->lastSparkSpawnMs = sithTime_curMs;
            pSpawned->child_signature = pPlayerInfo->actorThing->signature;
        }
    }
}

// MOTS altered
void jkSaber_Enable(sithThing *pThing, float damage, float bladeLength, float stunDelay)
{
    if (!pThing || !pThing->playerInfo) return; // MOTS added

    pThing->playerInfo->saberCollideInfo.damage = damage;
    pThing->playerInfo->saberCollideInfo.bladeLength = bladeLength;
    pThing->playerInfo->saberCollideInfo.stunDelay = stunDelay;
    pThing->playerInfo->saberCollideInfo.field_1A4 = 1;
    pThing->playerInfo->saberCollideInfo.numDamagedThings = 0;
    pThing->playerInfo->saberCollideInfo.numDamagedSurfaces = 0;

    _memset(pThing->playerInfo->saberCollideInfo.damagedThings, 0, sizeof(pThing->playerInfo->saberCollideInfo.damagedThings));
    _memset(pThing->playerInfo->saberCollideInfo.damagedSurfaces, 0, sizeof(pThing->playerInfo->saberCollideInfo.damagedSurfaces));
    
    pThing->playerInfo->lastSparkSpawnMs = 0;
#ifdef LIGHTSABER_MARKS
	pThing->playerInfo->lastMarkSpawnMs = 0;
#endif

#ifdef JKM_SABER
    pThing->playerInfo->jkmUnk1 = 0; // MOTS added
#endif
}

// MOTS altered
void jkSaber_Disable(sithThing *player)
{
    //MOTS added:
    if (!player || !player->playerInfo) return;

    player->playerInfo->saberCollideInfo.field_1A4 = 0;
#ifdef JKM_SABER
    player->playerInfo->jkmUnk1 = 0; // MOTS added
#endif
}