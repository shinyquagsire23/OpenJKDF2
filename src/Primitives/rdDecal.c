#include "rdDecal.h"

#include "General/stdMath.h"
#include "General/stdString.h"
#include "Engine/rdroid.h"
#include "Raster/rdCache.h"
#include "Engine/rdClip.h"
#include "Engine/rdColormap.h"
#include "Primitives/rdPrimit3.h"
#include <math.h>

#if defined(DECAL_RENDERING) || defined(RENDER_DROID2)

rdDecal* rdDecal_New(char* fpath, char* materialFpath, uint32_t flags, rdVector3* color, rdVector3* size, float fadeTime, float angleFade)
{
	rdDecal* decal = (rdDecal*)rdroid_pHS->alloc(sizeof(rdDecal));
    if (decal)
    {
		rdDecal_NewEntry(decal, fpath, materialFpath, flags, color, size, fadeTime, angleFade);
    }    
    return decal;
}

int rdDecal_NewEntry(rdDecal* decal, char* decalPath, char* material, uint32_t flags, rdVector3* color, rdVector3* size, float fadeTime, float angleFade)
{
    if (decalPath)
    {
        stdString_SafeStrCopy(decal->path, decalPath, 0x20);
    }
	decal->size = *size;
	decal->fadeTime = fadeTime;
	decal->flags = flags;
	decal->color = *color;
	decal->material = rdMaterial_Load(material, 0, 0);
	decal->radius = rdVector_Len3(size);
	decal->angleFade = cosf(angleFade * (M_PI / 180.0f) * 0.5f);
    if (decal->material)
    {
		return 1;
	}
    else
	{
        jk_printf("OpenJKDF2: Decal `%s` is missing material.\n", decal->path);
    }
    return 0;
}

void rdDecal_Free(rdDecal* decal)
{
    if (decal)
    {
        rdDecal_FreeEntry(decal);
        rdroid_pHS->free(decal);
    }
}

void rdDecal_FreeEntry(rdDecal* decal)
{
}

void rdDecal_Draw(rdThing* thing, rdMatrix34* matrix)
{
	rdDecal* decal = thing->decal;
	
	int clipResult;
	rdVector3 viewPos;
	rdMatrix_TransformPoint34(&viewPos, &matrix->scale, &rdCamera_pCurCamera->view_matrix);
	clipResult = rdClip_SphereInFrustrum(rdCamera_pCurCamera->pClipFrustum, &viewPos, decal->radius);

	if (clipResult == 2)
		return;

	rdVector3 color;
	rdVector_Copy3(&color, &decal->color);
	if (decal->fadeTime > 0.0)
	{
		float fadeSeconds = (float)(sithTime_curMs - thing->createMs) / 1000.0f;
		//if(fadeSeconds > decal->fadeTime)
			//return;
		
		float fadeFactor = 1.0f - fadeSeconds / decal->fadeTime;
		if (fadeFactor < 0)
		{
			rdVector_Zero3(&color);
		}
		else
		{
			rdVector_Scale3Acc(&color, fadeFactor);
		}
	}

	if ((decal->flags & RD_DECAL_ADD) && !(decal->flags & RD_DECAL_HEAT)
		&& color.x <= 0.0
		&& color.y <= 0.0
		&& color.z <= 0.0)
	{
		return;
	}

#ifdef RENDER_DROID2
	rdMatrix34 mat;
	rdMatrix_Copy34(&mat, matrix);

	rdVector4 size;
	size.x = decal->size.x * thing->decalScale.x;
	size.y = decal->size.y * thing->decalScale.y;
	size.z = decal->size.z * thing->decalScale.z;
	size.w = 1;
	//rdMatrix_PreScale34(&mat, &size);

	//rdMatrix_PostMultiply34(&mat, &rdCamera_pCurCamera->view_matrix);
	rdMatrixMode(RD_MATRIX_MODEL);
	rdLoadMatrix34(matrix);

	rdScale(&size);

	rdAddDecal(decal, &mat, &color, &size, decal->angleFade);

	rdIdentity();
#else
	rdCache_DrawDecal(decal, matrix, &color, &thing->decalScale, decal->angleFade);
#endif

	return;
}

#endif
