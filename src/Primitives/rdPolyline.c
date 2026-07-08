#include "rdPolyline.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/rdroid.h"
#include "Engine/rdCamera.h"
#include "General/stdMath.h"
#include "General/stdString.h"
#include "Raster/rdCache.h"
#include "Engine/rdColormap.h"
#include "Primitives/rdPrimit3.h"
#include "Primitives/rdDebug.h"
#include <math.h>

static rdVector3 polylineVerts[32]; // idk the size on this
static rdVector3 rdPolyline_FaceVerts[32];

rdPolyline* rdPolyline_New(char *polyline_fname, char *material_fname, char *material_fname2, flex_t length, flex_t base_rad, flex_t tip_rad, int lightmode, int texmode, int sortingmethod, flex_t extraLight)
{
    rdPolyline* polyline;

    polyline = (rdPolyline *)RDROID_ALLOC(sizeof(rdPolyline));
    if (polyline)
    {
        memset(polyline, 0, sizeof(*polyline)); // Added: clear struct
        rdPolyline_NewEntry(polyline, polyline_fname, material_fname, material_fname2, length, base_rad, tip_rad, lightmode, texmode, sortingmethod, extraLight);
    }
    return polyline;
}

int rdPolyline_NewEntry(rdPolyline *polyline, char *polyline_fname, char *material_side_fname, char *material_tip_fname, flex_t length, flex_t base_rad, flex_t tip_rad, rdGeoMode_t edgeGeometryMode, rdLightMode_t edgeLightingMode, rdTexMode_t edgeTextureMode, flex_t extraLight)
{

    rdMaterial *mat;
    int *vertexPosIdx;
    unsigned int numVertices;
    rdVector2 *extraUVTipMaybe;
    int *vertexUVIdx;
    rdVector2 *extraUVFaceMaybe;
    tVBuffer *v22;

    // Added: memleak mitigation
    rdPolyline_FreeEntry(polyline);

    if ( polyline_fname )
    {
        // TODO: caching?
#ifdef SITH_DEBUG_STRUCT_NAMES
        stdString_SafeStrCopy(polyline->fname, polyline_fname, 32);
#endif
    }
    polyline->length = length;
    polyline->baseRadius = base_rad;
    polyline->face.textureMode = edgeTextureMode;
    polyline->textureMode = edgeTextureMode;
    polyline->lightingMode = edgeLightingMode;
    polyline->tipRadius = tip_rad;
    polyline->face.type = 0;
    polyline->face.geometryMode = edgeGeometryMode;
    polyline->face.lightingMode = edgeLightingMode;
    polyline->geometryMode = edgeGeometryMode;
    polyline->face.extraLight = extraLight;

    polyline->face.material = rdMaterial_Load(material_side_fname, 0, 0);
    if ( !polyline->face.material )
        return 0;
    rdMaterial_EnsureDataForced(polyline->face.material); // Added: TWL
    polyline->face.numVertices = 4;
    vertexPosIdx = (int *)RDROID_ALLOC(sizeof(int) * polyline->face.numVertices);
    polyline->face.vertexPosIdx = vertexPosIdx;
    if ( !vertexPosIdx )
        return 0;
    numVertices = polyline->face.numVertices;
    for (int i = 0; i < numVertices; ++vertexPosIdx )
        *vertexPosIdx = i++;
    if ( polyline->face.geometryMode >= RD_GEOMETRY_FULL)
    {
        vertexUVIdx = (int *)RDROID_ALLOC(4 * numVertices);
        polyline->face.vertexUVIdx = vertexUVIdx;
        if ( !vertexUVIdx )
            return 0;
        for (int j = 0; j < polyline->face.numVertices; ++vertexUVIdx )
            *vertexUVIdx = j++;
        extraUVTipMaybe = (rdVector2 *)RDROID_ALLOC(sizeof(rdVector2) * polyline->face.numVertices);
        polyline->extraUVTipMaybe = extraUVTipMaybe;
        if ( !extraUVTipMaybe )
            return 0;
        // Odd quirk: This requires the material be actually loaded
        // Added: nullptr fallbacks
        v22 = NULL;
        if (polyline->face.material->texinfos[0] && polyline->face.material->texinfos[0]->texture_ptr) {
            v22 = polyline->face.material->texinfos[0]->texture_ptr->texture_struct[0];
        }
        extraUVTipMaybe[0].x = (flex_d_t)(v22 ? (unsigned int)v22->format.width : 1) - 0.01;// Added: nullptr check and fallback
        extraUVTipMaybe[0].y = 0.0;
        extraUVTipMaybe[1].x = 0.0;
        extraUVTipMaybe[1].y = 0.0;
        extraUVTipMaybe[2].x = 0.0;
        extraUVTipMaybe[2].y = (flex_d_t)(v22 ? (unsigned int)v22->format.height : 1) - 0.01;// Added: nullptr check and fallback
        extraUVTipMaybe[3].x = (flex_d_t)(v22 ? (unsigned int)v22->format.width : 1) - 0.01;// Added: nullptr check and fallback
        extraUVTipMaybe[3].y = (flex_d_t)(v22 ? (unsigned int)v22->format.height : 1) - 0.01;// Added: nullptr check and fallback
    }
    rdMaterial_OptionalFree(polyline->face.material); // Added: TWL
    polyline->tipFace.textureMode = edgeTextureMode;
    polyline->textureMode = edgeTextureMode;
    polyline->lightingMode = edgeLightingMode;
    polyline->tipFace.type = 0;
    polyline->tipFace.geometryMode = edgeGeometryMode;
    polyline->tipFace.lightingMode = edgeLightingMode;
    polyline->geometryMode = edgeGeometryMode;
    polyline->tipFace.extraLight = extraLight;
    polyline->tipFace.material = rdMaterial_Load(material_tip_fname, 0, 0);
    if ( !polyline->tipFace.material )
        return 0;
    rdMaterial_EnsureDataForced(polyline->tipFace.material); // Added: TWL
    polyline->tipFace.numVertices = 4;
    vertexPosIdx = (int *)RDROID_ALLOC(sizeof(int) * polyline->tipFace.numVertices);
    polyline->tipFace.vertexPosIdx = vertexPosIdx;
    if ( !vertexPosIdx )
        return 0;
    for (int k = 0; k < polyline->tipFace.numVertices; ++vertexPosIdx )
        *vertexPosIdx = k++;
    if ( polyline->tipFace.geometryMode >= RD_GEOMETRY_FULL)
    {
        vertexUVIdx = (int *)RDROID_ALLOC(sizeof(int) * polyline->tipFace.numVertices);
        polyline->tipFace.vertexUVIdx = vertexUVIdx;
        if ( !vertexUVIdx )
            return 0;
        for (int l = 0; l < polyline->tipFace.numVertices; ++vertexUVIdx )
            *vertexUVIdx = l++;
        extraUVFaceMaybe = (rdVector2 *)RDROID_ALLOC(sizeof(rdVector2) * polyline->tipFace.numVertices);
        polyline->extraUVFaceMaybe = extraUVFaceMaybe;
        if ( !extraUVFaceMaybe )
            return 0;
        // Odd quirk: This requires the material be actually loaded
        // Added: nullptr fallbacks
        v22 = NULL;
        if (polyline->tipFace.material->texinfos[0] && polyline->tipFace.material->texinfos[0]->texture_ptr) {
            v22 = polyline->tipFace.material->texinfos[0]->texture_ptr->texture_struct[0];
        }
        extraUVFaceMaybe[0].x = (flex_d_t)(v22 ? (unsigned int)v22->format.width : 1.0) - 0.01; // Added: nullptr check and fallback
        extraUVFaceMaybe[0].y = 0.0;
        extraUVFaceMaybe[1].x = 0.0;
        extraUVFaceMaybe[1].y = 0.0;
        extraUVFaceMaybe[2].x = 0.0;
        extraUVFaceMaybe[2].y = (flex_d_t)(v22 ? (unsigned int)v22->format.height : 1.0) - 0.01; // Added: nullptr check and fallback
        extraUVFaceMaybe[3].x = (flex_d_t)(v22 ? (unsigned int)v22->format.width : 1.0) - 0.01; // Added: nullptr check and fallback
        extraUVFaceMaybe[3].y = (flex_d_t)(v22 ? (unsigned int)v22->format.height : 1.0) - 0.01; // Added: nullptr check and fallback
    }
    rdMaterial_OptionalFree(polyline->tipFace.material); // Added: TWL
    return 1;
}

void rdPolyline_Free(rdPolyline *pPolyline)
{
    if ( pPolyline )
    {
        rdPolyline_FreeEntry(pPolyline);
        RDROID_FREE(pPolyline);
    }
}

void rdPolyline_FreeEntry(rdPolyline *pPolyline)
{
    if ( pPolyline->extraUVFaceMaybe )
    {
        RDROID_FREE(pPolyline->extraUVFaceMaybe);
        pPolyline->extraUVFaceMaybe = 0;
    }
    if ( pPolyline->extraUVTipMaybe )
    {
        RDROID_FREE(pPolyline->extraUVTipMaybe);
        pPolyline->extraUVTipMaybe = 0;
    }
    if ( pPolyline->tipFace.vertexPosIdx )
    {
        RDROID_FREE(pPolyline->tipFace.vertexPosIdx);
        pPolyline->tipFace.vertexPosIdx = 0;
    }
    if ( pPolyline->tipFace.vertexUVIdx )
    {
        RDROID_FREE(pPolyline->tipFace.vertexUVIdx);
        pPolyline->tipFace.vertexUVIdx = 0;
    }
    if ( pPolyline->face.vertexPosIdx )
    {
        RDROID_FREE(pPolyline->face.vertexPosIdx);
        pPolyline->face.vertexPosIdx = 0;
    }
    if ( pPolyline->face.vertexUVIdx )
    {
        RDROID_FREE(pPolyline->face.vertexUVIdx);
        pPolyline->face.vertexUVIdx = 0;
    }
}

int rdPolyline_Draw(rdThing *pLine, rdMatrix34 *pOrient)
{
    rdPolyline *polyline;
    flex_t length;
    flex_d_t tip_left;
    flex_d_t tip_bottom;
    flex_d_t tip_right;
    flex_d_t tip_top;
    flex_t ang;
    flex_t angSin;
    flex_t angCos;
    rdVector3 vertex_out;
    rdMatrix34 out;
    rdVector3 vertex;
    rdMeshinfo idxInfo;

    polyline = pLine->polyline;
    
    // This is slightly different than IDA?
    idxInfo.numVertices = 4;
    idxInfo.aVertices = polylineVerts;
    idxInfo.paDynamicLight = 0;
    idxInfo.intensities = 0;

    rdMatrix_Multiply34(&out, &rdCamera_g_pCurCamera->orient, pOrient);
    vertex.x = 0.0;
    vertex.y = polyline->length;
    vertex.z = 0.0;
    rdMatrix_TransformPoint34(&vertex_out, &vertex, &out);
    tip_left = vertex_out.x - polyline->tipRadius;
    tip_bottom = vertex_out.z - polyline->tipRadius;
    tip_right = vertex_out.x + polyline->tipRadius;
    tip_top = vertex_out.z + polyline->tipRadius;

    flex_t epislon = -0.001;

    // Tip
    {
        polylineVerts[0].x = tip_left;
        polylineVerts[0].y = vertex_out.y - epislon;
        polylineVerts[0].z = tip_bottom;
        polylineVerts[1].x = tip_right;
        polylineVerts[1].y = vertex_out.y - epislon;
        polylineVerts[1].z = tip_bottom;
        polylineVerts[2].x = tip_right;
        polylineVerts[2].y = vertex_out.y - epislon;
        polylineVerts[2].z = tip_top;
        polylineVerts[3].x = tip_left;
        polylineVerts[3].y = vertex_out.y - epislon;
        polylineVerts[3].z = tip_top;
        idxInfo.aTexVerticies = polyline->extraUVFaceMaybe;
        rdPolyline_DrawFace(pLine, &polyline->tipFace, polylineVerts, &idxInfo);
    }

    // Base
    {
        polylineVerts[0].x = out.scale.x - polyline->baseRadius;
        polylineVerts[0].y = out.scale.y - epislon;
        polylineVerts[0].z = out.scale.z - polyline->baseRadius;
        polylineVerts[1].x = out.scale.x + polyline->baseRadius;
        polylineVerts[1].y = out.scale.y - epislon;
        polylineVerts[1].z = out.scale.z - polyline->baseRadius;
        polylineVerts[2].x = out.scale.x + polyline->baseRadius;
        polylineVerts[2].y = out.scale.y - epislon;
        polylineVerts[2].z = out.scale.z + polyline->baseRadius;
        polylineVerts[3].x = out.scale.x - polyline->baseRadius;
        polylineVerts[3].y = out.scale.y - epislon;
        polylineVerts[3].z = out.scale.z + polyline->baseRadius;
        idxInfo.aTexVerticies = polyline->extraUVFaceMaybe;
        rdPolyline_DrawFace(pLine, &polyline->tipFace, polylineVerts, &idxInfo);
    }
    

    // Blade
    {
        flex_t zdist = vertex_out.z - out.scale.z;
        flex_t xdist = vertex_out.x - out.scale.x;
        flex_t mag = stdMath_Sqrt(xdist * xdist + zdist * zdist);

        // Added: prevent div 0
        if (mag == 0)
        {
            mag = 0.000001f;
        }

        ang = stdMath_ArcSin3((-xdist) / mag);
        if ( zdist < 0.0 )
        {
            if ( xdist <= 0.0 )
                ang = -(ang - -180.0);
            else
                ang = 180.0 - ang;
        }
        stdMath_SinCos(ang, &angSin, &angCos);
        polylineVerts[0].x = (polyline->tipRadius * angCos) - (mag * angSin) + out.scale.x;
        polylineVerts[0].y = vertex_out.y;
        polylineVerts[0].z = (polyline->tipRadius * angSin) + (mag * angCos) + out.scale.z;
        
        polylineVerts[1].x = (-polyline->tipRadius * angCos) - (mag * angSin) + out.scale.x;
        polylineVerts[1].y = vertex_out.y;
        polylineVerts[1].z = (-polyline->tipRadius * angSin) + (mag * angCos) + out.scale.z;
        
        polylineVerts[2].x = (-polyline->baseRadius * angCos) - (flex_t)0.0 + out.scale.x;
        polylineVerts[2].y = out.scale.y;
        polylineVerts[2].z = (-polyline->baseRadius * angSin) + (flex_t)0.0 + out.scale.z;
        
        polylineVerts[3].x = (polyline->baseRadius * angCos) - (flex_t)0.0 + out.scale.x;
        polylineVerts[3].y = out.scale.y;
        polylineVerts[3].z = (polyline->baseRadius * angSin) + (flex_t)0.0 + out.scale.z;
        idxInfo.aTexVerticies = polyline->extraUVTipMaybe;
        rdPolyline_DrawFace(pLine, &polyline->face, polylineVerts, &idxInfo);
    }
    return 1;
}

void rdPolyline_DrawFace(rdThing *pLine, rdFace *pFace, rdVector3 *aVertices, rdMeshinfo *aUVs)
{
    rdProcEntry *procEntry;
    rdMeshinfo mesh_out;
    flex_t staticLight;

    procEntry = rdCache_GetProcEntry();
    if (!procEntry)
        return;

    mesh_out.aVertices = rdPolyline_FaceVerts;
    mesh_out.verticesOrig = procEntry->aVertices;
    mesh_out.aTexVerticies = procEntry->aTexVerticies;
    mesh_out.paDynamicLight = procEntry->vertexIntensities;
    
    aUVs->numVertices = pFace->numVertices;
    aUVs->vertexPosIdx = pFace->vertexPosIdx;
    aUVs->vertexUVIdx = pFace->vertexUVIdx;
    
    rdGeoMode_t curGeometryMode_ = rdroid_g_curGeometryMode;
    rdLightMode_t curLightingMode_ = rdroid_g_curLightingMode;
    rdTexMode_t curTextureMode_ = rdroid_curTextureMode;

    if ( curGeometryMode_ >= pFace->geometryMode )
        curGeometryMode_ = pFace->geometryMode;
    if ( curGeometryMode_ >= pLine->curGeoMode )
    {
        procEntry->geometryMode = pLine->curGeoMode;
    }    
    else if ( rdroid_g_curGeometryMode >= pFace->geometryMode )
    {
        procEntry->geometryMode = pFace->geometryMode;
    }
    else
    {
        procEntry->geometryMode = rdroid_g_curGeometryMode;
    }
    
    procEntry->geometryMode = procEntry->geometryMode;
    if ( rdroid_g_curRenderOptions & 2 && rdCamera_g_pCurCamera->ambientLight >= 1.0 )
    {
        procEntry->lightingMode = RD_LIGHTMODE_FULLYLIT;
    }
    else
    {
        if ( curLightingMode_ >= pFace->lightingMode )
            curLightingMode_ = pFace->lightingMode;
        if ( curLightingMode_ >= pLine->curLightMode )
        {
            pFace->lightingMode = pLine->curLightMode;
        }
        else if ( rdroid_g_curLightingMode < pFace->lightingMode )
        {
            pFace->lightingMode = rdroid_g_curLightingMode;
        }
        procEntry->lightingMode = pFace->lightingMode;
    }

    if ( curTextureMode_ >= pFace->textureMode )
        curTextureMode_ = pFace->textureMode;
    
    procEntry->textureMode = pLine->curTexMode;
    if ( curTextureMode_ < procEntry->textureMode )
    {
        if ( curTextureMode_ >= pFace->textureMode )
            procEntry->textureMode = pFace->textureMode;
        else
            procEntry->textureMode = rdroid_curTextureMode;
    }

    rdPrimit3_ClipFace(rdCamera_g_pCurCamera->pClipFrustum, procEntry->geometryMode, procEntry->lightingMode, procEntry->textureMode, aUVs, &mesh_out, &pFace->texVertOffset);
    if ( mesh_out.numVertices < 3 )
        return;

    rdCamera_g_pCurCamera->pfProjectList(mesh_out.verticesOrig, mesh_out.aVertices, mesh_out.numVertices);

    if ( rdroid_g_curRenderOptions & 2 )
        procEntry->ambientLight = rdCamera_g_pCurCamera->ambientLight;
    else
        procEntry->ambientLight = 0.0;

    // Software renderer optimizations, skip
#ifndef TARGET_TWL
    if ( procEntry->lightingMode )
    {
        if ( procEntry->ambientLight < 1.0 )
        {
            if ( procEntry->lightingMode == 2 )
            {
                if ( procEntry->light_level_static < 1.0 || rdColormap_pCurMap != rdColormap_pIdentityMap )
                {
                    if ( procEntry->light_level_static <= 0.0 )
                        procEntry->lightingMode = 1;
                }
                else
                {
                    procEntry->lightingMode = 0;
                }
            }
            else if ( procEntry->lightingMode == 3 )
            {
                int i;
                staticLight = *procEntry->vertexIntensities;
                for (i = 1; i < mesh_out.numVertices; i++)
                {
                    if ( procEntry->vertexIntensities[i] != staticLight )
                        break;
                }
                if ( i == mesh_out.numVertices )
                {
                    if ( staticLight == 1.0 )
                    {
                        if ( rdColormap_pCurMap == rdColormap_pIdentityMap )
                        {
                            procEntry->lightingMode = 0;
                        }
                        else
                        {
                            procEntry->lightingMode = 2;
                            procEntry->light_level_static = 1.0;
                        }
                    }
                    else if ( staticLight == 0.0 )
                    {
                        procEntry->lightingMode = 1;
                        procEntry->light_level_static = 0.0;
                    }
                    else
                    {
                        procEntry->lightingMode = 2;
                        procEntry->light_level_static = staticLight;
                    }
                }
            }
        }
        else if ( rdColormap_pCurMap == rdColormap_pIdentityMap )
        {
            procEntry->lightingMode = 0;
        }
        else
        {
            procEntry->lightingMode = 2;
            procEntry->light_level_static = 1.0;
        }
    }
#else
    if ( procEntry->lightingMode == 3 )
    {
        procEntry->light_level_static = *procEntry->vertexIntensities;
    }
#endif
    
    int procFaceFlags = 1;
    if ( procEntry->geometryMode >= 4 )
        procFaceFlags = 3;
    if ( procEntry->lightingMode >= 3 )
        procFaceFlags |= 4u;

    procEntry->light_flags = 0;
    procEntry->wallCel = pLine->wallCel;
    procEntry->type = pFace->type;
    procEntry->extralight = pFace->extraLight;
    procEntry->material = pFace->material;

    // Added: Polylines should always be drawn
    rdMaterial_EnsureDataForced(procEntry->material);

    rdCache_AddProcFace(0, mesh_out.numVertices, procFaceFlags);
}
