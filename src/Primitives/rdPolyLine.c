#include "rdPolyLine.h"

#include "Engine/rdroid.h"
#include "Engine/rdCamera.h"
#include "General/stdMath.h"
#include "Engine/rdCache.h"
#include "Engine/rdColormap.h"
#include "Primitives/rdPrimit3.h"
#include "Primitives/rdDebug.h"
#include <math.h>

static rdVector3 polylineVerts[32]; // idk the size on this
static rdVector3 rdPolyLine_FaceVerts[32];

rdPolyLine* rdPolyLine_New(char *polyline_fname, char *material_fname, char *material_fname2, float length, float base_rad, float tip_rad, int lightmode, int texmode, int sortingmethod, float extraLight)
{
    rdPolyLine* polyline;

    polyline = (rdPolyLine *)rdroid_pHS->alloc(sizeof(rdPolyLine));
    if (polyline)
    {
        rdPolyLine_NewEntry(polyline, polyline_fname, material_fname, material_fname2, length, base_rad, tip_rad, lightmode, texmode, sortingmethod, extraLight);
    }
    return polyline;
}

int rdPolyLine_NewEntry(rdPolyLine *polyline, char *polyline_fname, char *material_side_fname, char *material_tip_fname, float length, float base_rad, float tip_rad, int edgeGeometryMode, int edgeLightingMode, int edgeTextureMode, float extraLight)
{

    rdMaterial *mat;
    int *vertexPosIdx;
    unsigned int numVertices;
    rdVector2 *extraUVTipMaybe;
    int *vertexUVIdx;
    rdVector2 *extraUVFaceMaybe;
    stdVBuffer *v22;

    if ( polyline_fname )
    {
        _strncpy(polyline->fname, polyline_fname, 0x1Fu);
        polyline->fname[31] = 0;
    }
    polyline->length = length;
    polyline->baseRadius = base_rad;
    polyline->edgeFace.textureMode = edgeTextureMode;
    polyline->textureMode = edgeTextureMode;
    polyline->lightingMode = edgeLightingMode;
    polyline->tipRadius = tip_rad;
    polyline->edgeFace.type = 0;
    polyline->edgeFace.geometryMode = edgeGeometryMode;
    polyline->edgeFace.lightingMode = edgeLightingMode;
    polyline->geometryMode = edgeGeometryMode;
    polyline->edgeFace.extraLight = extraLight;

    polyline->edgeFace.material = rdMaterial_Load(material_side_fname, 0, 0);
    if ( !polyline->edgeFace.material )
        return 0;
    polyline->edgeFace.numVertices = 4;
    vertexPosIdx = (int *)rdroid_pHS->alloc(sizeof(int) * polyline->edgeFace.numVertices);
    polyline->edgeFace.vertexPosIdx = vertexPosIdx;
    if ( !vertexPosIdx )
        return 0;
    numVertices = polyline->edgeFace.numVertices;
    for (int i = 0; i < numVertices; ++vertexPosIdx )
        *vertexPosIdx = i++;
    if ( polyline->edgeFace.geometryMode >= 4 )
    {
        vertexUVIdx = (int *)rdroid_pHS->alloc(4 * numVertices);
        polyline->edgeFace.vertexUVIdx = vertexUVIdx;
        if ( !vertexUVIdx )
            return 0;
        for (int j = 0; j < polyline->edgeFace.numVertices; ++vertexUVIdx )
            *vertexUVIdx = j++;
        extraUVTipMaybe = (rdVector2 *)rdroid_pHS->alloc(sizeof(rdVector2) * polyline->edgeFace.numVertices);
        polyline->extraUVTipMaybe = extraUVTipMaybe;
        if ( !extraUVTipMaybe )
            return 0;
        v22 = polyline->edgeFace.material->texinfos[0]->texture_ptr->texture_struct[0];
        extraUVTipMaybe[0].x = (double)((unsigned int)v22->format.width) - 0.0099999998;
        extraUVTipMaybe[0].y = 0.0;
        extraUVTipMaybe[1].x = 0.0;
        extraUVTipMaybe[1].y = 0.0;
        extraUVTipMaybe[2].x = 0.0;
        extraUVTipMaybe[2].y = (double)((unsigned int)v22->format.height) - 0.0099999998;
        extraUVTipMaybe[3].x = (double)((unsigned int)v22->format.width) - 0.0099999998;
        extraUVTipMaybe[3].y = (double)((unsigned int)v22->format.height) - 0.0099999998;
    }
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
    polyline->tipFace.numVertices = 4;
    vertexPosIdx = (int *)rdroid_pHS->alloc(sizeof(int) * polyline->tipFace.numVertices);
    polyline->tipFace.vertexPosIdx = vertexPosIdx;
    if ( !vertexPosIdx )
        return 0;
    for (int k = 0; k < polyline->tipFace.numVertices; ++vertexPosIdx )
        *vertexPosIdx = k++;
    if ( polyline->tipFace.geometryMode >= 4 )
    {
        vertexUVIdx = (int *)rdroid_pHS->alloc(sizeof(int) * polyline->tipFace.numVertices);
        polyline->tipFace.vertexUVIdx = vertexUVIdx;
        if ( !vertexUVIdx )
            return 0;
        for (int l = 0; l < polyline->tipFace.numVertices; ++vertexUVIdx )
            *vertexUVIdx = l++;
        extraUVFaceMaybe = (rdVector2 *)rdroid_pHS->alloc(sizeof(rdVector2) * polyline->tipFace.numVertices);
        polyline->extraUVFaceMaybe = extraUVFaceMaybe;
        if ( !extraUVFaceMaybe )
            return 0;
        v22 = polyline->tipFace.material->texinfos[0]->texture_ptr->texture_struct[0];
        extraUVFaceMaybe[0].x = (double)((unsigned int)v22->format.width) - 0.0099999998;
        extraUVFaceMaybe[0].y = 0.0;
        extraUVFaceMaybe[1].x = 0.0;
        extraUVFaceMaybe[1].y = 0.0;
        extraUVFaceMaybe[2].x = 0.0;
        extraUVFaceMaybe[2].y = (double)((unsigned int)v22->format.height) - 0.0099999998;
        extraUVFaceMaybe[3].x = (double)((unsigned int)v22->format.width) - 0.0099999998;
        extraUVFaceMaybe[3].y = (double)((unsigned int)v22->format.height) - 0.0099999998;
    }
    return 1;
}

void rdPolyLine_Free(rdPolyLine *polyline)
{
    if ( polyline )
    {
        rdPolyLine_FreeEntry(polyline);
        rdroid_pHS->free(polyline);
    }
}

void rdPolyLine_FreeEntry(rdPolyLine *polyline)
{
    if ( polyline->extraUVFaceMaybe )
    {
        rdroid_pHS->free(polyline->extraUVFaceMaybe);
        polyline->extraUVFaceMaybe = 0;
    }
    if ( polyline->extraUVTipMaybe )
    {
        rdroid_pHS->free(polyline->extraUVTipMaybe);
        polyline->extraUVTipMaybe = 0;
    }
    if ( polyline->tipFace.vertexPosIdx )
    {
        rdroid_pHS->free(polyline->tipFace.vertexPosIdx);
        polyline->tipFace.vertexPosIdx = 0;
    }
    if ( polyline->tipFace.vertexUVIdx )
    {
        rdroid_pHS->free(polyline->tipFace.vertexUVIdx);
        polyline->tipFace.vertexUVIdx = 0;
    }
    if ( polyline->edgeFace.vertexPosIdx )
    {
        rdroid_pHS->free(polyline->edgeFace.vertexPosIdx);
        polyline->edgeFace.vertexPosIdx = 0;
    }
    if ( polyline->edgeFace.vertexUVIdx )
    {
        rdroid_pHS->free(polyline->edgeFace.vertexUVIdx);
        polyline->edgeFace.vertexUVIdx = 0;
    }
}

int rdPolyLine_Draw(rdThing *thing, rdMatrix34 *matrix)
{
    rdPolyLine *polyline;
    float length;
    double tip_left;
    double tip_bottom;
    double tip_right;
    double tip_top;
    float ang;
    float angSin;
    float angCos;
    rdVector3 vertex_out;
    rdMatrix34 out;
    rdVector3 vertex;
    rdVertexIdxInfo idxInfo;

    polyline = thing->polyline;
    
    // This is slightly different than IDA?
    idxInfo.numVertices = 4;
    idxInfo.vertices = polylineVerts;
    idxInfo.paDynamicLight = 0;
    idxInfo.intensities = 0;

    rdMatrix_Multiply34(&out, &rdCamera_pCurCamera->view_matrix, matrix);
    vertex.x = 0.0;
    vertex.y = polyline->length;
    vertex.z = 0.0;
    rdMatrix_TransformPoint34(&vertex_out, &vertex, &out);
    tip_left = vertex_out.x - polyline->tipRadius;
    tip_bottom = vertex_out.z - polyline->tipRadius;
    tip_right = vertex_out.x + polyline->tipRadius;
    tip_top = vertex_out.z + polyline->tipRadius;
    polylineVerts[0].x = tip_left;
    polylineVerts[0].y = vertex_out.y - -0.001;
    polylineVerts[0].z = tip_bottom;
    polylineVerts[1].x = tip_right;
    polylineVerts[1].y = vertex_out.y - -0.001;
    polylineVerts[1].z = tip_bottom;
    polylineVerts[2].x = tip_right;
    polylineVerts[2].y = vertex_out.y - -0.001;
    polylineVerts[2].z = tip_top;
    polylineVerts[3].x = tip_left;
    polylineVerts[3].y = vertex_out.y - -0.001;
    polylineVerts[3].z = tip_top;
    idxInfo.vertexUVs = polyline->extraUVFaceMaybe;
    rdPolyLine_DrawFace(thing, &polyline->tipFace, polylineVerts, &idxInfo);

    polylineVerts[0].x = out.scale.x - polyline->baseRadius;
    polylineVerts[0].y = out.scale.y - -0.001;
    polylineVerts[0].z = out.scale.z - polyline->baseRadius;
    polylineVerts[1].x = out.scale.x + polyline->baseRadius;
    polylineVerts[1].y = out.scale.y - -0.001;
    polylineVerts[1].z = out.scale.z - polyline->baseRadius;
    polylineVerts[2].x = out.scale.x + polyline->baseRadius;
    polylineVerts[2].y = out.scale.y - -0.001;
    polylineVerts[2].z = out.scale.z + polyline->baseRadius;
    polylineVerts[3].x = out.scale.x - polyline->baseRadius;
    polylineVerts[3].y = out.scale.y - -0.001;
    polylineVerts[3].z = out.scale.z + polyline->baseRadius;
    idxInfo.vertexUVs = polyline->extraUVFaceMaybe;
    rdPolyLine_DrawFace(thing, &polyline->tipFace, polylineVerts, &idxInfo);
    
    float zdist = vertex_out.z - out.scale.z;
    float xdist = vertex_out.x - out.scale.x;
    float mag = stdMath_Sqrt(xdist * xdist + zdist * zdist);

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
    polylineVerts[2].x = (-polyline->baseRadius * angCos) - (float)0.0 + out.scale.x;
    polylineVerts[2].y = out.scale.y;
    polylineVerts[2].z = (-polyline->baseRadius * angSin) + (float)0.0 + out.scale.z;
    polylineVerts[3].x = (polyline->baseRadius * angCos) - (float)0.0 + out.scale.x;
    polylineVerts[3].y = out.scale.y;
    polylineVerts[3].z = (polyline->baseRadius * angSin) + (float)0.0 + out.scale.z;
    idxInfo.vertexUVs = polyline->extraUVTipMaybe;
    rdPolyLine_DrawFace(thing, &polyline->edgeFace, polylineVerts, &idxInfo);
    return 1;
}

void rdPolyLine_DrawFace(rdThing *thing, rdFace *face, rdVector3 *unused, rdVertexIdxInfo *idxInfo)
{
    rdProcEntry *procEntry;
    int geometryMode;
    int textureMode;
    rdMeshinfo mesh_out;
    float staticLight;

    procEntry = rdCache_GetProcEntry();
    if (!procEntry)
        return;

    mesh_out.verticesProjected = rdPolyLine_FaceVerts;
    mesh_out.verticesOrig = procEntry->vertices;
    mesh_out.vertexUVs = procEntry->vertexUVs;
    mesh_out.paDynamicLight = procEntry->vertexIntensities;
    
    idxInfo->numVertices = face->numVertices;
    idxInfo->vertexPosIdx = face->vertexPosIdx;
    idxInfo->vertexUVIdx = face->vertexUVIdx;
    
    if ( rdroid_curGeometryMode >= face->geometryMode )
        rdroid_curGeometryMode = face->geometryMode;
    geometryMode = thing->geometryMode;
    if ( rdroid_curGeometryMode < thing->geometryMode )
    {
        if ( rdroid_curGeometryMode >= face->geometryMode )
            geometryMode = face->geometryMode;
        else
            geometryMode = rdroid_curGeometryMode;
    }
    
    procEntry->geometryMode = geometryMode;
    if ( rdroid_curRenderOptions & 2 && rdCamera_pCurCamera->ambientLight >= 1.0 )
    {
        procEntry->lightingMode = 0;
    }
    else
    {
        if ( rdroid_curLightingMode >= face->lightingMode )
            rdroid_curLightingMode = face->lightingMode;
        if ( rdroid_curLightingMode >= thing->lightingMode )
        {
            face->lightingMode = thing->lightingMode;
        }
        else if ( rdroid_curLightingMode < face->lightingMode )
        {
            face->lightingMode = rdroid_curLightingMode;
        }
        procEntry->lightingMode = face->lightingMode;
    }
    
    if ( rdroid_curTextureMode >= face->textureMode )
        rdroid_curTextureMode = face->textureMode;
    textureMode = thing->textureMode;
    if ( rdroid_curTextureMode < textureMode )
    {
        if ( rdroid_curTextureMode >= face->textureMode )
            textureMode = face->textureMode;
        else
            textureMode = rdroid_curTextureMode;
    }
    
    procEntry->textureMode = textureMode;
    rdPrimit3_ClipFace(rdCamera_pCurCamera->cameraClipFrustum, geometryMode, procEntry->lightingMode, textureMode, idxInfo, &mesh_out, &face->clipIdk);
    if ( mesh_out.numVertices < 3 )
        return;

    rdCamera_pCurCamera->projectLst(mesh_out.verticesOrig, mesh_out.verticesProjected, mesh_out.numVertices);

    if ( rdroid_curRenderOptions & 2 )
        procEntry->ambientLight = rdCamera_pCurCamera->ambientLight;
    else
        procEntry->ambientLight = 0.0;

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
    
    int procFaceFlags = 1;
    if ( procEntry->geometryMode >= 4 )
        procFaceFlags = 3;
    if ( procEntry->lightingMode >= 3 )
        procFaceFlags |= 4u;

    procEntry->light_flags = 0;
    procEntry->wallCel = thing->wallCel;
    procEntry->type = face->type;
    procEntry->extralight = face->extraLight;
    procEntry->material = face->material;
    rdCache_AddProcFace(0, mesh_out.numVertices, procFaceFlags);
}
