#include "sithArchLighting.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "jk.h"
#include "globals.h"
#include "General/stdConffile.h"
#include "Main/Main.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdModel3.h"
#include "Raster/rdFace.h"
#include "General/stdMath.h"
#include "Primitives/rdVector.h"
#include "World/sithWorld.h"
#include <math.h>

#ifdef JKM_LIGHTING

static void sithArchLighting_FreeGrid(void);

void sithArchLighting_Free(SithWorld* pWorld)
{
    sithArchLighting_FreeGrid(); // Added
    if (pWorld->aArchlights)
    {
        for (int i = 0; i < pWorld->numArchLights; i++) 
        {
            sithArchLight* psVar3 = &pWorld->aArchlights[i];
            for (int j = 0; j < psVar3->numMeshes; j++) 
            {
                SITH_FREE(psVar3->aMeshes[j].aMono);
                SITH_FREE(psVar3->aMeshes[j].aRed);
                SITH_FREE(psVar3->aMeshes[j].aGreen);
                SITH_FREE(psVar3->aMeshes[j].aBlue);
                //SITH_FREE(psVar3->aMeshes[j]); // MOTS bug
            }
            SITH_FREE(psVar3->aMeshes); // Added: free correctly
        }
        SITH_FREE(pWorld->aArchlights);
        pWorld->aArchlights = NULL;
        pWorld->numArchLights = 0;
    }
}

int sithArchLighting_ParseSection(SithWorld *pWorld, int unk)
{
    uint32_t uVar2;
    sithArchLight *psVar3;
    sithArchLightMesh *psVar4;
    uint32_t uVar5;
    flex_t *pfVar6;
    int iVar7;
    uint32_t uVar8;
    sithArchLightMesh *ppvVar11;
    int iVar9;
    void **ppvVar10;
    char *pcVar11;
    char *pcVar12;
    int bVar13;
    flex_t fVar15;
    flex_t fVar14;
    int iStack12;
    
    if (unk) 
    {
        unk = 0;
        sithArchLighting_Free(pWorld);
    }

    stdConffile_ReadArgs();

    if (strncmp(stdConffile_g_entry.aArgs[0].value, "num", strlen("num"))) return 0;
    if (strncmp(stdConffile_g_entry.aArgs[1].value, "archobjects", strlen("archobjects"))) return 0;

    uVar2 = _atoi(stdConffile_g_entry.aArgs[2].value);
    uVar8 = uVar2 * sizeof(sithArchLight);
    if (uVar8 == 0) {
        uVar8 = sizeof(sithArchLight); // Added: 1 -> sizeof(sithArchLight)
    }
    psVar3 = (sithArchLight *)SITH_ALLOC(uVar8);
    pWorld->aArchlights = psVar3;
    if (!psVar3) return 0;

    pWorld->numArchLights = uVar2;
    unk = 0;
    if (uVar2 != 0) {
        do {
            psVar3 = pWorld->aArchlights + unk;
            stdConffile_ReadArgs();
            _atoi(stdConffile_g_entry.aArgs[1].value);
            stdConffile_ReadArgs();
            if (!strncmp(stdConffile_g_entry.aArgs[0].value, "nummeshes:", strlen("nummeshes:"))) {
                iStack12 = _atoi(stdConffile_g_entry.aArgs[1].value);
                psVar3->numMeshes = iStack12;
                psVar4 = (sithArchLightMesh *)SITH_ALLOC(iStack12 * sizeof(sithArchLightMesh));
                psVar3->aMeshes = psVar4;
                if (iStack12 != 0) {
                    iVar9 = 0;
                    do {
                        stdConffile_ReadArgs();
                        _atoi(stdConffile_g_entry.aArgs[1].value);
                        ppvVar11 = &psVar3->aMeshes[iVar9];
                        stdConffile_ReadArgs();
                        
                        if (!strncmp(stdConffile_g_entry.aArgs[0].value, "numvertices:", strlen("numvertices:"))) {
                            uVar5 = _atoi(stdConffile_g_entry.aArgs[1].value);
                            ppvVar11->numVertices = uVar5;
                            uVar8 = uVar5 * sizeof(flex_t);
                            pfVar6 = (flex_t *)SITH_ALLOC(uVar8);
                            ppvVar11->aMono = pfVar6;
                            pfVar6 = (flex_t *)SITH_ALLOC(uVar8);
                            ppvVar11->aRed = pfVar6;
                            pfVar6 = (flex_t *)SITH_ALLOC(uVar8);
                            ppvVar11->aGreen = pfVar6;
                            pfVar6 = (flex_t *)SITH_ALLOC(uVar8);
                            uVar8 = 0;
                            ppvVar11->aBlue = pfVar6;
                            if (uVar5 != 0) {
                                do {
                                    stdConffile_ReadArgs();
                                    fVar14 = _atof(stdConffile_g_entry.aArgs[1].value);
                                    pcVar11 = stdConffile_g_entry.aArgs[2].value;
                                    ppvVar11->aMono[uVar8] = fVar14;
                                    fVar15 = _atof(pcVar11);
                                    pcVar11 = stdConffile_g_entry.aArgs[3].value;
                                    ppvVar11->aRed[uVar8] = fVar15;
                                    fVar15 = _atof(pcVar11);
                                    pcVar11 = stdConffile_g_entry.aArgs[4].value;
                                    ppvVar11->aGreen[uVar8] = fVar15;
                                    fVar15 = _atof(pcVar11);
                                    ppvVar11->aBlue[uVar8] = fVar15;
                                    uVar8 = uVar8 + 1;
                                } while (uVar8 < uVar5);
                            }
                        }
                        iVar9++;
                        iStack12 = iStack12 + -1;
                    } while (iStack12 != 0);
                }
            }
            unk = unk + 1;
        } while (unk < uVar2);
    }
    return 1;
}

// Added: light for players, weapons and pickups from the level's own baked light.
// Things that are not architecture take only their sector's flat ambient light as the least light
// they get. A JK level built from 3DO architecture that ships its own baked light (ARCHLIGHTING), such
// as a JO/JA import, can be one sector for the whole map, so everything not baked sat at that one value
// (dark even in full sun). Here the upward faces of the baked architecture are sampled once onto a grid
// (height and baked light per cell), and a thing takes the light of the floor right below it, blended
// between neighbouring cells, whenever that is more than its sector's own ambient light.

typedef struct sithArchLighting_GridEntry
{
    flex_t z;
    flex_t light;
} sithArchLighting_GridEntry;

static SithWorld* sithArchLighting_pGridWorld = NULL;
static int sithArchLighting_gridState = 0; // 0: not built, 1: built, -1: nothing to sample
static flex_t sithArchLighting_gridX0, sithArchLighting_gridY0, sithArchLighting_gridCell;
static int sithArchLighting_gridW, sithArchLighting_gridH;
static int* sithArchLighting_aGridStart = NULL;             // gridW * gridH + 1 offsets
static sithArchLighting_GridEntry* sithArchLighting_aGrid = NULL;
// build-time list: (cell, entry)
static int* sithArchLighting_aTmpCell = NULL;
static sithArchLighting_GridEntry* sithArchLighting_aTmpEntry = NULL;
static int sithArchLighting_numTmp = 0, sithArchLighting_sizeTmp = 0;

#define SITHARCHLIGHTING_MAX_FACE_VERTS (32)
#define SITHARCHLIGHTING_MAX_CELLS (4 * 1024 * 1024)
#define SITHARCHLIGHTING_ABOVE (0.05)    // a floor up to this far above a thing's centre still counts (slopes, steps)
#define SITHARCHLIGHTING_BELOW (2.0)     // and down to this far below it (a jump)

static void sithArchLighting_FreeGrid(void)
{
    if (sithArchLighting_aGridStart) SITH_FREE(sithArchLighting_aGridStart);
    if (sithArchLighting_aGrid) SITH_FREE(sithArchLighting_aGrid);
    if (sithArchLighting_aTmpCell) SITH_FREE(sithArchLighting_aTmpCell);
    if (sithArchLighting_aTmpEntry) SITH_FREE(sithArchLighting_aTmpEntry);
    sithArchLighting_aGridStart = NULL;
    sithArchLighting_aGrid = NULL;
    sithArchLighting_aTmpCell = NULL;
    sithArchLighting_aTmpEntry = NULL;
    sithArchLighting_numTmp = sithArchLighting_sizeTmp = 0;
    sithArchLighting_pGridWorld = NULL;
    sithArchLighting_gridState = 0;
}

static int sithArchLighting_AddTmp(int cell, flex_t z, flex_t light)
{
    if (sithArchLighting_numTmp >= sithArchLighting_sizeTmp) {
        int newSize = sithArchLighting_sizeTmp ? sithArchLighting_sizeTmp * 2 : 4096;
        int* pCell = (int*)SITH_REALLOC(sithArchLighting_aTmpCell, newSize * sizeof(int));
        if (!pCell) return 0;
        sithArchLighting_aTmpCell = pCell;
        sithArchLighting_GridEntry* pEntry = (sithArchLighting_GridEntry*)SITH_REALLOC(sithArchLighting_aTmpEntry, newSize * sizeof(sithArchLighting_GridEntry));
        if (!pEntry) return 0;
        sithArchLighting_aTmpEntry = pEntry;
        sithArchLighting_sizeTmp = newSize;
    }
    sithArchLighting_aTmpCell[sithArchLighting_numTmp] = cell;
    sithArchLighting_aTmpEntry[sithArchLighting_numTmp].z = z;
    sithArchLighting_aTmpEntry[sithArchLighting_numTmp].light = light;
    sithArchLighting_numTmp++;
    return 1;
}

// Calls fn for every upward, drawn, solid face of the level's static baked architecture, in world space.
typedef int (*sithArchLighting_FaceFn)(const rdVector3* aPos, const flex_t* aLight, int numVerts);
static int sithArchLighting_ForEachFloorFace(SithWorld* pWorld, sithArchLighting_FaceFn fn)
{
    rdVector3 aPos[SITHARCHLIGHTING_MAX_FACE_VERTS];
    flex_t aLight[SITHARCHLIGHTING_MAX_FACE_VERTS];
    for (int i = 0; i < pWorld->numThingsLoaded; i++)
    {
        SithThing* pThing = &pWorld->aThings[i];
        if (pThing->type == SITH_THING_FREE || pThing->moveType == SITH_MT_PATH)
            continue;
        if (pThing->archlightIdx < 0 || pThing->archlightIdx >= pWorld->numArchLights)
            continue;
        if (pThing->renderData.type != RD_THING_MODEL3 || !pThing->renderData.model3)
            continue;
        rdModel3* pModel = pThing->renderData.model3;
        sithArchLight* pArch = &pWorld->aArchlights[pThing->archlightIdx];
        if (!pModel->numGeos || !pArch->aMeshes)
            continue;
        rdGeoset* pGeoset = &pModel->aGeos[0];
        for (uint32_t j = 0; j < pGeoset->numMeshes && (int)j < pArch->numMeshes; j++)
        {
            rdMesh* pMesh = &pGeoset->aMeshes[j];
            sithArchLightMesh* pLight = &pArch->aMeshes[j];
            if (!pMesh->faces || !pMesh->aVertices || !pLight->aMono || pLight->numVertices < pMesh->numVertices)
                continue;
            // only meshes drawn where the model is (no hierarchy offset or turn)
            int bMoved = 0;
            for (uint32_t n = 0; n < pModel->numHNodes && pModel->aHierarchyNodes; n++)
            {
                rdHierarchyNode* pNode = &pModel->aHierarchyNodes[n];
                if (pNode->meshIdx != j) continue;
                if (pNode->pos.x != 0.0 || pNode->pos.y != 0.0 || pNode->pos.z != 0.0
                    || pNode->rot.x != 0.0 || pNode->rot.y != 0.0 || pNode->rot.z != 0.0
                    || pNode->pivot.x != 0.0 || pNode->pivot.y != 0.0 || pNode->pivot.z != 0.0)
                    bMoved = 1;
            }
            if (bMoved) continue;
            for (int f = 0; f < pMesh->numFaces; f++)
            {
                rdFace* pFace = &pMesh->faces[f];
                if (pFace->geometryMode == 0 || (pFace->type & RD_FF_TEX_TRANSLUCENT) || !pFace->vertexPosIdx)
                    continue;
                if (pFace->numVertices < 3 || pFace->numVertices > SITHARCHLIGHTING_MAX_FACE_VERTS)
                    continue;
                rdVector3 normal;
                rdMatrix_TransformVector34(&normal, &pFace->normal, &pThing->orient);
                if (normal.z < 0.7)
                    continue;
                int bOk = 1;
                for (uint32_t v = 0; v < pFace->numVertices; v++)
                {
                    int vi = pFace->vertexPosIdx[v];
                    if (vi < 0 || vi >= pMesh->numVertices) { bOk = 0; break; }
                    rdMatrix_TransformVector34(&aPos[v], &pMesh->aVertices[vi], &pThing->orient);
                    rdVector_Add3Acc(&aPos[v], &pThing->position);
                    aLight[v] = pLight->aMono[vi];
                }
                if (bOk && !fn(aPos, aLight, pFace->numVertices))
                    return 0;
            }
        }
    }
    return 1;
}

static flex_t sithArchLighting_bbMinX, sithArchLighting_bbMinY, sithArchLighting_bbMaxX, sithArchLighting_bbMaxY;
static int sithArchLighting_numFloorFaces;

static int sithArchLighting_GrowBounds(const rdVector3* aPos, const flex_t* aLight, int numVerts)
{
    for (int v = 0; v < numVerts; v++)
    {
        if (!sithArchLighting_numFloorFaces && !v) {
            sithArchLighting_bbMinX = sithArchLighting_bbMaxX = aPos[0].x;
            sithArchLighting_bbMinY = sithArchLighting_bbMaxY = aPos[0].y;
        }
        if (aPos[v].x < sithArchLighting_bbMinX) sithArchLighting_bbMinX = aPos[v].x;
        if (aPos[v].x > sithArchLighting_bbMaxX) sithArchLighting_bbMaxX = aPos[v].x;
        if (aPos[v].y < sithArchLighting_bbMinY) sithArchLighting_bbMinY = aPos[v].y;
        if (aPos[v].y > sithArchLighting_bbMaxY) sithArchLighting_bbMaxY = aPos[v].y;
    }
    sithArchLighting_numFloorFaces++;
    return 1;
}

static int sithArchLighting_CellOf(flex_t x, flex_t y)
{
    int cx = (int)floor((x - sithArchLighting_gridX0) / sithArchLighting_gridCell);
    int cy = (int)floor((y - sithArchLighting_gridY0) / sithArchLighting_gridCell);
    if (cx < 0) cx = 0;
    if (cy < 0) cy = 0;
    if (cx >= sithArchLighting_gridW) cx = sithArchLighting_gridW - 1;
    if (cy >= sithArchLighting_gridH) cy = sithArchLighting_gridH - 1;
    return cy * sithArchLighting_gridW + cx;
}

// every cell centre inside the face gets the face's height and blended light there
static int sithArchLighting_RasterFace(const rdVector3* aPos, const flex_t* aLight, int numVerts)
{
    flex_t minX = aPos[0].x, maxX = aPos[0].x, minY = aPos[0].y, maxY = aPos[0].y;
    for (int v = 1; v < numVerts; v++)
    {
        if (aPos[v].x < minX) minX = aPos[v].x;
        if (aPos[v].x > maxX) maxX = aPos[v].x;
        if (aPos[v].y < minY) minY = aPos[v].y;
        if (aPos[v].y > maxY) maxY = aPos[v].y;
    }
    const flex_t c = sithArchLighting_gridCell;
    int ix0 = (int)ceil((minX - sithArchLighting_gridX0) / c - 0.5);
    int ix1 = (int)floor((maxX - sithArchLighting_gridX0) / c - 0.5);
    int iy0 = (int)ceil((minY - sithArchLighting_gridY0) / c - 0.5);
    int iy1 = (int)floor((maxY - sithArchLighting_gridY0) / c - 0.5);
    int numAdded = 0;
    for (int iy = iy0; iy <= iy1; iy++)
    {
        if (iy < 0 || iy >= sithArchLighting_gridH) continue;
        flex_t py = sithArchLighting_gridY0 + (iy + 0.5) * c;
        for (int ix = ix0; ix <= ix1; ix++)
        {
            if (ix < 0 || ix >= sithArchLighting_gridW) continue;
            flex_t px = sithArchLighting_gridX0 + (ix + 0.5) * c;
            for (int k = 1; k < numVerts - 1; k++)
            {
                const rdVector3* a = &aPos[0];
                const rdVector3* b = &aPos[k];
                const rdVector3* d = &aPos[k + 1];
                flex_d_t v0x = b->x - a->x, v0y = b->y - a->y, v1x = d->x - a->x, v1y = d->y - a->y;
                flex_d_t v2x = px - a->x, v2y = py - a->y;
                flex_d_t den = v0x * v1y - v1x * v0y;
                if (fabs(den) < 1e-12) continue;
                flex_d_t u = (v2x * v1y - v1x * v2y) / den;
                flex_d_t w = (v0x * v2y - v2x * v0y) / den;
                if (u < -1e-6 || w < -1e-6 || u + w > 1.0 + 1e-6) continue;
                flex_d_t t = 1.0 - u - w;
                flex_t z = (flex_t)(t * a->z + u * b->z + w * d->z);
                flex_t l = (flex_t)(t * aLight[0] + u * aLight[k] + w * aLight[k + 1]);
                if (!sithArchLighting_AddTmp(iy * sithArchLighting_gridW + ix, z, l)) return 0;
                numAdded++;
                break;
            }
        }
    }
    if (!numAdded)
    {
        // smaller than a cell (a step, a ledge): one entry at its middle
        rdVector3 mid = {0, 0, 0};
        flex_t l = 0.0;
        for (int v = 0; v < numVerts; v++)
        {
            rdVector_Add3Acc(&mid, &aPos[v]);
            l += aLight[v];
        }
        if (!sithArchLighting_AddTmp(sithArchLighting_CellOf(mid.x / numVerts, mid.y / numVerts), mid.z / numVerts, l / numVerts))
            return 0;
    }
    return 1;
}

static void sithArchLighting_BuildGrid(SithWorld* pWorld)
{
    sithArchLighting_FreeGrid();
    sithArchLighting_pGridWorld = pWorld;
    sithArchLighting_gridState = -1;

    sithArchLighting_numFloorFaces = 0;
    sithArchLighting_ForEachFloorFace(pWorld, sithArchLighting_GrowBounds);
    if (!sithArchLighting_numFloorFaces)
        return;

    flex_t cell = 0.0625;
    flex_t spanX = sithArchLighting_bbMaxX - sithArchLighting_bbMinX;
    flex_t spanY = sithArchLighting_bbMaxY - sithArchLighting_bbMinY;
    while ((spanX / cell + 2.0) * (spanY / cell + 2.0) > SITHARCHLIGHTING_MAX_CELLS)
        cell *= 2.0;
    sithArchLighting_gridCell = cell;
    sithArchLighting_gridX0 = sithArchLighting_bbMinX - cell;
    sithArchLighting_gridY0 = sithArchLighting_bbMinY - cell;
    sithArchLighting_gridW = (int)(spanX / cell) + 3;
    sithArchLighting_gridH = (int)(spanY / cell) + 3;

    if (!sithArchLighting_ForEachFloorFace(pWorld, sithArchLighting_RasterFace) || !sithArchLighting_numTmp)
    {
        sithArchLighting_FreeGrid();
        sithArchLighting_pGridWorld = pWorld;
        sithArchLighting_gridState = -1;
        return;
    }

    // counting sort of the entries into their cells
    int numCells = sithArchLighting_gridW * sithArchLighting_gridH;
    sithArchLighting_aGridStart = (int*)SITH_ALLOC((numCells + 1) * sizeof(int));
    sithArchLighting_aGrid = (sithArchLighting_GridEntry*)SITH_ALLOC(sithArchLighting_numTmp * sizeof(sithArchLighting_GridEntry));
    if (!sithArchLighting_aGridStart || !sithArchLighting_aGrid)
    {
        sithArchLighting_FreeGrid();
        sithArchLighting_pGridWorld = pWorld;
        sithArchLighting_gridState = -1;
        return;
    }
    memset(sithArchLighting_aGridStart, 0, (numCells + 1) * sizeof(int));
    for (int i = 0; i < sithArchLighting_numTmp; i++)
        sithArchLighting_aGridStart[sithArchLighting_aTmpCell[i] + 1]++;
    for (int i = 0; i < numCells; i++)
        sithArchLighting_aGridStart[i + 1] += sithArchLighting_aGridStart[i];
    int* pFill = (int*)SITH_ALLOC(numCells * sizeof(int));
    if (!pFill)
    {
        sithArchLighting_FreeGrid();
        sithArchLighting_pGridWorld = pWorld;
        sithArchLighting_gridState = -1;
        return;
    }
    memcpy(pFill, sithArchLighting_aGridStart, numCells * sizeof(int));
    for (int i = 0; i < sithArchLighting_numTmp; i++)
        sithArchLighting_aGrid[pFill[sithArchLighting_aTmpCell[i]]++] = sithArchLighting_aTmpEntry[i];
    SITH_FREE(pFill);

    SITH_FREE(sithArchLighting_aTmpCell);
    SITH_FREE(sithArchLighting_aTmpEntry);
    sithArchLighting_aTmpCell = NULL;
    sithArchLighting_aTmpEntry = NULL;
    sithArchLighting_numTmp = sithArchLighting_sizeTmp = 0;
    sithArchLighting_gridState = 1;
}

flex_t sithArchLighting_ThingAmbient(SithThing* pThing, flex_t ambient)
{
    SithWorld* pWorld = sithWorld_g_pCurrentWorld;
    if (Main_bMotsCompat || !pThing || !pWorld || !pWorld->aArchlights || pWorld->numArchLights <= 0)
        return ambient;
    if (pThing->archlightIdx >= 0) // the architecture itself carries its light already
        return ambient;
    if (sithArchLighting_pGridWorld != pWorld || !sithArchLighting_gridState)
        sithArchLighting_BuildGrid(pWorld);
    if (sithArchLighting_gridState != 1)
        return ambient;

    const flex_t c = sithArchLighting_gridCell;
    flex_d_t fx = (pThing->position.x - sithArchLighting_gridX0) / c - 0.5;
    flex_d_t fy = (pThing->position.y - sithArchLighting_gridY0) / c - 0.5;
    int ix = (int)floor(fx), iy = (int)floor(fy);
    flex_d_t tx = fx - ix, ty = fy - iy;
    flex_d_t sum = 0.0, wsum = 0.0;
    for (int dy = 0; dy < 2; dy++)
    {
        int cy = iy + dy;
        if (cy < 0 || cy >= sithArchLighting_gridH) continue;
        for (int dx = 0; dx < 2; dx++)
        {
            int cx = ix + dx;
            if (cx < 0 || cx >= sithArchLighting_gridW) continue;
            int cell = cy * sithArchLighting_gridW + cx;
            flex_t bestZ = -1e30f, bestLight = 0.0;
            int bFound = 0;
            for (int e = sithArchLighting_aGridStart[cell]; e < sithArchLighting_aGridStart[cell + 1]; e++)
            {
                const sithArchLighting_GridEntry* pE = &sithArchLighting_aGrid[e];
                if (pE->z > pThing->position.z + SITHARCHLIGHTING_ABOVE || pE->z < pThing->position.z - SITHARCHLIGHTING_BELOW)
                    continue;
                if (pE->z > bestZ) { bestZ = pE->z; bestLight = pE->light; bFound = 1; }
            }
            if (!bFound) continue;
            flex_d_t w = (dx ? tx : 1.0 - tx) * (dy ? ty : 1.0 - ty);
            sum += w * bestLight;
            wsum += w;
        }
    }
    if (wsum < 1e-4)
        return ambient;
    flex_t light = stdMath_Clamp((flex_t)(sum / wsum), 0.0, 1.0);
    return light > ambient ? light : ambient;
}

#endif // JKM_LIGHTING
