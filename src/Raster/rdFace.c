#include "rdFace.h"

#include "stdPlatform.h"
#include "Engine/rdroid.h"

rdFace *rdFace_New()
{
    rdFace *out;

    out = (rdFace*)RDROID_ALLOC(sizeof(rdFace));
    if (!out)
        return 0;

    rdFace_NewEntry(out);
    return out;
}

int rdFace_NewEntry(rdFace* pFace)
{
    pFace->num = 0;
    pFace->type = 0;
    pFace->numVertices = 0;
    pFace->vertexPosIdx = 0;
    pFace->vertexUVIdx = 0;
    pFace->material = 0;
    pFace->wallCel = -1;
    pFace->normal.x = 0.0;
    pFace->normal.y = 0.0;
    pFace->normal.z = 0.0;
    pFace->texVertOffset.x = 0.0;
    pFace->texVertOffset.y = 0.0;
    pFace->extraLight = 0.0;
    return 1;
}

void rdFace_Free(rdFace *pFace)
{
    if (!pFace)
        return;
    rdFace_FreeEntry(pFace);
}

void rdFace_FreeEntry(rdFace *pFace)
{
    if ( pFace->vertexPosIdx )
        RDROID_FREE(pFace->vertexPosIdx);
    if ( pFace->vertexUVIdx )
        RDROID_FREE(pFace->vertexUVIdx);
}
