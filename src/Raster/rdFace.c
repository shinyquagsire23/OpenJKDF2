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

int rdFace_NewEntry(rdFace* out)
{
    out->num = 0;
    out->type = 0;
    out->numVertices = 0;
    out->vertexPosIdx = 0;
    out->vertexUVIdx = 0;
    out->material = 0;
    out->wallCel = -1;
    out->normal.x = 0.0;
    out->normal.y = 0.0;
    out->normal.z = 0.0;
    out->texVertOffset.x = 0.0;
    out->texVertOffset.y = 0.0;
    out->extraLight = 0.0;
    return 1;
}

void rdFace_Free(rdFace *face)
{
    if (!face)
        return;
    rdFace_FreeEntry(face);
}

void rdFace_FreeEntry(rdFace *face)
{
    if ( face->vertexPosIdx )
        RDROID_FREE(face->vertexPosIdx);
    if ( face->vertexUVIdx )
        RDROID_FREE(face->vertexUVIdx);
}
