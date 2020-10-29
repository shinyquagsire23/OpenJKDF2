#ifndef _SITHWORLD_H
#define _SITHWORLD_H

#include <stdint.h>

#include "Cog/sithCog.h"
#include "Cog/sithCogVm.h"
#include "Engine/rdKeyframe.h"
#include "World/sithThing.h"
#include "Engine/rdMaterial.h"

typedef struct sithWorld
{
    uint32_t level_type_maybe;
    char map_jkl_fname[32];
    char some_text_jk1[32];
    int numColormaps;
    void* colormaps;
    int numSectors;
    void* sectors;
    int numMaterialsLoaded;
    int numMaterials;
    rdMaterial* materials;
    uint32_t materials2;
    int numModelsLoaded;
    int numModels;
    void* models;
    int numSpritesLoaded;
    int numSprites;
    void* sprites;
    int numParticles;
    uint8_t field_80;
    uint8_t field_81;
    uint8_t field_82;
    uint8_t field_83;
    void* particles;
    int numVertices;
    rdVector3* vertices;
    rdVector3* verticesTransformed;
    void* alloc_unk98;
    void* alloc_unk94;
    void* alloc_unk9c;
    int numVertexUVs;
    void* vertexUVs;
    int numSurfaces;
    void* surfaces;
    int numAdjoinsLoaded;
    int numAdjoins;
    void* adjoins;
    int numThingsLoaded;
    int numThings;
    sithThing* things;
    int numTemplatesLoaded;
    int numTemplates;
    sithThing* templates;
    float worldGravity;
    uint32_t field_D8;
    float ceilingSky;
    float horizontalDistance;
    float horizontalPixelsPerRev;
    rdVector2 horizontalSkyOffs;
    rdVector2 ceilingSkyOffs;
    rdVector4 mipmapDistance;
    rdVector4 loadDistance;
    float perspectiveDistance;
    float gouradDistance;
    void* cameraFocus;
    sithThing* playerThing;
    uint32_t field_128;
    int numSoundsLoaded;
    int numSounds;
    void* sounds;
    int numSoundClassesLoaded;
    int numSoundClasses;
    void* soundclasses;
    int numCogScriptsLoaded;
    int numCogScripts;
    sithCogScript* cogScripts;
    int numCogsLoaded;
    int numCogs;
    sithCog* cogs;
    int numAIClassesLoaded;
    int numAIClasses;
    void* aiclasses;
    int numKeyframesLoaded;
    int numKeyframes;
    rdKeyframe* keyframes;
    int numAnimClassesLoaded;
    int numAnimClasses;
    void* animclasses;
} sithWorld;

#define sithWorld_pCurWorld (*(sithWorld**)0x8339C8)
#define sithWorld_pStatic (*(sithWorld**)0x8339CC)
#define sithWorld_pLoading (*(sithWorld**)0x8339D0)

#endif // _SITHWORLD_H
