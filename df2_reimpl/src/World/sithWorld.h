#ifndef _SITHWORLD_H
#define _SITHWORLD_H

#include <stdint.h>

#include "Cog/sithCog.h"
#include "Cog/sithCogVm.h"
#include "Engine/rdKeyframe.h"
#include "World/sithThing.h"
#include "Engine/rdMaterial.h"

#define sithWorld_Startup_ADDR (0x004CF6F0)
#define sithWorld_Shutdown_ADDR (0x004CFAB0)
#define sithWorld_SetLoadPercentCallback_ADDR (0x004CFB00)
#define sithWorld_UpdateLoadPercent_ADDR (0x004CFB10)
#define sithWorld_Load_ADDR (0x004CFB30)
#define sithWorld_NewEntry_ADDR (0x004CFD50)
#define sithWorld_Parse_ADDR (0x004CFF20)
#define sithWorld_Free_ADDR (0x004D0080)
#define sithWorld_New_ADDR (0x004D00B0)
#define sithWorld_FreeEntry_ADDR (0x004D00E0)
#define sithWorld_GetMemorySize_ADDR (0x004D0540)
#define sithWorld_set_section_parser_ADDR (0x004D0820)
#define sithWorld_sub_4D08B0_ADDR (0x004D08B0)
#define sithWorld_sub_4D0930_ADDR (0x004D0930)
#define sithWorld_sub_4D0A20_ADDR (0x004D0A20)
#define sithWorld_sub_4D0AA0_ADDR (0x004D0AA0)
#define sithWorld_Verify_ADDR (0x004D0B00)
#define sithWorld_CalcChecksumIdk_ADDR (0x004D0C30)
#define sithWorld_Initialize_ADDR (0x004D0D10)
#define sithWorld_TimeSectionParse_ADDR (0x004D0D50)
#define sithWorld_FindSectionParser_ADDR (0x004D0E20)
#define sithWorld_LoadGeoresource_ADDR (0x004D0E70)


typedef void (__cdecl *sithWorldProgressCallback_t)(float);

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
    uint32_t numModelsLoaded;
    uint32_t numModels;
    rdModel3* models;
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

void sithWorld_SetLoadPercentCallback(sithWorldProgressCallback_t func);
void sithWorld_UpdateLoadPercent(float percent);

#define sithWorld_pCurWorld (*(sithWorld**)0x8339C8)
#define sithWorld_pStatic (*(sithWorld**)0x8339CC)
#define sithWorld_pLoading (*(sithWorld**)0x8339D0)

#endif // _SITHWORLD_H
