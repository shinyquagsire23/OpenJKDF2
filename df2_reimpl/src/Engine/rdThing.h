#ifndef _RDTHING_H
#define _RDTHING_H

#include "Primitives/rdMatrix.h"
#include "types.h"

enum RD_THINGTYPE
{
    RD_THINGTYPE_0   = 0,
    RD_THINGTYPE_MODEL  = 1,
    RD_THINGTYPE_CAMERA  = 2,
    RD_THINGTYPE_LIGHT  = 3,
    RD_THINGTYPE_SPRITE3  = 4,
    RD_THINGTYPE_PARTICLECLOUD  = 5,
    RD_THINGTYPE_POLYLINE  = 6
};

typedef struct sithThing sithThing;

typedef struct rdThing
{
    int type;
    union containedObj
    {
        void* model3;
        void* camera;
        void* light;
        void* sprite3;
        void* particlecloud;
        void* polyline;
    };
    uint32_t gap8;
    uint32_t field_C;
    uint32_t field_10;
    void* puppet; // rdPuppet*
    uint32_t field_18;
    uint32_t field_1C;
    rdMatrix34 *hierarchyNodeMatrices;
    uint32_t hierarchyNodes2;
    int* amputatedJoints;
    uint32_t gap2C;
    uint32_t dword30;
    uint32_t lightingMode;
    uint32_t textureMode;
    uint32_t sortingMethod;
    uint32_t clippingIdk;
    sithThing* parentSithThing;
} rdThing;

#endif // _RDTHING_H
