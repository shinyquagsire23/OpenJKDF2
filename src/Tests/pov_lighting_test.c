/* Original synthetic fixture around the complete extracted production DrawPov.
 * Model/saber submission and cache flushing observe the actual selected mode.
 * Math/camera/GPU operations are explicit stubs; this is not an engine ABI test. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "FAIL pov-mono line %d: %s\n", __LINE__, #value); exit(1); } } while (0)
typedef float flex_t;
typedef struct rdVector3 { flex_t x, y, z; } rdVector3;
typedef struct rdMatrix34 { rdVector3 rvec, lvec, uvec, scale; } rdMatrix34;
typedef struct rdThing { void* model3; void* puppet; } rdThing;
typedef struct SithThing {
    flex_t waggle;
    struct { rdVector3 vel; flex_t maxVelocity; } physicsParams;
    struct { rdVector3 eyeOffset; } actorParams;
    int jkFlags;
} SithThing;
typedef struct rdCamera { flex_t aspectRatio, ambientLight; } rdCamera;
typedef struct SithSector { flex_t extraLight, ambientLight; void* colormap; } SithSector;
typedef struct SithCamera {
    int type;
    SithThing* pPrimaryFocusThing;
    SithSector* sector;
    rdCamera rdCamera;
    rdMatrix34 orient;
} SithCamera;
static struct { rdThing povModel; SithThing* actorThing; } playerThings[1];
static int playerThingIdx;
static struct { SithThing* pCameraFocusThing; } world;
static SithCamera camera, *sithCamera_g_pCurCamera=&camera;
#define sithWorld_g_pCurrentWorld (&world)
static flex_t sithTime_g_frameTimeFlex=.04f, jkPlayer_waggleMag=1, jkPlayer_waggleAngle;
static int jkPlayer_bDisableWeaponWaggle;
static rdVector3 jkPlayer_waggleVec, jkSaber_rotateVec;
static rdMatrix34 jkSaber_rotateMat;
enum { RD_ZBUFFER_READ_WRITE=1, RD_ZBUFFER_NOREAD_NOWRITE=2, RD_ZBUFFER_READ_NOWRITE=3, JKFLAG_SABERON=1 };
static int colorMode, modelDraws, saberDraws, flushes, puppetUpdates, zClears, modeAssignments;
static int rdModel3_bRenderingPOV;
static void rdSetVertexColorMode(int mode) { colorMode=mode; modeAssignments++; }
static void rdPuppet_UpdateTracks(void* puppet, flex_t dt) { CHECK(puppet && dt==.04f); puppetUpdates++; }
static flex_t stdMath_Fabs(flex_t value) { return fabsf(value); }
static flex_t stdMath_Clamp(flex_t value, flex_t lo, flex_t hi) { return value<lo?lo:value>hi?hi:value; }
static void stdMath_SinCos(flex_t angle, flex_t* sine, flex_t* cosine) { *sine=sinf(angle); *cosine=cosf(angle); }
static flex_t rdVector_Len3(rdVector3* value) { return sqrtf(value->x*value->x+value->y*value->y+value->z*value->z); }
static void rdMatrix_BuildRotate34(rdMatrix34* matrix, rdVector3* value) { memset(matrix,0,sizeof(*matrix)); matrix->scale=*value; }
static void std3D_ClearZBuffer(void) { zClears++; }
static void rdSetZBufferMethod(int mode) { (void)mode; }
static void rdSetSortingMethod(int mode) { CHECK(mode==2); }
static void rdSetOcclusionMethod(int mode) { CHECK(mode==0); }
static void rdCamera_SetAmbientLight(rdCamera* value, flex_t ambient) { value->ambientLight=ambient; }
static void rdColormap_SetCurrent(void* value) { (void)value; }
static void rdMatrix_Copy34(rdMatrix34* target, const rdMatrix34* value) { *target=*value; }
static void rdVector_Copy3(rdVector3* target, const rdVector3* value) { *target=*value; }
static void rdVector_Neg3Acc(rdVector3* value) { value->x=-value->x; value->y=-value->y; value->z=-value->z; }
static void rdMatrix_PreTranslate34(rdMatrix34* matrix, rdVector3* value) { matrix->scale=*value; }
static void rdMatrix_PreMultiply34(rdMatrix34* matrix, rdMatrix34* value) { (void)matrix; (void)value; }
static void jkSaber_Draw(rdMatrix34* matrix) { CHECK(matrix && colorMode==0); saberDraws++; }
static void rdThing_Draw(rdThing* thing, rdMatrix34* matrix) {
    CHECK(thing==&playerThings[0].povModel && matrix && colorMode==0);
    CHECK(rdModel3_bRenderingPOV==1);
    modelDraws++;
}
static void rdCache_Flush(void) {
    CHECK(colorMode==0 && modelDraws==1 && rdModel3_bRenderingPOV==0);
    flushes++;
}

#include "actual_draw_pov.inc"

static SithThing player, other;
static SithSector sector;
static void setup(void) {
    memset(&player,0,sizeof(player)); memset(&camera,0,sizeof(camera));
    memset(playerThings,0,sizeof(playerThings)); memset(&sector,0,sizeof(sector));
    player.physicsParams.maxVelocity=1; player.jkFlags=JKFLAG_SABERON;
    playerThings[0].actorThing=&player; playerThings[0].povModel.model3=&player;
    playerThings[0].povModel.puppet=&player;
    camera.pPrimaryFocusThing=&player; camera.sector=&sector; world.pCameraFocusThing=&player;
    sector.ambientLight=.25f; sector.extraLight=.25f; camera.rdCamera.aspectRatio=1;
    colorMode=1; modelDraws=saberDraws=flushes=puppetUpdates=zClears=modeAssignments=0;
    rdModel3_bRenderingPOV=0;
}
int main(void) {
    for (int incoming=0; incoming<=1; incoming++) {
        setup(); colorMode=incoming; jkPlayer_DrawPov();
        CHECK(colorMode==0 && modelDraws==1 && saberDraws==1);
        CHECK(rdModel3_bRenderingPOV==0);
        CHECK(puppetUpdates==1 && camera.rdCamera.ambientLight==.5f);
#ifdef SDL2_RENDER
        CHECK(flushes==2 && zClears==1);
#else
        CHECK(flushes==1 && zClears==0);
#endif
    }
    setup(); player.jkFlags=0; jkPlayer_DrawPov(); CHECK(modelDraws==1 && saberDraws==0 && colorMode==0);
    setup(); playerThings[0].povModel.model3=NULL; jkPlayer_DrawPov();
    CHECK(colorMode==1 && modeAssignments==0 && modelDraws==0 && flushes==0 && puppetUpdates==0);
    setup(); camera.type=4; jkPlayer_DrawPov();
    CHECK(colorMode==1 && modeAssignments==0 && modelDraws==0 && flushes==0 && puppetUpdates==1);
    CHECK(rdModel3_bRenderingPOV==0);
    setup(); camera.pPrimaryFocusThing=&other; jkPlayer_DrawPov();
    CHECK(colorMode==1 && modeAssignments==0 && modelDraws==0 && flushes==0 && puppetUpdates==1);
    puts("PASS actual DrawPov: RGB/mono entry, weapon/saber/cache mono contract, absent-model and non-POV paths");
    return 0;
}
