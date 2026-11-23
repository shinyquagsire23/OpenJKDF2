/* Complete extracted alpha/ARCH functions and RGB primitive/clippers, plus
 * exact opaque setup and solid-cache normalization/encoding blocks. Camera projection, cache
 * submission and unrelated mono/non-Gouraud clippers are explicit stubs.
 * Public lighting records are extracted; world/model fixtures contain only
 * the fields accessed here and do not assert the complete engine ABI.
 * No proprietary assets, window, GL context or game process is used.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#define JKM_LIGHTING
#define SDL2_RENDER
#define SITHRENDER_SPHERE_TEST_SURFACES
#define NO_ALIAS
#define LIKELY(x) (x)
#define _memcpy memcpy
#define __int64 int64_t
typedef float flex_t;
typedef double flex_d_t;
typedef int32_t rdGeoMode_t;
typedef int32_t rdLightMode_t;
typedef int32_t rdTexMode_t;
typedef struct { flex_t x, y; } rdVector2;
typedef struct { flex_t x, y, z; } rdVector3;
typedef struct { int unused; } rdMaterial;
typedef struct rdColormap rdColormap;
#include "actual_types.inc"
#include "actual_constants.inc"
#define SITH_SURFACE_1000000 0x1000000
#define rdCameraProjectType_Perspective 1
#define rdVector_Copy3(dst, src) (*(dst) = *(src))
#define STD_ARRAYLEN(a) (sizeof(a) / sizeof((a)[0]))
#define RD_ASSERTREL(x) assert(x)

static unsigned checks;
static const char* scenario = "setup";
static void check(int ok, const char* expr, int line) {
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL %s line %d: %s\n", scenario, line, expr); exit(1); }
}
#define CHECK(x) check(!!(x), #x, __LINE__)
#define NEAR(a,b) CHECK(fabs((double)(a)-(double)(b)) < 0.00001)
static flex_t stdMath_Clamp(flex_t v, flex_t lo, flex_t hi) { return v < lo ? lo : v > hi ? hi : v; }

typedef struct { uint32_t numMeshes; struct rdMesh* aMeshes; } rdGeoset;
typedef struct rdMesh {
    int numVertices;
    flex_t *vertices_i, *vertices_unk, *paRedIntensities, *paGreenIntensities, *paBlueIntensities;
    rdVector3 *aVertices, *vertexNormals;
    flex_t extraLight;
} rdMesh;
typedef struct { uint32_t numGeos; rdGeoset aGeos[4]; } rdModel3;
typedef struct { int archlightIdx; struct { rdModel3* model3; int type; } renderData; } SithThing;
typedef struct {
    rdClipFrustum* pClipFrustum;
    flex_t ambientLight, extraLight;
    rdColormap* colormap;
    int id;
} SithSector;
typedef struct {
    SithSector* pSector;
    int flags, field_4;
    sithSurfaceInfo surfaceInfo;
    rdVector3 center;
    flex_t radius;
} SithSurface;
typedef struct {
    rdVector3 *aVertices, *aTransformedVertices;
    rdVector2* aTexVerticies;
    flex_t* aVertDynamicLights;
    int* alloc_unk98;
    rdColormap* colormaps;
    int numArchLights;
    sithArchLight* aArchlights;
} SithWorld;
typedef struct {
    rdClipFrustum* pClipFrustum;
    int projectType, orient;
    flex_t ambientLight, attenuationMin;
    void (*pfProjectList)(rdVector3*, const rdVector3*, unsigned);
} rdCamera;
static rdCamera camera;
static rdCamera* rdCamera_g_pCurCamera = &camera;
static SithWorld world;
static SithWorld* sithWorld_g_pCurrentWorld = &world;
static int sithRender_numAlphaAdjoins, sithRender_lastRenderTick, sithRender_lightingIRMode;
static int sithRender_geoMode = 4, sithRender_lightMode = 3, sithRender_texMode = 3;
static int rdroid_curAcceleration = 1, sithRender_renderflags, colorMode;
static flex_t sithRender_008d4098, sithRender_f_83198C;
static SithSurface* sithRender_aAlphaAdjoins[4];
static rdMeshinfo sithRender_faceView, meshinfo_out;
static rdVector3 sithRender_aClipVertices[32];
static rdClipFrustum sithRender_absoluteMaxFrustum;
static int sphereResult, submitted, flushes, zbuffer, sorting, occlusion, monoClipCalls;
static rdProcEntry entry;
static rdVector3 projected[32];
static rdVector2 outUv[32];
static flex_t outMono[32], outR[32], outG[32], outB[32];
static int rdGetVertexColorMode(void) { return colorMode; }
static void rdSetVertexColorMode(int v) { colorMode = v; }
static void rdSetZBufferMethod(int v) { zbuffer = v; }
static void rdSetOcclusionMethod(int v) { occlusion = v; }
static void rdSetSortingMethod(int v) { sorting = v; }
static void rdSetProcFaceUserData(int v) { CHECK(v == 7); }
static void rdCache_Flush(void) { ++flushes; }
static rdProcEntry* rdCache_GetProcEntry(void) { return &entry; }
static void rdCamera_SetAmbientLight(rdCamera* c, flex_t v) { c->ambientLight = v; }
static void rdColormap_SetCurrent(rdColormap* c) { entry.colormap = c; }
static void rdMatrix_TransformPoint34(rdVector3* d, const rdVector3* s, const int* m) { (void)m; *d = *s; }
static void rdMatrix_TransformPoint34Acc(rdVector3* d, const int* m) { (void)d; (void)m; }
static int rdClip_SphereInFrustrum(const rdClipFrustum* f, const rdVector3* p, flex_t r) {
    (void)f; (void)p; (void)r; return sphereResult;
}
static void project(rdVector3* d, const rdVector3* s, unsigned n) { memcpy(d, s, n * sizeof(*d)); }
static void rdCache_AddProcFace(int a, unsigned n, char flags) {
    CHECK(a == 0); CHECK(n >= 3 && n <= 32); CHECK(flags & 1);
    entry.numVertices = n; ++submitted;
}
static void rdPrimit3_NoClipFace(int geo, int light, int tex, rdMeshinfo* in, rdMeshinfo* out, rdVector2* offset) {
    (void)geo; (void)light; (void)tex; (void)offset; ++monoClipCalls;
    out->numVertices = in->numVertices;
    for (unsigned i = 0; i < in->numVertices; ++i) {
        int v = in->vertexPosIdx[i];
        out->aVertices[i] = in->aVertices[v];
        out->paDynamicLight[i] = stdMath_Clamp(in->intensities[i] + in->paDynamicLight[v], 0, 1);
    }
}
static void rdPrimit3_ClipFace(const rdClipFrustum* f, int geo, int light, int tex,
                             rdMeshinfo* in, rdMeshinfo* out, rdVector2* offset) {
    (void)f; rdPrimit3_NoClipFace(geo, light, tex, in, out, offset);
}
// Non-Gouraud fallback clippers are outside these regression scenarios.
static int rdClip_Face3S(const rdClipFrustum* f, rdVector3* v, int n) { (void)f; (void)v; return n; }
#define rdClip_Face3SOrtho rdClip_Face3S
#define rdClip_Face3W rdClip_Face3S
#define rdClip_Face3WOrtho rdClip_Face3S
static int rdClip_Face3GT(const rdClipFrustum* f, rdVector3* v, rdVector2* uv, int n) {
    (void)uv; return rdClip_Face3S(f, v, n);
}
#define rdClip_Face3TOrtho rdClip_Face3GT
static int rdClip_g_faceStatus;
#include "actual_clip_buffers.inc"
#include "actual_clip.inc"
#include "actual_primitive.inc"
static void rdVector_Add2Acc(rdVector2* a, const rdVector2* b) { a->x+=b->x; a->y+=b->y; }
#include "actual_model_primitive.inc"
#ifdef OLD_ALPHA
#include "old_alpha.inc"
#else
#include "actual_alpha.inc"
#endif

static size_t allocations, releases;
static int failAllocation, drawResult, drawCalls, expectedArch, expectedRgb;
static rdMesh* checkedMesh;
static flex_t* expectedScratch;
static flex_t* expectedBase;
static sithArchLightMesh* checkedArch;
static void* test_alloc(size_t n) { if (failAllocation) return NULL; ++allocations; return malloc(n); }
static void test_free(void* p) { ++releases; free(p); }
#define SITH_ALLOC test_alloc
#define SITH_FREE test_free
static int sithRender_RenderThing(SithThing* t) {
    ++drawCalls;
    if(t->renderData.type!=RD_THING_MODEL3) return drawResult;
    CHECK(checkedMesh->vertices_unk == expectedScratch);
    CHECK(checkedMesh->vertices_i == (expectedArch && !expectedRgb ? checkedArch->aMono : expectedBase));
    if (expectedRgb) {
        CHECK(checkedMesh->paRedIntensities == (expectedArch ? checkedArch->aRed : expectedBase));
        CHECK(checkedMesh->paGreenIntensities == (expectedArch ? checkedArch->aGreen : expectedBase));
        CHECK(checkedMesh->paBlueIntensities == (expectedArch ? checkedArch->aBlue : expectedBase));
    }
    // A real draw writes its calculated lights into the scratch buffer.
    checkedMesh->vertices_unk[0] = 0.9f;
    return drawResult;
}
#include "actual_arch.inc"

static int Main_bMotsCompat=1;
static void rdVector_Sub3(rdVector3* out, const rdVector3* a, const rdVector3* b) {
    *out=(rdVector3){a->x-b->x,a->y-b->y,a->z-b->z};
}
static flex_t rdVector_Dot3(const rdVector3* a,const rdVector3* b) { return a->x*b->x+a->y*b->y+a->z*b->z; }
static flex_t rdVector_Len3(const rdVector3* a) { return sqrtf(rdVector_Dot3(a,a)); }
static flex_t rdVector_Normalize3Acc(rdVector3* a) {
    flex_t len=rdVector_Len3(a); if(len) {a->x/=len; a->y/=len; a->z/=len;} return len;
}
#ifdef OLD_VERTEX_BASE
#include "old_light.inc"
#else
#include "actual_light.inc"
#endif
static rdLight* apMeshLights[2];
static rdVector3 rdModel3_aLocalLightPos[2],rdModel3_aLocalLightDir[2];
static int rdModel3_numMeshLights;
static void calculate_model(rdMesh* pCurMesh) {
    rdMesh* pMesh=pCurMesh;
#ifdef OLD_DOUBLE_BASE
#include "old_model_light_call.inc"
#else
#include "actual_model_light_call.inc"
#endif
}

static struct { flex_t lightLevel; } rdCache_aHWVertices[1];
static int rdCache_totalVerts;
// The wrapper preserves every production statement in both contiguous blocks,
// including the Gouraud branch, scalar fallback and goto join point.
static rdColor24 solid(rdProcEntry* active_6c, int lighting_capability, flex_t v148, unsigned solidColor) {
    flex_t *v70; int v71; flex_t v72, v73, v75, v76, v78;
#ifdef OLD_SCALE
#include "old_solid_normalize.inc"
#else
#include "actual_solid_normalize.inc"
#endif
LABEL_232:;
    int vtx_idx = 0;
    struct { struct { unsigned solidColor; } header; } texinfo = {{solidColor}}, *v137 = &texinfo;
    rdColormap* v91;
    flex_t v92;
    int v93, v94, v95, v96, v97, v98, red_and_alpha, green, blue;
#ifdef OLD_CHANNELS
#include "old_solid_encode.inc"
#else
#include "actual_solid_encode.inc"
#endif
    return (rdColor24){(uint8_t)red_and_alpha, (uint8_t)green, (uint8_t)blue};
}

// Execute the contiguous production setup, including its accelerated/software
// decision. The rest of the opaque surface traversal is outside this fixture.
static void begin_opaque(void) {
#ifdef OLD_OPAQUE_ACCELERATED
#include "old_opaque_accelerated.inc"
#elif defined(OLD_OPAQUE_SOFTWARE)
#include "old_opaque_software.inc"
#else
#include "actual_opaque_setup.inc"
#endif
}

static void test_opaque(void) {
    scenario = "opaque";
    uint8_t table[64*256] = {0};
    rdColormap map = {.lightlevel=table};
    table[7]=3; map.colors[3]=(rdColor24){10,30,70};
    table[31*256+7]=4; map.colors[4]=(rdColor24){22,44,66};
    for (int accelerated=0; accelerated<2; ++accelerated)
    for (int rgb=0; rgb<2; ++rgb)
    for (int occlusionOff=0; occlusionOff<2; ++occlusionOff)
    for (int prior=0; prior<2; ++prior) {
        rdroid_curAcceleration=accelerated;
        sithRender_renderflags=(rgb ? 0x80 : 0) | (occlusionOff ? 0x20 : 0);
        colorMode=prior; zbuffer=sorting=occlusion=-1;
        begin_opaque();
        CHECK(colorMode == (accelerated && rgb));
        CHECK(zbuffer == (accelerated ? RD_ZBUFFER_READ_WRITE : RD_ZBUFFER_NOREAD_WRITE));
        CHECK(sorting == 0);
        CHECK(occlusion == (accelerated ? -1 : !occlusionOff));
        // Observe the selected mode's effect through the actual cache blocks,
        // with independently calculated palette/RGB bytes.
        flex_t r=.1f,g=.2f,b=.3f,mono=.5f;
        rdProcEntry e={.numVertices=1,.paRedIntensities=&r,.paGreenIntensities=&g,.paBlueIntensities=&b,
            .vertexIntensities=&mono,.colormap=&map};
        rdColor24 got=solid(&e,3,0,7);
        if (accelerated && rgb) CHECK(got.r==35 && got.g==80 && got.b==146);
        else CHECK(got.r==22 && got.g==44 && got.b==66);
    }
}

static rdVector3 vertices[9], transformed[9];
static rdVector2 uvs[9];
static flex_t dynamic[9], intensities[12];
static int ticks[9], indices[3] = {8, 2, 5}, uvIndices[3] = {1, 6, 3};
static rdColormap cmap;
static SithSector sector;
static SithSurface surface;
static rdClipFrustum frustum;

static void setup_alpha(void) {
    scenario = "alpha";
    memset(&entry, 0, sizeof(entry)); memset(outMono, 0, sizeof(outMono));
    memset(&world, 0, sizeof(world)); memset(ticks, 0, sizeof(ticks));
    memset(&surface, 0, sizeof(surface));
    frustum = (rdClipFrustum){.bClipFar=1, .nearPlane=1, .farPlane=10, .farTop=1, .bottom=-1,
        .farLeft=-1, .right=1, .nearTop=1, .nearLeft=-1};
    camera = (rdCamera){.pClipFrustum=&frustum, .projectType=1, .pfProjectList=project};
    sector = (SithSector){.pClipFrustum=&frustum, .ambientLight=.3f, .extraLight=.1f, .colormap=&cmap, .id=7};
    world.aVertices=vertices; world.aTransformedVertices=transformed; world.aTexVerticies=uvs;
    world.aVertDynamicLights=dynamic; world.alloc_unk98=ticks; world.colormaps=&cmap;
    vertices[8]=(rdVector3){-.5f,2,-.5f}; vertices[2]=(rdVector3){.5f,2,-.5f}; vertices[5]=(rdVector3){0,2,.5f};
    dynamic[8]=.1f; dynamic[2]=.2f; dynamic[5]=.3f;
    for (int i=0;i<9;++i) uvs[i]=(rdVector2){(flex_t)i,(flex_t)(i*2)};
    for (int i=0;i<3;++i) { intensities[i]=.9f; intensities[i+3]=.1f; intensities[i+6]=.2f; intensities[i+9]=.3f; }
    surface.pSector=&sector; surface.flags=SITH_SURFACE_1000000; surface.radius=.5f;
    surface.surfaceInfo.intensities=intensities;
    surface.surfaceInfo.face=(rdFace){.geometryMode=4,.lightingMode=3,.textureMode=3,.numVertices=3,
        .vertexPosIdx=indices,.vertexUVIdx=uvIndices,.extraLight=.05f,.type=2};
    entry.aVertices=projected; entry.aTexVerticies=outUv; entry.vertexIntensities=outMono;
    entry.paRedIntensities=outR; entry.paGreenIntensities=outG; entry.paBlueIntensities=outB;
    sithRender_aAlphaAdjoins[0]=&surface; sithRender_numAlphaAdjoins=1; sithRender_lastRenderTick=7;
    sithRender_renderflags=0x80; rdroid_curAcceleration=1; colorMode=0; sphereResult=SPHERE_FULLY_INSIDE;
    submitted=flushes=monoClipCalls=0; sithRender_008d4098=.1f;
}

static void render_alpha(void) {
    sithRender_RenderAlphaAdjoins();
    CHECK(occlusion == 0);
}

static void test_alpha(void) {
    for(int clipped=0;clipped<2;++clipped) for(int geo=3;geo<=4;++geo) {
        setup_alpha(); sphereResult=clipped?SPHERE_CLIPPING_EDGE:SPHERE_FULLY_INSIDE;
        surface.surfaceInfo.face.geometryMode=geo;
        render_alpha();
        CHECK(submitted==1); CHECK(colorMode==1); CHECK(monoClipCalls==0); CHECK(entry.lightingMode==3);
        CHECK(entry.numVertices==3); CHECK(camera.pClipFrustum==&frustum);
        NEAR(camera.ambientLight,.5); NEAR(entry.ambientLight,.2); NEAR(entry.extralight,.05);
        CHECK(zbuffer==RD_ZBUFFER_READ_WRITE); CHECK(sorting==2); CHECK(flushes==2);
        for(int i=0;i<3;++i) { NEAR(outR[i],.2+.1*i); NEAR(outG[i],.3+.1*i); NEAR(outB[i],.4+.1*i); }
        if(geo==4) { NEAR(outUv[0].x,1); NEAR(outUv[1].x,6); NEAR(outUv[2].x,3); }
    }
    setup_alpha(); surface.flags=0; render_alpha();
    for(int i=0;i<3;++i) { NEAR(outR[i],1); NEAR(outG[i],1); NEAR(outB[i],1); }
    setup_alpha(); sithRender_renderflags=0; colorMode=1; render_alpha();
    CHECK(colorMode==0); CHECK(monoClipCalls==1);
    setup_alpha(); rdroid_curAcceleration=0; render_alpha(); CHECK(colorMode==0);
    setup_alpha(); sphereResult=SPHERE_FULLY_OUTSIDE; render_alpha(); CHECK(submitted==0);
    // A triangle crossing the near plane produces two new interpolated corners.
    setup_alpha(); sphereResult=SPHERE_CLIPPING_EDGE;
    vertices[8]=(rdVector3){0,.5f,0}; vertices[2]=(rdVector3){.5f,2,0}; vertices[5]=(rdVector3){0,2,.5f};
    render_alpha(); CHECK(submitted==1); CHECK(entry.numVertices==4);
    int intersections=0;
    for(unsigned i=0;i<entry.numVertices;++i) {
        if(fabs(projected[i].y-1)<.00001) {
            ++intersections; NEAR(outG[i]-outR[i],.1); NEAR(outB[i]-outG[i],.1);
            CHECK(outR[i]>.2f && outR[i]<.4f);
        }
    }
    CHECK(intersections==2);
    // Exercise all six frustum planes in both RGB clipper variants. Constant
    // channel differences must survive independently interpolated clip points.
    const rdVector3 outside[6]={{-3,2,0},{3,2,0},{0,2,3},{0,2,-3},{0,.5f,0},{0,11,0}};
    for(int plane=0;plane<6;++plane) for(int geo=3;geo<=4;++geo) {
        setup_alpha(); sphereResult=SPHERE_CLIPPING_EDGE;
        surface.surfaceInfo.face.geometryMode=geo;
        vertices[8]=outside[plane];
        vertices[2]=(rdVector3){.5f,2,-.5f}; vertices[5]=(rdVector3){-.5f,2,.5f};
        render_alpha(); CHECK(submitted==1); CHECK(entry.numVertices==4);
        for(unsigned i=0;i<entry.numVertices;++i) {
            CHECK(projected[i].y>=.99999f && projected[i].y<=10.00001f);
            CHECK(projected[i].x>=-projected[i].y-.00001f && projected[i].x<=projected[i].y+.00001f);
            CHECK(projected[i].z>=-projected[i].y-.00001f && projected[i].z<=projected[i].y+.00001f);
            NEAR(outG[i]-outR[i],.1); NEAR(outB[i]-outG[i],.1);
        }
    }
}

static void test_solid(void) {
    scenario="solid"; colorMode=1;
    uint8_t table[64*256]={0}; rdColormap map={.lightlevel=table};
    table[7]=3; map.colors[3]=(rdColor24){10,30,70};
    flex_t r=.1f,g=.2f,b=.3f,mono=.4f;
    rdProcEntry e={.numVertices=1,.paRedIntensities=&r,.paGreenIntensities=&g,.paBlueIntensities=&b,
        .vertexIntensities=&mono,.colormap=&map};
    rdColor24 got=solid(&e,3,0,7);
    CHECK(got.r==35); CHECK(got.g==80); CHECK(got.b==146);
    NEAR(r,.1); NEAR(g,.2); NEAR(b,.3); NEAR(rdCache_aHWVertices[0].lightLevel,.18596);
    r=-1;g=.1f;b=2;e.extralight=.2f;
    got=solid(&e,3,.25f,7);
    CHECK(got.r==73); CHECK(got.g==106); CHECK(got.b==255);
    NEAR(r,.25); NEAR(g,.3); NEAR(b,1);
    colorMode=0; e.extralight=0; mono=.5f;
    table[31*256+7]=4; map.colors[4]=(rdColor24){22,44,66};
    got=solid(&e,3,0,7); CHECK(got.r==22 && got.g==44 && got.b==66); NEAR(mono,31.5);
    map.colors[7]=(rdColor24){11,33,55}; got=solid(&e,0,0,7); CHECK(got.r==11 && got.g==33 && got.b==55);
    colorMode=1; e.extralight=.25f; r=.7f; g=.8f; b=.9f;
    got=solid(&e,1,.5f,7); CHECK(got.r==22 && got.g==44 && got.b==66);
    NEAR(r,.7); NEAR(g,.8); NEAR(b,.9);
    e.light_level_static=.1f; e.extralight=.2f;
    table[18*256+7]=5; map.colors[5]=(rdColor24){19,29,39};
    got=solid(&e,2,.1f,7); CHECK(got.r==19 && got.g==29 && got.b==39);
    NEAR(r,.7); NEAR(g,.8); NEAR(b,.9);
}

static void test_arch(void) {
    scenario="arch"; memset(&world,0,sizeof(world));
    flex_t rgbOld[3]={0};
    rdMesh meshes[2]={0};
    for(int i=0;i<2;++i) {
        meshes[i].numVertices=3-i;
        meshes[i].vertices_i=malloc(3*sizeof(flex_t)); meshes[i].vertices_unk=malloc(3*sizeof(flex_t));
        for(int v=0;v<3;++v) { meshes[i].vertices_i[v]=.1f*(v+1); meshes[i].vertices_unk[v]=0; }
        meshes[i].paRedIntensities=&rgbOld[0]; meshes[i].paGreenIntensities=&rgbOld[1]; meshes[i].paBlueIntensities=&rgbOld[2];
    }
    flex_t mono[3]={.2f,.5f,.8f},red[3]={.3f,.6f,.9f},green[3]={.4f,.7f,.1f},blue[3]={.5f,.8f,.2f};
    sithArchLightMesh light={mono,red,green,blue,3}; sithArchLight arch={1,&light};
    world.numArchLights=1; world.aArchlights=&arch;
    rdModel3 model={.numGeos=2,.aGeos={{1,&meshes[0]},{1,&meshes[1]}}};
    SithThing thing={.archlightIdx=0,.renderData={&model,RD_THING_MODEL3}};
    checkedMesh=&meshes[0]; expectedScratch=meshes[0].vertices_unk; expectedBase=meshes[0].vertices_i; checkedArch=&light;
    for(int pass=0;pass<8;++pass) {
        colorMode=expectedRgb=pass%2; drawResult=pass%3!=0; expectedArch=1;
        int before=drawCalls; CHECK(sithRender_DrawLevelGeometryThing(&thing)==drawResult); CHECK(drawCalls==before+1);
        for(int i=0;i<2;++i) {
            CHECK(meshes[i].vertices_i!=meshes[i].vertices_unk);
            CHECK(meshes[i].paRedIntensities==&rgbOld[0]); CHECK(meshes[i].paGreenIntensities==&rgbOld[1]); CHECK(meshes[i].paBlueIntensities==&rgbOld[2]);
            for(int v=0;v<3;++v) NEAR(meshes[i].vertices_i[v],.1*(v+1));
        }
    }
    colorMode=expectedRgb=1; expectedArch=0;
    for(int bad=0;bad<8;++bad) {
        thing.archlightIdx=0; world.aArchlights=&arch; arch.numMeshes=1; arch.aMeshes=&light;
        light.numVertices=3; light.aRed=red;
        if(bad==0) thing.archlightIdx=-2;
        if(bad==1) thing.archlightIdx=1;
        if(bad==2) world.aArchlights=NULL;
        if(bad==3) arch.numMeshes=0;
        if(bad==4) arch.aMeshes=NULL;
        if(bad==5) light.numVertices=1; // short even for the lower LOD
        if(bad==6) light.aRed=NULL;
        if(bad==7) light.numVertices=-1;
        CHECK(sithRender_DrawLevelGeometryThing(&thing)==drawResult);
        CHECK(meshes[0].paRedIntensities==&rgbOld[0]);
    }
    thing.archlightIdx=-1; failAllocation=1;
    int before=drawCalls; CHECK(sithRender_DrawLevelGeometryThing(&thing)==drawResult); CHECK(drawCalls==before+1);
    ++before; // Small scopes no longer need an allocator.
    failAllocation=0; model.numGeos=5;
    CHECK(sithRender_DrawLevelGeometryThing(&thing)==0); CHECK(drawCalls==before);
    model.numGeos=2;
    CHECK(allocations==releases);
    thing.renderData.type=0;
    thing.renderData.model3=(rdModel3*)(uintptr_t)1;
    CHECK(sithRender_DrawLevelGeometryThing(&thing)==drawResult);
    CHECK(drawCalls==before+1); CHECK(allocations==releases);
    // Real allocator/sanitizer must allow separate destruction after repeated
    // alternating instance draws, including failed draws and invalid bindings.
    for(int i=0;i<2;++i) { free(meshes[i].vertices_i); free(meshes[i].vertices_unk); }
}

static void test_model(void) {
    setup_alpha(); scenario="model";
    flex_t base[3]={.1f,.3f,.6f}, scratch[3]={0};
    rdVector3 positions[3]={{-.5f,2,-.5f},{.5f,2,-.5f},{0,2,.5f}};
    rdVector3 normals[3]={{0,0,1},{0,0,1},{0,0,1}};
    rdMesh mesh={.numVertices=3,.vertices_i=base,.vertices_unk=scratch,.aVertices=positions,.vertexNormals=normals};
    rdModel3_numMeshLights=0; camera.attenuationMin=0;
    for(int mots=0;mots<2;++mots) {
        Main_bMotsCompat=mots; colorMode=0; calculate_model(&mesh);
        for(int i=0;i<3;++i) NEAR(scratch[i],base[i]);
        if(mots) NEAR(mesh.extraLight,1.0/3.0);
        colorMode=1; calculate_model(&mesh);
        for(int i=0;i<3;++i) NEAR(scratch[i],0);
    }
    Main_bMotsCompat=1;
    // Two directional-facing point lights; the engine applies its own distance
    // and normal calculations. Their contributions add to each distinct base.
    rdLight lights[2]={{.type=2,.minRadius=20,.intensity=.1f},{.type=2,.minRadius=20,.intensity=.2f}};
    apMeshLights[0]=&lights[0]; apMeshLights[1]=&lights[1];
    rdModel3_aLocalLightPos[0]=(rdVector3){0,2,4}; rdModel3_aLocalLightPos[1]=(rdVector3){0,2,4};
    rdModel3_numMeshLights=2;
    colorMode=0; calculate_model(&mesh);
    for(int i=0;i<3;++i) {
        double dz=4-positions[i].z;
        double contribution=.3*dz/sqrt(positions[i].x*positions[i].x+dz*dz);
        NEAR(scratch[i],base[i]+contribution);
    }
    colorMode=1; calculate_model(&mesh);
    for(int i=0;i<3;++i) CHECK(scratch[i]>.29f && scratch[i]<=.3f);
    // Use nonsequential model indices, actual RGB primitive paths, distinct
    // ARCH RGB, and scalar 3DO fallback. No scalar base is added a second time.
    int order[3]={2,0,1}; int texOrder[3]={1,2,0};
    rdVector2 tex[3]={{1,2},{3,4},{5,6}},offset={0};
    flex_t red[3]={.1f,.2f,.3f},green[3]={.2f,.3f,.4f},blue[3]={.3f,.4f,.5f};
    rdMeshinfo in={.numVertices=3,.vertexPosIdx=order,.vertexUVIdx=texOrder,.aVertices=positions,
        .aTexVerticies=tex,.paDynamicLight=scratch};
    rdMeshinfo out={.aVertices=projected,.aTexVerticies=outUv,.paRedIntensities=outR,
        .paGreenIntensities=outG,.paBlueIntensities=outB};
    for(int arch=0;arch<2;++arch) for(int clip=0;clip<2;++clip) for(int geo=3;geo<=4;++geo) {
        in.paRedIntensities=arch?red:base; in.paGreenIntensities=arch?green:base; in.paBlueIntensities=arch?blue:base;
        if(clip) rdPrimit3_ClipFaceRGB(&frustum,geo,3,3,&in,&out,&offset);
        else rdPrimit3_NoClipFaceRGB(geo,3,3,&in,&out,&offset);
        CHECK(out.numVertices==3);
        for(int i=0;i<3;++i) {
            int v=order[i];
            NEAR(outR[i],in.paRedIntensities[v]+scratch[v]);
            NEAR(outG[i],in.paGreenIntensities[v]+scratch[v]);
            NEAR(outB[i],in.paBlueIntensities[v]+scratch[v]);
        }
    }
    const flex_t originalBase[3]={.1f,.3f,.6f};
    for(int i=0;i<3;++i) NEAR(base[i],originalBase[i]);
}

int main(int argc,char** argv) {
    if(argc==1 || !strcmp(argv[1],"opaque")) test_opaque();
    if(argc==1 || !strcmp(argv[1],"alpha")) test_alpha();
    if(argc==1 || !strcmp(argv[1],"solid")) test_solid();
    if(argc==1 || !strcmp(argv[1],"arch")) test_arch();
    if(argc==1 || !strcmp(argv[1],"model")) test_model();
    printf("PASS production MotS lighting paths: %u checks\n",checks);
    return 0;
}
