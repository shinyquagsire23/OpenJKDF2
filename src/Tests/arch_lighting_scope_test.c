/* Actual model/world types and actual scope helper; only allocator/draw seams.
 * No renderer, GPU, COG VM or game assets are executed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Primitives/rdModel3.h"

static SithWorld world;
static SithWorld* sithWorld_g_pCurrentWorld = &world;
static int mode = 1, failAlloc, allocations, releases, checks, failures;
static int drawCalls, drawResult = 1, nesting, maxNesting;
static SithThing* nestedThing;
static flex_t* outerRed;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; fprintf(stderr,"%d: %s\n",__LINE__,#c); } } while (0)
static void* test_alloc(size_t n) { if(failAlloc)return NULL;void*p=malloc(n);if(p)++allocations;return p; }
static void test_free(void*p) { if(p){++releases;free(p);} }
#define SITH_ALLOC test_alloc
#define SITH_FREE test_free
static int rdGetVertexColorMode(void) {return mode;}
static int sithRender_RenderThing(SithThing*);
#ifdef ARCH_SCOPE_BASELINE
#include "arch_scope_baseline.inc"
static void sithRender_FreeArchLightingBuffers(void) {}
#else
#include "Engine/sithRenderArchLighting.h"
#endif

static int sithRender_RenderThing(SithThing* thing) {
    ++drawCalls;
    if(nestedThing && nesting<maxNesting) {
        ++nesting;
        flex_t* before=thing->renderData.model3->aGeos[0].aMeshes[0].paRedIntensities;
        CHECK(sithRender_DrawLevelGeometryThing(nestedThing)==drawResult);
        CHECK(thing->renderData.model3->aGeos[0].aMeshes[0].paRedIntensities==before);
        --nesting;
    }
    if(outerRed && nesting==0)CHECK(thing->renderData.model3->aGeos[0].aMeshes[0].paRedIntensities==outerRed);
    return drawResult;
}

static void model_case(unsigned meshes, int recursive) {
    rdMesh* data=calloc(meshes,sizeof(*data));
    sithArchLightMesh* lights=calloc(meshes,sizeof(*lights));
    flex_t original[4]={.1f,.2f,.3f,.4f}, archValues[4]={.5f,.6f,.7f,.8f};
    for(unsigned i=0;i<meshes;++i){
        data[i].numVertices=1;data[i].vertices_i=&original[0];data[i].vertices_unk=&original[1];
        data[i].paRedIntensities=&original[3];data[i].paGreenIntensities=&original[2];data[i].paBlueIntensities=&original[1];
        lights[i]=(sithArchLightMesh){.numVertices=1,.aMono=&archValues[0],.aRed=&archValues[1],.aGreen=&archValues[2],.aBlue=&archValues[3]};
    }
    rdModel3 model={0};model.numGeos=1;model.aGeos[0].numMeshes=meshes;model.aGeos[0].aMeshes=data;
    SithThing thing={0};thing.archlightIdx=0;thing.renderData.type=RD_THING_MODEL3;thing.renderData.model3=&model;
    sithArchLight arch={.numMeshes=(int)meshes,.aMeshes=lights};world.numArchLights=1;world.aArchlights=&arch;
    nestedThing=recursive?&thing:NULL;maxNesting=recursive;outerRed=&archValues[1];
    int before=drawCalls;
    CHECK(sithRender_DrawLevelGeometryThing(&thing)==drawResult);
    CHECK(drawCalls==before+recursive+1);
    for(unsigned i=0;i<meshes;++i){
        CHECK(data[i].vertices_i==&original[0]);CHECK(data[i].vertices_unk==&original[1]);
        CHECK(data[i].paRedIntensities==&original[3]);CHECK(data[i].paGreenIntensities==&original[2]);CHECK(data[i].paBlueIntensities==&original[1]);
    }
    nestedThing=NULL;outerRed=NULL;free(lights);free(data);
}

static void failure_case(unsigned meshes) {
    rdMesh* data=calloc(meshes,sizeof(*data));flex_t original[4]={0};
    for(unsigned i=0;i<meshes;++i){data[i].numVertices=1;data[i].vertices_i=&original[0];data[i].paRedIntensities=&original[1];data[i].paGreenIntensities=&original[2];data[i].paBlueIntensities=&original[3];}
    rdModel3 model={0};model.numGeos=1;model.aGeos[0].numMeshes=meshes;model.aGeos[0].aMeshes=data;
    SithThing thing={0};thing.archlightIdx=-1;thing.renderData.type=RD_THING_MODEL3;thing.renderData.model3=&model;
    int before=drawCalls;failAlloc=1;
    CHECK(sithRender_DrawLevelGeometryThing(&thing)==0);CHECK(drawCalls==before);
    for(unsigned i=0;i<meshes;++i){CHECK(data[i].vertices_i==&original[0]);CHECK(data[i].paRedIntensities==&original[1]);CHECK(data[i].paGreenIntensities==&original[2]);CHECK(data[i].paBlueIntensities==&original[3]);}
    failAlloc=0;free(data);
}

int main(void) {
    /* Small models must render even if allocator is unavailable. This fails
     * behaviorally on the previous per-draw-allocation helper. */
    failAlloc=1;model_case(2,0);failAlloc=0;CHECK(allocations==0);
    model_case(65,0);int warm=allocations;
    for(int i=0;i<8;++i){drawResult=i%2;model_case(65,0);CHECK(allocations==warm);}
    drawResult=1;model_case(65,2);warm=allocations;
    for(int i=0;i<5;++i){drawResult=i%2;model_case(65,2);CHECK(allocations==warm);}
    failure_case(193);drawResult=1;failAlloc=1;model_case(65,2);failAlloc=0;
    /* Growth and later reuse have no arbitrary mesh limit. */
    model_case(257,0);warm=allocations;model_case(257,0);CHECK(allocations==warm);
    sithRender_FreeArchLightingBuffers();CHECK(allocations==releases);
    printf("ARCH scope: %d checks, %d failures, %d allocations, %d releases\n",checks,failures,allocations,releases);
    return failures?1:0;
}
