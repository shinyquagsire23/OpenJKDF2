/* Execute the complete production scalar calculator with JKM_LIGHTING absent.
 * Light storage is the extracted production declaration. Elementary vector math
 * is a fixture substitute; no renderer, game data or complete engine ABI is used.
 * The two safe controls detect a stuck scalar iterator and a nonzero null base.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#ifdef JKM_LIGHTING
#error This fixture must compile the non-JKM production branch.
#endif
typedef float flex_t;
typedef double flex_d_t;
typedef struct { flex_t x, y, z; } rdVector3;
#include "actual_light_type.inc"

static unsigned checks;
static void check(int ok, const char* expr, int line) {
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL scalar-light line %d: %s\n", line, expr); exit(1); }
}
#define CHECK(x) check(!!(x), #x, __LINE__)
#define NEAR(a,b) CHECK(fabs((double)(a)-(double)(b)) < 0.00001)
static void rdVector_Sub3(rdVector3* out, const rdVector3* a, const rdVector3* b) {
    *out=(rdVector3){a->x-b->x,a->y-b->y,a->z-b->z};
}
static flex_t rdVector_Dot3(const rdVector3* a,const rdVector3* b) { return a->x*b->x+a->y*b->y+a->z*b->z; }
static flex_t rdVector_Len3(const rdVector3* a) { return sqrtf(rdVector_Dot3(a,a)); }
static flex_t rdVector_Normalize3Acc(rdVector3* a) {
    flex_t len=rdVector_Len3(a); if(len) {a->x/=len; a->y/=len; a->z/=len;} return len;
}
#ifdef OLD_SCALAR_ITERATOR
#include "old_scalar_iterator.inc"
#elif defined(OLD_SCALAR_NULL_BASE)
#include "old_scalar_null_base.inc"
#else
#include "actual_light.inc"
#endif

static void expect_three(const flex_t* out, flex_t a, flex_t b, flex_t c) {
    NEAR(out[0],a); NEAR(out[1],b); NEAR(out[2],c);
}

int main(void) {
    flex_t base[3]={.1f,.3f,.6f};
    flex_t guarded[5]={-7,0,0,0,9}, *out=&guarded[1];
    rdVector3 vertices[3]={{0,0,0},{0,0,1},{0,0,2}};
    rdVector3 normals[3]={{0,0,1},{0,0,1},{0,0,1}};
    rdVector3 positions[2]={{0,0,4},{0,0,8}};
    rdLight lights[2]={{.minRadius=100,.intensity=.1f},{.minRadius=100,.intensity=.2f}};
    rdLight* refs[2]={&lights[0],&lights[1]};

    NEAR(rdLight_CalcVertexIntensities(NULL,NULL,0,normals,vertices,base,out,3,0),0);
    expect_three(out,.1f,.3f,.6f);
    NEAR(rdLight_CalcVertexIntensities(NULL,NULL,0,normals,vertices,NULL,out,3,0),0);
    expect_three(out,0,0,0);

    NEAR(rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,base,out,3,0),0);
    expect_three(out,.4f,.6f,.9f);
    rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,NULL,out,3,0);
    expect_three(out,.3f,.3f,.3f);
    // Distances are exactly 4/8, 3/7 and 2/6: attenuation removes .12/.10/.08.
    rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,base,out,3,.01f);
    expect_three(out,.28f,.50f,.82f);
    rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,NULL,out,3,.01f);
    expect_three(out,.18f,.20f,.22f);

    lights[0].minRadius=3;
    rdLight_CalcVertexIntensities(refs,positions,1,normals,vertices,NULL,out,3,0);
    expect_three(out,0,0,.1f); // At the exact radius the light is excluded.
    lights[0].minRadius=100;
    normals[0]=(rdVector3){0,0,-1}; normals[1]=(rdVector3){1,0,0};
    rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,base,out,3,0);
    expect_three(out,.1f,.3f,.9f);

    // Characterize the existing scalar saturation rule: stop adding lights
    // after crossing one, without importing the JKM branch's clamp.
    flex_t bright[3]={.95f,.95f,.95f};
    normals[0]=normals[1]=(rdVector3){0,0,1};
    rdLight_CalcVertexIntensities(refs,positions,2,normals,vertices,bright,out,3,0);
    expect_three(out,1.05f,1.05f,1.05f);

    out[0]=.12f; out[1]=.34f; out[2]=.56f;
    NEAR(rdLight_CalcVertexIntensities(NULL,NULL,0,NULL,NULL,NULL,out,0,0),0);
    expect_three(out,.12f,.34f,.56f);
    expect_three(base,.1f,.3f,.6f);
    NEAR(guarded[0],-7); NEAR(guarded[4],9);
    printf("PASS actual vertex-light calculator without JKM_LIGHTING: %u checks\n",checks);
    return 0;
}
