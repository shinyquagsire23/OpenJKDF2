#include "Platform/std3D.h"

#include <nds.h>

#include "General/stdMath.h"
#include "General/stdBitmap.h"
#include "Win95/stdDisplay.h"
#include "World/sithSurface.h"
#include "stdPlatform.h"

int std3D_bReinitHudElements = 0;

int textureIDS[8];
int paletteIDS[3];
flex_t fCamera = 1.0;
int nTexture = 0;

uint16_t i8Pal[256];
uint16_t i8PalWorld[256];

//stdBitmap* std3D_aUIBitmaps[STD3D_MAX_TEXTURES] = {0};
//int std3D_aUITextures[STD3D_MAX_TEXTURES] = {0};
rdDDrawSurface* std3D_aLoadedSurfaces[STD3D_MAX_TEXTURES] = {0};
int std3D_aLoadedTextures[STD3D_MAX_TEXTURES] = {0};
//size_t std3D_loadedUITexturesAmt = 0;

typedef struct TWLVERTEX
{
    v16 x;
    v16 y;
    v16 z;
    flex_t tu;
    flex_t tv;
    uint32_t color;
} TWLVERTEX;

size_t std3D_loadedTexturesAmt = 0;
static rdTri GL_tmpTris[STD3D_MAX_TRIS] = {0};
static size_t GL_tmpTrisAmt = 0;
static TWLVERTEX GL_tmpVertices[STD3D_MAX_VERTICES] = {0};
static size_t GL_tmpVerticesAmt = 0;
static size_t rendered_tris = 0;

static flex_t res_fix_x = (1.0/(640.0-(2.5*256.0/640.0)));
static flex_t res_fix_y = (1.0/(480.0-(2.5*192.0/480.0)));

static float test_idk = 32.0;
int std3D_bHasInitted = 0;
int std3D_bPurgeTexturesOnEnd = 0;
uint16_t std3D_fogDepth = 0x6000;
uint8_t std3D_fogColorIdx = 0;
int std3D_bTwlFlipTextures = 0;
int std3D_bNeedsToPurgeMenuBuffers = 0;
int std3D_timeWastedWaitingAround = 0;

u8* i8Bitmap = NULL;
u8* i8Bitmap2 = NULL;
u8* i8Bitmap_flip = NULL;
u8* i8Bitmap2_flip = NULL;

//verticies for the cube
v16 CubeVectors[] = {
    floattov16(0.0), floattov16(0.0), floattov16(0.5), 
    floattov16(2.56-0.005),  floattov16(0.0), floattov16(0.5),
    floattov16(2.56-0.005),  floattov16(0.0), floattov16(-0.5),
    floattov16(0.0), floattov16(0.0), floattov16(-0.5),

    floattov16(0.0), floattov16(1.28),  floattov16(0.5), 
    floattov16(2.56-0.005),  floattov16(1.28),  floattov16(0.5),
    floattov16(2.56-0.005),  floattov16(1.28),  floattov16(-0.5),
    floattov16(0.0), floattov16(1.28),  floattov16(-0.5),

    floattov16(0.0), floattov16(1.28), floattov16(0.5), 
    floattov16(2.56-0.005),  floattov16(1.28), floattov16(0.5),
    floattov16(2.56-0.005),  floattov16(1.28), floattov16(-0.5),
    floattov16(0.0), floattov16(1.28), floattov16(-0.5),

    floattov16(0.0), floattov16(1.92-0.005),  floattov16(0.5), 
    floattov16(2.56-0.005),  floattov16(1.92-0.005),  floattov16(0.5),
    floattov16(2.56-0.005),  floattov16(1.92-0.005),  floattov16(-0.5),
    floattov16(0.0), floattov16(1.92),  floattov16(-0.5)
};

//polys
u8 CubeFaces[] = {
    0+8,1+8,5+8,4+8,
    0,1,5,4,
};

//texture coordinates
u32 uv[] =
{

    //TEXTURE_PACK(inttot16(16), 0),
    //TEXTURE_PACK(inttot16(16),inttot16(16)),
    //TEXTURE_PACK(0, inttot16(16)),
    //TEXTURE_PACK(0,0)

    TEXTURE_PACK(0, inttot16(64)),
    TEXTURE_PACK(inttot16(256),inttot16(64)),
    TEXTURE_PACK(inttot16(256), 0),
    TEXTURE_PACK(0,0),

    TEXTURE_PACK(0, inttot16(128)),
    TEXTURE_PACK(inttot16(256),inttot16(128)),
    TEXTURE_PACK(inttot16(256), 0),
    TEXTURE_PACK(0,0)
};

u32 normals[] =
{
    NORMAL_PACK(0,floattov10(-.97),0),
    NORMAL_PACK(0,0,floattov10(.97)),
    NORMAL_PACK(floattov10(.97),0,0),
    NORMAL_PACK(0,0,floattov10(-.97)),
    NORMAL_PACK(floattov10(-.97),0,0),
    NORMAL_PACK(0,floattov10(.97),0)

};

//draw a cube face at the specified color
void drawQuad(int poly)
{   

    u32 f1 = CubeFaces[poly * 4] ;
    u32 f2 = CubeFaces[poly * 4 + 1] ;
    u32 f3 = CubeFaces[poly * 4 + 2] ;
    u32 f4 = CubeFaces[poly * 4 + 3] ;

    //not using lighting; not using normals
    //glNormal(normals[poly]);

    GFX_TEX_COORD = (uv[(poly*4)+0]);
    glVertex3v16(CubeVectors[f1*3], CubeVectors[f1*3 + 1], CubeVectors[f1*3 +  2] );

    GFX_TEX_COORD = (uv[(poly*4)+1]);
    glVertex3v16(CubeVectors[f2*3], CubeVectors[f2*3 + 1], CubeVectors[f2*3 + 2] );

    GFX_TEX_COORD = (uv[(poly*4)+2]);
    glVertex3v16(CubeVectors[f3*3], CubeVectors[f3*3 + 1], CubeVectors[f3*3 + 2] );

    GFX_TEX_COORD = (uv[(poly*4)+3]);
    glVertex3v16(CubeVectors[f4*3], CubeVectors[f4*3 + 1], CubeVectors[f4*3 + 2] );
}

static void update_from_display_palette()
{
    for (int i = 0; i < 256; i++) {
        u8 rval = stdDisplay_masterPalette[i].r;
        u8 gval = stdDisplay_masterPalette[i].g;
        u8 bval = stdDisplay_masterPalette[i].b;
        i8Pal[i] = RGB15((rval>>3),(gval>>3),(bval>>3));
    }
}

static void* loaded_colormap = NULL;

static void update_from_world_palette()
{
    if (sithWorld_pCurrentWorld && sithWorld_pCurrentWorld->colormaps && loaded_colormap != sithWorld_pCurrentWorld->colormaps)
    {

        for (int i = 0; i < 256; i++) {
            u8 rval = sithWorld_pCurrentWorld->colormaps->colors[i].r;
            u8 gval = sithWorld_pCurrentWorld->colormaps->colors[i].g;
            u8 bval = sithWorld_pCurrentWorld->colormaps->colors[i].b;
            i8PalWorld[i] = RGB15((rval>>3),(gval>>3),(bval>>3));
        }

        loaded_colormap = sithWorld_pCurrentWorld->colormaps;
    }

    
}

int std3D_LoadResources() {
    if (std3D_bHasInitted) {
        return 1;
    }
    glGenTextures(4, &textureIDS[0]);
    //glGenTextures(1, &paletteIDS[0]);

    update_from_display_palette();
    
    //glBindTexture(0, paletteIDS[0]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8Pal );

    std3D_bHasInitted = 1;
    return 1;
}

int std3D_Startup()
{
    // initialize gl
    glInit();

    glEnable(GL_TEXTURE_2D);
    glEnable(GL_ANTIALIAS);
    glEnable(GL_BLEND);
    glEnable(GL_FOG);

    // setup the rear plane
    glClearColor(0,0,0,31); // BG must be opaque for AA to work
    glClearPolyID(63); // BG must have a unique polygon ID for AA to work
    glClearDepth(0x7FFF);

    glViewport(0,0,255,191);

    // TODO
    vramSetBankA(VRAM_A_TEXTURE);
    vramSetBankB(VRAM_B_TEXTURE);
    //vramSetBankC(VRAM_C_TEXTURE);
    vramSetBankD(VRAM_D_TEXTURE);
    //vramSetBankE(VRAM_E_TEXTURE);
    vramSetBankE(VRAM_E_TEX_PALETTE);
    vramSetBankF(VRAM_F_TEX_PALETTE_SLOT0);
    //vramSetBankG(VRAM_G_TEX_PALETTE_SLOT5);

    std3D_LoadResources();

    glResetMatrixStack();

    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    //gluPerspective(70, 256.0 / 192.0, 0.1, 40);
    glOrtho(0.0, 2.56, 0.0, 1.92, 0.01, 100);
    //glFrustum(0.0, 0.256, 0.0, 0.192, 0.1, 100);

    glMatrixMode(GL_TEXTURE);
    glLoadIdentity();

    return 0;
}
void std3D_Shutdown() {
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

    free(i8Bitmap);
    i8Bitmap = NULL;
    free(i8Bitmap2);
    i8Bitmap2 = NULL;

    free(i8Bitmap_flip);
    i8Bitmap_flip = NULL;
    free(i8Bitmap2_flip);
    i8Bitmap2_flip = NULL;
}

/*
                                                  | b11 b12 b13 b14 |
  | c11 c12 c13 c14 |  =  | a11 a12 a13 a14 |  *  | b21 b22 b23 b24 |
                                                  | b31 b32 b33 b34 |
                                                  | b41 b42 b43 b44 |

The formula for calculating the separate elements is same as above,

  cyx = ay1*b1x + ay2*b2x + ay3*b3x + ay4*b4x


c14 = a11*b14 + a12*b24 + a13*b34 + a14*b44
*/

void std3DTwl_LoadProjection() {
    MATRIX_LOAD4x4 = floattof32(2.0f);
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = floattof32(0.0f);

    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = -floattof32(2.0f);
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = floattof32(0.0f);

    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = floattof32(0.0F);
    MATRIX_LOAD4x4 = floattof32(1.0F);

    MATRIX_LOAD4x4 = -floattof32(1.0f);//0;
    MATRIX_LOAD4x4 = floattof32(1.0f);; //0;
    MATRIX_LOAD4x4 = floattof32(0.0F);//-divf32(zFar + zNear, zFar - zNear);//0;
    MATRIX_LOAD4x4 = floattof32(0.0f);
}


void wOverridef32(int w) {
    MATRIX_LOAD4x4 = floattof32(1.0f);
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;

    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = floattof32(1.0f);
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;

    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = floattof32(1.0F);
    MATRIX_LOAD4x4 = floattof32(1.0F);

    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
    MATRIX_LOAD4x4 = 0;
}

void wOverride(float w) {
    wOverridef32(floattof32(w));
}

int std3D_finishingFrameIdx = 0;

// We want to defer waiting for vblank for as long as possible,
// so that we spend 100% of our CPU time instead of having 0-16ms busy waits
void std3D_ActuallyNeedToWaitForGeometryToFinish() {
    if (std3D_finishingFrameIdx <= std3D_frameCount) {
        int before_ms = stdPlatform_GetTimeMsec();
        while (GFX_STATUS & (1<<27)) {
            ;
        }
        std3D_timeWastedWaitingAround = stdPlatform_GetTimeMsec() - before_ms;
        std3D_finishingFrameIdx = std3D_frameCount;
    }
}

int std3D_StartScene()
{
    // At this point, everything in the game has updated, so now we wait for vsync
    //std3D_ActuallyNeedToWaitForGeometryToFinish();

    ++std3D_frameCount;

    if (!std3D_bHasInitted) {
        std3D_LoadResources();
    }
    rendered_tris = 0;

    //glFlush(GL_WBUFFERING); // GL_WBUFFERING

    if (jkGame_isDDraw) {
        if (std3D_bNeedsToPurgeMenuBuffers) {
            std3D_ActuallyNeedToWaitForGeometryToFinish();
            std3D_PurgeEntireTextureCache();
            std3D_bNeedsToPurgeMenuBuffers = 0;

            glMatrixMode(GL_PROJECTION);
            std3DTwl_LoadProjection();

            glMatrixMode(GL_MODELVIEW);
            wOverride(0);

            std3D_fogDepth = 5;
        
            // TODO: Make this dynamic based on the furthest Z?
            glFogShift(11);
            glFogOffset(std3D_fogDepth & 0x7FFF);
            rdColor24 skyColor = sithWorld_pCurrentWorld->colormaps->colors[sithSurface_skyColorGuess];
            glFogColor(skyColor.r >> 3, skyColor.g >> 3, skyColor.b >> 3, 31);
            glClearColor(skyColor.r >> 3, skyColor.g >> 3, skyColor.b >> 3, 31);
            for (int i = 0; i < 32; i++) {
                glFogDensity(i, stdMath_ClampInt((i-6)*6, 0, 127));
            }
            glFogDensity(31,127);
        }
    }
    else {
        //glFogOffset(0x6000);
        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();
        std3D_fogDepth = 0x6000;
    }
    

    return 0;
}
int std3D_EndScene()
{
    //glMatrixMode(GL_MODELVIEW);
    //glPopMatrix(1);

    if (jkGame_isDDraw) {
        //glMatrixMode(GL_PROJECTION);
        //glPopMatrix(1);
    }

#if 0
    static int last_ms = 0;
    int cur_ms = stdPlatform_GetTimeMsec();
    printf("EndScene %d\n", cur_ms - last_ms);
    last_ms = cur_ms;
#endif

    //int before_ms = stdPlatform_GetTimeMsec();
    glFlush(GL_WBUFFERING | GL_TRANS_MANUALSORT); // This doesn't force the CPU to wait for blank, but bit 27 in GFX_STATUS will clear after vblank
    std3D_finishingFrameIdx = std3D_frameCount;
    //swiWaitForVBlank();
    //std3D_timeWastedWaitingAround = stdPlatform_GetTimeMsec() - before_ms;

#if 0
    cur_ms = stdPlatform_GetTimeMsec();
    printf("EndScene2 %d\n", cur_ms - last_ms);
    last_ms = cur_ms;
    glFlush(GL_WBUFFERING | GL_TRANS_MANUALSORT); // GL_WBUFFERING
    //swiWaitForVBlank();
    while (GFX_STATUS & (1<<27)) {
        ;
    }

    cur_ms = stdPlatform_GetTimeMsec();
    printf("EndScene3 %d\n\n\n\n\n\n", cur_ms - last_ms);
    last_ms = cur_ms;
    glFlush(GL_WBUFFERING | GL_TRANS_MANUALSORT); // GL_WBUFFERING
    //swiWaitForVBlank();
    while (GFX_STATUS & (1<<27)) {
        ;
    }
#endif

    if (std3D_bPurgeTexturesOnEnd) {
        std3D_ActuallyNeedToWaitForGeometryToFinish();
        std3D_PurgeEntireTextureCache();
        std3D_bPurgeTexturesOnEnd = 0;
    }

    return 0;
}
void std3D_ResetRenderList() 
{
    rendered_tris += GL_tmpTrisAmt;

    GL_tmpVerticesAmt = 0;
    GL_tmpTrisAmt = 0;
    //GL_tmpLinesAmt = 0;
}
int std3D_RenderListVerticesFinish()
{
    return 0;
}

#define COMP_B(c) (c & 0xFF)
#define COMP_G(c) ((c>>8) & 0xFF)
#define COMP_R(c) ((c>>16) & 0xFF)
#define COMP_A(c) ((c>>24) & 0xFF)

void std3D_DrawRenderList()
{
    //printf("DrawRenderList %u %u\n", GL_tmpTrisAmt, GL_tmpVerticesAmt);
    if (!GL_tmpTrisAmt) return;

    TWLVERTEX* vertexes = GL_tmpVertices;
    rdTri* tris = GL_tmpTris;

    std3D_ActuallyNeedToWaitForGeometryToFinish();

    update_from_world_palette();

    glBindTexture(0, textureIDS[nTexture]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8PalWorld );

    glColor3b(255,255,255);
    //glBindTexture(0, textureIDS[4]);

    //glPolyFmt(POLY_ALPHA(31) | POLY_CULL_NONE);
    int polyid = 0;
    int last_alpha = -1;
    uint32_t last_flags = 0;

    //glPolyFmt(POLY_ALPHA(last_alpha) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(polyid++) ) ;
    //glBegin(GL_TRIANGLES);

    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        
        rdDDrawSurface* tex = tris[j].texture;
        int tex_id = -1;
        int tex_w = tex->width;
        int tex_h = tex->height;
        uint32_t flags = tris[j].flags;
        if (tex) {
            tex_id = tex->texture_id;
        }
        if (tex_id != -1) {
            glBindTexture(0, tex_id);
        }
        else {
            glBindTexture(0, textureIDS[4]);
        }
        //glTexParameter(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S | GL_TEXTURE_WRAP_T | TEXGEN_POSITION);
        //printf("tri %d %dx%d\n", tex_id, tex_w, tex_h);


        TWLVERTEX* v1 = &vertexes[tris[j].v1];
        TWLVERTEX* v2 = &vertexes[tris[j].v2];
        TWLVERTEX* v3 = &vertexes[tris[j].v3];

        int avg_alpha = COMP_A(v3->color) + COMP_A(v2->color) + COMP_A(v1->color);
        if (avg_alpha != 0x2FD) {
            avg_alpha = ((avg_alpha / 3) >> 3) & 0x1F;
        }
        else {
            avg_alpha = 0x1F;
        }
        if (avg_alpha != last_alpha || (flags & 0x20000) != (last_flags & 0x20000) || (flags & 0x10000) != (last_flags & 0x10000)) {
            glEnd();
            glPolyFmt(POLY_ALPHA(avg_alpha) | ((flags & 0x10000) ? POLY_CULL_NONE : POLY_CULL_BACK) | POLY_MODULATION | POLY_ID(polyid++) | ((flags & 0x20000) ? 0 : POLY_FOG) ) ;
            glBegin(GL_TRIANGLES);
        }
        last_alpha = avg_alpha;
        last_flags = flags;

        {
            if (tex_id != -1) {
                GFX_TEX_COORD = TEXTURE_PACK(inttot16((int)(v3->tu*tex_w)), inttot16((int)(v3->tv*tex_h)));    
            }
            
            //glColor3b((int)(v3->tu*255.0), (int)(v3->tv*255.0), 255);
            //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
            //glVertex3v16(floattov16(0.0), floattov16(1.92), floattov16(0.6));
            glColor3b(COMP_R(v3->color),COMP_G(v3->color),COMP_B(v3->color));
            //glColor3b(0xFF, 0x00, 0x00);
            glVertex3v16(v3->x, v3->y, v3->z);
        }
        
        {
            if (tex_id != -1) {
                GFX_TEX_COORD = TEXTURE_PACK(inttot16((int)(v2->tu*tex_w)), inttot16((int)(v2->tv*tex_h)));
            }
            //glColor3b((int)(v2->tu*255.0), (int)(v2->tv*255.0), 255);
            //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
            //glVertex3v16(floattov16(2.56), floattov16(1.28), floattov16(0.6));
            glColor3b(COMP_R(v2->color),COMP_G(v2->color),COMP_B(v2->color));
            //glColor3b(0, 0xff, 0x00);
            glVertex3v16(v2->x, v2->y, v2->z);

        }
        
        {
            if (tex_id != -1) {
                GFX_TEX_COORD = TEXTURE_PACK(inttot16((int)(v1->tu*tex_w)), inttot16((int)(v1->tv*tex_h)));
            }
            //glColor3b((int)(v1->tu*255.0), (int)(v1->tv*255.0), 255);
            //glVertex3v16(floattov16(0.0), floattov16(1.28), floattov16(0.6));
            glColor3b(COMP_R(v1->color),COMP_G(v1->color),COMP_B(v1->color));
            //glColor3b(0, 0x00, 0xff);
            glVertex3v16(v1->x, v1->y, v1->z);
        }
        
        
    }
    glEnd();
    //glFlush(0);
    

    std3D_ResetRenderList();
}
int std3D_SetCurrentPalette(rdColor24 *a1, int a2)
{
    return 0;
}
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int *outW, unsigned int *outH)
{
    // TODO hack for JKE? I don't know what they're doing
    *outW = inW > 256 ? 256 : inW;
    *outH = inH > 256 ? 256 : inH;
}
int std3D_DrawOverlay()
{
    return 0;
}
void std3D_UnloadAllTextures()
{
    std3D_PurgeEntireTextureCache();
    std3D_loadedTexturesAmt = 0;
}

void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris) 
{
    //printf("Add %u tris\n", num_tris);
    if (GL_tmpTrisAmt + num_tris > STD3D_MAX_TRIS)
    {
        return;
    }
    
    memcpy(&GL_tmpTris[GL_tmpTrisAmt], tris, sizeof(rdTri) * num_tris);
    
    GL_tmpTrisAmt += num_tris;
}
void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines) {}

//#define flextov16(n) (floattov16((float)n))

int std3D_AddRenderListVertices(D3DVERTEX *vertices, int count)
{
    if (GL_tmpVerticesAmt + count >= STD3D_MAX_VERTICES)
    {
        return 0;
    }
    
    for (int i = 0; i < count; i++)
    {
        D3DVERTEX* v = &vertices[i];
        TWLVERTEX* t = &GL_tmpVertices[GL_tmpVerticesAmt+i];

        flex_t twl_z = v->z;//(float)v->z;
        flex_t twl_x = (v->x * res_fix_x) * twl_z;// * (256.0/128.0);
        flex_t twl_y = (v->y * res_fix_y) * twl_z;// * (256.0/128.0);
        
#ifndef EXPERIMENTAL_FIXED_POINT
        t->x = floattov16(twl_x);
        t->y = floattov16(twl_y);
        t->z = floattov16(twl_z);
#else
        t->x = flextov16(twl_x);
        t->y = flextov16(twl_y);
        t->z = flextov16(twl_z);
#endif
        
        t->tu = v->tu;
        t->tv = v->tv;
        t->color = v->color;
    }
    
    GL_tmpVerticesAmt += count;
    
    return 1;
}

// From https://github.com/smlu/OpenJones3D/blob/main/Libs/std/Win95/std3D.c
void std3D_UpdateFrameCount(rdDDrawSurface *pTexture) {
    pTexture->frameNum = std3D_frameCount;
    std3D_RemoveTextureFromCacheList(pTexture);
    std3D_AddTextureToCacheList(pTexture);
}

// From https://github.com/smlu/OpenJones3D/blob/main/Libs/std/Win95/std3D.c
void std3D_RemoveTextureFromCacheList(rdDDrawSurface *pCacheTexture) {
    if ( pCacheTexture == std3D_pFirstTexCache )
    {
        std3D_pFirstTexCache = pCacheTexture->pNextCachedTexture;
        if ( std3D_pFirstTexCache )
        {
            std3D_pFirstTexCache->pPrevCachedTexture = NULL;
            if ( !std3D_pFirstTexCache->pNextCachedTexture ) {
                std3D_pLastTexCache = std3D_pFirstTexCache;
            }
        }
        else {
            std3D_pLastTexCache = NULL;
        }
    }
    else if ( pCacheTexture == std3D_pLastTexCache )
    {
        std3D_pLastTexCache = pCacheTexture->pPrevCachedTexture;
        pCacheTexture->pPrevCachedTexture->pNextCachedTexture = NULL;
    }
    else
    {
        pCacheTexture->pPrevCachedTexture->pNextCachedTexture = pCacheTexture->pNextCachedTexture;
        pCacheTexture->pNextCachedTexture->pPrevCachedTexture = pCacheTexture->pPrevCachedTexture;
    }

    pCacheTexture->pNextCachedTexture = NULL;
    pCacheTexture->pPrevCachedTexture = NULL;
    pCacheTexture->frameNum = 0;

    --std3D_numCachedTextures;
    //std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
}

// From https://github.com/smlu/OpenJones3D/blob/main/Libs/std/Win95/std3D.c
void std3D_AddTextureToCacheList(rdDDrawSurface *pTexture) {
    if ( std3D_pFirstTexCache )
    {
        std3D_pLastTexCache->pNextCachedTexture = pTexture;
        pTexture->pPrevCachedTexture            = std3D_pLastTexCache;
        pTexture->pNextCachedTexture            = NULL;
        std3D_pLastTexCache                     = pTexture;
    }
    else
    {
        std3D_pLastTexCache          = pTexture;
        std3D_pFirstTexCache         = pTexture;
        pTexture->pPrevCachedTexture = NULL;
        pTexture->pNextCachedTexture = NULL;
    }

    ++std3D_numCachedTextures;
    //std3D_pCurDevice->availableMemory -= pTexture->textureSize;
}

int std3D_ClearZBuffer()
{
    return 0;
}

int std3D_twl_dims_convert_to_e(int width) {
    int width_e = TEXTURE_SIZE_8;
    if (width == 8) {
        width_e = TEXTURE_SIZE_8;
    }
    else if (width == 16) {
        width_e = TEXTURE_SIZE_16;
    }
    else if (width == 32) {
        width_e = TEXTURE_SIZE_32;
    }
    else if (width == 64) {
        width_e = TEXTURE_SIZE_64;
    }
    else if (width == 128) {
        width_e = TEXTURE_SIZE_128;
    }
    else if (width == 256) {
        width_e = TEXTURE_SIZE_256;
    }
    else if (width == 512) {
        width_e = TEXTURE_SIZE_512;
    }
    else {
        printf("Failed to find size for width: %d\n", width);
    }

    return width_e;
}

int std3D_EstimateTWLSize(int width_e, int height_e, int type) {
    int size = 1 << (width_e + height_e + 6);

    switch (type) {
        case GL_RGB:
        case GL_RGBA:
            size = size << 1;
            break;
        case GL_RGB4:
        case GL_COMPRESSED:
            size = size >> 2;
            break;
        case GL_RGB16:
            size = size >> 1;
            break;
        default:
            break;
    }
    return size;
}

int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha)
{
    //printf("Add to cache %p %p\n", vbuf, texture);
    //if (Main_bHeadless) return 1;
    if (!vbuf || !texture) return 1;
    if (texture->texture_loaded) return 1;

    if (std3D_loadedTexturesAmt >= STD3D_MAX_TEXTURES) {
        stdPlatform_Printf("ERROR: Texture cache exhausted!! Ask ShinyQuagsire to increase the size.\n");
        std3D_bPurgeTexturesOnEnd = 1;
        return 1;
    }

    if (!vbuf->surface_lock_alloc) {
        stdPlatform_Printf("VBuffer missing surface!\n");
        return 1;
    }
    
    int image_texture;
    int res = glGenTextures(1, &image_texture);
    if (!res) {
        res = std3D_PurgeTextureCache(texture->textureSize);
        if (!res) {
            stdPlatform_Printf("Out of texture IDs!\n");
            std3D_bPurgeTexturesOnEnd = 1;
            return 1;
        }
    }
    uint8_t* image_8bpp = (uint8_t*)vbuf->surface_lock_alloc;
    uint16_t* image_16bpp = (uint16_t*)vbuf->surface_lock_alloc;
    uint8_t* pal = (uint8_t*)vbuf->palette;
    
    uint32_t width, height;
    width = vbuf->format.width;
    height = vbuf->format.height;

    glBindTexture(GL_TEXTURE_2D, image_texture);
    //glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    //glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameter(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S);
    glTexParameter(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T);
    //glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    //glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    //glPixelStorei(GL_PACK_ALIGNMENT, 1);

    //glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
    //glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);

    int width_e = std3D_twl_dims_convert_to_e(width);
    int height_e = std3D_twl_dims_convert_to_e(height);
    int32_t textureSize = 0;
    res = 0;

    if (vbuf->format.format.is16bit)
    {
        //textureSize = width * height * sizeof(uint16_t);
        textureSize = std3D_EstimateTWLSize(width_e, height_e, GL_RGBA);
        DC_FlushRange((u8*)image_8bpp, textureSize); // TODO remove if updating libnds
#if 1
        texture->is_16bit = 1;
#if 0
        if (!is_alpha_tex)
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB8, width, height, 0,  GL_RGB, GL_UNSIGNED_SHORT_5_6_5_REV, image_8bpp);
        else
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0,  GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, image_8bpp);
#endif
        if (!is_alpha_tex) {
            res = glTexImage2D(0, 0, GL_RGBA, width_e, height_e, 0, GL_TEXTURE_WRAP_S | GL_TEXTURE_WRAP_T | TEXGEN_TEXCOORD, (u8*)image_16bpp);
            if (!res) {
                res = std3D_PurgeTextureCache(textureSize);
                if (res) {
                    res = glTexImage2D(0, 0, GL_RGBA, width_e, height_e, 0, GL_TEXTURE_WRAP_S | GL_TEXTURE_WRAP_T | TEXGEN_TEXCOORD, (u8*)image_16bpp);
                }
            }
        }

#ifdef __NOTDEF_FORMAT_CONVERSION
        void* image_data = malloc(width*height*4);
    
        for (int j = 0; j < height; j++)
        {
            for (int i = 0; i < width; i++)
            {
                uint32_t index = (i*height) + j;
                uint32_t val_rgba = 0x00000000;
                
                uint16_t val = image_16bpp[index];
                if (!is_alpha_tex) // RGB565
                {
                    uint8_t val_a1 = 1;
                    uint8_t val_r5 = (val >> 11) & 0x1F;
                    uint8_t val_g6 = (val >> 5) & 0x3F;
                    uint8_t val_b5 = (val >> 0) & 0x1F;

                    uint8_t val_a8 = val_a1 ? 0xFF : 0x0;
                    uint8_t val_r8 = ( val_r5 * 527 + 23 ) >> 6;
                    uint8_t val_g8 = ( val_g6 * 259 + 33 ) >> 6;
                    uint8_t val_b8 = ( val_b5 * 527 + 23 ) >> 6;

#ifdef __NOTDEF_TRANSPARENT_BLACK
                    uint8_t transparent_r8 = (vbuf->transparent_color >> 16) & 0xFF;
                    uint8_t transparent_g8 = (vbuf->transparent_color >> 8) & 0xFF;
                    uint8_t transparent_b8 = (vbuf->transparent_color >> 0) & 0xFF;

                    if (val_r8 == transparent_r8 && val_g8 == transparent_g8 && val_b8 == transparent_b8) {
                        val_a1 = 0;
                    }
#endif // __NOTDEF_TRANSPARENT_BLACK

                    val_rgba |= (val_a8 << 24);
                    val_rgba |= (val_b8 << 16);
                    val_rgba |= (val_g8 << 8);
                    val_rgba |= (val_r8 << 0);
                }
                else // RGB1555
                {
                    uint8_t val_a1 = (val >> 15);
                    uint8_t val_r5 = (val >> 10) & 0x1F;
                    uint8_t val_g5 = (val >> 5) & 0x1F;
                    uint8_t val_b5 = (val >> 0) & 0x1F;

                    uint8_t val_a8 = val_a1 ? 0xFF : 0x0;
                    uint8_t val_r8 = ( val_r5 * 527 + 23 ) >> 6;
                    uint8_t val_g8 = ( val_g5 * 527 + 23 ) >> 6;
                    uint8_t val_b8 = ( val_b5 * 527 + 23 ) >> 6;

                    val_rgba |= (val_a8 << 24);
                    val_rgba |= (val_b8 << 16);
                    val_rgba |= (val_g8 << 8);
                    val_rgba |= (val_r8 << 0);
                }
                    
                *(uint32_t*)(image_data + index*4) = val_rgba;
            }
        }
        
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_BGRA, GL_UNSIGNED_BYTE, image_data);

        texture->pDataDepthConverted = image_data;
#endif // __NOTDEF_FORMAT_CONVERSION
#endif
    }
    else {
#if 0
        void* image_data = malloc(width*height*4);
    
        for (int j = 0; j < height; j++)
        {
            for (int i = 0; i < width; i++)
            {
                uint32_t index = (i*height) + j;
                uint32_t val_rgba = 0xFF000000;
                
                if (pal)
                {
                    uint8_t val = image_8bpp[index];
                    val_rgba |= (pal[(val * 3) + 2] << 16);
                    val_rgba |= (pal[(val * 3) + 1] << 8);
                    val_rgba |= (pal[(val * 3) + 0] << 0);
                }
                else
                {
                    uint8_t val = image_8bpp[index];
                    rdColor24* pal_master = (rdColor24*)sithWorld_pCurrentWorld->colormaps->colors;//stdDisplay_gammaPalette;
                    rdColor24* color = &pal_master[val];
                    val_rgba |= (color->r << 16);
                    val_rgba |= (color->g << 8);
                    val_rgba |= (color->b << 0);
                }
                
                *(uint32_t*)(image_data + index*4) = val_rgba;
            }
        }
        
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);

        texture->pDataDepthConverted = image_data;
#endif

        //textureSize = width * height * sizeof(uint8_t);

        textureSize = std3D_EstimateTWLSize(width_e, height_e, GL_RGB256);
        DC_FlushRange((u8*)image_8bpp, textureSize); // TODO remove if updating libnds

        texture->is_16bit = 0;
        //glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB256, width, height, 0, GL_RED, GL_UNSIGNED_BYTE, image_8bpp);
        res = glTexImage2D(0, 0, GL_RGB256, width_e, height_e, 0, GL_TEXTURE_WRAP_S | GL_TEXTURE_WRAP_T | TEXGEN_TEXCOORD | (is_alpha_tex ? GL_TEXTURE_COLOR0_TRANSPARENT : 0), (u8*)image_8bpp);
        if (!res) {
            res = std3D_PurgeTextureCache(textureSize);
            if (res) {
                res = glTexImage2D(0, 0, GL_RGB256, width_e, height_e, 0, GL_TEXTURE_WRAP_S | GL_TEXTURE_WRAP_T | TEXGEN_TEXCOORD | (is_alpha_tex ? GL_TEXTURE_COLOR0_TRANSPARENT : 0), (u8*)image_8bpp);
            }
        }

        //texture->pDataDepthConverted = NULL;
    }

    if (!res) {
        stdPlatform_Printf("Out of VRAM!\n");
        glDeleteTextures(1, &image_texture);

        std3D_bPurgeTexturesOnEnd = 1;
        glBindTexture(GL_TEXTURE_2D, textureIDS[4]);
        return 1; // Kinda hacky, don't alert rdCache

        // TODO: Free any unused textures instead of having a white texture for one frame
        //return std3D_AddToTextureCache(vbuf, texture, is_alpha_tex, no_alpha);
    }

    int foundTextureSlot = -1;
    for (int i = 0; i < std3D_loadedTexturesAmt; i++) {
        if (!std3D_aLoadedSurfaces[i] && !std3D_aLoadedTextures[i]) {
            foundTextureSlot = i;
            std3D_aLoadedSurfaces[i] = texture;
            std3D_aLoadedTextures[i] = image_texture;
            break;
        }
    }
    if (foundTextureSlot == -1) {
        std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = texture;
        std3D_aLoadedTextures[std3D_loadedTexturesAmt++] = image_texture;
    }
    
    /*ext->surfacebuf = image_data;
    ext->surfacetex = image_texture;
    ext->surfacepaltex = pal_texture;*/
    
    texture->texture_id = image_texture;
    //texture->emissive_texture_id = 0;
    //texture->displacement_texture_id = 0;
    texture->texture_loaded = 1;
    texture->textureSize = textureSize;
#if 0
    texture->emissive_factor[0] = 0.0;
    texture->emissive_factor[1] = 0.0;
    texture->emissive_factor[2] = 0.0;
    texture->albedo_factor[0] = 1.0;
    texture->albedo_factor[1] = 1.0;
    texture->albedo_factor[2] = 1.0;
    texture->albedo_factor[3] = 1.0;
    texture->displacement_factor = 0.0;
    texture->albedo_data = NULL;
    texture->displacement_data = NULL;
    texture->emissive_data = NULL;
#endif

    glBindTexture(GL_TEXTURE_2D, textureIDS[4]);
    
    return 1;
}

int fb_shift_x = 192;
int fb_shift_y = 128;

void std3D_DrawMenu()
{
    if (jkGame_isDDraw) return;

    touchPosition touchXY;
    touchRead(&touchXY);
    if (touchXY.px != 0 || touchXY.py != 0) {
        fb_shift_x = (int)(((flex_t)touchXY.px / 256.0) * (640-256));// FLEXTODO
        fb_shift_y = (int)(((flex_t)touchXY.py / 192.0) * (480-192));// FLEXTODO

        if (fb_shift_x > 640-256) {
            fb_shift_x = 640-256;
        }
        if (fb_shift_y > 480-192) {
            fb_shift_y = 480-192;
        }
        if (fb_shift_x < 0) {
            fb_shift_x = 0;
        }
        if (fb_shift_y < 0) {
            fb_shift_y = 0;
        }
    }

    if (!i8Bitmap) {
        i8Bitmap = (u8*)malloc(256*64);
        i8Bitmap2 = (u8*)malloc(256*128);
        i8Bitmap_flip = (u8*)malloc(256*64);
        i8Bitmap2_flip = (u8*)malloc(256*128);
    }

    u8* whichBitmap = std3D_bTwlFlipTextures ? i8Bitmap : i8Bitmap_flip;
    u8* whichBitmap2 = std3D_bTwlFlipTextures ? i8Bitmap2 : i8Bitmap2_flip;

    if (Video_menuBuffer.surface_lock_alloc)
    {
        uint32_t pitch = Video_menuBuffer.format.width_in_bytes;
        for (int x = 0; x < 256; x++)
        {
            for(int y = 0; y < 64; y++)
            {
                whichBitmap[(y*256)+x] = Video_menuBuffer.surface_lock_alloc[(pitch*(y+fb_shift_y))+(x+fb_shift_x)];
                //Video_menuBuffer.surface_lock_alloc[(pitch*y)+x] = (y*128)+x;
            }
        }

        for (int x = 0; x < 256; x++)
        {
            for(int y = 0; y < 128; y++)
            {
                whichBitmap2[(y*256)+x] = Video_menuBuffer.surface_lock_alloc[(pitch*((y+fb_shift_y)+64))+(x+fb_shift_x)];
                //Video_menuBuffer.surface_lock_alloc[(pitch*y)+x] = (y*128)+x;
            }
        }
    }

    DC_FlushRange((u8*)whichBitmap, 256*64);
    DC_FlushRange((u8*)whichBitmap2, 256*128);

    std3D_ActuallyNeedToWaitForGeometryToFinish();

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();
    //gluPerspective(70, 256.0 / 192.0, 0.1, 40);
    glOrtho(0.0, 2.55, 0.0, 1.91, 0.1, 100);

    //printf("std3D_DrawMenu\n");
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();

    gluLookAt(  0.0, 0.0, fCamera,      //camera possition 
        0.0, 0.0, 0.0,      //look at
        0.0, 1.0, 0.0);     //up

    update_from_display_palette();
    
    glBindTexture(0, textureIDS[std3D_bTwlFlipTextures ? 0 : 2]);
    glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_256, TEXTURE_SIZE_64, 0, TEXGEN_TEXCOORD, (u8*)whichBitmap);

    glBindTexture(0, textureIDS[std3D_bTwlFlipTextures ? 1 : 3]);
    glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_256, TEXTURE_SIZE_128, 0, TEXGEN_TEXCOORD, (u8*)whichBitmap2);

    std3D_bNeedsToPurgeMenuBuffers = 1;
    

    glBindTexture(0, textureIDS[nTexture]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8Pal );

    //draw the obj
    glColor3b(255,255,255);
    //glScalef(0.4f,0.4f,0.4f);
    //glScalef(1.0f/0.4f,1.0f/0.4f,1.0f/0.4f);
    int polyid = 1;
    //for(int j = 0; j < 2; j++)
    {
        for(int i = 0; i < 2; i++)
        {
            //glAssignColorTable(0,paletteIDS[0]);

            glBindTexture(0, textureIDS[i+(std3D_bTwlFlipTextures?0:2)]);
            //glBindTexture(0, textureIDS[4]);
            glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(polyid) ) ;
            glBegin(GL_QUAD);
            drawQuad(i);
            glEnd();
            polyid++;
        }

        
    }

    std3D_bTwlFlipTextures = !std3D_bTwlFlipTextures;

#if 0
    glColor3b(255,255,255);
    glBindTexture(0, textureIDS[4]);
    for (int j = 0; j < 1; j++)
    {
        //glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(j) ) ;
        glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(j));
        glBegin(GL_TRIANGLE);

        //drawQuad(0);

        //printf("%u: %f %f %f\n", j, v1->x, v1->y, v1->z);

        /*glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v1->x / 100.0), floattov16(v1->y / 100.0), floattov16(v1->z));
        glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v2->x / 100.0), floattov16(v2->y / 100.0), floattov16(v2->z));
        glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v3->x / 100.0), floattov16(v3->y / 100.0), floattov16(v3->z));*/

        GFX_TEX_COORD = TEXTURE_PACK(0, inttot16(0));
        //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(0.0), floattov16(1.28), floattov16(0.6));

        GFX_TEX_COORD = TEXTURE_PACK(0, inttot16(16));
        //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(2.56), floattov16(1.28), floattov16(0.6));

        GFX_TEX_COORD = TEXTURE_PACK(inttot16(16), inttot16(16));
        //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(0.0), floattov16(1.92), floattov16(0.6));

        glEnd();
    }
#endif
    //glPopMatrix(1);

    //glFlush(GL_TRANS_MANUALSORT);

    glMatrixMode(GL_MODELVIEW);
    glPopMatrix(1);

    glMatrixMode(GL_PROJECTION);
    glPopMatrix(1);

}
void std3D_DrawSceneFbo() {}
void std3D_FreeResources() {
    std3D_PurgeEntireTextureCache();

    glResetTextures();
    
    loaded_colormap = NULL;

    std3D_bReinitHudElements = 1;

    std3D_bHasInitted = 0;
}
void std3D_InitializeViewport(rdRect *viewRect) {}
int std3D_GetValidDimensions(int a1, int a2, int a3, int a4)
{
    return 0;
}
int std3D_FindClosestDevice(uint32_t index, int a2)
{
    return 0;
}
int std3D_SetRenderList(intptr_t a1)
{
    return 0;
}
intptr_t std3D_GetRenderList()
{
    return 0;
}
int std3D_CreateExecuteBuffer()
{
    return 0;
}

int std3D_HasAlpha() { return 1; }
int std3D_HasAlphaFlatStippled() { return 1; }
int std3D_HasModulateAlpha() { return 1; }

void std3D_PurgeBitmapRefs(stdBitmap *pBitmap)
{
#if 0
    for (int i = 0; i < STD3D_MAX_TEXTURES; i++)
    {
        int texId = std3D_aUITextures[i];
        stdBitmap* tex = std3D_aUIBitmaps[i];
        if (!tex) continue;
        if (tex != pBitmap) continue;

        for (int j = 0; j < tex->numMips; j++)
        {
            if (tex->aTextureIds[j] == texId) {
                std3D_PurgeUIEntry(i, j);
                break;
            }
        }
    }
#endif
}

void std3D_PurgeSurfaceRefs(rdDDrawSurface *texture)
{
    //stdPlatform_Printf("std3D_PurgeSurfaceRefs\n");
    for (int i = 0; i < STD3D_MAX_TEXTURES; i++)
    {
        rdDDrawSurface* tex = std3D_aLoadedSurfaces[i];
        if (!tex) continue;
        if (tex != texture) continue;

        std3D_PurgeTextureEntry(i);
    }
}

void std3D_PurgeTextureEntry(int i) {
    //stdPlatform_Printf("std3D_PurgeTextureEntry %d\n", i);
    if (std3D_aLoadedTextures[i]) {
        std3D_ActuallyNeedToWaitForGeometryToFinish();
        glDeleteTextures(1, &std3D_aLoadedTextures[i]);
        std3D_aLoadedTextures[i] = 0;
    }

    rdDDrawSurface* tex = std3D_aLoadedSurfaces[i];
    if (!tex) return;

#if 0
    if (tex->pDataDepthConverted != NULL) {
        free(tex->pDataDepthConverted);
        tex->pDataDepthConverted = NULL;
    }

    if (tex->albedo_data != NULL) {
        //jkgm_aligned_free(tex->albedo_data);
        tex->albedo_data = NULL;
    }

    if (tex->emissive_data != NULL) {
        //jkgm_aligned_free(tex->emissive_data);
        tex->emissive_data = NULL;
    }

    if (tex->displacement_data != NULL) {
        //jkgm_aligned_free(tex->displacement_data);
        tex->displacement_data = NULL;
    }

    if (tex->emissive_texture_id != 0) {
        glDeleteTextures(1, &tex->emissive_texture_id);
        tex->emissive_texture_id = 0;
    }

    if (tex->displacement_texture_id != 0) {
        glDeleteTextures(1, &tex->displacement_texture_id);
        tex->displacement_texture_id = 0;
    }

    tex->emissive_factor[0] = 0.0;
    tex->emissive_factor[1] = 0.0;
    tex->emissive_factor[2] = 0.0;
    tex->albedo_factor[0] = 1.0;
    tex->albedo_factor[1] = 1.0;
    tex->albedo_factor[2] = 1.0;
    tex->albedo_factor[3] = 1.0;
    tex->displacement_factor = 0.0;
#endif
    tex->texture_loaded = 0;
    tex->texture_id = 0;

    std3D_aLoadedSurfaces[i] = NULL;
    //std3D_loadedTexturesAmt--;
}

void std3D_PurgeUIEntry(int i, int idx) {
#if 0
    if (std3D_aUITextures[i]) {
        glDeleteTextures(1, &std3D_aUITextures[i]);
        std3D_aUITextures[i] = 0;
    }

    stdBitmap* tex = std3D_aUIBitmaps[i];
    if (!tex) return;

    tex->abLoadedToGPU[idx] = 0;
    tex->aTextureIds[idx] = 0;
    free(tex->paDataDepthConverted[idx]);
    tex->paDataDepthConverted[idx] = NULL;

    std3D_aUIBitmaps[i] = NULL;
    std3D_loadedUITexturesAmt--;
#endif
}

// From https://github.com/smlu/OpenJones3D/blob/main/Libs/std/Win95/std3D.c
int std3D_PurgeTextureCache(size_t size)
{
    size_t purgedBytes = 0;
    for ( rdDDrawSurface* pCacheTexture = std3D_pFirstTexCache; pCacheTexture && pCacheTexture->frameNum != std3D_frameCount; pCacheTexture = pCacheTexture->pNextCachedTexture )
    {
        if ( pCacheTexture->textureSize == size )
        {
            //IDirect3DTexture2_Release(pCacheTexture->pD3DCachedTex);
            std3D_PurgeSurfaceRefs(pCacheTexture);
            //pCacheTexture->pD3DCachedTex = NULL;
            std3D_RemoveTextureFromCacheList(pCacheTexture);
            return 1;
        }
    }

    rdDDrawSurface* pNextCachedTexture = NULL;
    for ( rdDDrawSurface* pCacheTexture = std3D_pFirstTexCache; pCacheTexture && purgedBytes < size; pCacheTexture = pNextCachedTexture )
    {
        pNextCachedTexture = pCacheTexture->pNextCachedTexture;
        if ( pCacheTexture->frameNum != std3D_frameCount )
        {
            //if ( pCacheTexture->pD3DCachedTex ) { // Added: Added check for null pointer
                //IDirect3DTexture2_Release(pCacheTexture->pD3DCachedTex);
                std3D_PurgeSurfaceRefs(pCacheTexture);
            //}
            //pCacheTexture->pD3DCachedTex = NULL;
            purgedBytes += pCacheTexture->textureSize;
            std3D_RemoveTextureFromCacheList(pCacheTexture);
        }
    }

    return purgedBytes != 0;
}

void std3D_PurgeEntireTextureCache()
{
#if 0
    if (Main_bHeadless) {
        std3D_loadedTexturesAmt = 0;
        return;
    }
#endif

    if (!std3D_loadedTexturesAmt) {
        //jk_printf("Skipping texture cache purge, nothing loaded.\n");
        return;
    }

    std3D_ActuallyNeedToWaitForGeometryToFinish();

    stdPlatform_Printf("Purging texture cache... %x\n", std3D_loadedTexturesAmt);
    for (int i = 0; i < std3D_loadedTexturesAmt; i++)
    {
        std3D_PurgeTextureEntry(i);
    }
    std3D_loadedTexturesAmt = 0;

    glResetTextures();
    std3D_bHasInitted = 0;
}

void std3D_UpdateSettings() {}
void std3D_Screenshot(const char* pFpath) {}

void std3D_ResetUIRenderList() {}
int std3D_AddBitmapToTextureCache(stdBitmap *texture, int mipIdx, int is_alpha_tex, int no_alpha) {}
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
int std3D_IsReady() {}