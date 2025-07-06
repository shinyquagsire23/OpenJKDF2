#include "Platform/std3D.h"

#include <nds.h>

#include "Win95/stdDisplay.h"

int std3D_bReinitHudElements = 0;

int textureIDS[8];
int paletteIDS[3];
flex_t fCamera = 1.25;
int nTexture = 0;

uint16_t i8Pal[256];

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

static flex_t res_fix_x = (256.0/640.0)/100.0;
static flex_t res_fix_y = (192.0/480.0)/100.0;

//verticies for the cube
v16 CubeVectors[] = {
    floattov16(0.0), floattov16(0.0), floattov16(0.5), 
    floattov16(2.56),  floattov16(0.0), floattov16(0.5),
    floattov16(2.56),  floattov16(0.0), floattov16(-0.5),
    floattov16(0.0), floattov16(0.0), floattov16(-0.5),

    floattov16(0.0), floattov16(1.28),  floattov16(0.5), 
    floattov16(2.56),  floattov16(1.28),  floattov16(0.5),
    floattov16(2.56),  floattov16(1.28),  floattov16(-0.5),
    floattov16(0.0), floattov16(1.28),  floattov16(-0.5),

    floattov16(0.0), floattov16(1.28), floattov16(0.5), 
    floattov16(2.56),  floattov16(1.28), floattov16(0.5),
    floattov16(2.56),  floattov16(1.28), floattov16(-0.5),
    floattov16(0.0), floattov16(1.28), floattov16(-0.5),

    floattov16(0.0), floattov16(1.92),  floattov16(0.5), 
    floattov16(2.56),  floattov16(1.92),  floattov16(0.5),
    floattov16(2.56),  floattov16(1.92),  floattov16(-0.5),
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

int std3D_Startup()
{
    // initialize gl
    glInit();

    glEnable(GL_TEXTURE_2D);
    glEnable(GL_ANTIALIAS);
    glEnable(GL_BLEND);

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

    glGenTextures(2, &textureIDS[0]);
    //glGenTextures(1, &paletteIDS[0]);

    u8* i8Bitmap = (u8*)malloc(16*16);
    for (int i = 0; i < 256; i++)
    {
        i8Bitmap[i] = i;
    }
    //glBindTexture(0, textureIDS[2]);
    //glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_16, TEXTURE_SIZE_16, 0, TEXGEN_TEXCOORD, (u8*)i8Bitmap);
    free(i8Bitmap);

    update_from_display_palette();
    
    //glBindTexture(0, paletteIDS[0]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8Pal );

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    //gluPerspective(70, 256.0 / 192.0, 0.1, 40);
    glOrtho(0.0, 2.56, 0.0, 1.92, 0.1, 100);

    return 0;
}
void std3D_Shutdown() {}
int std3D_StartScene()
{
    rendered_tris = 0;

    glFlush(0);

    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();

    gluLookAt(  0.0, 0.0, fCamera,      //camera possition 
        0.0, 0.0, 0.0,      //look at
        0.0, 1.0, 0.0);     //up

    return 0;
}
int std3D_EndScene()
{
    glPopMatrix(1);        
    //printf("EndScene\n");

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

void std3D_DrawRenderList()
{
    //printf("DrawRenderList %u %u\n", GL_tmpTrisAmt, GL_tmpVerticesAmt);
    if (!GL_tmpTrisAmt) return;

    TWLVERTEX* vertexes = GL_tmpVertices;
    rdTri* tris = GL_tmpTris;

    glColor3b(255,255,255);
    glBindTexture(0, textureIDS[2]);

    glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(0) ) ;
    //glPolyFmt(POLY_ALPHA(31) | POLY_CULL_NONE);
    glBegin(GL_TRIANGLES);

    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        
        
        TWLVERTEX* v1 = &vertexes[tris[j].v1];
        TWLVERTEX* v2 = &vertexes[tris[j].v2];
        TWLVERTEX* v3 = &vertexes[tris[j].v3];

        //printf("%u: %f %f %f\n", j, v1->x, v1->y, v1->z);

        /*glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v1->x / 100.0), floattov16(v1->y / 100.0), floattov16(v1->z));
        glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v2->x / 100.0), floattov16(v2->y / 100.0), floattov16(v2->z));
        glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        glVertex3v16(floattov16(v3->x / 100.0), floattov16(v3->y / 100.0), floattov16(v3->z));*/

        GFX_TEX_COORD = TEXTURE_PACK(inttot16(16), inttot16(16));
        //glColor3b((int)(v3->tu*255.0), (int)(v3->tv*255.0), 255);
        //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        //glVertex3v16(floattov16(0.0), floattov16(1.92), floattov16(0.6));
        glColor3b(COMP_R(v3->color),COMP_G(v3->color),COMP_B(v3->color));
        glVertex3v16(v3->x, v3->y, v3->z);

        GFX_TEX_COORD = TEXTURE_PACK(0, inttot16(16));
        //glColor3b((int)(v2->tu*255.0), (int)(v2->tv*255.0), 255);
        //glColor3b((j&0xFF),(j&0xFF),(j&0xFF));
        //glVertex3v16(floattov16(2.56), floattov16(1.28), floattov16(0.6));
        glColor3b(COMP_R(v2->color),COMP_G(v2->color),COMP_B(v2->color));
        glVertex3v16(v2->x, v2->y, v2->z);


        GFX_TEX_COORD = TEXTURE_PACK(0, inttot16(0));
        //glColor3b((int)(v1->tu*255.0), (int)(v1->tv*255.0), 255);
        //glVertex3v16(floattov16(0.0), floattov16(1.28), floattov16(0.6));
        glColor3b(COMP_R(v1->color),COMP_G(v1->color),COMP_B(v1->color));
        glVertex3v16(v1->x, v1->y, v1->z);

        
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

        t->x = floattov16(v->x * res_fix_x);
        t->y = floattov16((480.0 - v->y) * res_fix_y);
        t->z = floattov16(-v->z);
        t->tu = v->tu;
        t->tv = v->tv;
        t->color = v->color;
    }
    
    GL_tmpVerticesAmt += count;
    
    return 1;
}
void std3D_UpdateFrameCount(rdDDrawSurface *surface) {}
void std3D_PurgeTextureCache() {}
int std3D_ClearZBuffer()
{
    return 0;
}
int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha)
{
    return 1;
}

int fb_shift_x = 192;
int fb_shift_y = 128;

void std3D_DrawMenu()
{
    if (jkGame_isDDraw) return;

    //printf("std3D_DrawMenu\n");
    /*glMatrixMode(GL_MODELVIEW);
    glPushMatrix();

    gluLookAt(  0.0, 0.0, fCamera,      //camera possition 
        0.0, 0.0, 0.0,      //look at
        0.0, 1.0, 0.0);     //up*/

    update_from_display_palette();

    u8* i8Bitmap = (u8*)malloc(256*64);
    u8* i8Bitmap2 = (u8*)malloc(256*128);

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

    if (Video_menuBuffer.surface_lock_alloc)
    {
        uint32_t pitch = Video_menuBuffer.format.width_in_bytes;
        for (int x = 0; x < 256; x++)
        {
            for(int y = 0; y < 64; y++)
            {
                i8Bitmap[(y*256)+x] = Video_menuBuffer.surface_lock_alloc[(pitch*(y+fb_shift_y))+(x+fb_shift_x)];
                //Video_menuBuffer.surface_lock_alloc[(pitch*y)+x] = (y*128)+x;
            }
        }

        for (int x = 0; x < 256; x++)
        {
            for(int y = 0; y < 128; y++)
            {
                i8Bitmap2[(y*256)+x] = Video_menuBuffer.surface_lock_alloc[(pitch*((y+fb_shift_y)+64))+(x+fb_shift_x)];
                //Video_menuBuffer.surface_lock_alloc[(pitch*y)+x] = (y*128)+x;
            }
        }
    }
    
    glBindTexture(0, textureIDS[0]);
    glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_256, TEXTURE_SIZE_64, 0, TEXGEN_TEXCOORD, (u8*)i8Bitmap);

    glBindTexture(0, textureIDS[1]);
    glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_256, TEXTURE_SIZE_128, 0, TEXGEN_TEXCOORD, (u8*)i8Bitmap2);
    free(i8Bitmap);
    free(i8Bitmap2);
    

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

            glBindTexture(0, textureIDS[i]);
            //glBindTexture(0, textureIDS[2]);
            glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(polyid) ) ;
            glBegin(GL_QUAD);
            drawQuad(i);
            glEnd();
            polyid++;
        }

        
    }

#if 0
    glColor3b(255,255,255);
    glBindTexture(0, textureIDS[2]);
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

}
void std3D_DrawSceneFbo() {}
void std3D_FreeResources() {}
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

int std3D_HasAlpha() { return 0; }
int std3D_HasAlphaFlatStippled() { return 0; }
int std3D_HasModulateAlpha() { return 0; }



void std3D_PurgeUIEntry(int i, int idx) {}
void std3D_PurgeTextureEntry(int i) {}
void std3D_PurgeBitmapRefs(stdBitmap *pBitmap) {}
void std3D_PurgeSurfaceRefs(rdDDrawSurface *texture) {}
void std3D_UpdateSettings() {}
void std3D_Screenshot(const char* pFpath) {}

void std3D_ResetUIRenderList() {}
int std3D_AddBitmapToTextureCache(stdBitmap *texture, int mipIdx, int is_alpha_tex, int no_alpha) {}
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
int std3D_IsReady() {}