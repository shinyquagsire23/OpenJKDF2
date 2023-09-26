#include "Platform/std3D.h"

#include <nds.h>

#include "Win95/stdDisplay.h"

int std3D_bReinitHudElements = 0;

int textureIDS[8];
int paletteIDS[3];
float fCamera = 1.25;
int nTexture = 0;

uint16_t i8Pal[256];


//verticies for the cube
v16 CubeVectors[] = {
    floattov16(-0.5), floattov16(-0.5), floattov16(0.5), 
    floattov16(0.5),  floattov16(-0.5), floattov16(0.5),
    floattov16(0.5),  floattov16(-0.5), floattov16(-0.5),
    floattov16(-0.5), floattov16(-0.5), floattov16(-0.5),
    floattov16(-0.5), floattov16(0.5),  floattov16(0.5), 
    floattov16(0.5),  floattov16(0.5),  floattov16(0.5),
    floattov16(0.5),  floattov16(0.5),  floattov16(-0.5),
    floattov16(-0.5), floattov16(0.5),  floattov16(-0.5)
};

//polys
u8 CubeFaces[] = {
    3,2,1,0,
    0,1,5,4,
    1,2,6,5,
    2,3,7,6,
    3,0,4,7,
    5,6,7,4
};

//texture coordinates
u32 uv[] =
{

    //TEXTURE_PACK(inttot16(16), 0),
    //TEXTURE_PACK(inttot16(16),inttot16(16)),
    //TEXTURE_PACK(0, inttot16(16)),
    //TEXTURE_PACK(0,0)

    TEXTURE_PACK(0, inttot16(16)),
    TEXTURE_PACK(inttot16(16),inttot16(16)),
    TEXTURE_PACK(inttot16(16), 0),
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

    GFX_TEX_COORD = (uv[0]);
    glVertex3v16(CubeVectors[f1*3], CubeVectors[f1*3 + 1], CubeVectors[f1*3 +  2] );

    GFX_TEX_COORD = (uv[1]);
    glVertex3v16(CubeVectors[f2*3], CubeVectors[f2*3 + 1], CubeVectors[f2*3 + 2] );

    GFX_TEX_COORD = (uv[2]);
    glVertex3v16(CubeVectors[f3*3], CubeVectors[f3*3 + 1], CubeVectors[f3*3 + 2] );

    GFX_TEX_COORD = (uv[3]);
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
    //vramSetBankB(VRAM_B_TEXTURE);
    //vramSetBankC(VRAM_C_TEXTURE);
    //vramSetBankD(VRAM_D_TEXTURE);
    //vramSetBankE(VRAM_E_TEX_PALETTE);
    vramSetBankF(VRAM_F_TEX_PALETTE_SLOT0);
    //vramSetBankG(VRAM_G_TEX_PALETTE_SLOT5);

    glGenTextures(1, &textureIDS[0]);
    glGenTextures(1, &paletteIDS[0]);

    u8* i8Bitmap = malloc(16*16);
    for (int i = 0; i < 256; i++)
    {
        i8Bitmap[i] = i;
    }

    update_from_display_palette();

    glBindTexture(0, textureIDS[0]);
    glTexImage2D(0, 0, GL_RGB256, TEXTURE_SIZE_16 , TEXTURE_SIZE_16, 0, TEXGEN_TEXCOORD, (u8*)i8Bitmap);
    
    //glBindTexture(0, paletteIDS[0]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8Pal );

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(70, 256.0 / 192.0, 0.1, 40);

    return 0;
}
void std3D_Shutdown() {}
int std3D_StartScene()
{
    return 0;
}
int std3D_EndScene()
{
    return 0;
}
void std3D_ResetRenderList() {}
int std3D_RenderListVerticesFinish()
{
    return 0;
}
void std3D_DrawRenderList() {}
int std3D_SetCurrentPalette(rdColor24 *a1, int a2)
{
    return 0;
}
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int *outW, unsigned int *outH) {}
int std3D_DrawOverlay()
{
    return 0;
}
void std3D_UnloadAllTextures() {}
void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris) {}
void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines) {}
int std3D_AddRenderListVertices(D3DVERTEX *vertex_array, int count)
{
    return 0;
}
void std3D_UpdateFrameCount(rdDDrawSurface *surface) {}
void std3D_PurgeTextureCache() {}
int std3D_ClearZBuffer()
{
    return 0;
}
int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha)
{
    return 0;
}
void std3D_DrawMenu()
{
    //printf("std3D_DrawMenu\n");
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();

    gluLookAt(  0.0, 0.0, fCamera,      //camera possition 
        0.0, 0.0, 0.0,      //look at
        0.0, 1.0, 0.0);     //up

    scanKeys();
    u16 keys = keysHeld();
    //if((keys & KEY_UP)) rotateX += 3;
    //if((keys & KEY_DOWN)) rotateX -= 3;
    //if((keys & KEY_LEFT)) rotateY += 3;
    //if((keys & KEY_RIGHT)) rotateY -= 3;
    if((keys & KEY_A)) fCamera -= 0.05f;
    if((keys & KEY_B)) fCamera += 0.05f;

    if(fCamera <= 0.58f) fCamera = 0.58f;

    u16 keysPressed = keysDown();

    update_from_display_palette();

    glBindTexture(0, textureIDS[nTexture]);
    glColorTableEXT( 0, 0, 256, 0, 0, (u16*)i8Pal );

    //draw the obj
    glColor3b(255,255,255);
    glScalef(0.4f,0.4f,0.4f);
    int polyid = 1;
    for(int j = 0; j < 2; j++)
    {
        for(int i = 0; i < 6; i++)
        {
            //glAssignColorTable(0,paletteIDS[0]);

            glPolyFmt(POLY_ALPHA(31) | POLY_CULL_BACK | POLY_MODULATION | POLY_ID(polyid) ) ;
            glBegin(GL_QUAD);
            drawQuad(i);
            glEnd();                
            polyid++;
        }

        glScalef(1.0f/0.4f,1.0f/0.4f,1.0f/0.4f);
    }

    glPopMatrix(1);

    glFlush(GL_TRANS_MANUALSORT);

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
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, float dstX, float dstY, rdRect* srcRect, float scaleX, float scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, float dstX, float dstY, rdRect* srcRect, float scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
int std3D_IsReady() {}