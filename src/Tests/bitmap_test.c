/* Adapted from andreipemberton's MotS fixes fork regression (218806adee57ab2109f448be385830878ccc2eff).
 * Actual stdBitmap function regression test. No renderer, game, or owned assets.
 * Dependencies below are explicit in-memory stubs; their calls and metadata
 * form the oracle. The engine's pixel-conversion implementation is not tested.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "General/stdBitmap.h"
#include "General/stdColor.h"
#include "Win95/stdDisplay.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line=%d: %s\n",__LINE__,#x); exit(1); } } while (0)
static uint32_t original_pixels[3][4], converted_pixels[3][4];
static tVBuffer originals[3], converted[3];
static tVBuffer* surfaces[3];
static stdBitmap bitmap;
static rdTexFormat expected_from, expected_to;
static int convert_calls, key_calls, pixel_calls;
static void fatal_assert(const char* message,const char* file,int line) {
    fprintf(stderr,"Unexpected engine assertion: %s %s:%d\n",message,file,line); exit(1);
}
static HostServices host={.assert=fatal_assert};
HostServices* std_g_pHS=&host;

/* Stub provides deterministic RGB565->RGB555 or reverse test conversion. */
static uint32_t convert_pixel(uint32_t color,const rdTexFormat* from,const rdTexFormat* to) {
    uint32_t red=(color>>from->r_shift)&((1u<<from->r_bits)-1);
    uint32_t green=(color>>from->g_shift)&((1u<<from->g_bits)-1);
    uint32_t blue=(color>>from->b_shift)&((1u<<from->b_bits)-1);
    if(from->g_bits>to->g_bits) green >>= from->g_bits-to->g_bits;
    else green <<= to->g_bits-from->g_bits;
    return (red<<to->r_shift)|(green<<to->g_shift)|(blue<<to->b_shift);
}
tVBuffer* stdDisplay_VBufferConvertColorFormat(void* format,tVBuffer* from) {
    rdTexFormat* to = format;
    int index=convert_calls++;
    CHECK(index>=0 && index<3);
    CHECK(from==&originals[index]);
    CHECK(memcmp(to,&expected_to,sizeof(*to))==0);
    CHECK(memcmp(&from->format.format,&expected_from,sizeof(*to))==0);
    CHECK(memcmp(&bitmap.format,&expected_from,sizeof(*to))==0); /* Metadata commits after loop. */
    converted[index]=*from;
    converted[index].format.format=*to;
    for(unsigned i=0;i<(unsigned)index+2;i++) converted_pixels[index][i]=convert_pixel(original_pixels[index][i],&from->format.format,to);
    converted[index].transparent_color=convert_pixel(from->transparent_color,&from->format.format,to);
    return &converted[index];
}
int stdDisplay_VBufferSetColorKey(tVBuffer* frame,int color) {
    CHECK(key_calls>=0 && key_calls<3);
    CHECK(frame==&converted[key_calls]);
    CHECK(color==frame->transparent_color);
    ++key_calls;
    return 1;
}
uint32_t stdColor_ColorConvertOnePixel(rdTexFormat* to,int color,rdTexFormat* from) {
    CHECK(pixel_calls++==0);
    CHECK(color==0x07e0 || color==0x03e0);
    CHECK(memcmp(from,&expected_from,sizeof(*from))==0);
    CHECK(memcmp(to,&expected_to,sizeof(*to))==0);
    return convert_pixel((uint32_t)color,from,to);
}


static rdTexFormat rgb565(void) { rdTexFormat f={0}; f.is16bit=1; f.bpp=16; f.r_bits=5; f.g_bits=6; f.b_bits=5; f.r_shift=11; f.g_shift=5; f.b_shift=0; return f; }
static rdTexFormat rgb555(void) { rdTexFormat f=rgb565(); f.g_bits=5; f.r_shift=10; return f; }
static void setup(rdTexFormat from,rdTexFormat to,int mips,int pal) {
    memset(&bitmap,0,sizeof(bitmap)); memset(originals,0,sizeof(originals)); memset(converted,0,sizeof(converted));
    expected_from=from; expected_to=to; convert_calls=key_calls=pixel_calls=0;
    bitmap.format=from; bitmap.numMips=mips; bitmap.palFmt=pal; bitmap.mipSurfaces=surfaces;
    bitmap.colorkey=from.g_bits==6?0x07e0:0x03e0; bitmap.field_20=42; bitmap.field_68=43; bitmap.xPos=-5; bitmap.yPos=77;
    bitmap.palette=(void*)(uintptr_t)0x1234; strcpy(bitmap.fpath,"synthetic-fixture");
    for(int i=0;i<3;i++) {
        originals[i].format.format=from; originals[i].format.width=i+2; originals[i].format.height=1;
        original_pixels[i][0]=from.g_bits==6?0xf800:0x7c00;
        original_pixels[i][1]=bitmap.colorkey; original_pixels[i][2]=0x001f;
        original_pixels[i][3]=from.g_bits==6?0xffff:0x7fff;
        originals[i].transparent_color=bitmap.colorkey; surfaces[i]=&originals[i];
    }
}
static void no_op(rdTexFormat from,rdTexFormat to) {
    setup(from,to,3,1); stdBitmap before=bitmap;
    tVBuffer frames[3]; memcpy(frames,originals,sizeof(frames));
    stdBitmap_ConvertColorFormat(&to,&bitmap);
    CHECK(memcmp(&before,&bitmap,sizeof(bitmap))==0);
    CHECK(memcmp(frames,originals,sizeof(frames))==0);
    CHECK(convert_calls==0 && key_calls==0 && pixel_calls==0);
    for(int i=0;i<3;i++) CHECK(surfaces[i]==&originals[i]);
}
static void real_branch(int mips,int pal,int reverse) {
    rdTexFormat from=reverse?rgb555():rgb565(),to=reverse?rgb565():rgb555();
    setup(from,to,mips,pal); stdBitmap expected=bitmap;
    expected.format=to; if(pal&1) expected.colorkey=reverse?0x07c0:0x03e0;
    stdBitmap_ConvertColorFormat(&to,&bitmap);
    CHECK(convert_calls==mips && key_calls==((pal&1)?mips:0) && pixel_calls==!!(pal&1));
    CHECK(memcmp(&expected,&bitmap,sizeof(bitmap))==0);
    for(int i=0;i<3;i++) {
        CHECK(surfaces[i]==(i<mips?&converted[i]:&originals[i]));
        if(i>=mips) continue;
        CHECK(converted[i].format.width==originals[i].format.width && converted[i].format.height==originals[i].format.height);
        CHECK(memcmp(&converted[i].format.format,&to,sizeof(to))==0);
        CHECK(converted_pixels[i][0]==(reverse?0xf800u:0x7c00u));
        CHECK(converted_pixels[i][1]==(reverse?0x07c0u:0x03e0u));
        if(i>=1) CHECK(converted_pixels[i][2]==0x001fu);
        if(i>=2) CHECK(converted_pixels[i][3]==(reverse?0xffdfu:0x7fffu));
    }
}
int main(void) {
    stdBitmap_ConvertColorFormat(NULL,NULL); CHECK(convert_calls==0 && key_calls==0 && pixel_calls==0);
    rdTexFormat same=rgb565(); no_op(same,same);
    rdTexFormat indexed={0},other={0}; indexed.bpp=other.bpp=8; other.unk_48=37; no_op(indexed,other);
    for(int mips=0;mips<=3;mips++) for(int pal=0;pal<=1;pal++) for(int reverse=0;reverse<=1;reverse++) real_branch(mips,pal,reverse);
    printf("PASS actual stdBitmap_ConvertColorFormat: %u assertions\n",checks);
    return 0;
}
