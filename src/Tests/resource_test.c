// Whole resource lifecycle tests. These link the production engine and use its
// file services, bitmap/material loaders, SDL surfaces, color conversion and
// cleanup. The files below are generated fixtures, not copies of loader code.
#include "types.h"
#include "globals.h"
#include "Main/Main.h"
#include "Win95/std.h"
#include "Win95/stdDisplay.h"
#include "General/stdBitmap.h"
#include "General/stdColor.h"
#include "Engine/rdMaterial.h"
#include "stdPlatform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef RDMATERIAL_LRU_LOAD_UNLOAD
#error resource_test requires the desktop immediate-loading configuration
#endif

static HostServices hs;
static unsigned checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 0; \
} } while (0)

static rdTexFormat pixel_format(unsigned bpp)
{
    rdTexFormat result = {0};
    result.bpp = bpp;
    result.is16bit = bpp != 8;
    if (bpp == 16) {
        result.r_bits = 5; result.g_bits = 6; result.b_bits = 5;
        result.r_shift = 11; result.g_shift = 5;
        result.r_bitdiff = 3; result.g_bitdiff = 2; result.b_bitdiff = 3;
    } else if (bpp > 16) {
        result.r_bits = result.g_bits = result.b_bits = 8;
        result.r_shift = 16; result.g_shift = 8;
    }
    return result;
}

static unsigned char pixel_byte(unsigned image, unsigned row, unsigned byte)
{
    return (unsigned char)(17 + image * 43 + row * 19 + byte * 7);
}

static int color_rows(void)
{
    rdTexFormat rgb565 = pixel_format(16);
    rdTexFormat rgb555 = rgb565;
    rgb555.g_bits = 5; rgb555.r_shift = 10; rgb555.g_bitdiff = 3;
    uint16_t source[] = {0x0000, 0xf800, 0x07e0, 0x001f, 0xffff};
    const uint16_t expected[] = {0x0000, 0x7c00, 0x03e0, 0x001f, 0x7fff};
    uint16_t actual[5] = {0};
    stdColor_ColorConvertOneRow((uint8_t *)actual, &rgb555, (uint8_t *)source, &rgb565, 5);
    CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
    for (unsigned i = 0; i < 5; ++i)
        CHECK((uint16_t)stdColor_ColorConvertOnePixel(&rgb555, source[i], &rgb565) == expected[i]);
    return 1;
}

static int write_pixels(FILE *fp, unsigned image, unsigned width, unsigned height,
                        unsigned bpp, int truncate_last)
{
    unsigned row_bytes = width * (bpp / 8);
    for (unsigned y = 0; y < height; ++y) {
        for (unsigned x = 0; x < row_bytes; ++x) {
            if (truncate_last && y + 1 == height && x + 1 == row_bytes) return 1;
            CHECK(fputc(pixel_byte(image, y, x), fp) != EOF);
        }
    }
    return 1;
}

static int check_surface(tVBuffer *surface, unsigned image, unsigned width,
                         unsigned height, unsigned bpp)
{
    CHECK(surface != NULL);
    CHECK(surface->format.width == width && surface->format.height == height);
    CHECK(surface->format.format.bpp == bpp);
    CHECK(surface->format.rowSize >= width * (bpp / 8));
    CHECK(stdDisplay_VBufferLock(surface));
    const unsigned char *pixels = (const unsigned char *)surface->surface_lock_alloc;
    CHECK(pixels != NULL);
    for (unsigned y = 0; y < height; ++y)
        for (unsigned x = 0; x < width * (bpp / 8); ++x)
            CHECK(pixels[y * surface->format.rowSize + x] == pixel_byte(image, y, x));
    stdDisplay_VBufferUnlock(surface);
    return 1;
}

static int check_bitmap(stdBitmap *bitmap, const bitmapHeader *header,
                        unsigned width, unsigned height)
{
    CHECK(bitmap != NULL);
    CHECK(bitmap->numMips == 2 && bitmap->xPos == 11 && bitmap->yPos == 13);
    CHECK(bitmap->colorkey == header->colorkey && bitmap->palFmt == header->palFmt);
    CHECK(memcmp(&bitmap->format, &header->format, sizeof(header->format)) == 0);
    for (unsigned image = 0; image < 2; ++image) {
        CHECK(check_surface(bitmap->mipSurfaces[image], image, width-image,
                            height-image, header->format.bpp));
        CHECK(bitmap->mipSurfaces[image]->transparent_color == header->colorkey);
    }
    if (header->format.bpp == 8) {
        CHECK(bitmap->palette != NULL);
        for (unsigned i = 0; i < 768; ++i)
            CHECK(((unsigned char *)bitmap->palette)[i] == ((i * 3 + 1) & 255));
    }
    return 1;
}

static int bitmap_lifecycle(unsigned bpp, unsigned width, unsigned height)
{
    const char *input = "resource_input.bm";
    const char *output = "resource_roundtrip.bm";
    bitmapHeader header = {0};
    memcpy(&header.magic, "BM  ", 4);
    header.field_4 = 70;
    header.palFmt = 1 | (bpp == 8 ? 2 : 0);
    header.numMips = 2;
    header.xPos = 11; header.yPos = 13;
    header.colorkey = bpp == 8 ? 7 : 0x07e0;
    header.format = pixel_format(bpp);
    FILE *fp = fopen(input, "wb");
    CHECK(fp != NULL);
    CHECK(fwrite(&header, sizeof(header), 1, fp) == 1);
    for (unsigned image = 0; image < 2; ++image) {
        uint32_t dimensions[2] = {width - image, height - image};
        CHECK(fwrite(dimensions, sizeof(dimensions), 1, fp) == 1);
        CHECK(write_pixels(fp, image, dimensions[0], dimensions[1], bpp, 0));
    }
    if (bpp == 8)
        for (unsigned i = 0; i < 768; ++i) CHECK(fputc((i * 3 + 1) & 255, fp) != EOF);
    CHECK(fclose(fp) == 0);

    stdBitmap *bitmap = stdBitmap_Load((char *)input, 0, 0);
    CHECK(check_bitmap(bitmap, &header, width, height));
    CHECK(stdBitmap_Write(output, bitmap));
    stdBitmap_Free(bitmap);
    bitmap = stdBitmap_Load((char *)output, 0, 0);
    CHECK(check_bitmap(bitmap, &header, width, height));

    // Equal-format conversion is a lifecycle no-op. Conversion metadata and
    // colorkey use the real color module; SDL's VBuffer conversion currently
    // keeps its surface, so this test does not claim converted SDL pixel bytes.
    tVBuffer *first = bitmap->mipSurfaces[0];
    stdBitmap_ConvertColorFormat(&header.format, bitmap);
    CHECK(bitmap->mipSurfaces[0] == first);
    if (bpp == 16) {
        rdTexFormat rgb555 = pixel_format(16);
        rgb555.g_bits = 5; rgb555.r_shift = 10;
        rgb555.g_bitdiff = 3;
        stdBitmap_ConvertColorFormat(&rgb555, bitmap);
        CHECK(memcmp(&bitmap->format, &rgb555, sizeof(rgb555)) == 0);
        CHECK(bitmap->colorkey == 0x03e0); // Full green RGB565 -> RGB555.
    }
    stdBitmap_Free(bitmap);
    CHECK(remove(input) == 0 && remove(output) == 0);
    return 1;
}

static int write_material(const char *path, unsigned bpp, unsigned width,
                          unsigned height, int invalid, int truncated)
{
    rdMaterialHeader header = {0};
    memcpy(header.magic, "MAT ", 4);
    header.revision = 50;
    header.num_texinfo = 2; header.num_textures = 2;
    header.texFormat = pixel_format(bpp);
    FILE *fp = fopen(path, "wb");
    CHECK(fp != NULL);
    CHECK(fwrite(&header, sizeof(header), 1, fp) == 1);
    for (unsigned cel = 0; cel < 2; ++cel) {
        rdTexinfoHeader info = {0};
        rdTexinfoExtHeader ext = {0};
        info.texture_type = 8;
        ext.unk_0c = 1 - cel; // Exercise actual cel-to-texture binding.
        CHECK(fwrite(&info, sizeof(info), 1, fp) == 1);
        CHECK(fwrite(&ext, sizeof(ext), 1, fp) == 1);
    }
    for (unsigned image = 0; image < 2; ++image) {
        rdTextureHeader texture = {0};
        texture.width = invalid && image == 0 ? 0 : width;
        texture.height = height;
        texture.num_mipmaps = 2;
        texture.alpha_en = 1; texture.unk_10 = 3;
        CHECK(fwrite(&texture, sizeof(texture), 1, fp) == 1);
        for (unsigned mip = 0; mip < 2; ++mip)
            CHECK(write_pixels(fp, image*2 + mip, width >> mip, height >> mip,
                               bpp, truncated && image == 1 && mip == 1));
    }
    CHECK(fclose(fp) == 0);
    return 1;
}

static int material_lifecycle(unsigned bpp, unsigned width, unsigned height)
{
    char path[] = "resource_input.mat";
    CHECK(write_material(path, bpp, width, height, 0, 0));
    rdMaterial material = {0};
    CHECK(rdMaterial_LoadEntry(path, &material, 0, 0));
    CHECK(rdMaterial_EnsureData(&material));
    CHECK(material.num_textures == 2 && material.num_texinfo == 2);
    CHECK(material.texinfos[0]->texture_ptr == &material.textures[1]);
    CHECK(material.texinfos[1]->texture_ptr == &material.textures[0]);
    for (unsigned image = 0; image < 2; ++image) {
        CHECK(material.textures[image].num_mipmaps == 2);
        for (unsigned mip = 0; mip < 2; ++mip) {
            tVBuffer *surface = material.textures[image].texture_struct[mip];
            CHECK(check_surface(surface, image*2 + mip, width >> mip, height >> mip, bpp));
            CHECK(surface->transparent_color == 3);
        }
    }
    rdMaterial_FreeEntry(&material);
    CHECK(material.textures == NULL && material.texinfos[0] == NULL && material.texinfos[1] == NULL);
    rdMaterial_FreeEntry(&material); // Entry cleanup is safe after completed teardown.

    for (unsigned failure = 0; failure < 2; ++failure) {
        CHECK(write_material(path, bpp, width, height, failure == 0, failure == 1));
        memset(&material, 0, sizeof(material));
        int loaded = rdMaterial_LoadEntry(path, &material, 0, 0);
        CHECK(!loaded);
        rdMaterial_FreeEntry(&material);
        CHECK(material.textures == NULL);
    }
    CHECK(remove(path) == 0);
    return 1;
}

int main(void)
{
    stdInitServices(&hs);
    hs.debugPrint = hs.messagePrint = hs.errorPrint = stdConsolePrintf;
    pHS = std_g_pHS = rdroid_g_pHS = pSithHS = pLowLevelHS = &hs;
    stdStartup(&hs);
    Main_bHeadless = 1; // Production headless path; no GL context or upload stubs.
    if (!color_rows()) return 1;
    const unsigned depths[] = {8, 16, 24, 32};
    const unsigned widths[] = {3, 4, 5, 8};
    for (unsigned depth = 0; depth < sizeof(depths)/sizeof(depths[0]); ++depth)
        for (unsigned width = 0; width < sizeof(widths)/sizeof(widths[0]); ++width) {
            if (!bitmap_lifecycle(depths[depth], widths[width], 5)) return 1;
            if (!material_lifecycle(depths[depth], widths[width], 5)) return 1;
        }
    stdShutdown();
    printf("Resource lifecycle: %u checks passed (BM load/write/convert/free; MAT load/bind/mips/reject/free).\n", checks);
    return 0;
}
