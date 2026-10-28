/* Adapted from andreipemberton's tests/test_rdMaterialIO.c in the MotS fixes fork (685dd18e).
 * Execute the unchanged upstream static helpers, not the fork's helper header.
 * Only HostServices/fileRead and the integer file handle are test substitutes.
 * No display surface, whole MAT loader, GPU upload, or retail data is involved.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t stdFile_t;
#include "texture_header.inc"

static unsigned checks, read_calls;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static uint8_t input[4096];
static size_t cursor, available, chunk;
static int oversized_read;

static size_t read_memory(stdFile_t file, void *out, size_t count)
{
    CHECK(file == 17);
    CHECK(cursor <= available);
    ++read_calls;
    /* A misreporting callback without writing past the supplied buffer. */
    if (oversized_read) return count + 1;
    if (count > chunk) count = chunk;
    if (count > available - cursor) count = available - cursor;
    memcpy(out, input + cursor, count);
    cursor += count;
    return count;
}

static struct TestHostServices {
    size_t (*fileRead)(stdFile_t, void *, size_t);
} host = {read_memory};
static struct TestHostServices *rdroid_g_pHS = &host;

#include "material_helpers.inc"

static void reset(size_t length, size_t short_chunk)
{
    cursor = 0;
    available = length;
    chunk = short_chunk;
    read_calls = 0;
    oversized_read = 0;
}

static void check_cels(size_t width, size_t height, size_t bytes_per_pixel,
                       size_t count, size_t short_chunk)
{
    const size_t row_bytes = width * bytes_per_pixel;
    const size_t stride = (row_bytes + 3) & ~(size_t)3;
    uint8_t output[512];
    reset(0, short_chunk);
    CHECK(1 + stride * height < sizeof(output));
    for (size_t cel = 0; cel < count; ++cel) {
        rdTextureHeader header = {
            (uint32_t)width, (uint32_t)height, 0, 0, 0, 1
        };
        CHECK(available + sizeof(header) + row_bytes * height < sizeof(input));
        memcpy(input + available, &header, sizeof(header));
        available += sizeof(header);
        for (size_t pixel = 0; pixel < row_bytes * height; ++pixel)
            input[available++] = (uint8_t)(cel + pixel + 1);
    }
    input[available++] = 0xa5;
    for (size_t cel = 0; cel < count; ++cel) {
        rdTextureHeader header = {0};
        CHECK(rdMaterial_ReadExact(17, &header, sizeof(header)));
        CHECK(header.width == width && header.height == height && header.num_mipmaps == 1);
        CHECK(header.alpha_en == 0 && header.unk_0c == 0 && header.unk_10 == 0);
        CHECK(rdMaterial_ValidTextureLayout(header.width, header.height, header.num_mipmaps, 4));
        memset(output, 0xcc, sizeof(output));
        CHECK(rdMaterial_ReadPackedRows(17, output + 1, stride * height,
                                       row_bytes, height, stride));
        CHECK(output[0] == 0xcc && output[1 + stride * height] == 0xcc);
        for (size_t y = 0; y < height; ++y) {
            for (size_t x = 0; x < row_bytes; ++x)
                CHECK(output[1 + y * stride + x] == (uint8_t)(cel + y * row_bytes + x + 1));
            for (size_t x = row_bytes; x < stride; ++x)
                CHECK(output[1 + y * stride + x] == 0);
        }
        /* Independent literal oracle for the characteristic padded 2x2 cel. */
        if (cel == 0 && width == 2 && height == 2 && bytes_per_pixel == 1) {
            static const uint8_t expected[] = {1, 2, 0, 0, 3, 4, 0, 0};
            CHECK(memcmp(output + 1, expected, sizeof(expected)) == 0);
        }
    }
    CHECK(cursor + 1 == available && input[cursor] == 0xa5);
    if (width == 2 && height == 2 && bytes_per_pixel == 1 && count == 14)
        CHECK(cursor == 392); /* Four pixels plus a 24-byte header, fourteen times. */
}

static void test_io_boundaries(void)
{
    uint8_t output[16];
    memset(output, 0xcc, sizeof(output));
    reset(3, 4096);
    CHECK(!rdMaterial_ReadPackedRows(17, output + 1, 8, 2, 2, 4));
    CHECK(cursor == 3);
    CHECK(output[0] == 0xcc && output[9] == 0xcc);
    CHECK(output[3] == 0 && output[4] == 0); /* Completed first row's padding. */

    reset(3, 4096);
    CHECK(!rdMaterial_ReadPackedRows(17, output, sizeof(output), 4, 2, 2));
    CHECK(!rdMaterial_ReadPackedRows(17, output, 7, 2, 2, 4));
    CHECK(!rdMaterial_ReadPackedRows(17, NULL, 8, 2, 2, 4));
    CHECK(!rdMaterial_ReadPackedRows(17, output, 8, 0, 2, 4));
    CHECK(!rdMaterial_ReadPackedRows(17, output, 8, 2, 0, 4));
    CHECK(!rdMaterial_ReadPackedRows(17, output, 8, 2, 2, 0));
    CHECK(cursor == 0 && read_calls == 0);

    CHECK(rdMaterial_ReadExact(17, output, 0));
    CHECK(read_calls == 0);
    oversized_read = 1;
    CHECK(!rdMaterial_ReadExact(17, output, 1));
    CHECK(read_calls == 1 && cursor == 0);
    reset(0, 4096);
    CHECK(!rdMaterial_ReadExact(17, output, 1));
    CHECK(read_calls == 1 && cursor == 0);
    reset(3, 1);
    rdTextureHeader header = {0};
    CHECK(!rdMaterial_ReadExact(17, &header, sizeof(header)));
    CHECK(cursor == 3);
}

static void test_layouts(void)
{
    /* The loader supplies a four-entry mip array. Keep this production domain:
     * do not exercise larger maxMipmaps with shifts outside uint32_t's width.
     */
    static const struct {
        uint32_t width, height, mips;
        int valid;
    } cases[] = {
        {2, 2, 1, 1}, {8, 8, 4, 1}, {8, 4, 3, 1},
        {1, 1, 1, 1}, {1, 1, 0, 1}, {2, 2, 0, 1},
        {2, 2, 3, 0}, {8, 4, 4, 0}, {64, 64, 5, 0},
        {0, 2, 1, 0}, {2, 0, 1, 0}, {0, 0, 0, 0},
        {UINT32_MAX, 2, 1, 0}, {2, UINT32_MAX, 1, 0},
        {2, 1, UINT32_MAX, 0}, {INT32_MAX, 8, 4, 1}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        CHECK(rdMaterial_ValidTextureLayout(cases[i].width, cases[i].height,
                                            cases[i].mips, 4) == cases[i].valid);
}

int main(void)
{
    check_cels(2, 2, 1, 14, 4096);
    check_cels(2, 2, 1, 14, 1);
    check_cels(1, 1, 1, 3, 2);
    check_cels(3, 4, 1, 3, 4096);
    check_cels(4, 4, 1, 3, 4096);
    check_cels(1, 2, 2, 3, 3);
    check_cels(3, 4, 2, 3, 4096);
    test_io_boundaries();
    test_layouts();
    printf("PASS actual MAT helpers: %u assertions, seven packed-cel sequences\n", checks);
    return 0;
}
