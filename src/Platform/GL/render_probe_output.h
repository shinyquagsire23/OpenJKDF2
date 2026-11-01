#ifndef OPENJKDF2_RENDER_PROBE_OUTPUT_H
#define OPENJKDF2_RENDER_PROBE_OUTPUT_H
#include <stdio.h>
#include <stdint.h>
#include <png.h>

// Own and close the stream even when an earlier write failed. Successful close
// includes stdio flushing; it does not promise crash-proof filesystem durability.
static int RenderProbe_CloseOutput(FILE* output, int writesSucceeded)
{
    int ok = writesSucceeded && !ferror(output);
    if (fclose(output)) ok = 0;
    return ok;
}

// Probe-only checked writer. Ordinary screenshots retain their existing writer.
// Takes ownership of output; framebuffer rows have OpenGL's bottom-up origin.
static int RenderProbe_WritePng(FILE* output, int width, int height, const uint8_t* pixels)
{
    if (!output) return 0;
    if (!pixels || width < 1 || width > 4096 || height < 1 || height > 2160)
        return RenderProbe_CloseOutput(output, 0);
    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) return RenderProbe_CloseOutput(output, 0);
    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_write_struct(&png, NULL);
        return RenderProbe_CloseOutput(output, 0);
    }
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        return RenderProbe_CloseOutput(output, 0);
    }
    png_init_io(png, output);
    png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_RGB,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);
    for (int y = height - 1; y >= 0; --y)
        png_write_row(png, pixels + (size_t)y * (size_t)width * 3);
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    return RenderProbe_CloseOutput(output, 1);
}
#endif
