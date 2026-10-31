// Host-only stdio failure injection. No renderer, game, or window system linked.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "Platform/GL/render_probe_output.h"

typedef struct {int failWrite, failClose, closed;} Sink;
static ssize_t sink_write(void* state, const char* data, size_t size)
{
    Sink* sink = state;
    (void)data;
    if (sink->failWrite) {errno = ENOSPC; return -1;}
    return (ssize_t)size;
}
static int sink_close(void* state)
{
    Sink* sink = state;
    ++sink->closed;
    if (sink->failClose) {errno = EIO; return -1;}
    return 0;
}
static FILE* output(Sink* sink)
{
    cookie_io_functions_t ops = {NULL, sink_write, NULL, sink_close};
    FILE* stream = fopencookie(sink, "w", ops);
    assert(stream);
    assert(!setvbuf(stream, NULL, _IONBF, 0));
    return stream;
}
int main(int argc, char** argv)
{
    assert(argc == 2);
    const unsigned char bottomUp[] = {1,2,3,4,5,6, 7,8,9,10,11,12};
    const unsigned char expected[] = {7,8,9,10,11,12, 1,2,3,4,5,6};
    FILE* file = fopen(argv[1], "wb"); assert(file);
    assert(RenderProbe_WritePng(file, 2, 2, bottomUp));
    // Use libpng's independent read path to verify the entire image and rows.
    png_image image; memset(&image, 0, sizeof(image)); image.version = PNG_IMAGE_VERSION;
    assert(png_image_begin_read_from_file(&image, argv[1]));
    assert(image.width == 2 && image.height == 2);
    image.format = PNG_FORMAT_RGB;
    unsigned char decoded[12];
    assert(png_image_finish_read(&image, NULL, decoded, 0, NULL));
    assert(!memcmp(decoded, expected, sizeof(expected)));
    png_image_free(&image);

    Sink failedWrite = {1,0,0};
    assert(!RenderProbe_WritePng(output(&failedWrite), 2, 2, bottomUp));
    assert(failedWrite.closed == 1);
    Sink failedClose = {0,1,0};
    assert(!RenderProbe_WritePng(output(&failedClose), 2, 2, bottomUp));
    assert(failedClose.closed == 1);
    Sink valid = {0,0,0};
    assert(RenderProbe_WritePng(output(&valid), 2, 2, bottomUp));
    assert(valid.closed == 1);

    // Sidecar completion uses the same checked stream-close helper.
    Sink sidecarClose = {0,1,0};
    file = output(&sidecarClose);
    assert(fprintf(file, "frame=3\n") > 0);
    assert(!RenderProbe_CloseOutput(file, 1));
    assert(sidecarClose.closed == 1);
    Sink sidecarWrite = {1,0,0};
    file = output(&sidecarWrite);
    (void)fprintf(file, "frame=3\n");
    assert(!RenderProbe_CloseOutput(file, 1));
    assert(sidecarWrite.closed == 1);
    Sink priorFailure = {0,0,0};
    assert(!RenderProbe_CloseOutput(output(&priorFailure), 0));
    assert(priorFailure.closed == 1);
    puts("PASS: probe PNG decode/orientation, write/close failures, sidecar completion");
    return 0;
}
