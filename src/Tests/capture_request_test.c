#define STDCAPTURE_UNIT_TEST
#include "Main/stdCapture.c"
#include <assert.h>

int main(int argc, char** argv)
{
    assert(argc == 2);
    char request[4096];
    snprintf(request, sizeof(request), "sed-engine-capture-v1\n64 64 2 3 1000\n1 2 3 0 180 0 75\n%s\n", argv[1]);
    stdCaptureRequest parsed;
    assert(stdCapture_Parse(request, &parsed));
    assert(parsed.width == 64 && parsed.sector == 2 && parsed.yaw == 180 && parsed.frame == 3);
    assert(!stdCapture_Parse("sed-engine-capture-v2\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 2 3 1000\n1 2 nan 0 180 0 75\n/tmp/a.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n2048 2048 2 3 1000\n1 2 3 0 180 0 75\n/tmp/a.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 -1 3 1000\n1 2 3 0 180 0 75\n/tmp/a.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 2 121 1000\n1 2 3 0 180 0 75\n/tmp/a.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 2 3 1000\n1 2 3 0 180 0 141\n/tmp/a.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 2 3 1000\n1 2 3 0 180 0 75\nrelative.ppm\n", &parsed));
    assert(!stdCapture_Parse("sed-engine-capture-v1\n64 64 2 3 1000\n1 2 3 0 180 0 75\n/tmp/a.ppm\nextra", &parsed));
    assert(stdCapture_Parse(request, &stdCapture_request)); active = 1;
    assert(!stdCapture_FrameReady());
    cameraApplied = 1; assert(!stdCapture_FrameReady()); cameraApplied = 1; assert(!stdCapture_FrameReady()); cameraApplied = 1; assert(stdCapture_FrameReady());
    unsigned char pixels[64*64*3] = {0}; pixels[0] = 201; pixels[63*64*3] = 117;
    assert(!stdCapture_WriteRgb(pixels, 63, 64));
    assert(stdCapture_WriteRgb(pixels, 64, 64));
    assert(!stdCapture_WriteRgb(pixels, 64, 64));
    FILE* image = fopen(argv[1], "rb"); assert(image);
    char header[14]; assert(fread(header, 1, 13, image) == 13); header[13] = 0;
    assert(!strcmp(header, "P6\n64 64\n255\n")); assert(fgetc(image) == 117); fclose(image);
    puts("capture request/write tests passed (parser, limits, orientation, no overwrite)");
    return 0;
}
