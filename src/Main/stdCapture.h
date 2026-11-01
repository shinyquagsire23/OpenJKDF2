#ifndef OPENJKDF2_STDCAPTURE_H
#define OPENJKDF2_STDCAPTURE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct stdCaptureRequest {
    int width, height, sector, frame, timeoutMs;
    double x, y, z, pitch, yaw, roll, fov;
    char output[1024];
} stdCaptureRequest;
extern stdCaptureRequest stdCapture_request;
int stdCapture_IsRequested(void);
int stdCapture_PreserveConsoleStreams(int argc, char** argv);
int stdCapture_IsActive(void);
void stdCapture_Trace(const char* message);
int stdCapture_Parse(const char* text, stdCaptureRequest* request);
int stdCapture_Init(int argc, char** argv);
void stdCapture_CheckDeadline(uint64_t nowMs);
void stdCapture_ApplyCamera(void);
int stdCapture_FrameReady(void);
int stdCapture_WriteRgb(const unsigned char* pixels, int width, int height);
void stdCapture_Complete(int success);
#ifdef __cplusplus
}
#endif
#endif
