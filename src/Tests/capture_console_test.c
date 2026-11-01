#define STDCAPTURE_UNIT_TEST
#include "Main/stdCapture.c"
#include <assert.h>

int main(void)
{
    assert(!unsetenv("OPENJKDF2_CAPTURE_REQUEST"));
    char* normal[] = {"game"};
    char* headless[] = {"game", "-headless", "-autostart", "-mp"};
    char* slashHeadless[] = {"game", "/HEADLESS"};
    char* capture[] = {"game", "-capture"};
    char* probe[] = {"game", "-renderprobe"};
    char* slashProbe[] = {"game", "/RenderProbe"};
    char* unknown[] = {"game", "-renderprobe-other"};
    assert(!stdCapture_PreserveConsoleStreams(1, normal));
    assert(!stdCapture_PreserveConsoleStreams(4, headless));
    assert(!stdCapture_PreserveConsoleStreams(2, slashHeadless));
    assert(stdCapture_PreserveConsoleStreams(2, capture));
    assert(stdCapture_PreserveConsoleStreams(2, probe));
    assert(stdCapture_PreserveConsoleStreams(2, slashProbe));
    assert(!stdCapture_PreserveConsoleStreams(2, unknown));
    assert(!setenv("OPENJKDF2_CAPTURE_REQUEST", "", 1));
    assert(!stdCapture_PreserveConsoleStreams(4, headless));
    assert(!setenv("OPENJKDF2_CAPTURE_REQUEST", "invalid-request-still-must-not-open-UI", 1));
    assert(stdCapture_PreserveConsoleStreams(1, normal));
    assert(stdCapture_PreserveConsoleStreams(4, headless));
    assert(!unsetenv("OPENJKDF2_CAPTURE_REQUEST"));
    puts("capture console policy passed: ordinary headless keeps console; explicit capture/probe preserves streams");
    return 0;
}
