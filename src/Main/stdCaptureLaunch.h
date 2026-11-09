#ifndef OPENJKDF2_STD_CAPTURE_LAUNCH_H
#define OPENJKDF2_STD_CAPTURE_LAUNCH_H
#include <ctype.h>
#include <stdlib.h>

/* This startup-only detector remains in ordinary builds so automation requests
 * cannot silently open a normal game when the developer feature is disabled. */
static inline int stdCapture_LaunchOptionEquals(const char* value, const char* option)
{
    while (*value && *option) {
        if (tolower((unsigned char)*value++) != (unsigned char)*option++) return 0;
    }
    return !*value && !*option;
}

static inline int stdCapture_LaunchRequested(int argc, char** argv)
{
    const char* request = getenv("OPENJKDF2_CAPTURE_REQUEST");
    if (request && *request) return 1;
    for (int i = 1; i < argc; ++i) {
        if (stdCapture_LaunchOptionEquals(argv[i], "-capture")) return 1;
        if (argv[i][0] != '-' && argv[i][0] != '/') continue;
        const char* names[] = {"renderprobe", "renderwidth", "renderheight", "renderframes",
            "renderdelayms", "renderout", "renderbloom", "renderssao"};
        for (unsigned int j = 0; j < sizeof(names) / sizeof(names[0]); ++j)
            if (stdCapture_LaunchOptionEquals(argv[i] + 1, names[j])) return 1;
    }
    return 0;
}
#endif
