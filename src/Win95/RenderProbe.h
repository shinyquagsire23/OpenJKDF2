#ifndef OPENJKDF2_RENDER_PROBE_H
#define OPENJKDF2_RENDER_PROBE_H

/* SDL bootstrap options: parsed before any window exists, separate from the
 * legacy whitespace tokenizer so output directories may contain spaces. */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct RenderProbeOptions {
    int enabled, width, height, frames, delayMs, bloom, ssao;
    char output[640];
} RenderProbeOptions;

static int RenderProbe_Equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a++) != tolower((unsigned char)*b++)) return 0;
    }
    return *a == *b;
}

/* 1 = flag, 2 = option with one value, 0 = unrelated engine argument. */
static int RenderProbe_OptionSize(const char *arg)
{
    if (*arg != '-' && *arg != '/') return 0;
    ++arg;
    if (RenderProbe_Equal(arg, "renderprobe")) return 1;
    const char *names[] = {"renderwidth", "renderheight", "renderframes", "renderdelayms", "renderout", "renderbloom", "renderssao"};
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); ++i)
        if (RenderProbe_Equal(arg, names[i])) return 2;
    return 0;
}

static int RenderProbe_Number(const char *s, int lo, int hi, int *out)
{
    char *end;
    if (!s || !*s || !isdigit((unsigned char)*s)) return 0;
    errno = 0;
    long value = strtol(s, &end, 10);
    if (errno || *end || value < lo || value > hi) return 0;
    *out = (int)value;
    return 1;
}

static int RenderProbe_LocalPath(const char *s)
{
    size_t n = strlen(s);
    if (!n || n >= 600) return 0;
    /* Absolute local drive or POSIX path. No UNC/device paths or traversal. */
    if (!((isalpha((unsigned char)s[0]) && s[1] == ':' && (s[2] == '/' || s[2] == '\\')) || s[0] == '/')) return 0;
    if (s[0] == '/' && (s[1] == '/' || s[1] == '\\')) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c >= 127 || c == '"' || c == '*' || c == '?' || c == '|' || c == '<' || c == '>' || (c == ':' && i != 1)) return 0;
        if (c == '.' && s[i+1] == '.' && (i == 0 || s[i-1] == '/' || s[i-1] == '\\') && (s[i+2] == 0 || s[i+2] == '/' || s[i+2] == '\\')) return 0;
    }
    return 1;
}

static int RenderProbe_Parse(int argc, char **argv, RenderProbeOptions *o)
{
    memset(o, 0, sizeof(*o));
    o->width = 1280; o->height = 720; o->frames = 300; o->delayMs = 3000;
    int options = 0, headless = 0, autostart = 0;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (RenderProbe_Equal(arg, "-headless") || RenderProbe_Equal(arg, "/headless")) headless = 1;
        if (RenderProbe_Equal(arg, "-autostart") || RenderProbe_Equal(arg, "/autostart")) autostart = 1;
        int size = RenderProbe_OptionSize(arg);
        if (!size) continue;
        if (size == 1) { o->enabled = 1; continue; }
        options = 1;
        if (++i == argc) return 0;
        const char *value = argv[i];
        ++arg;
        if (RenderProbe_Equal(arg,"renderout")) {
            if (!RenderProbe_LocalPath(value)) return 0;
            strcpy(o->output,value);
        }
        else if (RenderProbe_Equal(arg,"renderwidth")) { if (!RenderProbe_Number(value,640,4096,&o->width)) return 0; }
        else if (RenderProbe_Equal(arg,"renderheight")) { if (!RenderProbe_Number(value,480,2160,&o->height)) return 0; }
        else if (RenderProbe_Equal(arg,"renderframes")) { if (!RenderProbe_Number(value,3,18000,&o->frames)) return 0; }
        else if (RenderProbe_Equal(arg,"renderdelayms")) { if (!RenderProbe_Number(value,0,60000,&o->delayMs)) return 0; }
        else if (RenderProbe_Equal(arg,"renderbloom")) { if (!RenderProbe_Number(value,0,1,&o->bloom)) return 0; }
        else if (RenderProbe_Equal(arg,"renderssao")) { if (!RenderProbe_Number(value,0,1,&o->ssao)) return 0; }
    }
    return o->enabled ? (!headless && autostart && o->output[0]) : !options;
}
#endif
