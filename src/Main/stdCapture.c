// An opt-in inspection capture. This does not implement deterministic simulation.
#include "Main/stdCapture.h"
#include "Main/stdAutostartCharacter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _WIN32
#include <io.h>
#define capture_open _open
#define capture_close _close
#define capture_fdopen _fdopen
#else
#include <unistd.h>
#define capture_open open
#define capture_close close
#define capture_fdopen fdopen
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

stdCaptureRequest stdCapture_request;
static int active, renderedFrames, cameraApplied;
static uint64_t firstMs;
static int write_world_state(FILE* file);
int stdCapture_IsRequested(void) { const char* p = getenv("OPENJKDF2_CAPTURE_REQUEST"); return p && *p; }
int stdCapture_IsActive(void) { return active; }
void stdCapture_Trace(const char* message) { if (active) { fprintf(stderr, "capture startup: %s\n", message); fflush(stderr); } }
static int absolute_path(const char* p) {
#ifdef _WIN32
    return p[0] && p[1] == ':' && (p[2] == '\\' || p[2] == '/');
#else
    return p[0] == '/';
#endif
}
int stdCapture_Parse(const char* text, stdCaptureRequest* request)
{
    stdCaptureRequest r = {0}; int n = 0; double counts[5];
    if (!text || strlen(text) > 4096 || strncmp(text, "sed-engine-capture-v1\n", 22)) return 0;
    if (sscanf(text + 22, "%lf %lf %lf %lf %lf\n%lf %lf %lf %lf %lf %lf %lf%n",
        &counts[0], &counts[1], &counts[2], &counts[3], &counts[4],
        &r.x, &r.y, &r.z, &r.pitch, &r.yaw, &r.roll, &r.fov, &n) != 12) return 0;
    for (int i = 0; i < 5; ++i) if (!isfinite(counts[i]) || counts[i] < 0 || counts[i] > 1000000 || floor(counts[i]) != counts[i]) return 0;
    r.width = (int)counts[0]; r.height = (int)counts[1]; r.sector = (int)counts[2]; r.frame = (int)counts[3]; r.timeoutMs = (int)counts[4];
    const char* path = text + 22 + n;
    if (*path++ != '\n') return 0;
    size_t len = strcspn(path, "\r\n");
    if (len < 5 || len >= sizeof(r.output) || strcmp(path + len, "\n") != 0) return 0;
    memcpy(r.output, path, len);
    if (!absolute_path(r.output) || strcmp(r.output + len - 4, ".ppm")) return 0;
    for (size_t i = 0; i < len; ++i) if ((unsigned char)r.output[i] < 32 || r.output[i] == '"') return 0;
    if (r.width < 64 || r.width > 2048 || r.height < 64 || r.height > 2048 || r.width*r.height > 2097152
        || r.sector < 0 || r.sector > 1000000 || r.frame < 1 || r.frame > 120 || r.timeoutMs < 1000 || r.timeoutMs > 60000) return 0;
    double values[] = {r.x, r.y, r.z, r.pitch, r.yaw, r.roll, r.fov};
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i) if (!isfinite(values[i]) || fabs(values[i]) > 1000000) return 0;
    if (r.fov < 20 || r.fov > 140) return 0;
    *request = r; return 1;
}
int stdCapture_Init(int argc, char** argv)
{
    if (!stdCapture_IsRequested()) {
        for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "-capture")) return 0;
        return 1;
    }
    int autostart = 0, singleplayer = 0, multiplayer = 0, episode = 0, map = 0, capture = 0, startupPath = 0, character = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-capture")) capture++;
        else if (!strcmp(argv[i], "-autostart")) autostart++;
        else if (!strcmp(argv[i], "-sp")) singleplayer++;
        else if (!strcmp(argv[i], "-mp")) multiplayer++;
        else if (!strcmp(argv[i], "-motsCompat") || !strcmp(argv[i], "-noHUD")) { }
        else if (!strcmp(argv[i], "-character")) {
            if (++character != 1 || ++i >= argc || !stdAutostart_CharacterNameValid(argv[i])) return 0;
        }
        else if (!strcmp(argv[i], "-path")) {
            // One explicitly staged startup directory, not arbitrary paths or
            // another installation. Main uses this same argument normally.
            if (++startupPath != 1 || ++i >= argc || !argv[i][0] || strlen(argv[i]) > 31) return 0;
            for (const char* p = argv[i]; *p; ++p)
                if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;
        }
        else if (!strcmp(argv[i], "-episode") || !strcmp(argv[i], "-map")) {
            int isMap = !strcmp(argv[i], "-map");
            if (++i >= argc || !argv[i][0] || strlen(argv[i]) > 100) return 0;
            for (const char* p = argv[i]; *p; ++p)
                if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return 0;
            if (isMap) map++; else episode++;
        } else return 0;
    }
    if (capture != 1 || autostart != 1 || singleplayer + multiplayer != 1 || episode != 1 || map != 1) return 0;
    if (character && multiplayer != 1) return 0;
    const char* path = getenv("OPENJKDF2_CAPTURE_REQUEST");
    if (!absolute_path(path)) return 0;
    FILE* input = fopen(path, "rb"); if (!input) return 0;
    char text[4098]; size_t size = fread(text, 1, sizeof(text)-1, input); int bad = ferror(input); fclose(input); text[size] = 0;
    if (bad || size > 4096 || memchr(text, 0, size) || !stdCapture_Parse(text, &stdCapture_request)) return 0;
    // The launcher must stage a private writable session. Never fall through to
    // installation discovery or an existing user's profile/resource directory.
    FILE* marker = fopen(".openjkdf2-capture-session", "rb"); if (!marker) return 0; fclose(marker);
    FILE* assets = fopen("resource/jk_.cd", "rb"); if (!assets) return 0; fclose(assets);
    active = 1; renderedFrames = 0; firstMs = 0; return 1;
}
void stdCapture_CheckDeadline(uint64_t nowMs)
{
    if (!active) return;
    if (!firstMs) firstMs = nowMs + 1;
    if (nowMs + 1 - firstMs > (uint64_t)stdCapture_request.timeoutMs) {
        fprintf(stderr, "capture: timed out before a completed frame\n"); exit(6);
    }
}
int stdCapture_FrameReady(void) {
    if (!active || !cameraApplied) return 0;
    cameraApplied = 0;
    return ++renderedFrames >= stdCapture_request.frame;
}
static FILE* create_new(const char* path) {
    int fd = capture_open(path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
    if (fd < 0) return NULL;
    FILE* result = capture_fdopen(fd, "wb");
    if (!result) { capture_close(fd); remove(path); }
    return result;
}
int stdCapture_WriteRgb(const unsigned char* pixels, int width, int height)
{
    if (!active || !pixels || width != stdCapture_request.width || height != stdCapture_request.height) return 0;
    char receipt[1100]; snprintf(receipt, sizeof(receipt), "%s.json", stdCapture_request.output);
    FILE* image = create_new(stdCapture_request.output); if (!image) return 0;
    FILE* record = create_new(receipt); if (!record) { fclose(image); remove(stdCapture_request.output); return 0; }
    int ok = fprintf(image, "P6\n%d %d\n255\n", width, height) > 0;
    for (int y = height - 1; ok && y >= 0; --y)
        ok = fwrite(pixels + (size_t)y*width*3, 3, width, image) == (size_t)width;
    if (fclose(image)) ok = 0;
    const stdCaptureRequest* r = &stdCapture_request;
    if (fprintf(record, "{\n  \"schemaVersion\": 1,\n  \"mode\": \"hidden-rendered-inspection\",\n  \"format\": \"ppm-rgb8\",\n  \"width\": %d,\n  \"height\": %d,\n  \"renderedFrame\": %d,\n  \"sector\": %d,\n  \"position\": [%.17g, %.17g, %.17g],\n  \"pitchYawRoll\": [%.17g, %.17g, %.17g],\n  \"horizontalFov\": %.17g,\n  \"deterministicSimulation\": false,\n  \"resourceHashesVerifiedByEngine\": false",
        width, height, renderedFrames, r->sector, r->x, r->y, r->z, r->pitch, r->yaw, r->roll, r->fov) < 0) ok = 0;
    if (!write_world_state(record) || fprintf(record, "\n}\n") < 0) ok = 0;
    if (fclose(record)) ok = 0;
    if (!ok) { remove(stdCapture_request.output); remove(receipt); }
    return ok;
}
void stdCapture_Complete(int success) { fprintf(stderr, "capture: %s\n", success ? "image and receipt written" : "failed; no completed capture"); exit(success ? 0 : 6); }

#if !defined(STDCAPTURE_UNIT_TEST) && defined(SDL2_RENDER) && defined(QOL_IMPROVEMENTS)
#include "types.h"
#include "globals.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "Engine/sithCamera.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdModel3.h"
#include "Main/Main.h"
#include "Gui/jkGUIMultiplayer.h"
#include "World/sithSoundClass.h"

static int write_name(FILE* file, const char* name)
{
    if (!name) return fputs("null", file) >= 0;
    if (fputc('"', file) == EOF) return 0;
    for (int i = 0; i < 32 && name[i]; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (c < 32 || c >= 127 || c == '"' || c == '\\') {
            if (fprintf(file, "\\u%04x", c) < 0) return 0;
        } else if (fputc(c, file) == EOF) return 0;
    }
    return fputc('"', file) != EOF;
}

static int write_world_state(FILE* file)
{
    SithThing* player = sithPlayer_g_pLocalPlayerThing;
    const char* model = player && player->renderData.type == RD_THING_MODEL3 && player->renderData.model3
        ? player->renderData.model3->filename : NULL;
    const char* sound = NULL;
#ifdef SITH_DEBUG_STRUCT_NAMES
    if (player && player->pSoundClass) sound = player->pSoundClass->aName;
#endif
    if (fprintf(file, ",\n  \"engineWorldStateAvailable\": true,\n  \"isMultiplayer\": %s,\n  \"motsCompat\": %s,\n  \"world\": ",
                sithNet_isMulti ? "true" : "false", Main_bMotsCompat ? "true" : "false") < 0) return 0;
    if (!write_name(file, sithWorld_g_pCurrentWorld ? sithWorld_g_pCurrentWorld->map_jkl_fname : NULL)) return 0;
    if (fputs(",\n  \"localPlayerModel\": ", file) < 0 || !write_name(file, model)) return 0;
    if (fputs(",\n  \"localPlayerSoundClass\": ", file) < 0 || !write_name(file, sound)) return 0;
    if (fputs(",\n  \"hostRequestedModel\": ", file) < 0 || !write_name(file, sithNet_isMulti ? jkGuiMultiplayer_mpcInfo.model : NULL)) return 0;
    if (fprintf(file, ",\n  \"localPlayerHierarchyNodes\": %u", model ? player->renderData.model3->numHNodes : 0) < 0) return 0;
    return 1;
}

void stdCapture_ApplyCamera(void)
{
    if (!active) return;
    if (!sithCamera_g_pCurCamera || !sithWorld_g_pCurrentWorld || stdCapture_request.sector >= sithWorld_g_pCurrentWorld->numSectors) stdCapture_Complete(0);
    const stdCaptureRequest* r = &stdCapture_request;
    SithCamera* camera = sithCamera_g_pCurCamera;
    rdVector3 pos = {r->x, r->y, r->z}, pyr = {r->pitch, r->yaw, r->roll};
    camera->sector = &sithWorld_g_pCurrentWorld->aSectors[r->sector];
    rdMatrix_Build34(&camera->orient, &pyr, &pos);
    camera->lookPos = pos; camera->lookPYR = pyr;
    jkPlayer_fovIsVertical = 0;
    rdCamera_SetFOV(&camera->rdCamera, r->fov);
    cameraApplied = 1;
}
#elif !defined(STDCAPTURE_UNIT_TEST)
void stdCapture_ApplyCamera(void) { }
static int write_world_state(FILE* file) { return fputs(",\n  \"engineWorldStateAvailable\": false", file) >= 0; }
#else
static int write_world_state(FILE* file) { return fputs(",\n  \"engineWorldStateAvailable\": false", file) >= 0; }
#endif
