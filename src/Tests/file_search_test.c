// Added: exercise corrected POSIX search code against owned temporary files.
// The runner extracts production search functions/types and case/asset-path
// helpers. Allocation/logging are stubs; scandir, directories and files are real.
#include <alloca.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "actual_search_types.inc"

static unsigned checks;
static int liveSearches;
static unsigned scanCalls;
static char aLastScan[512];
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "FAIL file-search line %d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

static void* stdFileUtil_TestAlloc(size_t size)
{
    void* p = malloc(size);
    if (p) ++liveSearches;
    return p;
}

static void stdFileUtil_TestFree(void* p)
{
    if (p) --liveSearches;
    free(p);
}

static int stdPlatform_Printf(const char* pFormat, ...)
{
    (void)pFormat;
    return 0;
}

static int stdFileUtil_TestScandir(const char* pDirectory, struct dirent*** ppList,
    int (*pFilter)(const struct dirent*),
    int (*pCompare)(const struct dirent**, const struct dirent**))
{
    CHECK(strlen(pDirectory) < sizeof(aLastScan));
    strcpy(aLastScan, pDirectory);
    ++scanCalls;
    return scandir(pDirectory, ppList, pFilter, pCompare);
}

#define STD_ALLOC stdFileUtil_TestAlloc
#define STD_FREE stdFileUtil_TestFree
#define _memset memset
#define __strnicmp strncasecmp
#define scandir stdFileUtil_TestScandir
#include "actual_search_functions.inc"
#undef scandir

static void make_directory(const char* pPath)
{
    CHECK(mkdir(pPath, 0700) == 0);
}

static void make_file(const char* pPath)
{
    FILE* pFile = fopen(pPath, "wb");
    CHECK(pFile != NULL);
    CHECK(fputs("owned file-search fixture\n", pFile) >= 0);
    CHECK(fclose(pFile) == 0);
}

static void expect_directory(const char* pPattern, const char* pDirectory, const char* pExtension)
{
    char aDirectory[128];
    const char* pActualExtension;
    CHECK(stdFileUtil_PrepareSearchDirectory(pPattern, strlen(pPattern) + 1,
        aDirectory, sizeof(aDirectory), &pActualExtension));
    CHECK(!strcmp(aDirectory, pDirectory));
    CHECK(pExtension ? pActualExtension && !strcmp(pActualExtension, pExtension) : !pActualExtension);
}

static void test_preparation(void)
{
    char aPattern[128];
    char aDirectory[128];
    const char* pExtension;

    expect_directory("Entries/*.gob", "Entries", ".gob");
    expect_directory("Entries//*.GoB", "Entries", ".GoB");
    expect_directory("folder.with.dots\\*.gob", "folder.with.dots", ".gob");
    expect_directory("*.*", ".", NULL);
    expect_directory("*.gob", ".", ".gob");
    expect_directory("/*.*", "/", NULL); // Pure preparation: never enumerate the host root.
    expect_directory("/*.gob", "/", ".gob");
    expect_directory("/cd/jk1/resource/*.gob", "/cd/jk1/resource", ".gob");
    expect_directory("Entries/*.backup.gob", "Entries", ".gob"); // Existing last-dot selection.
    expect_directory("Entries/*.", "Entries", ".");

    CHECK(stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), "", 2, NULL));
    CHECK(!strcmp(aPattern, "./*.*"));
    CHECK(stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), "/", 2, NULL));
    CHECK(!strcmp(aPattern, "/*.*"));
    CHECK(stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), "Entries/", 3, ".GoB"));
    CHECK(!strcmp(aPattern, "Entries/*.GoB"));
    CHECK(stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), "Entries\\", 3, "gob"));
    CHECK(!strcmp(aPattern, "Entries/*.gob"));

    // Corrected-code limits only. No former implementation or malformed-input
    // reproduction is built/executed by this suite.
    memset(aDirectory, 'd', 121);
    aDirectory[121] = 0;
    CHECK(stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), aDirectory, 3, "gob"));
    CHECK(strlen(aPattern) == sizeof(aPattern) - 1);
    CHECK(aPattern[120] == 'd');
    aDirectory[121] = 'd';
    aDirectory[122] = 0;
    CHECK(!stdFileUtil_PrepareSearchPath(aPattern, sizeof(aPattern), aDirectory, 3, "gob"));
    CHECK(!aPattern[0]);
    CHECK(stdFileUtil_NewFind(aDirectory, 3, "gob") == NULL);
    CHECK(!stdFileUtil_PrepareSearchPath(aPattern, 4, "Entries", 3, "gob"));
    CHECK(!aPattern[0]);
    CHECK(!stdFileUtil_PrepareSearchDirectory("Entries", 8, aDirectory, sizeof(aDirectory), &pExtension));
    CHECK(!stdFileUtil_PrepareSearchDirectory("", 1, aDirectory, sizeof(aDirectory), &pExtension));
    CHECK(!stdFileUtil_PrepareSearchDirectory("Entries/*.gob", 14, aDirectory, 3, &pExtension));
    CHECK(!stdFileUtil_PrepareSearchDirectory("Entries/*.go*", 14, aDirectory, sizeof(aDirectory), &pExtension));
    CHECK(stdFileUtil_NewFind(NULL, 2, NULL) == NULL);
    CHECK(stdFileUtil_NewFind("Entries", -1, NULL) == NULL);
    CHECK(stdFileUtil_NewFind("Entries", 4, NULL) == NULL);
    CHECK(stdFileUtil_NewFind("Entries", 3, NULL) == NULL);
    CHECK(stdFileUtil_NewFind("Entries", 3, "gob/other") == NULL);
    CHECK(liveSearches == 0);
}

static const char* const aAllNames[] = {
    "!first.gob", ".cache", ".hidden.gob", "Bravo.GoB", "gamma.gox", "notes.txt", "plain", "subdir"
};
static const char* const aGobNames[] = {
    "!first.gob", ".cache", ".hidden.gob", "Bravo.GoB", "gamma.gox"
};

static void expect_entries(stdFileSearch* pSearch, const char* const* ppNames, size_t count)
{
    stdFileSearchResult result;
    for (size_t i = 0; i < count; ++i) {
        memset(&result, 0, sizeof(result));
        CHECK(stdFileUtil_FindNext(pSearch, &result));
        CHECK(!strcmp(result.fpath, ppNames[i]));
        CHECK(strcmp(result.fpath, ".") && strcmp(result.fpath, ".."));
        int bDirectory = !strcmp(ppNames[i], "subdir") || !strcmp(ppNames[i], ".cache");
        CHECK(result.is_subdirectory == (bDirectory ? 0x10 : 0));
        CHECK(result.time_write == 0);
    }
    CHECK(!stdFileUtil_FindNext(pSearch, &result));
    CHECK(!stdFileUtil_FindNext(pSearch, &result));
}

static void expect_search(const char* pPath, int mode, const char* pFilter,
    const char* const* ppNames, size_t count)
{
    stdFileSearch* pSearch = stdFileUtil_NewFind(pPath, mode, pFilter);
    CHECK(pSearch != NULL);
    expect_entries(pSearch, ppNames, count);
    stdFileUtil_FindReset(pSearch);
    CHECK(!pSearch->isNotFirst && !pSearch->nFoundFiles && !pSearch->namelist);
    expect_entries(pSearch, ppNames, count);
    stdFileUtil_DisposeFind(pSearch);
    CHECK(liveSearches == 0);
}

static void test_enumeration(void)
{
    char aAbsolute[256];
    CHECK(getcwd(aAbsolute, sizeof(aAbsolute)) != NULL);
    CHECK(strlen(aAbsolute) + strlen("/Entries") < sizeof(aAbsolute));
    strcat(aAbsolute, "/Entries");
    for (int mode = 0; mode <= 2; ++mode)
        expect_search("Entries", mode, NULL, aAllNames, 8);
    expect_search("Entries/", 2, NULL, aAllNames, 8);
    expect_search("Entries\\", 2, NULL, aAllNames, 8);
    expect_search(aAbsolute, 2, NULL, aAllNames, 8);
    expect_search("Entries", 3, "*", aAllNames, 8);
    expect_search("Entries", 3, "gob", aGobNames, 5);
    expect_search("Entries/", 3, ".GOB", aGobNames, 5);
#ifdef FS_POSIX
    expect_search("entries", 3, "GoB", aGobNames, 5); // Preserve directory case correction.
#endif
    expect_search("Empty", 2, NULL, NULL, 0);
    expect_search("Empty", 3, "gob", NULL, 0);
    expect_search("Missing", 3, "gob", NULL, 0);

    CHECK(stdFileUtil_CountMatches("Entries", 2, NULL) == 8);
    CHECK(stdFileUtil_CountMatches("Entries", 3, "gob") == 5);
    stdFileSearchResult result;
    CHECK(stdFileUtil_FindQuick("Entries", 3, "GoB", &result));
    CHECK(!strcmp(result.fpath, "!first.gob"));

    stdFileSearch* pSearch = stdFileUtil_NewFind("Entries", 2, NULL);
    CHECK(pSearch != NULL);
    CHECK(stdFileUtil_FindNext(pSearch, &result));
    stdFileUtil_FindReset(pSearch); // Reset while entries are still owned.
    expect_entries(pSearch, aAllNames, 8);
    stdFileUtil_DisposeFind(pSearch);
    pSearch = stdFileUtil_NewFind("Entries", 2, NULL);
    CHECK(pSearch != NULL && stdFileUtil_FindNext(pSearch, &result));
    stdFileUtil_DisposeFind(pSearch); // Dispose while entries are still owned.
    stdFileUtil_FindReset(NULL);
    stdFileUtil_DisposeFind(NULL);
    CHECK(!stdFileUtil_FindNext(NULL, &result));
    CHECK(liveSearches == 0);

    CHECK(chdir("Entries") == 0);
    expect_search("", 3, "gob", aGobNames, 5);
    expect_search(".", 2, NULL, aAllNames, 8);
    CHECK(chdir("..") == 0);
}

#ifdef TARGET_RETRO_HOMEBREW
static void test_retro_resolution_limit(void)
{
    char aStart[256], aCwd[512], aComponent[64];
    CHECK(getcwd(aStart, sizeof(aStart)) != NULL);
    memset(aComponent, 'd', sizeof(aComponent) - 1);
    aComponent[sizeof(aComponent) - 1] = 0;
    do {
        make_directory(aComponent);
        CHECK(chdir(aComponent) == 0);
        CHECK(getcwd(aCwd, sizeof(aCwd)) != NULL);
    } while (strlen(aCwd) < 220);
    make_directory(aComponent);
    // A valid relative directory can exceed the bounded retro absolute path
    // after joining the CWD. Reject it without scanning a shortened prefix.
    stdFileSearch* pSearch = stdFileUtil_NewFind(aComponent, 2, NULL);
    stdFileSearchResult result;
    CHECK(pSearch != NULL);
    unsigned before = scanCalls;
    CHECK(!stdFileUtil_FindNext(pSearch, &result));
    CHECK(scanCalls == before);
    stdFileUtil_FindReset(pSearch);
    CHECK(!stdFileUtil_FindNext(pSearch, &result));
    CHECK(scanCalls == before);
    stdFileUtil_DisposeFind(pSearch);
    CHECK(chdir(aStart) == 0);
    CHECK(liveSearches == 0);
}
#endif

#ifdef TARGET_DREAMCAST
static void test_asset_routing(void)
{
    make_directory("assets");
    make_directory("assets/resource");
    make_file("assets/resource/stock.gob");
    make_directory("player");
    make_file("player/local.mpc");
    CHECK(getcwd(dcStorage_assetRoot, sizeof(dcStorage_assetRoot)) != NULL);
    CHECK(strlen(dcStorage_assetRoot) + strlen("/assets") < sizeof(dcStorage_assetRoot));
    strcat(dcStorage_assetRoot, "/assets");
    dcStorage_bInit = 1;
    const char* aAssets[] = {"stock.gob"};
    const char* aProfiles[] = {"local.mpc"};
    expect_search("resource", 3, "gob", aAssets, 1);
    CHECK(strstr(aLastScan, "/assets/resource") != NULL);
    expect_search("player/", 3, "mpc", aProfiles, 1);
    CHECK(strstr(aLastScan, "/assets/") == NULL);
    CHECK(chdir("Entries") == 0);
    expect_search("", 3, "gob", aGobNames, 5);
    CHECK(chdir("..") == 0);
    dcStorage_bInit = 0;
}
#endif

int main(int argc, char** argv)
{
    CHECK(argc == 2 && setlocale(LC_ALL, "C") != NULL);
    CHECK(chdir(argv[1]) == 0);
    make_directory("Entries");
    make_directory("Empty");
    make_directory("Entries/.cache");
    make_directory("Entries/subdir");
    for (size_t i = 0; i < 8; ++i) {
        if (!strcmp(aAllNames[i], ".cache") || !strcmp(aAllNames[i], "subdir")) continue;
        char aPath[128];
        CHECK(snprintf(aPath, sizeof(aPath), "Entries/%s", aAllNames[i]) > 0);
        make_file(aPath);
    }
    test_preparation();
    test_enumeration();
#ifdef TARGET_RETRO_HOMEBREW
    test_retro_resolution_limit();
#endif
#ifdef TARGET_DREAMCAST
    test_asset_routing();
#endif
    CHECK(liveSearches == 0);
    printf("{\"passed\":true,\"assertions\":%u,\"directory_scans\":%u}\n", checks, scanCalls);
    return 0;
}
