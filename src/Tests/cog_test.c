// COG subsystem lifecycle: real file parsing, bytecode, symbol tables, thing
// argument binding, message execution and world teardown. No COG loader,
// interpreter, networking or thing-parser functions are replaced by fixtures.
#include "types.h"
#include "globals.h"
#include "Main/Main.h"
#include "Win95/std.h"
#include "stdPlatform.h"
#include "Cog/sithCog.h"
#include "Cog/sithCogParse.h"
#include "World/sithThing.h"
#include "Gameplay/sithEvent.h"

#include <stdio.h>
#include <string.h>

static HostServices hs;
static unsigned checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 0; \
} } while (0)

static int write_cog(const char *path, unsigned flags)
{
    FILE *fp = fopen(path, "wb");
    CHECK(fp != NULL);
    CHECK(fprintf(fp,
        "flags=0x%x\n"
        "symbols\n"
        "int calls=0 local\n"
        "message pulse\n"
        "message startup\n"
        "end\n"
        "code\n"
        "pulse:\n"
        "calls = calls + 1;\n"
        "return;\n"
        "startup:\n"
        "calls = calls + 10;\n"
        "return;\n"
        "end\n", flags) > 0);
    CHECK(fclose(fp) == 0);
    return 1;
}

static int expect_calls(sithCog *cog, int expected)
{
    // Names belong to the parsed script; runtime instances copy indexed slots,
    // not its parse-time hash table. Resolve the declaration, then its instance.
    SithCogSymbol *declaration = sithCogParse_GetSymbol(cog->pScript->pSymbolTable, "calls");
    CHECK(declaration != NULL);
    SithCogSymbol *symbol = sithCogParse_GetSymbolByID(cog->pSymbolTable, declaration->id);
    CHECK(symbol != NULL);
    CHECK(symbol->val.type == SITHCOG_VALUE_INT || symbol->val.type == SITHCOG_VALUE_FLOAT);
    double actual = symbol->val.type == SITHCOG_VALUE_INT
        ? symbol->val.data[0] : symbol->val.dataAsFloat[0];
    CHECK(actual == expected);
    return 1;
}

static void send_message(sithCog *cog, int message)
{
    sithCog_SendMessage(cog, message, SENDERTYPE_SYSTEM, 0, SENDERTYPE_SYSTEM, 0, 0);
}

static int run_mode(int mots)
{
    Main_bMotsCompat = mots;
    CHECK(sithEvent_Startup());
    CHECK(sithThing_Startup());
    CHECK(sithCog_Startup());
    SithWorld world = {0};
    CHECK(sithCog_AllocWorldCogScripts(&world, 32));
    CHECK(sithCog_AllocWorldCogs(&world, 32));
    sithWorld_g_pLastLoadedWorld = sithWorld_g_pCurrentWorld = &world;
    sithNet_isMulti = 0;
    sithNet_isServer = 0;

    const unsigned flags[] = {0, SITH_COG_SERVER, SITH_COG_LOCAL,
                              SITH_COG_SERVER | SITH_COG_LOCAL, SITH_COG_DISABLED};
    for (unsigned i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        char name[40], path[48];
        snprintf(name, sizeof(name), "lifecycle_%d_%u.cog", mots, i);
        snprintf(path, sizeof(path), "cog/%s", name);
        CHECK(write_cog(path, flags[i]));
        StdConffileArg argument = {"cog", name};
        SithThing first = {0}, second = {0};
        first.type = second.type = SITH_THING_GHOST;
        CHECK(sithThing_ParseArg(&argument, &first));
        CHECK(sithThing_ParseArg(&argument, &second));
        CHECK(first.pCog != NULL && second.pCog != NULL);
        CHECK(first.pCog != second.pCog);
        CHECK(first.pCog->pScript == second.pCog->pScript); // One cached script, independent instances.
        CHECK(first.pCog->pSymbolTable != second.pCog->pSymbolTable);
        CHECK(first.pCog->pScript->pCode != NULL);
        CHECK(first.pCog->pScript->numHandlers == 2);
        CHECK(first.flags & SITH_TF_CAPTURED);
        unsigned expected_flags = flags[i] | SITH_COG_CLASS;
        if (!mots || !(flags[i] & SITH_COG_SERVER)) expected_flags |= SITH_COG_LOCAL;
        CHECK(first.pCog->flags == expected_flags);
        CHECK(second.pCog->flags == expected_flags);
        CHECK(expect_calls(first.pCog, 0) && expect_calls(second.pCog, 0));

        // Actual bytecode executes in single-player and host configurations.
        // On a client, a server-only class must not execute the pulse locally.
        // Pulse deliberately avoids network forwarding; no remote peer is faked.
        int count = 0;
        int enabled = !(flags[i] & SITH_COG_DISABLED);
        sithNet_isMulti = 0;
        send_message(first.pCog, SITH_MESSAGE_PULSE);
        count += enabled;
        CHECK(expect_calls(first.pCog, count));
        sithNet_isMulti = 1;
        sithNet_isServer = 1;
        send_message(first.pCog, SITH_MESSAGE_PULSE);
        count += enabled;
        CHECK(expect_calls(first.pCog, count));
        sithNet_isServer = 0;
        send_message(first.pCog, SITH_MESSAGE_PULSE);
        count += enabled && !!(expected_flags & SITH_COG_LOCAL);
        CHECK(expect_calls(first.pCog, count));

        // Startup is allowed locally even for a server-only class, while a
        // missing handler and paused script leave the symbol state unchanged.
        send_message(first.pCog, SITH_MESSAGE_STARTUP);
        count += enabled * 10;
        CHECK(expect_calls(first.pCog, count));
        send_message(first.pCog, SITH_MESSAGE_USER0);
        CHECK(expect_calls(first.pCog, count));
        first.pCog->flags |= SITH_COG_PAUSED;
        send_message(first.pCog, SITH_MESSAGE_PULSE);
        CHECK(expect_calls(first.pCog, count));
        first.pCog->flags &= ~SITH_COG_PAUSED;
        CHECK(expect_calls(second.pCog, 0)); // Instance symbol tables stay independent.
        CHECK(remove(path) == 0);
    }

    SithThing missing = {0};
    StdConffileArg absent = {"cog", "lifecycle_absent.cog"};
    int before = world.numCogs;
    CHECK(sithThing_ParseArg(&absent, &missing));
    CHECK(missing.pCog == NULL && !(missing.flags & SITH_TF_CAPTURED));
    CHECK(world.numCogs == before);
    StdConffileArg unknown = {"not_a_thing_parameter", "1"};
    CHECK(!sithThing_ParseArg(&unknown, &missing));
    // Use a valid file to discriminate capacity exhaustion from parser failure.
    CHECK(write_cog("cog/lifecycle_capacity.cog", 0));
    int capacity = world.sizeCogs;
    int scripts_before = world.numCogScripts;
    world.sizeCogs = world.numCogs;
    CHECK(sithCog_Load("lifecycle_capacity.cog") == NULL);
    CHECK(world.numCogs == before && world.numCogScripts == scripts_before);
    world.sizeCogs = capacity;
    CHECK(sithCog_Load("lifecycle_capacity.cog") != NULL);
    CHECK(world.numCogs == before + 1);
    CHECK(remove("cog/lifecycle_capacity.cog") == 0);

    sithCog_FreeWorldCogs(&world);
    CHECK(world.aCogs == NULL && world.aCogScripts == NULL);
    CHECK(world.numCogs == 0 && world.numCogScripts == 0);
    sithWorld_g_pLastLoadedWorld = sithWorld_g_pCurrentWorld = NULL;
    sithCog_Shutdown();
    sithThing_Shutdown();
    sithEvent_Shutdown();
    return 1;
}

int main(void)
{
    stdInitServices(&hs);
    hs.debugPrint = hs.messagePrint = hs.errorPrint = stdConsolePrintf;
    pHS = std_g_pHS = rdroid_g_pHS = pSithHS = pLowLevelHS = &hs;
    stdStartup(&hs);
    Main_bHeadless = 1;
    if (!run_mode(0) || !run_mode(1)) return 1;
    stdShutdown();
    printf("COG lifecycle: %u checks passed (parse/bind/execute/instance isolation/teardown, JK and MotS).\n", checks);
    return 0;
}
