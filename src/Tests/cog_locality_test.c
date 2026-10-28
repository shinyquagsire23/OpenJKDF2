/*
 * Adapted from andreipemberton's MotS fixes fork regression (c77fc8f2a67cea15a566678cd00c1acb8b2b7d21).
 * run_cog_locality_test.py supplies the extracted production includes below.
 * Minimal structs and loader/executor/network stubs isolate class binding and
 * message routing; they do not model the production ABI or execute game scripts.
 * Co-op branches, debug-name printing, and real multiplayer delivery are outside
 * this matrix. The runner also checks an old-inversion mutation of the case.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "production_constants.h"

#define SITH_ASSERTREL assert

/* These member names must match the fields used by the production functions. */
typedef struct
{
    uint32_t trigId;
    uint32_t trigPc;
    uint32_t field_8;
} sithCogTrigger;

typedef struct
{
    uint32_t numHandlers;
    sithCogTrigger aHandlers[3];
} SithCogScript;

typedef struct sithCog
{
    SithCogScript *pScript;
    uint32_t flags;
    int32_t idx;
    int32_t senderId;
    int32_t senderRef;
    int32_t senderType;
    int32_t sourceIdx;
    int32_t sourceType;
    cog_flex_t params[4];
    cog_flex_t returnValue;
} sithCog;

typedef struct
{
    sithCog *pCog;
    uint32_t flags;
} SithThing;

typedef struct
{
    const char *value;
} CogArgument;

static int Main_bMotsCompat;
static int sithNet_isMulti;
static int sithNet_isServer;
static int sithMulti_multiModeFlags;
static int sithNet_serverNetId = 123;
static sithCog *sithCog_g_pMasterCog;
static sithCog *loaded_cog;

static unsigned assertion_count;
static unsigned dispatch_case_count;
static unsigned binding_case_count;
static const char *current_case = "setup";
static int current_mode;
static int current_network;
static int current_message;
static int current_api;
static int current_guard;

static void check(int condition, const char *expression, int line)
{
    ++assertion_count;
    if (!condition)
    {
        fprintf(
            stderr,
            "FAIL %s line %d: %s [mots=%d net=%d msg=%d api=%d guard=%d]\n",
            current_case,
            line,
            expression,
            current_mode,
            current_network,
            current_message,
            current_api,
            current_guard);
        exit(1);
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

typedef struct
{
    unsigned execution_count;
    unsigned forward_count;
    unsigned handler_index;
    sithCog *cog;
    int message;
    int sender_type;
    int sender_index;
    int source_type;
    int source_index;
    int link_id;
    int target_net_id;
    cog_flex_t params[4];
} DispatchObservation;

static DispatchObservation observation;

static sithCog *sithCog_Load(const char *name)
{
    CHECK(strcmp(name, "fixture.cog") == 0);
    return loaded_cog;
}

static void sithCogExec_ExecuteMessage(sithCog *cog, uint32_t handler_index)
{
    ++observation.execution_count;
    observation.cog = cog;
    observation.handler_index = handler_index;
    cog->returnValue = 42.25f;
}

static void sithDSSCog_SendMessage(
    sithCog *cog,
    int message,
    int sender_type,
    int sender_index,
    int source_type,
    int source_index,
    int link_id,
    cog_flex_t param0,
    cog_flex_t param1,
    cog_flex_t param2,
    cog_flex_t param3,
    int target_net_id)
{
    ++observation.forward_count;
    observation.cog = cog;
    observation.message = message;
    observation.sender_type = sender_type;
    observation.sender_index = sender_index;
    observation.source_type = source_type;
    observation.source_index = source_index;
    observation.link_id = link_id;
    observation.params[0] = param0;
    observation.params[1] = param1;
    observation.params[2] = param2;
    observation.params[3] = param3;
    observation.target_net_id = target_net_id;
}

/* Only the switch shell is a test wrapper; its case is extracted verbatim. */
static int bind_class(SithThing *pThing, CogArgument *arg)
{
    sithCog *pCog;
    int result = 0;

    switch (THINGPARAM_COG)
    {
#ifdef OLD_INVERSION
#include "thingparam_cog_old_inversion.inc"
#else
#include "thingparam_cog.inc"
#endif
    }

    return result;
}

#include "sithCog_SendMessage.inc"
#include "sithCog_SendMessageEx.inc"

typedef struct
{
    const char *name;
    uint32_t input_flags;
    uint32_t mots_flags;
    uint32_t jk_flags;
} FlagExpectation;

/* Explicit semantic expectations include deliberately declared SERVER|LOCAL. */
static const FlagExpectation flag_expectations[] =
{
    {
        "default",
        0,
        SITH_COG_CLASS | SITH_COG_LOCAL,
        SITH_COG_CLASS | SITH_COG_LOCAL
    },
    {
        "server",
        SITH_COG_SERVER,
        SITH_COG_SERVER | SITH_COG_CLASS,
        SITH_COG_SERVER | SITH_COG_CLASS | SITH_COG_LOCAL
    },
    {
        "local",
        SITH_COG_LOCAL,
        SITH_COG_LOCAL | SITH_COG_CLASS,
        SITH_COG_LOCAL | SITH_COG_CLASS
    },
    {
        "server+local",
        SITH_COG_SERVER | SITH_COG_LOCAL,
        SITH_COG_SERVER | SITH_COG_LOCAL | SITH_COG_CLASS,
        SITH_COG_SERVER | SITH_COG_LOCAL | SITH_COG_CLASS
    },
    {
        "nosync",
        SITHCOG_NOSYNC,
        SITHCOG_NOSYNC | SITH_COG_CLASS | SITH_COG_LOCAL,
        SITHCOG_NOSYNC | SITH_COG_CLASS | SITH_COG_LOCAL
    },
    {
        "server+nosync",
        SITH_COG_SERVER | SITHCOG_NOSYNC,
        SITH_COG_SERVER | SITHCOG_NOSYNC | SITH_COG_CLASS,
        SITH_COG_SERVER | SITHCOG_NOSYNC | SITH_COG_CLASS | SITH_COG_LOCAL
    },
    {
        "global+debug",
        SITH_COG_GLOBAL | SITH_COG_DEBUG,
        SITH_COG_GLOBAL | SITH_COG_DEBUG | SITH_COG_CLASS | SITH_COG_LOCAL,
        SITH_COG_GLOBAL | SITH_COG_DEBUG | SITH_COG_CLASS | SITH_COG_LOCAL
    },
    {
        "server+global+debug",
        SITH_COG_SERVER | SITH_COG_GLOBAL | SITH_COG_DEBUG,
        SITH_COG_SERVER | SITH_COG_GLOBAL | SITH_COG_DEBUG | SITH_COG_CLASS,
        SITH_COG_SERVER | SITH_COG_GLOBAL | SITH_COG_DEBUG | SITH_COG_CLASS | SITH_COG_LOCAL
    }
};

static const int messages[] =
{
    SITH_MESSAGE_NEWPLAYER,
    SITH_MESSAGE_TIMER,
    SITH_MESSAGE_PULSE,
    SITH_MESSAGE_STARTUP,
    SITH_MESSAGE_SHUTDOWN,
    SITH_MESSAGE_DAMAGED
};

enum
{
    DROP,
    EXECUTE,
    FORWARD
};

enum
{
    NETWORK_SINGLEPLAYER,
    NETWORK_HOST,
    NETWORK_CLIENT,
    NETWORK_COUNT
};

enum
{
    GUARD_ACTIVE,
    GUARD_DISABLED,
    GUARD_PAUSED,
    GUARD_EMPTY_HANDLERS,
    GUARD_MISSING_HANDLER,
    GUARD_COUNT
};

/* Rows: network mode, then absent/present LOCAL. Columns follow messages[]. */
static const int expected_routes[NETWORK_COUNT][2][6] =
{
    {
        /* Singleplayer. */
        {EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE},
        {EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE}
    },
    {
        /* Multiplayer host. */
        {EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE},
        {EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE}
    },
    {
        /* Multiplayer client. */
        {FORWARD, DROP, DROP, EXECUTE, EXECUTE, FORWARD},
        {EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE, EXECUTE}
    }
};

static void init_cog(sithCog *cog, SithCogScript *script, uint32_t flags)
{
    memset(cog, 0, sizeof(*cog));
    cog->pScript = script;
    cog->flags = flags;
    cog->idx = 19;
    cog->senderId = -88;
    cog->senderRef = -88;
    cog->senderType = -88;
    cog->sourceIdx = -88;
    cog->sourceType = -88;
    for (int param_index = 0; param_index < 4; ++param_index)
    {
        cog->params[param_index] = -77.0f;
    }
    cog->returnValue = -66.0f;
}

static void run_matrix_case(
    const FlagExpectation *flags,
    int mots,
    int network,
    int message_index,
    int extended_api,
    int guard)
{
    const int message = messages[message_index];
    current_case = flags->name;
    current_mode = mots;
    current_network = network;
    current_message = message;
    current_api = extended_api;
    current_guard = guard;

    Main_bMotsCompat = mots;
    sithNet_isMulti = network != NETWORK_SINGLEPLAYER;
    sithNet_isServer = network == NETWORK_HOST;
    sithMulti_multiModeFlags = 0;
    sithCog_g_pMasterCog = NULL;

    /* Put the matching handler last so dispatch must search past other IDs. */
    SithCogScript script =
    {
        .numHandlers = 3,
        .aHandlers =
        {
            {SITH_MESSAGE_ACTIVATE, 1, 0},
            {SITH_MESSAGE_REMOVED, 2, 0},
            {message, 3, 0}
        }
    };
    uint32_t guard_flags = guard == GUARD_DISABLED ? SITH_COG_DISABLED
        : guard == GUARD_PAUSED ? SITH_COG_PAUSED : 0;
    if (guard == GUARD_EMPTY_HANDLERS)
    {
        script.numHandlers = 0;
    }
    if (guard == GUARD_MISSING_HANDLER)
    {
        script.aHandlers[2].trigId = SITH_MESSAGE_TRIGGER;
    }

    sithCog cog;
    init_cog(&cog, &script, flags->input_flags | guard_flags);
    SithThing thing = {.pCog = NULL, .flags = 0x80000000u};
    CogArgument argument = {"fixture.cog"};
    loaded_cog = &cog;
    uint32_t expected_flags = (mots ? flags->mots_flags : flags->jk_flags) | guard_flags;

    CHECK(bind_class(&thing, &argument) == 1);
    ++binding_case_count;
    CHECK(thing.pCog == &cog);
    CHECK(thing.flags == (0x80000000u | SITH_TF_CAPTURED));
    CHECK(cog.flags == expected_flags);

    sithCog before_dispatch = cog;
    memset(&observation, 0, sizeof(observation));
    cog_flex_t result = 0;
    if (extended_api)
    {
        result = sithCog_SendMessageEx(
            &cog, message, 3, 101, 6, 202, 303,
            1.25f, -2.5f, 3.75f, -4.0f);
    }
    else
    {
        sithCog_SendMessage(&cog, message, 3, 101, 6, 202, 303);
    }
    ++dispatch_case_count;

    int is_local = (expected_flags & SITH_COG_LOCAL) != 0;
    int expected_route = guard != GUARD_ACTIVE ? DROP
        : expected_routes[network][is_local][message_index];
    CHECK(observation.execution_count == (unsigned)(expected_route == EXECUTE));
    CHECK(observation.forward_count == (unsigned)(expected_route == FORWARD));
    CHECK(cog.flags == expected_flags);

    if (expected_route == EXECUTE)
    {
        CHECK(observation.cog == &cog);
        CHECK(observation.handler_index == 2);
        CHECK(cog.senderId == 303 && cog.senderRef == 101 && cog.senderType == 3
            && cog.sourceIdx == 202 && cog.sourceType == 6);
        CHECK(cog.params[0] == (extended_api ? 1.25f : 0));
        CHECK(cog.params[1] == (extended_api ? -2.5f : 0));
        CHECK(cog.params[2] == (extended_api ? 3.75f : 0));
        CHECK(cog.params[3] == (extended_api ? -4.0f : 0));
    }
    else
    {
        CHECK(memcmp(&cog, &before_dispatch, sizeof(cog)) == 0);
    }

    if (expected_route == FORWARD)
    {
        CHECK(observation.cog == &cog && observation.message == message);
        CHECK(observation.sender_type == 3 && observation.sender_index == 101
            && observation.source_type == 6 && observation.source_index == 202
            && observation.link_id == 303);
        CHECK(observation.target_net_id == 123);
        CHECK(observation.params[0] == (extended_api ? 1.25f : 0));
        CHECK(observation.params[1] == (extended_api ? -2.5f : 0));
        CHECK(observation.params[2] == (extended_api ? 3.75f : 0));
        CHECK(observation.params[3] == (extended_api ? -4.0f : 0));
    }

    if (extended_api)
    {
        CHECK(result == (guard != GUARD_ACTIVE ? -9999.9873046875f
            : expected_route == EXECUTE ? 42.25f : 0.0f));
    }
}

static void test_matrix(void)
{
    for (unsigned flag_index = 0;
         flag_index < sizeof(flag_expectations) / sizeof(flag_expectations[0]);
         ++flag_index)
    {
        for (int mots = 0; mots < 2; ++mots)
        {
            for (int network = 0; network < NETWORK_COUNT; ++network)
            {
                for (int message_index = 0; message_index < 6; ++message_index)
                {
                    for (int extended_api = 0; extended_api < 2; ++extended_api)
                    {
                        for (int guard = 0; guard < GUARD_COUNT; ++guard)
                        {
                            run_matrix_case(
                                &flag_expectations[flag_index], mots, network,
                                message_index, extended_api, guard);
                        }
                    }
                }
            }
        }
    }
}

static void test_null_inputs(void)
{
    current_case = "null inputs";
    for (int mots = 0; mots < 2; ++mots)
    {
        Main_bMotsCompat = mots;
        loaded_cog = NULL;
        SithThing thing =
        {
            .pCog = (sithCog *)(uintptr_t)1,
            .flags = 0x12345678u
        };
        CogArgument argument = {"fixture.cog"};

        CHECK(bind_class(&thing, &argument) == 1);
        CHECK(thing.pCog == NULL);
        CHECK(thing.flags == 0x12345678u);
        ++binding_case_count;
    }

    memset(&observation, 0, sizeof(observation));
    sithCog_SendMessage(NULL, SITH_MESSAGE_NEWPLAYER, 0, 0, 0, 0, 0);
    CHECK(sithCog_SendMessageEx(
        NULL, SITH_MESSAGE_NEWPLAYER, 0, 0, 0, 0, 0, 1, 2, 3, 4)
        == -9999.9873046875f);
    CHECK(!observation.execution_count && !observation.forward_count);
    dispatch_case_count += 2;
}

int main(void)
{
    test_matrix();
    test_null_inputs();
    printf(
        "PASS assertions=%u binding_cases=%u dispatch_cases=%u\n",
        assertion_count, binding_case_count, dispatch_case_count);
    puts("Production case and both complete production message-dispatch bodies; "
        "stubbed loader, executor and network transport. No game execution.");
    return 0;
}
