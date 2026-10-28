/* Adapted from andreipemberton, original contribution 1bfba38600e2ccee7bbd7fbe5f6b5d947b7cc78a;
 * source snapshot 6fa54630a123485d8c7b602c47992613a1f397b5. */
/*
 * Asset-free execution of extracted production team-model arrays, lookup and
 * complete JK/MotS saber/team handlers. The packet reader macros are copied
 * unchanged from sithMulti.h; fixtures independently lay out aligned native
 * S32/S16/string bytes. Minimal structs are not the full engine ABI. Model,
 * sound, saber, transport and score-sync stubs record calls without game data.
 * This does not test rendering, skin colors, transport, packet truncation or
 * cross-endian/retro networking. Model names below are independent expectations;
 * Soldier team 3 is blue (b), team 4 green (g), following native team labels.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "team_model_constants.h"

typedef float flex32_t;
typedef struct { float x, y; } rdVector2;
typedef struct { float x, y, z; } rdVector3;
typedef struct { int x, y, z; } rdVector3i;
typedef struct { float value[12]; } rdMatrix34;
typedef struct { char filename[32]; } rdModel3;
typedef struct { int unused; } sithSoundClass;
typedef struct SithThing SithThing;
typedef struct { int teamNum; SithThing *pLocalPlayer; } SithPlayer;
struct SithThing {
    int guid;
    struct { SithPlayer *pPlayer; } actorParams;
    void *playerInfo;
    rdModel3 *model;
};
typedef struct {
    struct { int flag_maybe, cogMsgId; size_t msg_size; } netMsg;
    _Alignas(uint32_t) unsigned char pktData[256];
} SithMessage;

#define _strncpy strncpy
#include "team_model_wire.h"

static int Main_bMotsCompat;
static int sithNet_isServer;
static int sithNet_MultiModeFlags;
static unsigned jkPlayer_maxPlayers = 4;
static SithPlayer jkPlayer_playerInfos[4];
static SithThing player;
static SithThing *sithPlayer_g_pLocalPlayerThing;
static int jkDSS_005aec8c;
static rdModel3 models[4];
static sithSoundClass sound;
static SithThing templates[3];
static int model_calls, model_assignments, sound_calls, sound_assignments;
static int saber_calls, mots_broadcasts, jk_broadcasts, scores;
static int broadcast_personality;
static int model_failures, sound_available;
static char requested_models[4][32], requested_sound[32], saber_side[32], saber_tip[32];
static unsigned assertions, cases;
static const char *current_case = "setup";

static void check(int condition, const char *expression, int line)
{
    ++assertions;
    if (!condition) {
        fprintf(stderr, "FAIL %s line %d: %s\n", current_case, line, expression);
        exit(1);
    }
}
#define CHECK(expression) check((expression), #expression, __LINE__)

static void copy_name(char *destination, const char *source)
{
    CHECK(source != NULL);
    CHECK(strlen(source) < 32);
    strcpy(destination, source);
}

static void stdString_SafeStrCopy(char *destination, const char *source, size_t size)
{
    CHECK(size == 32);
    copy_name(destination, source);
}

static SithThing *sithThing_GetGuidThing(int guid)
{
    return guid == player.guid ? &player : NULL;
}

static rdModel3 *sithModel_Load(const char *name, int create)
{
    CHECK(create == 1);
    CHECK(model_calls < 4);
    copy_name(requested_models[model_calls], name);
    copy_name(models[model_calls].filename, name);
    ++model_calls;
    return model_calls <= model_failures ? NULL : &models[model_calls - 1];
}

static void sithThing_SetThingModel(SithThing *thing, rdModel3 *model)
{
    CHECK(thing == &player && model != NULL);
    ++model_assignments;
    thing->model = model;
}

static sithSoundClass *sithSoundClass_Load(const char *name)
{
    ++sound_calls;
    copy_name(requested_sound, name);
    return sound_available ? &sound : NULL;
}

static void sithSoundClass_SetThingClass(SithThing *thing, sithSoundClass *klass)
{
    CHECK(thing == &player && klass == &sound);
    ++sound_assignments;
}

static SithThing *sithTemplate_GetTemplate(const char *name)
{
    const char *names[] = {"+ssparks_wall", "+ssparks_blood", "+ssparks_saber"};
    for (int i = 0; i < 3; ++i)
        if (!strcmp(name, names[i])) return &templates[i];
    CHECK(0);
    return NULL;
}

static void jkSaber_InitializeSaberInfo(SithThing *thing, const char *side, const char *tip,
                                     double width, double tip_width, double length,
                                     SithThing *wall, SithThing *blood, SithThing *sparks)
{
    CHECK(thing == &player);
    CHECK(width > 0.0031 && width < 0.0033);
    CHECK(tip_width == 0.0018 && length == 0.12);
    CHECK(wall == &templates[0] && blood == &templates[1] && sparks == &templates[2]);
    copy_name(saber_side, side);
    copy_name(saber_tip, tip);
    ++saber_calls;
}

static void jkDSS_SendSetSaberInfoMots(SithThing *thing, int personality)
{
    CHECK(thing == &player);
    ++mots_broadcasts;
    broadcast_personality = personality;
}

static void jkDSS_SendSetSaberInfo(SithThing *thing)
{
    CHECK(thing == &player);
    ++jk_broadcasts;
}

static void sithMulti_SyncScores(void) { ++scores; }
static void jk_fatal(void) { CHECK(0); }

#include "team_model_arrays.inc"
#include "team_model_lookup.inc"

/* The production network macros declare scratch values for every packet type;
 * decompiled handlers also retain unused locals. Keep warning exceptions scoped
 * to the unmodified extracted code, not the fixture or stub implementation. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-value"
#include "team_model_handlers.inc"
#pragma GCC diagnostic pop

static const char *expected_models[5][5] = {
    {"ky.3do", "kyX0.3do", "kyU0.3do", "kyV0.3do", "kyT0.3do"},
    {"ky.3do", "kyX0.3do", "kyU0.3do", "kyV0.3do", "kyT0.3do"},
    {"kyh4.3do", "kyh4r.3do", "kyh4y.3do", "kyh4b.3do", "kyh4g.3do"},
    {"kypr.3do", "kyprr.3do", "kypry.3do", "kyprb.3do", "kyprg.3do"},
    {"kym13.3do", "kym13r.3do", "kym13y.3do", "kym13b.3do", "kym13g.3do"},
};

static void reset(const char *name)
{
    current_case = name;
    ++cases;
    Main_bMotsCompat = sithNet_isServer = 1;
    sithNet_MultiModeFlags = MULTIMODEFLAG_TEAMS | MULTIMODEFLAG_100;
    memset(jkPlayer_playerInfos, 0, sizeof(jkPlayer_playerInfos));
    memset(&player, 0, sizeof(player));
    player.guid = 0x1020304;
    player.actorParams.pPlayer = &jkPlayer_playerInfos[1];
    player.playerInfo = &player;
    jkPlayer_playerInfos[1].teamNum = 2;
    jkPlayer_playerInfos[1].pLocalPlayer = &player;
    sithPlayer_g_pLocalPlayerThing = &player;
    jkDSS_005aec8c = 99;
    model_calls = model_assignments = sound_calls = sound_assignments = 0;
    saber_calls = mots_broadcasts = jk_broadcasts = scores = 0;
    broadcast_personality = -99;
    model_failures = 0;
    sound_available = 1;
    memset(requested_models, 0, sizeof(requested_models));
    memset(requested_sound, 0, sizeof(requested_sound));
}

static SithMessage saber_packet(int id, int personality, int mots)
{
    SithMessage message = {0};
    int32_t guid = player.guid;
    int16_t wire_personality = (int16_t)personality;
    const char *names[] = {"custom.3do", "custom.snd", "custom-side.mat", "custom-tip.mat"};
    message.netMsg.cogMsgId = id;
    memcpy(message.pktData, &guid, sizeof(guid));
    for (int i = 0; i < 4; ++i)
        strcpy((char *)message.pktData + 4 + i * 32, names[i]);
    if (mots) memcpy(message.pktData + 132, &wire_personality, sizeof(wire_personality));
    message.netMsg.msg_size = mots ? 134 : 132;
    return message;
}

static SithMessage team_packet(int player_idx, int team, int personality, int mots)
{
    SithMessage message = {0};
    int16_t values[] = {(int16_t)player_idx, (int16_t)team, (int16_t)personality};
    message.netMsg.cogMsgId = DSS_SETTEAM;
    message.netMsg.msg_size = mots ? 6 : 4;
    memcpy(message.pktData, values, message.netMsg.msg_size);
    return message;
}

static void expect_saber(const char *model, const char *sound_name)
{
    CHECK(model_calls == 1 && model_assignments == 1);
    CHECK(player.model != NULL && !strcmp(player.model->filename, model));
    CHECK(sound_calls == 1 && sound_assignments == 1);
    CHECK(!strcmp(requested_sound, sound_name));
    CHECK(saber_calls == 1);
    CHECK(!strcmp(saber_side, "custom-side.mat") && !strcmp(saber_tip, "custom-tip.mat"));
}

static void test_matrix(void)
{
    CHECK(sizeof(jkDSS_aMotsKyTeamModels) / sizeof(jkDSS_aMotsKyTeamModels[0]) == 25);
    for (int personality = 0; personality <= 4; ++personality) {
        for (int team = 0; team <= 4; ++team) {
            reset("native-and-legacy-class-team-matrix");
            CHECK(!strcmp(jkDSS_GetMotsTeamModel(personality, team), expected_models[personality][team]));
            jkPlayer_playerInfos[1].teamNum = team;
            SithMessage message = saber_packet(DSS_SABERINFO1, personality, 1);
            CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
            expect_saber(expected_models[personality][team], "ky.snd");
            CHECK(mots_broadcasts == 1 && broadcast_personality == personality);
            CHECK(jk_broadcasts == 0 && scores == 0);
            if (!team) continue; /* Team-change requests deliberately reject neutral team 0. */
            reset("native-and-legacy-set-team-matrix");
            message = team_packet(1, team, personality, 1);
            CHECK(jkDSS_ProcessSetTeam(&message) == 1);
            CHECK(jkPlayer_playerInfos[1].teamNum == team);
            CHECK(model_calls == 1 && model_assignments == 1);
            CHECK(!strcmp(player.model->filename, expected_models[personality][team]));
            CHECK(mots_broadcasts == 1 && broadcast_personality == personality);
            CHECK(jk_broadcasts == 0 && scores == 1 && saber_calls == 0);
        }
    }
}

static void test_invalid(void)
{
    const int invalid_classes[] = {-32768, -1, 5, 7, 8, 32767};
    const int invalid_teams[] = {-32768, -1, 5, 32767};
    reset("helper-integer-extremes");
    CHECK(jkDSS_GetMotsTeamModel(INT_MIN, 1) == NULL);
    CHECK(jkDSS_GetMotsTeamModel(INT_MAX, 1) == NULL);
    CHECK(jkDSS_GetMotsTeamModel(4, INT_MIN) == NULL);
    CHECK(jkDSS_GetMotsTeamModel(4, INT_MAX) == NULL);
    for (unsigned i = 0; i < sizeof(invalid_classes) / sizeof(*invalid_classes); ++i) {
        int personality = invalid_classes[i];
        reset("invalid-class-saber-fallback");
        CHECK(jkDSS_GetMotsTeamModel(personality, 2) == NULL);
        SithMessage message = saber_packet(DSS_SABERINFO1, personality, 1);
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
        expect_saber("kk.3do", "ky.snd");
        CHECK(mots_broadcasts == 1 && broadcast_personality == personality);
        for (int no_local_thing = 0; no_local_thing <= 1; ++no_local_thing) {
            reset("invalid-class-team-no-state-change");
            if (no_local_thing) jkPlayer_playerInfos[1].pLocalPlayer = NULL;
            SithPlayer before_infos[4];
            memcpy(before_infos, jkPlayer_playerInfos, sizeof(before_infos));
            SithThing before_player = player;
            message = team_packet(1, 4, personality, 1);
            CHECK(jkDSS_ProcessSetTeam(&message) == 0);
            CHECK(memcmp(before_infos, jkPlayer_playerInfos, sizeof(before_infos)) == 0);
            CHECK(memcmp(&before_player, &player, sizeof(player)) == 0);
            CHECK(model_calls == 0 && model_assignments == 0);
            CHECK(sound_calls == 0 && sound_assignments == 0 && saber_calls == 0);
            CHECK(scores == 0 && mots_broadcasts == 0 && jk_broadcasts == 0);
            CHECK(jkDSS_005aec8c == 99);
        }
    }
    for (unsigned i = 0; i < sizeof(invalid_teams) / sizeof(*invalid_teams); ++i) {
        reset("invalid-team-saber-fallback");
        int team = invalid_teams[i];
        CHECK(jkDSS_GetMotsTeamModel(4, team) == NULL);
        jkPlayer_playerInfos[1].teamNum = team;
        SithMessage message = saber_packet(DSS_SABERINFO1, 4, 1);
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
        expect_saber("kk.3do", "ky.snd");
        reset("invalid-team-request-no-state-change");
        message = team_packet(1, team, 4, 1);
        CHECK(jkDSS_ProcessSetTeam(&message) == 0);
        CHECK(jkPlayer_playerInfos[1].teamNum == 2 && model_calls == 0 && scores == 0);
    }
    reset("neutral-team-request-rejected");
    SithMessage message = team_packet(1, 0, 4, 1);
    CHECK(jkDSS_ProcessSetTeam(&message) == 0 && model_calls == 0 && scores == 0);
    const int invalid_players[] = {-1, 4, 32767};
    for (unsigned i = 0; i < sizeof(invalid_players) / sizeof(*invalid_players); ++i) {
        reset("invalid-player-request-rejected");
        message = team_packet(invalid_players[i], 4, 4, 1);
        CHECK(jkDSS_ProcessSetTeam(&message) == 0 && model_calls == 0 && scores == 0);
    }
}

static void test_preserved_paths(void)
{
    for (int server = 0; server <= 1; ++server) {
        reset("authoritative-saber-broadcast-preserves-custom");
        sithNet_isServer = server;
        SithMessage message = saber_packet(DSS_SABERINFO2, 7, 1);
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
        expect_saber("custom.3do", "custom.snd");
        CHECK(jkDSS_005aec8c == 0 && mots_broadcasts == 0);
    }
    const int no_substitution_flags[] = {0, MULTIMODEFLAG_TEAMS};
    for (unsigned i = 0; i < sizeof(no_substitution_flags) / sizeof(*no_substitution_flags); ++i) {
        reset("no-team-skin-substitution-preserves-custom");
        sithNet_MultiModeFlags = no_substitution_flags[i];
        SithMessage message = saber_packet(DSS_SABERINFO1, -1, 1);
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
        expect_saber("custom.3do", "custom.snd");
    }
    const int inactive_team_flags[] = {0, MULTIMODEFLAG_TEAMS, MULTIMODEFLAG_100};
    for (unsigned i = 0; i < sizeof(inactive_team_flags) / sizeof(*inactive_team_flags); ++i) {
        reset("inactive-team-mode-does-not-change-custom-model");
        sithNet_MultiModeFlags = inactive_team_flags[i];
        SithMessage message = team_packet(1, 4, -1, 1);
        CHECK(jkDSS_ProcessSetTeam(&message) == 1);
        CHECK(jkPlayer_playerInfos[1].teamNum == 2 && model_calls == 0 && scores == 0);
    }
    reset("mots-forced-default-skin-preserved");
    sithNet_MultiModeFlags = MULTIMODEFLAG_20;
    SithMessage message = saber_packet(DSS_SABERINFO1, 4, 1);
    CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
    expect_saber("kk.3do", "ky.snd");
    reset("client-does-not-process-saber-request");
    sithNet_isServer = 0;
    message = saber_packet(DSS_SABERINFO1, 4, 1);
    CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1 && model_calls == 0);
    message = team_packet(1, 4, 4, 1);
    CHECK(jkDSS_ProcessSetTeam(&message) == 0 && model_calls == 0 && scores == 0);
    for (int absent = 0; absent < 3; ++absent) {
        reset("missing-player-prerequisite");
        message = saber_packet(DSS_SABERINFO1, 4, 1);
        if (absent == 0) memset(message.pktData, 0, 4);
        if (absent == 1) player.actorParams.pPlayer = NULL;
        if (absent == 2) player.playerInfo = NULL;
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 0 && model_calls == 0);
    }
    for (int failures = 1; failures <= 2; ++failures) {
        reset("missing-model-load-fallback");
        model_failures = failures;
        message = saber_packet(DSS_SABERINFO1, 4, 1);
        CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
        CHECK(model_calls == 2 && !strcmp(requested_models[1], "kk.3do"));
        CHECK(model_assignments == (failures == 1) && saber_calls == 1);
    }
    reset("missing-team-model-no-assignment-or-broadcast");
    model_failures = 1;
    message = team_packet(1, 4, 4, 1);
    CHECK(jkDSS_ProcessSetTeam(&message) == 1);
    CHECK(jkPlayer_playerInfos[1].teamNum == 4 && scores == 1);
    CHECK(model_calls == 1 && model_assignments == 0 && mots_broadcasts == 0);
    reset("team-change-with-no-local-thing");
    jkPlayer_playerInfos[1].pLocalPlayer = NULL;
    message = team_packet(1, 4, 4, 1);
    CHECK(jkDSS_ProcessSetTeam(&message) == 1);
    CHECK(jkPlayer_playerInfos[1].teamNum == 4 && scores == 1 && model_calls == 0);
    reset("missing-sound-keeps-saber-initialization");
    sound_available = 0;
    message = saber_packet(DSS_SABERINFO1, 4, 1);
    CHECK(jkDSS_ProcessSetSaberInfoMots(&message) == 1);
    CHECK(sound_assignments == 0 && saber_calls == 1 && model_assignments == 1);
}

static void test_jk(void)
{
    for (int team = 0; team <= 4; ++team) {
        reset("jk-saber-team-models-unchanged");
        Main_bMotsCompat = 0;
        jkPlayer_playerInfos[1].teamNum = team;
        SithMessage message = saber_packet(DSS_SABERINFO1, 0, 0);
        CHECK(jkDSS_ProcessSetSaberInfo(&message) == 1);
        expect_saber(expected_models[0][team], "ky.snd");
        CHECK(jk_broadcasts == 1 && mots_broadcasts == 0);
        if (!team) continue;
        reset("jk-four-byte-team-packet-unchanged");
        Main_bMotsCompat = 0;
        message = team_packet(1, team, -32768, 0);
        CHECK(message.netMsg.msg_size == 4);
        CHECK(jkDSS_ProcessSetTeam(&message) == 1);
        CHECK(!strcmp(player.model->filename, expected_models[0][team]));
        CHECK(jk_broadcasts == 1 && mots_broadcasts == 0 && scores == 1);
    }
    reset("jk-custom-skin-unchanged");
    Main_bMotsCompat = sithNet_MultiModeFlags = 0;
    SithMessage message = saber_packet(DSS_SABERINFO1, 0, 0);
    CHECK(jkDSS_ProcessSetSaberInfo(&message) == 1);
    expect_saber("custom.3do", "custom.snd");
    reset("jk-forced-mode-early-return-unchanged");
    Main_bMotsCompat = 0;
    sithNet_MultiModeFlags = MULTIMODEFLAG_20;
    message = saber_packet(DSS_SABERINFO1, 0, 0);
    CHECK(jkDSS_ProcessSetSaberInfo(&message) == 1 && model_calls == 0);
    const int invalid_teams[] = {INT_MIN, -1, 5, INT_MAX};
    for (unsigned i = 0; i < sizeof(invalid_teams) / sizeof(*invalid_teams); ++i) {
        reset("jk-invalid-team-rejected-before-model-or-sound-load");
        Main_bMotsCompat = 0;
        jkPlayer_playerInfos[1].teamNum = invalid_teams[i];
        message = saber_packet(DSS_SABERINFO1, 0, 0);
        CHECK(jkDSS_ProcessSetSaberInfo(&message) == 0);
        CHECK(model_calls == 0 && sound_calls == 0 && saber_calls == 0 && jk_broadcasts == 0);
    }
}

int main(void)
{
    test_matrix();
    test_invalid();
    test_preserved_paths();
    test_jk();
    printf("PASS team-model regression: %u cases, %u assertions; real packet macros and both MotS handlers, JK controls\n",
           cases, assertions);
    return 0;
}
