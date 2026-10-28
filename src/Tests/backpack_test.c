/* Adapted from andreipemberton, original contribution 4dc57962e46a72662b59d36c30f15eacef6234b5;
 * source snapshot 6fa54630a123485d8c7b602c47992613a1f397b5. */
/*
 * run_backpack_test.py extracts the current inventory functions, backpack
 * structs, and DSS item cases. Minimal thing/inventory/network stubs exercise
 * bin selection and physical bounds without a game, retail assets, or the
 * production ABI. Packet tokens test field order, not transport or byte order;
 * surrounding thing-state updates and general packet-length validation are
 * outside this harness.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backpack_constants.h"

typedef float flex_t;
typedef struct { float x, y, z; } rdVector3;
typedef struct SithSector SithSector;
#include "backpack_structs.h"

typedef struct { flex_t amount; } InventoryItem;
typedef struct { InventoryItem aItems[SITHBIN_NUMBINS]; } SithPlayer;
typedef struct { uint32_t flags; } SithInventoryType;
typedef struct
{
    int type;
    SithItemInfo itemParams;
    struct { SithPlayer *pPlayer; } actorParams;
} SithThing;

#define SITH_ASSERTREL assert
#define CAPACITY ((int)(sizeof(((SithItemInfo *)0)->contents) / sizeof(SithBackpackItem)))

static SithInventoryType sithInventory_g_aTypes[SITHBIN_NUMBINS];
static int Main_bMotsCompat;
static int sithNet_isMulti;
static SithThing backpack_template;
static SithThing created_backpack;
static int template_available;
static int creation_available;
static int creation_calls;
static int network_calls;
static int observed_count;
static int observed_bins[CAPACITY];
static flex_t observed_values[CAPACITY];
static SithThing *observed_player;
static unsigned assertions;
static unsigned pickup_cases;
static const char *current_case = "setup";

static void check(int condition, const char *expression, int line)
{
    ++assertions;
    if (!condition)
    {
        fprintf(stderr, "FAIL %s line %d: %s\n", current_case, line, expression);
        exit(1);
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

static SithThing *sithTemplate_GetTemplate(const char *name)
{
    CHECK(strcmp(name, "+backpack") == 0);
    return template_available ? &backpack_template : NULL;
}

static SithThing *sithThing_CreateThing(SithThing *source, SithThing *player)
{
    (void)player;
    CHECK(source == &backpack_template);
    ++creation_calls;
    return creation_available ? &created_backpack : NULL;
}

static void sithDSSThing_CreateThing(SithThing *source, SithThing *backpack,
                                   SithThing *player, int a, int b, int c,
                                   int destination, int flags)
{
    (void)source; (void)player; (void)a; (void)b; (void)c;
    CHECK(backpack == &created_backpack);
    CHECK(destination == 255 && flags == 1);
    ++network_calls;
}

static void sithDSSThing_UpdateState(SithThing *backpack, int destination, int flags)
{
    CHECK(backpack == &created_backpack);
    CHECK(destination == -1 && flags == 255);
    ++network_calls;
}

static flex_t sithInventory_ChangeInventory(SithThing *player, int bin, flex_t value)
{
    CHECK(observed_count < CAPACITY);
    observed_player = player;
    observed_bins[observed_count] = bin;
    observed_values[observed_count++] = value;
    return value;
}

#include "backpack_inventory.inc"

enum TokenKind { TOKEN_S32, TOKEN_S16, TOKEN_F32 };
typedef struct { enum TokenKind kind; double value; } Token;
static Token tokens[2 + 2 * CAPACITY];
static int token_count;
static int token_read;

static void push_token(enum TokenKind kind, double value)
{
    CHECK(token_count < (int)(sizeof(tokens) / sizeof(tokens[0])));
    tokens[token_count++] = (Token){kind, value};
}

static double pop_token(enum TokenKind kind)
{
    CHECK(token_read < token_count);
    CHECK(tokens[token_read].kind == kind);
    return tokens[token_read++].value;
}

#define NETMSG_PUSHS32(value) push_token(TOKEN_S32, (value))
#define NETMSG_PUSHS16(value) push_token(TOKEN_S16, (value))
#define NETMSG_PUSHF32(value) push_token(TOKEN_F32, (value))
#define NETMSG_POPS32() ((int32_t)pop_token(TOKEN_S32))
#define NETMSG_POPS16() ((int16_t)pop_token(TOKEN_S16))
#define NETMSG_POPF32() ((float)pop_token(TOKEN_F32))

static void pack_item(SithThing *pThing)
{
    switch (pThing->type)
    {
#include "backpack_dss_pack.inc"
        default: break;
    }
}

static int unpack_item(SithThing *pThing)
{
    switch (pThing->type)
    {
#include "backpack_dss_unpack.inc"
        default: break;
    }
    return 1;
}

static void reset(SithThing *player, SithPlayer *inventory, SithThing *backpack)
{
    memset(player, 0, sizeof(*player));
    memset(inventory, 0, sizeof(*inventory));
    memset(backpack, 0, sizeof(*backpack));
    memset(sithInventory_g_aTypes, 0, sizeof(sithInventory_g_aTypes));
    memset(&created_backpack, 0, sizeof(created_backpack));
    player->actorParams.pPlayer = inventory;
    backpack->type = SITH_THING_ITEM;
    backpack->itemParams.flags = SITH_ITEM_BACKPACK;
    for (int i = 0; i < CAPACITY; ++i)
        backpack->itemParams.contents[i].binIdx = -1;
    template_available = creation_available = sithNet_isMulti = 1;
    creation_calls = network_calls = observed_count = token_count = token_read = 0;
    observed_player = NULL;
}

static void test_pickup(void)
{
    SithThing player, backpack;
    SithPlayer inventory;
    const unsigned carried = SITHINVENTORY_TYPE_REGISTERED | SITHINVENTORY_TYPE_BACKPACKITEM;
    const unsigned descriptor_flags[] = {0, SITHINVENTORY_TYPE_REGISTERED,
                                        SITHINVENTORY_TYPE_BACKPACKITEM, carried};

    current_case = "drazen-map-bin43-slot0";
    reset(&player, &inventory, &backpack);
    backpack.itemParams.numBins = 1;
    backpack.itemParams.contents[0] = (SithBackpackItem){43, 0, 1.0f};
    sithInventory_g_aTypes[43].flags = carried;
    sithInventory_PickupBackpack(&player, &backpack);
    CHECK(observed_count == 1);
    CHECK(observed_bins[0] == 43 && observed_values[0] == 1.0f);

    current_case = "pickup-bin-descriptor-matrix";
    for (int bin = 0; bin < SITHBIN_NUMBINS; ++bin)
    for (int slot = 0; slot < CAPACITY; ++slot)
    for (unsigned flag = 0; flag < sizeof(descriptor_flags) / sizeof(descriptor_flags[0]); ++flag)
    {
        reset(&player, &inventory, &backpack);
        backpack.itemParams.numBins = CAPACITY;
        backpack.itemParams.contents[slot] = (SithBackpackItem){bin, 0, 3.5f};
        sithInventory_g_aTypes[slot].flags = descriptor_flags[flag] == carried ? 0 : carried;
        sithInventory_g_aTypes[bin].flags = descriptor_flags[flag];
        sithInventory_PickupBackpack(&player, &backpack);
        CHECK(observed_count == (descriptor_flags[flag] == carried ? 1 : 0));
        if (observed_count)
        {
            CHECK(observed_player == &player);
            CHECK(observed_bins[0] == bin);
            CHECK(observed_values[0] == 3.5f);
        }
        ++pickup_cases;
    }

    current_case = "pickup-invalid-bins-and-counts";
    const int bad_bins[] = {-32768, -1, SITHBIN_NUMBINS, 32767};
    for (unsigned b = 0; b < sizeof(bad_bins) / sizeof(bad_bins[0]); ++b)
    {
        reset(&player, &inventory, &backpack);
        backpack.itemParams.numBins = 1;
        backpack.itemParams.contents[0].binIdx = bad_bins[b];
        sithInventory_PickupBackpack(&player, &backpack);
        CHECK(observed_count == 0);
    }
    const int counts[] = {-32768, -1, 0, 1, CAPACITY, CAPACITY + 1, 32767};
    for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
    {
        reset(&player, &inventory, &backpack);
        backpack.itemParams.numBins = counts[c];
        for (int i = 0; i < CAPACITY; ++i)
        {
            backpack.itemParams.contents[i] = (SithBackpackItem){43, 0, 1.0f};
            sithInventory_g_aTypes[43].flags = carried;
        }
        int expected = counts[c] < 0 ? 0 : counts[c] > CAPACITY ? CAPACITY : counts[c];
        CHECK(sithInventory_GetNumBackpackItems(&backpack) == expected);
        sithInventory_PickupBackpack(&player, &backpack);
        CHECK(observed_count == expected);
        for (int item = -2; item <= CAPACITY + 1; ++item)
        {
            int valid = item >= 0 && item < expected;
            CHECK(sithInventory_GetBackpackItemID(&backpack, item) == (valid ? 43 : -1));
            CHECK(sithInventory_GetBackpackItemValue(&backpack, item) == (valid ? 1.0f : -1.0f));
        }
    }
}

static void test_creation(void)
{
    SithThing player, backpack;
    SithPlayer inventory;
    const unsigned carried = SITHINVENTORY_TYPE_REGISTERED | SITHINVENTORY_TYPE_BACKPACKITEM;
    const int bins[] = {1, 11, 43, 131, SITHBIN_NUMBINS - 1};
    const int jk_order[] = {1, 11, 43, 131, SITHBIN_NUMBINS - 1};
    const int mots_order[] = {131, 11, 43, SITHBIN_NUMBINS - 1};

    current_case = "creation-mode-order";
    for (int mode = 0; mode <= 1; ++mode)
    {
        reset(&player, &inventory, &backpack);
        Main_bMotsCompat = mode;
        for (unsigned i = 0; i < sizeof(bins) / sizeof(bins[0]); ++i)
        {
            sithInventory_g_aTypes[bins[i]].flags = carried;
            inventory.aItems[bins[i]].amount = bins[i] + 0.25f;
        }
        sithInventory_g_aTypes[42].flags = SITHINVENTORY_TYPE_REGISTERED;
        inventory.aItems[42].amount = 1;
        sithInventory_g_aTypes[44].flags = carried;
        CHECK(sithInventory_CreateBackpack(&player) == &created_backpack);
        CHECK(creation_calls == 1 && network_calls == 2);
        CHECK(created_backpack.itemParams.flags & SITH_ITEM_BACKPACK);
        const int *order = mode ? mots_order : jk_order;
        int expected = mode ? 4 : 5;
        CHECK(created_backpack.itemParams.numBins == expected);
        for (int i = 0; i < expected; ++i)
        {
            CHECK(created_backpack.itemParams.contents[i].binIdx == order[i]);
            CHECK(created_backpack.itemParams.contents[i].value == order[i] + 0.25f);
        }
    }

    current_case = "creation-physical-capacity";
    for (int mode = 0; mode <= 1; ++mode)
    for (int weapons = 0; weapons <= 1; ++weapons)
    {
        reset(&player, &inventory, &backpack);
        Main_bMotsCompat = mode;
        int first = weapons ? 121 : 20;
        for (int bin = first; bin < first + 20; ++bin)
        {
            sithInventory_g_aTypes[bin].flags = carried;
            inventory.aItems[bin].amount = 1.0f;
        }
        CHECK(sithInventory_CreateBackpack(&player) == &created_backpack);
        CHECK(created_backpack.itemParams.numBins == CAPACITY);
        for (int i = 0; i < CAPACITY; ++i)
            CHECK(created_backpack.itemParams.contents[i].binIdx == first + i);
    }

    current_case = "creation-failure-guards";
    for (int guard = 0; guard < 3; ++guard)
    {
        reset(&player, &inventory, &backpack);
        if (guard == 0) sithNet_isMulti = 0;
        if (guard == 1) template_available = 0;
        if (guard == 2) creation_available = 0;
        CHECK(sithInventory_CreateBackpack(&player) == NULL);
        CHECK(network_calls == 0);
    }
}

static void test_network_cases(void)
{
    SithThing player, backpack;
    SithPlayer inventory;
    const int counts[] = {-1, 0, 1, CAPACITY, CAPACITY + 1, 32767};

    current_case = "dss-pack-count-and-wire-order";
    for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
    {
        reset(&player, &inventory, &backpack);
        backpack.itemParams.numBins = counts[c];
        for (int i = 0; i < CAPACITY; ++i)
            backpack.itemParams.contents[i] = (SithBackpackItem){43 + i, 0, i + 0.5f};
        pack_item(&backpack);
        int expected = counts[c] < 0 ? 0 : counts[c] > CAPACITY ? CAPACITY : counts[c];
        CHECK(token_count == 2 + 2 * expected);
        CHECK(tokens[0].kind == TOKEN_S32 && tokens[0].value == SITH_ITEM_BACKPACK);
        CHECK(tokens[1].kind == TOKEN_S16 && tokens[1].value == expected);
        for (int i = 0; i < expected; ++i)
        {
            CHECK(tokens[2 + 2 * i].kind == TOKEN_S16 && tokens[2 + 2 * i].value == 43 + i);
            CHECK(tokens[3 + 2 * i].kind == TOKEN_F32 && tokens[3 + 2 * i].value == i + 0.5f);
        }
        CHECK(backpack.itemParams.numBins == counts[c]);
    }

    current_case = "dss-unpack-valid-and-rejected-counts";
    for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c)
    {
        reset(&player, &inventory, &backpack);
        backpack.itemParams.flags = 0x40;
        backpack.itemParams.numBins = 2;
        SithItemInfo before = backpack.itemParams;
        push_token(TOKEN_S32, SITH_ITEM_BACKPACK);
        push_token(TOKEN_S16, counts[c]);
        int valid = counts[c] >= 0 && counts[c] <= CAPACITY;
        if (valid)
        {
            for (int i = 0; i < counts[c]; ++i)
            {
                push_token(TOKEN_S16, 43 + i);
                push_token(TOKEN_F32, i + 0.5f);
            }
        }
        CHECK(unpack_item(&backpack) == valid);
        CHECK(token_read == token_count);
        if (valid)
        {
            CHECK(backpack.itemParams.flags == SITH_ITEM_BACKPACK);
            CHECK(backpack.itemParams.numBins == counts[c]);
            for (int i = 0; i < counts[c]; ++i)
            {
                CHECK(backpack.itemParams.contents[i].binIdx == 43 + i);
                CHECK(backpack.itemParams.contents[i].value == i + 0.5f);
            }
        }
        else
            CHECK(memcmp(&before, &backpack.itemParams, sizeof(before)) == 0);
    }

    current_case = "dss-non-backpack-unchanged";
    reset(&player, &inventory, &backpack);
    backpack.itemParams.flags = 0x40;
    backpack.itemParams.numBins = 7;
    pack_item(&backpack);
    CHECK(token_count == 1 && tokens[0].kind == TOKEN_S32);
    CHECK(unpack_item(&backpack) == 1);
    CHECK(backpack.itemParams.numBins == 7 && backpack.itemParams.flags == 0x40);
}

int main(void)
{
    test_pickup();
    test_creation();
    test_network_cases();
    printf("PASS backpack regression: %u assertions, %u pickup matrix cases, capacity %d\n",
           assertions, pickup_cases, CAPACITY);
    return 0;
}
