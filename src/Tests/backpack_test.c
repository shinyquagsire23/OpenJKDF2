/* Adapted from andreipemberton's backpack coverage; narrowed to rejected-count
 * item flags. Uses the full production types, but only the actual receiver's
 * item case. Safe byte-reader seams do not qualify network transport. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

#define CAPACITY ((int)(sizeof(((SithItemInfo *)0)->contents) / sizeof(SithBackpackItem)))
static unsigned checks, cases;
static const char *current_case;
static unsigned char packet[256];
static size_t used, cursor;
static void check(int condition, const char *expression, int line) {
    ++checks;
    if (!condition) {
        fprintf(stderr, "FAIL %s line %d: %s\n", current_case, line, expression);
        exit(1);
    }
}
#define CHECK(x) check((x), #x, __LINE__)
static void put(const void *value, size_t size) {
    CHECK(used + size <= sizeof(packet)); memcpy(packet + used, value, size); used += size;
}
static void get(void *value, size_t size) {
    CHECK(cursor + size <= used); memcpy(value, packet + cursor, size); cursor += size;
}
static int32_t pop_s32(void) { int32_t x; get(&x, sizeof(x)); return x; }
static int16_t pop_s16(void) { int16_t x; get(&x, sizeof(x)); return x; }
static float pop_f32(void) { float x; get(&x, sizeof(x)); return x; }
#define NETMSG_POPS32() pop_s32()
#define NETMSG_POPS16() pop_s16()
#define NETMSG_POPF32() pop_f32()
static int receive_item(SithThing *pThing) {
    switch (pThing->type) {
#include "backpack_dss_unpack.inc"
        default: break;
    }
    return 1;
}
static void scenario(int16_t count, int valid) {
    SithThing thing, expected;
    memset(&thing, 0xa5, sizeof(thing));
    thing.type = SITH_THING_ITEM;
    thing.itemParams.flags = 0x40;
    thing.itemParams.numBins = 2;
    expected = thing;
    used = cursor = 0;
    int32_t flags = SITH_ITEM_BACKPACK | 0x80;
    put(&flags, sizeof(flags)); put(&count, sizeof(count));
    if (valid) {
        expected.itemParams.flags = flags;
        expected.itemParams.numBins = count;
        for (int i = 0; i < count; ++i) {
            int16_t bin = 43 + i; float amount = i + 0.5f;
            put(&bin, sizeof(bin)); put(&amount, sizeof(amount));
            expected.itemParams.contents[i].binIdx = bin;
            expected.itemParams.contents[i].value = amount;
        }
    }
    current_case = valid ? "valid-backpack-state" : "rejected-count-preserves-item-flags";
    CHECK(receive_item(&thing) == valid);
    CHECK(cursor == used);
    CHECK(thing.itemParams.flags == expected.itemParams.flags);
    CHECK(memcmp(&thing, &expected, sizeof(thing)) == 0);
    ++cases;
}
static void non_backpack(void) {
    SithThing thing, expected;
    memset(&thing, 0x5a, sizeof(thing)); thing.type = SITH_THING_ITEM;
    thing.itemParams.flags = SITH_ITEM_BACKPACK; thing.itemParams.numBins = 7;
    expected = thing; expected.itemParams.flags = 0x40;
    used = cursor = 0; int32_t flags = 0x40; put(&flags, sizeof(flags));
    current_case = "non-backpack-flags-only";
    CHECK(receive_item(&thing) == 1); CHECK(cursor == used);
    CHECK(memcmp(&thing, &expected, sizeof(thing)) == 0); ++cases;
}
int main(void) {
    current_case = "setup";
    scenario(-32768, 0); scenario(-1, 0);
    scenario(0, 1); scenario(1, 1); scenario(12, 1);
#ifdef QOL_IMPROVEMENTS
    CHECK(CAPACITY == 16); scenario(13, 1); scenario(16, 1);
#else
    CHECK(CAPACITY == 12); scenario(13, 0); scenario(16, 0);
#endif
    scenario(17, 0); scenario(32767, 0); non_backpack();
    printf("PASS backpack item flags: %u cases, %u assertions, capacity %d; full production types\n", cases, checks, CAPACITY);
    return 0;
}
