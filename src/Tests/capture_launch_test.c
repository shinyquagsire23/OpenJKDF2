#define STDCAPTURE_UNIT_TEST
#include "Main/stdCapture.c"
#include <assert.h>

static void check(int expected, int argc, char** argv)
{
    active = 0;
    assert(stdCapture_Init(argc, argv) == expected);
    assert(stdCapture_IsActive() == expected);
}

int main(int argc, char** argv)
{
    assert(argc == 2);
    assert(!setenv("OPENJKDF2_CAPTURE_REQUEST", argv[1], 1));
    char* sp[] = {"game", "-capture", "-autostart", "-sp", "-episode", "ep", "-map", "map.jkl"};
    char* mp[] = {"game", "-capture", "-autostart", "-mp", "-episode", "ep", "-map", "map.jkl", "-path", "startup", "-character", "WBW_Test-1"};
    check(1, 8, sp);
    assert(!rename(".openjkdf2-capture-session", ".session-held"));
    check(0, 8, sp);
    assert(!rename(".session-held", ".openjkdf2-capture-session"));
    assert(!rename("resource/jk_.cd", "resource/held.cd"));
    check(0, 8, sp);
    assert(!rename("resource/held.cd", "resource/jk_.cd"));
    check(1, 12, mp);
    check(1, 8, mp);  // Multiplayer capture without an overlay or character.
    check(0, 11, mp); // Missing character argument.
    mp[11] = "../secret"; check(0, 12, mp);
    mp[11] = "character.mpc"; check(0, 12, mp);
    mp[11] = "12345678901234567890123456789012"; check(0, 12, mp);
    mp[11] = "WBW"; mp[3] = "-sp"; check(0, 12, mp);
    mp[3] = "-mp"; mp[9] = "../startup"; check(0, 12, mp);
    mp[9] = "C:/other"; check(0, 12, mp);
    mp[9] = "startup";
    char* both[] = {"game", "-capture", "-autostart", "-sp", "-episode", "ep", "-map", "map.jkl", "-mp"};
    check(0, 9, both);
    both[8] = "-sp"; check(0, 9, both);
    both[8] = "-renderprobe"; check(0, 9, both);
    both[8] = "/renderprobe"; check(0, 9, both);
    sp[3] = "-headless"; check(0, 8, sp);
    assert(stdAutostart_CharacterNameValid("1234567890123456789012345678901"));
    assert(!stdAutostart_CharacterNameValid(NULL));
    assert(!stdAutostart_CharacterNameValid(""));
    assert(!stdAutostart_CharacterNameValid("two words"));
    assert(!unsetenv("OPENJKDF2_CAPTURE_REQUEST"));
    assert(!stdCapture_Init(8, sp));
    char* normal[] = {"game"};
    assert(stdCapture_Init(1, normal));
    char* probe[] = {"game", "-renderprobe", "-autostart", "-renderout", "/tmp/probe"};
    assert(stdCapture_Init(5, probe));
    assert(!stdCapture_IsActive());
    puts("capture launch tests passed (explicit SP/MP, profile character, staged overlay, invalid combinations)");
    return 0;
}
