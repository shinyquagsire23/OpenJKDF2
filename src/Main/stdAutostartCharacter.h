#ifndef OPENJKDF2_STDAUTOSTARTCHARACTER_H
#define OPENJKDF2_STDAUTOSTARTCHARACTER_H
#include <stddef.h>

// A character name inside the chosen profile, not a filesystem path. Keep the
// opt-in command bounded to the engine's 31-byte MPC name contract.
static inline int stdAutostart_CharacterNameValid(const char* name)
{
    if (!name || !name[0]) return 0;
    size_t length = 0;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p) {
        if (++length > 31 || !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
            || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;
    }
    return 1;
}
#endif
