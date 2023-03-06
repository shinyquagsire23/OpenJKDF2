#if defined(WIN64_MINGW)
#define CURL_DISABLE_LDAP 1
#define HAVE_MINGW_ORIGINAL 1
#define _tcspbrk strpbrk
#include "config-win32.h"
#elif defined(MACOS)
#include "config-mac_mine.h"
#elif defined(__linux__)
#include "config-linux_mine.h"
#else
#endif