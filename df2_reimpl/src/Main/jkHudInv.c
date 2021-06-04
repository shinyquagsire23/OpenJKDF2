#include "jkHudInv.h"

#include "jk.h"

int jkHudInv_Initialize()
{
    _memset(jkHudInv_idkItems, 0, 14 * sizeof(int)); // sizeof(jkHudInv_idkItems)
    return 1;
}
