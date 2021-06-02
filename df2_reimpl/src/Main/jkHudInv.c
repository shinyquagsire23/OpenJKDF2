#include "jkHudInv.h"

int jkHudInv_Initialize()
{
    memset(jkHudInv_idkItems, 0, 14 * sizeof(int)); // sizeof(jkHudInv_idkItems)
    return 1;
}
