#include "gdi32.h"

#include "uc_utils.h"

uint32_t Gdi32::GetStockObject(uint32_t a)
{
    return 0;
}

uint32_t Gdi32::GetDeviceCaps(uint32_t device, uint32_t index)
{
    printf("Get caps for %x, index %i\n", device, index);
    switch (index)
    {
        case BITSPIXEL:
            return 16;
        default:
            return 0;
    }
}

/*uint32_t Gdi32::(uint32_t )
{
}*/
