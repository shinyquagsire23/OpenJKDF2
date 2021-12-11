#include "Platform/std3D.h"

// Added helpers
int std3D_HasAlpha()
{
    return d3d_device_ptr->hasAlpha;
}

int std3D_HasModulateAlpha()
{
    return d3d_device_ptr->hasModulateAlpha;
}

int std3D_HasAlphaFlatStippled()
{
    return d3d_device_ptr->hasAlphaFlatStippled;
}