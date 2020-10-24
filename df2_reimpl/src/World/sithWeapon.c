#include "sithWeapon.h"

void sithWeapon_InitDefaults()
{
    sithWeapon_InitDefaults2();
}

void sithWeapon_InitDefaults2()
{
    sithWeapon_bAutoPickup = 1;
    sithWeapon_bAutoSwitch = 3;
    sithWeapon_bAutoReload = 0;
    sithWeapon_bMultiAutoPickup = 15;
    sithWeapon_bMultiplayerAutoSwitch = 3;
    sithWeapon_bMultiAutoReload = 3;
    sithWeapon_bAutoAim = 1;
    g_flt_8BD040 = 0.0;
    g_flt_8BD044 = 5.0;
    g_flt_8BD048 = 10.0;
    g_flt_8BD04C = 30.0;
    g_flt_8BD050 = 1.5;
    g_flt_8BD054 = 0.5;
    g_flt_8BD058 = 2.0;
}
