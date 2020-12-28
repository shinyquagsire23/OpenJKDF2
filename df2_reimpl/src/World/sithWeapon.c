#include "sithWeapon.h"

#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "jk.h"

void sithWeapon_InitDefaults()
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

void sithWeapon_Startup()
{
    sithWeapon_InitDefaults();
}

void sithWeapon_Underwater(sithThing *weapon, float deltaSeconds)
{
    int typeFlags = weapon->weaponParams.typeflags;
    if (typeFlags & THING_TYPEFLAGS_ISBLOCKING)
    {
        sithWeapon_sub_4D35E0(weapon);
    }
    else if (typeFlags & THING_TYPEFLAGS_SCREAMING)
    {
        sithWeapon_sub_4D3920(weapon);
    }
    else
    {
        if (typeFlags & SITH_TF_NOHARD 
            && weapon->weaponParams.damage > (double)weapon->weaponParams.mindDamage)
        {
            float v3 = weapon->weaponParams.damage - weapon->weaponParams.rate * deltaSeconds;
            weapon->weaponParams.damage = v3;
            // no idea if this is even correct but it makes sense?
            // c0 | c3, https://c9x.me/x86/html/file_module_x86_id_87.html
            if (v3 <= 0.0)
                v3 = weapon->weaponParams.mindDamage;
            weapon->weaponParams.damage = v3;
        }
        if ( (typeFlags & SITH_TF_TIMER) != 0 && (((uint8_t)bShowInvisibleThings + (weapon->thingIdx & 0xFF)) & 7) == 0 )
            sithSector_AddEntry(weapon->sector, &weapon->position, 2, 2.0, weapon);
    }
}
