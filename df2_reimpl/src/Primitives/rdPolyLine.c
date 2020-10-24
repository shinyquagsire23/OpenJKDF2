#include "rdPolyLine.h"

#include "Engine/rdroid.h"

rdPolyLine* rdPolyLine_New(char *polyline_fname, char *material_fname, char *material_fname2, float a4, float base_rad, float tip_rad, int a7, int a8, int a9, int a10)
{
    rdPolyLine *polyline;

    polyline = (rdPolyLine *)rdroid_pHS->alloc(0xC0u);
    if (polyline)
    {
        rdPolyLine_NewEntry(
            polyline,
            polyline_fname,
            material_fname,
            material_fname2,
            a4,
            base_rad,
            tip_rad,
            a7,
            a8,
            a9,
            a10);
    }
    return polyline;
}
