#ifndef _RDPOLYLINE_H
#define _RDPOLYLINE_H

#define rdPolyLine_New_ADDR (0x00448710)
#define rdPolyLine_NewEntry_ADDR (0x00448770)
#define rdPolyline_Free_ADDR (0x00448A40)
#define rdPolyLine_FreeEntry_ADDR (0x00448A60)
#define rdPolyLine_Draw_ADDR (0x00448B10)
#define rdPolyLine_DrawFace_ADDR (0x00448FA0)

typedef struct rdThing rdThing;
typedef struct rdPolyLine rdPolyLine;

rdPolyLine* rdPolyLine_New(char *polyline_fname, char *material_fname, char *material_fname2, float a4, float base_rad, float tip_rad, int a7, int a8, int a9, int a10);

static int (*rdPolyLine_NewEntry)(rdPolyLine *a1, char *polyline_fname, char *material_side_fname, char *material_tip_fname, float a5, float base_rad, float tip_rad, int a8, int a9, int a10, int a11) = rdPolyLine_NewEntry_ADDR;

static void (*rdPolyLine_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdPolyLine_Draw_ADDR;

#endif // _RDPOLYLINE_H
