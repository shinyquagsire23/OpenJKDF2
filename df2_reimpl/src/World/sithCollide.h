#ifndef _SITHCOLLIDE_H
#define _SITHCOLLIDE_H

#include "types.h"

#define sithCollide_sub_507EA0_ADDR (0x00507EA0)
#define sithCollide_IsSphereInSector_ADDR (0x00507F30)
#define sithCollide_sub_508070_ADDR (0x00508070)
#define sithCollide_sub_5080D0_ADDR (0x005080D0)
#define sithCollide_sub_508370_ADDR (0x00508370)
#define sithCollide_sub_508400_ADDR (0x00508400)
#define sithCollide_sub_508540_ADDR (0x00508540)
#define sithCollide_sub_508750_ADDR (0x00508750)
#define sithCollide_sub_508990_ADDR (0x00508990)
#define sithCollide_sub_508BE0_ADDR (0x00508BE0)
#define sithCollide_sub_508D20_ADDR (0x00508D20)
#define sithCollide_sub_5090B0_ADDR (0x005090B0)

#if 1
int sithCollide_IsSphereInSector(const rdVector3 *pos, float radius, sithSector *sector);
int sithCollide_sub_5080D0(sithThing *thing, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, sithThing *a6, int a7, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11);
int sithCollide_sub_508540(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int a8, int a9);
int sithCollide_sub_508D20(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdFace *a5, rdVector3 *a6, float *a7, rdVector3 *a8, int a9);
int sithCollide_sub_508BE0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *surfaceNormal, rdVector3 *a6, float *a7, int a8);
int sithCollide_sub_508750(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int *a5);
int sithCollide_sub_5090B0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, sithSurfaceInfo *a5, rdVector3 *a6, float *a7, int a8);
#endif

#if 0
static int (*sithCollide_IsSphereInSector)(rdVector3 *pos, float radius, sithSector *sector) = (void*)sithCollide_IsSphereInSector_ADDR;
static int (*sithCollide_sub_508540)(rdVector3 *a1, rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int a8, int a9) = (void*)sithCollide_sub_508540_ADDR;
static int (*sithCollide_sub_5080D0)(sithThing *thing, rdVector3 *a2, rdVector3 *a3, float a4, float a5, sithThing *a6, int a7, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11) = (void*)sithCollide_sub_5080D0_ADDR;
static int (*sithCollide_sub_508750)(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int *a5) = (void*)sithCollide_sub_508750_ADDR;
static int (*sithCollide_sub_5090B0)(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, sithSurfaceInfo *a5, rdVector3 *a6, float *a7, int a8) = (void*)sithCollide_sub_5090B0_ADDR;
#endif

static int (*_sithCollide_sub_508D20)(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdFace *a5, rdVector3 *a6, float *a7, rdVector3 *a8, int a9) = (void*)sithCollide_sub_508D20_ADDR;
static int (*_sithCollide_sub_508BE0)(rdVector3 *a1, rdVector3 *a2, float a3, float a4, rdVector3 *surfaceNormal, rdVector3 *a6, float *a7, int a8) = (void*)sithCollide_sub_508BE0_ADDR;

static int (*sithCollide_sub_508990)(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int a5, rdVector3 *a6) = (void*)sithCollide_sub_508990_ADDR;
static int (*sithCollide_sub_508400)(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdMesh *mesh, float *a6, rdFace **faceOut, rdVector3 *a8) = (void*)sithCollide_sub_508400_ADDR;

#endif // _SITHCOLLIDE_H
