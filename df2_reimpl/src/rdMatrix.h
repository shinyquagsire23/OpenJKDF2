#ifndef _RDMATRIX_H
#define _RDMATRIX_H

#include "rdVector.h"
#include "hook.h"

/*
rdMatrix_Build34	.text	0043F6F0	00000121	00000024	0000000C	R	.	.	.	.	T	.
rdMatrix_BuildFromLook34	.text	0043F820	00000164	00000008	00000008	R	.	.	.	.	T	.
rdMatrix_BuildCamera34	.text	0043F990	00000146	0000002C	0000000C	R	.	.	.	.	.	.
rdMatrix_InvertOrtho34	.text	0043FAE0	000000C7	00000004	00000008	R	.	.	.	.	T	.
rdMatrix_Build44	.text	0043FBB0	0000013F	00000020	0000000C	R	.	.	.	.	T	.
*/

#define rdMatrix_BuildRotate34_ADDR (0x0043FCF0)
/*
rdMatrix_BuildInverseRotate34	.text	0043FE10	00000119	00000020	00000008	R	.	.	.	.	T	.
rdMatrix_BuildRotate44	.text	0043FF30	00000131	00000018	00000008	R	.	.	.	.	T	.
rdMatrix_BuildTranslate34	.text	00440070	0000002E	00000008	00000008	R	.	.	.	.	T	.
rdMatrix_BuildTranslate44	.text	004400A0	00000035	00000008	00000008	R	.	.	.	.	.	.
rdMatrix_BuildScale34	.text	004400E0	0000003B	00000004	00000008	R	.	.	.	.	.	.
rdMatrix_BuildScale44	.text	00440120	00000041	00000004	00000008	R	.	.	.	.	.	.
rdMatrix_BuildFromVectorAngle34	.text	00440170	00000220	00000028	0000000C	R	.	.	.	.	T	.
rdMatrix_LookAt	.text	00440390	00000313	00000054	00000010	R	.	.	.	.	T	.
rdMatrix_ExtractAngles34	.text	004406B0	00000230	00000028	00000008	R	.	.	.	.	T	.
rdMatrix_Normalize34	.text	004408E0	000000A5	0000000C	00000004	R	.	.	.	.	.	.
rdMatrix_Identity34	.text	00440990	00000015	00000008	00000004	R	.	.	.	.	.	.
rdMatrix_Identity44	.text	004409B0	00000015	00000008	00000004	R	.	.	.	.	.	.
rdMatrix_Copy34	.text	004409D0	00000014	00000008	00000008	R	.	.	.	.	.	.
rdMatrix_Copy44	.text	004409F0	00000014	00000008	00000008	R	.	.	.	.	.	.
rdMatrix_Copy34to44	.text	00440A10	00000063	00000004	00000008	R	.	.	.	.	.	.
rdMatrix_Copy44to34	.text	00440A80	0000004F	00000000	00000008	R	.	.	.	.	.	.
rdMatrix_Transpose44	.text	00440AD0	0000008D	00000048	00000008	R	.	.	.	.	.	.
rdMatrix_Multiply34	.text	00440B60	000001C0	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_Multiply44	.text	00440D20	000002F8	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_PreMultiply34	.text	00441020	000001CC	00000038	00000008	R	.	.	.	.	T	.
rdMatrix_PreMultiply44	.text	004411F0	000002FB	00000048	00000008	R	.	.	.	.	.	.
rdMatrix_PostMultiply34	.text	004414F0	000001D4	00000038	00000008	R	.	.	.	.	.	.
rdMatrix_PostMultiply44	.text	004416D0	000002F5	00000048	00000008	R	.	.	.	.	.	.
rdMatrix_PreRotate34	.text	004419D0	0000002B	00000030	00000008	R	.	.	.	.	.	.
rdMatrix_PreRotate44	.text	00441A00	0000002B	00000040	00000008	R	.	.	.	.	.	.
rdMatrix_PostRotate34	.text	00441A30	0000002B	00000030	00000008	R	.	.	.	.	.	.
rdMatrix_PostRotate44	.text	00441A60	0000002B	00000040	00000008	R	.	.	.	.	.	.
rdMatrix_PreTranslate34	.text	00441A90	00000045	00000038	00000008	R	.	.	.	.	T	.
rdMatrix_PreTranslate44	.text	00441AE0	0000004D	00000048	00000008	R	.	.	.	.	.	.
rdMatrix_PostTranslate34	.text	00441B30	0000002D	00000000	00000008	R	.	.	.	.	.	.
rdMatrix_PostTranslate44	.text	00441B60	0000002D	00000000	00000008	R	.	.	.	.	.	.
rdMatrix_PreScale34_0	.text	00441B90	0000006F	00000030	00000008	R	.	.	.	.	.	.
rdMatrix_PreScale44_0	.text	00441C00	00000077	00000040	00000008	R	.	.	.	.	.	.
rdMatrix_PostScale34	.text	00441C80	0000006F	00000030	00000008	R	.	.	.	.	.	.
rdMatrix_PostScale44	.text	00441CF0	00000077	00000040	00000008	R	.	.	.	.	.	.
rdMatrix_SetRowVector34_0	.text	00441D70	00000023	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_SetRowVector44_0	.text	00441DA0	00000028	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_GetRowVector34_0	.text	00441DD0	00000023	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_GetRowVector44_0	.text	00441E00	00000022	00000000	0000000C	R	.	.	.	.	.	.
*/
#define rdMatrix_TransformVector34_ADDR (0x00441E30)
#define rdMatrix_TransformVector34Acc_ADDR (0x00441F10)
//rdMatrix_TransformVector34Acc_0	.text	00441EA0

/*
rdMatrix_TransformVector44	.text	00441FB0	000000B3	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_TransformVector44Acc	.text	00442070	000000D7	00000010	00000008	R	.	.	.	.	.	.
rdMatrix_TransformPoint34	.text	00442150	00000074	00000000	0000000C	R	.	.	.	.	T	.
rdMatrix_TransformPoint34Acc	.text	004421D0	000000A0	00000014	00000008	R	.	.	.	.	.	.
rdMatrix_TransformPoint44	.text	00442270	0000009D	00000000	0000000C	R	.	.	.	.	.	.
rdMatrix_TransformPoint44Acc	.text	00442310	000000BF	00000010	00000008	R	.	.	.	.	.	.
rdMatrix_TransformPointLst34	.text	004423D0	0000009D	00000000	00000010	R	.	.	.	.	.	.
rdMatrix_TransformPointLst44	.text	00442470	0000009D	00000000	00000010	R	.	.	.	.	.	.

*/

typedef struct rdMatrix33
{
    rdVector3 right;
    rdVector3 left;
    rdVector3 up;
} rdMatrix33;

typedef struct rdMatrix34
{
    rdVector3 right;
    rdVector3 left;
    rdVector3 up;
    rdVector3 scale;
} rdMatrix34;

typedef struct rdMatrix44
{
    rdVector4 idk1;
    rdVector4 idk2;
    rdVector4 idk3;
    rdVector4 idk4;
} rdMatrix44;

IMPORT_FUNC(rdMatrix_BuildRotate34, void, (rdMatrix34*, rdVector3*), rdMatrix_BuildRotate34_ADDR)
IMPORT_FUNC(rdMatrix_TransformVector34, void, (rdVector3*, rdVector3*, rdMatrix34*), rdMatrix_TransformVector34_ADDR)
IMPORT_FUNC(rdMatrix_TransformVector34Acc, void, (rdVector3*, rdMatrix34*), rdMatrix_TransformVector34Acc_ADDR)

#endif // _RDMATRIX_H
