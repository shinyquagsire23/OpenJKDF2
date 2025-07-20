#ifndef _RDMATRIX_H
#define _RDMATRIX_H

#include "types.h"
#include "rdVector.h"
#include "hook.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rdMatrix_Build34_ADDR (0x0043F6F0)
#define rdMatrix_BuildFromLook34_ADDR (0x0043F820)
#define rdMatrix_BuildCamera34_ADDR (0x0043F990)
#define rdMatrix_InvertOrtho34_ADDR (0x0043FAE0)
#define rdMatrix_Build44_ADDR (0x0043FBB0)
#define rdMatrix_BuildRotate34_ADDR (0x0043FCF0)
#define rdMatrix_BuildInverseRotate34_ADDR (0x0043FE10)
#define rdMatrix_BuildRotate44_ADDR (0x0043FF30)
#define rdMatrix_BuildTranslate34_ADDR (0x00440070)
#define rdMatrix_BuildTranslate44_ADDR (0x004400A0)
#define rdMatrix_BuildScale34_ADDR (0x004400E0)
#define rdMatrix_BuildScale44_ADDR (0x00440120)
#define rdMatrix_BuildFromVectorAngle34_ADDR (0x00440170)
#define rdMatrix_LookAt_ADDR (0x00440390)
#define rdMatrix_ExtractAngles34_ADDR (0x004406B0)
#define rdMatrix_Normalize34_ADDR (0x004408E0)
#define rdMatrix_Identity34_ADDR (0x00440990)
#define rdMatrix_Identity44_ADDR (0x004409B0)
#define rdMatrix_Copy34_ADDR (0x004409D0)
#define rdMatrix_Copy44_ADDR (0x004409F0)
#define rdMatrix_Copy34to44_ADDR (0x00440A10)
#define rdMatrix_Copy44to34_ADDR (0x00440A80)
#define rdMatrix_Transpose44_ADDR (0x00440AD0)
#define rdMatrix_Multiply34_ADDR (0x00440B60)
#define rdMatrix_Multiply44_ADDR (0x00440D20)
#define rdMatrix_PreMultiply34_ADDR (0x00441020)
#define rdMatrix_PreMultiply44_ADDR (0x004411F0)
#define rdMatrix_PostMultiply34_ADDR (0x004414F0)
#define rdMatrix_PostMultiply44_ADDR (0x004416D0)
#define rdMatrix_PreRotate34_ADDR (0x004419D0)
#define rdMatrix_PreRotate44_ADDR (0x00441A00)
#define rdMatrix_PostRotate34_ADDR (0x00441A30)
#define rdMatrix_PostRotate44_ADDR (0x00441A60)
#define rdMatrix_PreTranslate34_ADDR (0x00441A90)
#define rdMatrix_PreTranslate44_ADDR (0x00441AE0)
#define rdMatrix_PostTranslate34_ADDR (0x00441B30)
#define rdMatrix_PostTranslate44_ADDR (0x00441B60)
#define rdMatrix_PreScale34_ADDR (0x00441B90)
#define rdMatrix_PreScale44_ADDR (0x00441C00)
#define rdMatrix_PostScale34_ADDR (0x00441C80)
#define rdMatrix_PostScale44_ADDR (0x00441CF0)
#define rdMatrix_SetRowVector34_ADDR (0x00441D70)
#define rdMatrix_SetRowVector44_ADDR (0x00441DA0)
#define rdMatrix_GetRowVector34_ADDR (0x00441DD0)
#define rdMatrix_GetRowVector44_ADDR (0x00441E00)
#define rdMatrix_TransformVector34_ADDR (0x00441E30)
#define rdMatrix_TransformVector34Acc_0_ADDR (0x00441EA0)
#define rdMatrix_TransformVector34Acc_ADDR (0x00441F10)
#define rdMatrix_TransformVector44_ADDR (0x00441FB0)
#define rdMatrix_TransformVector44Acc_ADDR (0x00442070)
#define rdMatrix_TransformPoint34_ADDR (0x00442150)
#define rdMatrix_TransformPoint34Acc_ADDR (0x004421D0)
#define rdMatrix_TransformPoint44_ADDR (0x00442270)
#define rdMatrix_TransformPoint44Acc_ADDR (0x00442310)
#define rdMatrix_TransformPointLst34_ADDR (0x004423D0)
#define rdMatrix_TransformPointLst44_ADDR (0x00442470)

MATH_FUNC FAST_FUNC void rdMatrix_Build34(rdMatrix34 *out, const rdVector3 *rot, const rdVector3 *pos);
MATH_FUNC FAST_FUNC void rdMatrix_BuildFromLook34(rdMatrix34 *out, const rdVector3 *lookAt);
MATH_FUNC FAST_FUNC void rdMatrix_BuildCamera34(rdMatrix34 *out, const rdVector3 *rot, const rdVector3 *pos);
MATH_FUNC FAST_FUNC void rdMatrix_InvertOrtho34(rdMatrix34 *out, const rdMatrix34 *in);
MATH_FUNC void rdMatrix_Build44(rdMatrix44 *out, const rdVector3 *rot, const rdVector3 *pos);
MATH_FUNC void rdMatrix_BuildRotate34(rdMatrix34 *out, const rdVector3 *rot);
MATH_FUNC void rdMatrix_BuildInverseRotate34(rdMatrix34 *out, const rdVector3 *rot);
MATH_FUNC void rdMatrix_BuildRotate44(rdMatrix44 *out, const rdVector3 *rot);
MATH_FUNC void rdMatrix_BuildTranslate34(rdMatrix34 *out, const rdVector3 *tV);
MATH_FUNC void rdMatrix_BuildTranslate44(rdMatrix44 *out, const rdVector3 *tV);
MATH_FUNC void rdMatrix_BuildScale34(rdMatrix34 *out, const rdVector3 *scale);
MATH_FUNC void rdMatrix_BuildScale44(rdMatrix44 *out, const rdVector3 *scale);
MATH_FUNC void rdMatrix_BuildFromVectorAngle34(rdMatrix34 *out, const rdVector3 *v, flex_t angle);
MATH_FUNC void rdMatrix_LookAt(rdMatrix34 *out, const rdVector3 *v1, const rdVector3 *v2, flex_t angle);
MATH_FUNC void rdMatrix_ExtractAngles34(const rdMatrix34 *in, rdVector3 *out);
MATH_FUNC void rdMatrix_Normalize34(rdMatrix34 *m);
MATH_FUNC void rdMatrix_Identity34(rdMatrix34 *out);
MATH_FUNC void rdMatrix_Identity44(rdMatrix44 *out);
MATH_FUNC void rdMatrix_Copy34(rdMatrix34 *dst, const rdMatrix34 *src);
MATH_FUNC void rdMatrix_Copy44(rdMatrix44 *dst, const rdMatrix44 *src);
MATH_FUNC void rdMatrix_Copy34to44(rdMatrix44 *dst, const rdMatrix34 *src);
MATH_FUNC void rdMatrix_Copy44to34(rdMatrix34 *dst, const rdMatrix44 *src);
MATH_FUNC void rdMatrix_Transpose44(rdMatrix44 *out, const rdMatrix44 *src);
MATH_FUNC FAST_FUNC void rdMatrix_Multiply34(rdMatrix34 *out, const rdMatrix34 *mat1, const rdMatrix34 *mat2);
MATH_FUNC void rdMatrix_Multiply44(rdMatrix44 *out, const rdMatrix44 *mat1, const rdMatrix44 *mat2);
MATH_FUNC FAST_FUNC void rdMatrix_PreMultiply34(rdMatrix34 *mat1, rdMatrix34 *mat2);
MATH_FUNC void rdMatrix_PreMultiply44(rdMatrix44 *mat1, rdMatrix44 *mat2);
MATH_FUNC FAST_FUNC void rdMatrix_PostMultiply34(rdMatrix34 *mat1, rdMatrix34 *mat2);
MATH_FUNC void rdMatrix_PostMultiply44(rdMatrix44 *mat1, rdMatrix44 *mat2);
MATH_FUNC void rdMatrix_PreRotate34(rdMatrix34 *out, rdVector3 *rot);
MATH_FUNC void rdMatrix_PreRotate44(rdMatrix44 *out, rdVector3 *rot);
MATH_FUNC void rdMatrix_PostRotate34(rdMatrix34 *out, rdVector3 *rot);
MATH_FUNC void rdMatrix_PostRotate44(rdMatrix44 *out, rdVector3 *rot);
MATH_FUNC void rdMatrix_PreTranslate34(rdMatrix34 *out, rdVector3 *trans);
MATH_FUNC void rdMatrix_PreTranslate44(rdMatrix44 *out, rdVector3 *tV);
MATH_FUNC void rdMatrix_PostTranslate34(rdMatrix34 *out, rdVector3 *trans);
MATH_FUNC void rdMatrix_PostTranslate44(rdMatrix44 *out, rdVector3 *tV);
MATH_FUNC void rdMatrix_PreScale34(rdMatrix34 *out, rdVector3 *scale);
MATH_FUNC void rdMatrix_PreScale44(rdMatrix44 *out, rdVector4 *scale);
MATH_FUNC void rdMatrix_PostScale34(rdMatrix34 *out, rdVector3 *scale);
MATH_FUNC void rdMatrix_PostScale44(rdMatrix44 *out, rdVector4 *scale);
MATH_FUNC void rdMatrix_SetRowVector34(rdMatrix34 *m, int row, rdVector3 *in);
MATH_FUNC void rdMatrix_SetRowVector44(rdMatrix44 *m, int row, rdVector4 *in);
MATH_FUNC void rdMatrix_GetRowVector34(rdMatrix34 *m, int row, rdVector3 *out);
MATH_FUNC void rdMatrix_GetRowVector44(rdMatrix44 *m, int row, rdVector4 *out);
MATH_FUNC FAST_FUNC void rdMatrix_TransformVector34(rdVector3 *out, const rdVector3 *v, const rdMatrix34 *m);
MATH_FUNC void rdMatrix_TransformVector34Acc_0(rdVector3 *a1, const rdVector3 *a2, const rdMatrix34 *a3);
MATH_FUNC void rdMatrix_TransformVector34Acc(rdVector3 *a1, const rdMatrix34 *a2);
MATH_FUNC void rdMatrix_TransformVector44(rdMatrix44 *a1, const rdVector4 *a2, const rdMatrix44 *a3);
MATH_FUNC void rdMatrix_TransformVector44Acc(rdVector4 *a1, const rdMatrix44 *a2);
MATH_FUNC FAST_FUNC void rdMatrix_TransformPoint34(rdVector3 *vertex_out, const rdVector3 *vertex, const rdMatrix34 *camera);
MATH_FUNC FAST_FUNC void rdMatrix_TransformPoint34Acc(rdVector3 *a1, const rdMatrix34 *a2);
MATH_FUNC void rdMatrix_TransformPoint44(rdVector4 *a1, const rdVector4 *a2, const rdMatrix44 *a3);
MATH_FUNC void rdMatrix_TransformPoint44Acc(rdVector4 *a1, const rdMatrix44 *a2);
MATH_FUNC void rdMatrix_TransformPointLst34(const rdMatrix34 *m, const rdVector3 *in, rdVector3 *out, int num);
MATH_FUNC void rdMatrix_TransformPointLst44(const rdMatrix44 *m, const rdVector4 *in, rdVector4 *out, int num);

// Added
void rdMatrix_Print34(const rdMatrix34 *viewMat);

extern const rdMatrix34 rdroid_identMatrix34;
extern const rdMatrix44 rdroid_identMatrix44;

#ifdef __cplusplus
}
#endif

//static void (*_rdMatrix_ExtractAngles34)(const rdMatrix34 *in, rdVector3 *out) = (void*)rdMatrix_ExtractAngles34_ADDR;

//IMPORT_FUNC(rdMatrix_BuildRotate34, void, (rdMatrix34*, rdVector3*), rdMatrix_BuildRotate34_ADDR)
//IMPORT_FUNC(rdMatrix_BuildRotate44, void, (rdMatrix44*, rdVector3*), rdMatrix_BuildRotate44_ADDR)
//IMPORT_FUNC(rdMatrix_TransformVector34, void, (rdVector3*, rdVector3*, rdMatrix34*), rdMatrix_TransformVector34_ADDR)
//IMPORT_FUNC(rdMatrix_TransformVector34Acc, void, (rdVector3*, rdMatrix34*), rdMatrix_TransformVector34Acc_ADDR)

#endif // _RDMATRIX_H
