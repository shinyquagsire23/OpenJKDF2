#ifndef _RDVECTOR_H
#define _RDVECTOR_H

//#define _ADDR (0x)

#define rdVector_Set2_ADDR    (0x00449280)
#define rdVector_Set3_ADDR    (0x004492A0)
#define rdVector_Set4_ADDR    (0x004492C0)
#define rdVector_Copy2_ADDR   (0x004492E0)
#define rdVector_Copy3_ADDR   (0x00449300)
#define rdVector_Copy4_ADDR   (0x00449320)
#define rdVector_Neg2_ADDR    (0x00449340)
#define rdVector_Neg3_ADDR    (0x00449360)
#define rdVector_Neg4_ADDR    (0x00449380)
#define rdVector_Neg2Acc_ADDR (0x004493B0)
#define rdVector_Neg3Acc_ADDR (0x004493D0)
#define rdVector_Neg4Acc_ADDR (0x004493F0)
#define rdVector_Add2_ADDR    (0x00449420)
#define rdVector_Add3_ADDR    (0x00449450)
#define rdVector_Add4_ADDR    (0x00449480)
#define rdVector_Add2Acc_ADDR (0x004494C0)
#define rdVector_Add3Acc_ADDR (0x004494E0)
#define rdVector_Add4Acc_ADDR (0x00449510)
#define rdVector_Sub2_ADDR (0x00449550)
#define rdVector_Sub3_ADDR (0x00449570)
#define rdVector_Sub4_ADDR (0x004495A0)
#define rdVector_Sub2Acc_ADDR (0x004495E0)
#define rdVector_Sub3Acc_ADDR (0x00449600)
#define rdVector_Sub4Acc_ADDR (0x00449630)
#define rdVector_Dot2_ADDR (0x00449660)
#define rdVector_Dot3_ADDR (0x00449680)
#define rdVector_Dot4_ADDR (0x004496B0)
#define rdVector_Cross3_ADDR (0x004496F0)
#define rdVector_Cross3Acc_ADDR (0x00449740)
#define rdVector_Len2_ADDR (0x004497B0)
#define rdVector_Len3_ADDR (0x004497D0)
#define rdVector_Len4_ADDR (0x00449810)
#define rdVector_Normalize2_ADDR (0x00449860)
#define rdVector_Normalize3_ADDR (0x004498B0)
#define rdVector_Normalize3Quick_ADDR (0x00449930)
#define rdVector_Normalize4_ADDR (0x00449AB7)
#define rdVector_Normalize2Acc_ADDR (0x00449B57)
#define rdVector_Normalize3Acc_ADDR (0x00449B97)
#define rdVector_Normalize3QuickAcc_ADDR (0x00449C07)
#define rdVector_Normalize4Acc_ADDR (0x00449D8E)
#define rdVector_Scale2_ADDR (0x00449E1E)
#define rdVector_Scale3_ADDR (0x00449E3E)
#define rdVector_Scale4_ADDR (0x00449E6E)
#define rdVector_Scale2Acc_ADDR (0x00449EAE)
#define rdVector_Scale3Acc_ADDR (0x00449ECE)
#define rdVector_Scale4Acc_ADDR (0x00449EFE)
#define rdVector_InvScale2_ADDR (0x00449F3E)
#define rdVector_InvScale3_ADDR (0x00449F5E)
#define rdVector_InvScale4_ADDR (0x00449F9E)
#define rdVector_InvScale2Acc_ADDR (0x00449FDE)
#define rdVector_InvScale3Acc_ADDR (0x00449FFE)
#define rdVector_InvScale4Acc_ADDR (0x0044A02E)
#define rdVector_Rotate3_ADDR (0x0044A06E)
#define rdVector_Rotate3Acc_ADDR (0x0044A09E)
#define rdVector_ExtractAngle_ADDR (0x0044A0CE)

typedef struct rdVector2i
{
    int x;
    int y;
} rdVector2i;

typedef struct rdVector3i
{
    int x;
    int y;
    int z;
} rdVector3i;

typedef struct rdVector2
{
    float x;
    float y;
} rdVector2;

typedef struct rdVector3
{
    float x;
    float y;
    float z;
} rdVector3;

typedef struct rdVector4
{
    float x;
    float y;
    float z;
    float w;
} rdVector4;

extern const rdVector3 rdroid_zeroVector3;
extern const rdVector3 rdroid_xVector3;
extern const rdVector3 rdroid_yVector3;
extern const rdVector3 rdroid_zVector3;

rdVector2* rdVector_Set2(rdVector2* v, float x, float y);
rdVector3* rdVector_Set3(rdVector3* v, float x, float y, float z);
rdVector4* rdVector_Set4(rdVector4* v, float x, float y, float z, float w);
void rdVector_Copy2(rdVector2* v1, const rdVector2* v2);
void rdVector_Copy3(rdVector3* v1, const rdVector3* v2);
void rdVector_Copy4(rdVector4* v1, const rdVector4* v2);
rdVector2* rdVector_Neg2(rdVector2* v1, const rdVector2* v2);
rdVector3* rdVector_Neg3(rdVector3* v1, const rdVector3* v2);
rdVector4* rdVector_Neg4(rdVector4* v1, const rdVector4* v2);
rdVector2* rdVector_Neg2Acc(rdVector2* v1);
rdVector3* rdVector_Neg3Acc(rdVector3* v1);
rdVector4* rdVector_Neg4Acc(rdVector4* v1);
rdVector2* rdVector_Add2(rdVector2* v1, const rdVector2* v2, const rdVector2* v3);
rdVector3* rdVector_Add3(rdVector3* v1, const rdVector3* v2, const rdVector3* v3);
rdVector4* rdVector_Add4(rdVector4* v1, const rdVector4* v2, const rdVector4* v3);
rdVector2* rdVector_Add2Acc(rdVector2* v1, const rdVector2* v2);
rdVector3* rdVector_Add3Acc(rdVector3* v1, const rdVector3* v2);
rdVector4* rdVector_Add4Acc(rdVector4* v1, const rdVector4* v2);
rdVector2* rdVector_Sub2(rdVector2* v1, const rdVector2* v2, const rdVector2* v3);
rdVector3* rdVector_Sub3(rdVector3* v1, const rdVector3* v2, const rdVector3* v3);
rdVector4* rdVector_Sub4(rdVector4* v1, const rdVector4* v2, const rdVector4* v3);
rdVector2* rdVector_Sub2Acc(rdVector2* v1, const rdVector2* v2);
rdVector3* rdVector_Sub3Acc(rdVector3* v1, const rdVector3* v2);
rdVector4* rdVector_Sub4Acc(rdVector4* v1, const rdVector4* v2);
float rdVector_Dot2(const rdVector2* v1, const rdVector2* v2);
float rdVector_Dot3(const rdVector3* v1, const rdVector3* v2);
float rdVector_Dot4(const rdVector4* v1, const rdVector4* v2);
void rdVector_Cross3(rdVector3 *v1, const rdVector3 *v2, const rdVector3 *v3);
void rdVector_Cross3Acc(rdVector3 *v1, const rdVector3 *v2);
float rdVector_Len2(const rdVector2* v);
float rdVector_Len3(const rdVector3* v);
float rdVector_Len4(const rdVector4* v);
float rdVector_Normalize2(rdVector2 *v1, const rdVector2 *v2);
float rdVector_Normalize3(rdVector3 *v1, const rdVector3 *v2);
float rdVector_Normalize3Quick(rdVector3 *v1, const rdVector3 *v2);
float rdVector_Normalize4(rdVector4 *v1, const rdVector4 *v2);
float rdVector_Normalize2Acc(rdVector2 *v1);
float rdVector_Normalize3Acc(rdVector3 *v1);
float rdVector_Normalize3QuickAcc(rdVector3 *v1);
float rdVector_Normalize4Acc(rdVector4 *v1);
rdVector2* rdVector_Scale2(rdVector2 *v1, const rdVector2 *v2, float scale);
rdVector3* rdVector_Scale3(rdVector3 *v1, const rdVector3 *v2, float scale);
rdVector4* rdVector_Scale4(rdVector4 *v1, const rdVector4 *v2, float scale);
rdVector2* rdVector_Scale2Acc(rdVector2 *v1, float scale);
rdVector3* rdVector_Scale3Acc(rdVector3 *v1, float scale);
rdVector4* rdVector_Scale4Acc(rdVector4 *v1, float scale);
rdVector2* rdVector_InvScale2(rdVector2 *v1, const rdVector2 *v2, float scale);
rdVector3* rdVector_InvScale3(rdVector3 *v1, const rdVector3 *v2, float scale);
rdVector4* rdVector_InvScale4(rdVector4 *v1, const rdVector4 *v2, float scale);
rdVector2* rdVector_InvScale2Acc(rdVector2 *v1, float scale);
rdVector3* rdVector_InvScale3Acc(rdVector3 *v1, float scale);
rdVector4* rdVector_InvScale4Acc(rdVector4 *v1, float scale);
void rdVector_Rotate3(rdVector3 *out, const rdVector3 *in, const rdVector3 *vAngs);
void rdVector_Rotate3Acc(rdVector3 *out, const rdVector3 *vAngs);
void rdVector_ExtractAngle(const rdVector3 *v1, rdVector3 *out);

// Added
float rdVector_Dist3(const rdVector3 *v1, const rdVector3 *v2);
rdVector3* rdVector_MultAcc3(rdVector3 *v1, const rdVector3 *v2, float scale);
void rdVector_Zero3(rdVector3 *v);
int rdVector_IsZero3(rdVector3* v);
float rdVector_NormalDot(const rdVector3* v1, const rdVector3* v2, const rdVector3* norm);
void rdVector_AbsRound3(rdVector3* v);
void rdVector_ClipPrecision3(rdVector3* v);
void rdVector_ClampRange3(rdVector3* v, float minVal, float maxVal);
void rdVector_ClampValue3(rdVector3* v, float val);

#endif // _RDVECTOR_H
