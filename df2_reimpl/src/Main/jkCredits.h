#ifndef _JKCREDITS_H
#define _JKCREDITS_H

#define jkCredits_Initialize_ADDR (0x004216C0)
#define jkCredits_Shutdown_ADDR (0x00421710)
#define jkCredits_Show_ADDR (0x00421760)
#define jkCredits_Skip_ADDR (0x00421AC0)
#define jkCredits_sub_421B50_ADDR (0x00421B50)
#define jkCredits_Handler_ADDR (0x00421F60)

#define jkCredits_table (*(stdStrTable*)0x0055AD70)
#define jkCredits_fontLarge (*(stdFont**)0x0055AD98)
#define jkCredits_fontSmall (*(stdFont**)0x0055AD9C)
#define jkCredits_bInitted (*(int*)0x0055ADA4)

void jkCredits_Initialize(char *fpath);

static void (*jkCredits_Shutdown)() = (void*)jkCredits_Shutdown_ADDR;

//static void (*jkCredits_Initialize)() = (void*)jkCredits_Initialize_ADDR;

#endif // _JKCREDITS_H
