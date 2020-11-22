#ifndef _JKGUIOBJECTIVES_H
#define _JKGUIOBJECTIVES_H

#define jkGuiObjectives_sub_417B00_ADDR (0x00417B00)
#define jkGuiObjectives_Show_ADDR (0x00417CE0)
#define jkGuiObjectives_Initialize_ADDR (0x00417E00)
#define jkGuiObjectives_Shutdown_ADDR (0x00417E20)

static int (*jkGuiObjectives_Show)() = (void*)jkGuiObjectives_Show_ADDR;
static void (*jkGuiObjectives_Initialize)() = (void*)jkGuiObjectives_Initialize_ADDR;
static void (*jkGuiObjectives_Shutdown)() = (void*)jkGuiObjectives_Shutdown_ADDR;

#endif // _JKGUIOBJECTIVES_H
