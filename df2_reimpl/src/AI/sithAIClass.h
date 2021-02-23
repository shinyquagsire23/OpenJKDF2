#ifndef _SITHAICLASS_H
#define _SITHAICLASS_H

#define sithAIClass_Startup_ADDR (0x004F11F0)
#define sithAIClass_Shutdown_ADDR (0x004F1210)
#define sithAIClass_ParseSection_ADDR (0x004F1230)
#define sithAIClass_New_ADDR (0x004F13A0)
#define sithAIClass_Free_ADDR (0x004F1410)
#define sithAIClass_Load_ADDR (0x004F14A0)
#define sithAIClass_LoadEntry_ADDR (0x004F15C0)

typedef struct sithAIClass
{
    uint8_t unk[0x94c];
} sithAIClass;

static int (*sithAIClass_ParseSection)(sithWorld *world, int a2) = (void*)sithAIClass_ParseSection_ADDR;
static sithAIClass* (*sithAIClass_Load)(char *a1) = (void*)sithAIClass_Load_ADDR;

#endif // _SITHAICLASS_H
