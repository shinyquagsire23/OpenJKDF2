#include "sithAI.h"

#include "jk.h"
#include "World/sithThing.h"
#include "AI/sithAICmd.h"
#include "General/stdHashTable.h"

int sithAI_Startup()
{
    int v0; // ebx
    int v1; // edx
    int *v2; // ebp
    sithActor *v3; // esi
    int v4; // eax
    sithActor *v5; // ecx

    if ( sithAI_bInit )
        return 0;

    sithAI_commandList = (sithAICommand *)pSithHS->alloc(sizeof(sithAICommand) * 32);
    if ( sithAI_commandList )
    {
        sithAI_commandsHashmap = stdHashTable_New(64);
        if ( !sithAI_commandsHashmap )
            pSithHS->free(sithAI_commandList);
    }

    sithAICmd_Startup();

    v0 = sithAI_inittedActors;
    _memset(sithAI_actors, 0, sizeof(sithActor) * 256);

    v1 = 255;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[255];
    sithAI_maxActors = 256;

    do
    {
        memset(v3, 0, sizeof(sithActor));
        if ( v1 == v0 )
        {
            v4 = v1 - 1;
            if ( v1 - 1 >= 0 )
            {
                v5 = &sithAI_actors[v4];
                do
                {
                    if ( v5->thing )
                        break;
                    --v4;
                    --v5;
                }
                while ( v4 >= 0 );
            }
            v0 = v4;
            sithAI_inittedActors = v4;
        }
        *v2++ = v1;
        v3--;
        --v1;
    }
    while ( (int)v3 >= (int)sithAI_actors );

    sithAI_bInit = 1;
    return 1;
}

int sithAI_Open()
{
    if (!sithAI_bInit)
        return 0;

    if (sithAI_bOpened)
        return 0;

    sithAI_bOpened = 1;
    return 1;
}

void sithAI_RegisterCommand(char *cmdName, void *func, int param1, int param2, int param3)
{
    if ( sithAI_numCommands >= 0x20 )
        return;

    sithAICommand* aiCmd = &sithAI_commandList[sithAI_numCommands];

    _strncpy(aiCmd->name, cmdName, 0x1Fu);
    aiCmd->name[31] = 0;
    
    aiCmd->func = func;
    aiCmd->param1 = param1;
    aiCmd->param2 = param2;
    aiCmd->param3 = param3;
    sithAI_numCommands++;
}

sithAICommand* sithAI_FindCommand(const char *cmdName)
{
    if ( !sithAI_numCommands )
        return NULL;

    for (uint32_t i = 0; i < sithAI_numCommands; i++)
    {
        if (!_strcmp(cmdName, sithAI_commandList[i].name))
            return &sithAI_commandList[i];
    }

    return NULL;
}
