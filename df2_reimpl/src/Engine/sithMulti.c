#include "sithMulti.h"

void sithMulti_SetHandleridk(sithMultiHandler_t a1)
{
    sithMulti_handlerIdk = a1;
}

#ifdef LINUX
int sithMulti_SendChat(char *a1, int a2, int a3)
{
    return 1;
}
#endif
