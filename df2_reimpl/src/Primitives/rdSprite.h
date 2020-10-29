#ifndef _RDSPRITE_H
#define _RDSPRITE_H

#define rdSprite_New_ADDR (0x0046C9C0)
#define rdSprite_NewEntry_ADDR (0x0046CA20)
#define rdSprite_Free_ADDR (0x0046CC20)
#define rdSprite_FreeEntry_ADDR (0x0046CC90)
#define rdSprite_Draw_ADDR (0x0046CCF0)

typedef struct rdThing rdThing;
typedef struct rdSprite
{
    
} rdSprite;

static void (*rdSprite_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdSprite_Draw_ADDR;

#endif // _RDSPRITE_H
