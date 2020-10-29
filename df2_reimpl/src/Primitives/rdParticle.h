#ifndef _RDPARTICLE_H
#define _RDPARTICLE_H

#define rdParticle_Startup_ADDR (0x0046BF70)
#define rdParticle_New_ADDR (0x0046BF80)
#define rdParticle_NewEntry_ADDR (0x0046BFC0)
#define rdParticle_Clone_ADDR (0x0046C090)
#define rdParticle_Free_ADDR (0x0046C110)
#define rdParticle_FreeEntry_ADDR (0x0046C160)
#define rdParticle_Load_ADDR (0x0046C1A0)
#define rdParticle_LoadEntry_ADDR (0x0046C230)
#define rdParticle_Write_ADDR (0x0046C540)
#define rdParticle_Draw_ADDR (0x0046C750)

typedef struct rdThing rdThing;

typedef struct rdParticle
{
} rdParticle;

static void (*rdParticle_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdParticle_Draw_ADDR;

#endif // _RDPARTICLE_H
