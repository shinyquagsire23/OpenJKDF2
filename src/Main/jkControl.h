#ifndef _JKCONTROL_H
#define _JKCONTROL_H

#include "types.h"

#define jkControl_Startup_ADDR (0x00402860)
#define jkControl_Shutdown_ADDR (0x004028C0)
#define jkControl_nullsub_37_ADDR (0x004028D0)
#define jkControl_HandleHudKeys_ADDR (0x004028E0)

int jkControl_Startup();
int jkControl_Shutdown();
void jkControl_nullsub_37();
int jkControl_HandleHudKeys(sithThing *player, flex_t b);

#endif // _JKCONTROL_H
