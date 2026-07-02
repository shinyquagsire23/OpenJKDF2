// Dreamcast CPU fault reporter -- draws PC/PR/faulting-address into the displayed
// framebuffer (with a border-blink fallback) when the SH4 takes an exception.
// See dcFault.c for the full story.

#ifndef DC_FAULT_H
#define DC_FAULT_H

#ifdef TARGET_DREAMCAST

// Register the fault handlers. Call once, early (any time after KOS init).
void dcFault_Install(void);

#endif // TARGET_DREAMCAST

#endif // DC_FAULT_H
