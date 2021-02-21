#ifndef _MAIN_SMACK_H
#define _MAIN_SMACK_H

#define smack_Initialize_ADDR (0x00426710)
#define smack_Shutdown_ADDR (0x00426720)
#define smack_idk_ADDR (0x00426730)
#define smack_sub_426940_ADDR (0x00426940)
#define smack_process_ADDR (0x004269C0)
#define smack_off_ADDR (0x00426B80)

static int (*smack_Initialize)() = (void*)smack_Initialize_ADDR;

#endif // _MAIN_SMACK_H
