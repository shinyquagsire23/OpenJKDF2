#ifndef _MAIN_SMACK_H
#define _MAIN_SMACK_H

#define smack_Startup_ADDR (0x00426710)
#define smack_Shutdown_ADDR (0x00426720)
#define smack_idk_ADDR (0x00426730) // MOTS altered
#define smack_sub_426940_ADDR (0x00426940)
#define smack_process_ADDR (0x004269C0)
#define smack_off_ADDR (0x00426B80)

//static int (*smack_Startup)() = (void*)smack_Startup_ADDR;
//static void (*smack_Shutdown)() = (void*)smack_Shutdown_ADDR;

//static int (*smack_process)(void) = (void*)smack_process_ADDR;
//static int (*smack_off)(int) = (void*)smack_off_ADDR;
//static void (*smack_sub_426940)() = (void*)smack_sub_426940_ADDR;

#endif // _MAIN_SMACK_H
