#ifndef _UTIL_H
#define _UTIL_H

#define util_FileExists_ADDR (0x0042F520)
#define util_files_exists_ADDR (0x0042F550)
#define util_unkcomparison1_ADDR (0x0042F700)
#define util_unkcomparison2_ADDR (0x0042F750)
#define util_unkcomparison3_ADDR (0x0042F7A0)
#define util_Weirdchecksum_ADDR (0x0042F810)

static int (*util_FileExists)(char *fpath) = (void*)util_FileExists_ADDR;

#endif // _UTIL_H
