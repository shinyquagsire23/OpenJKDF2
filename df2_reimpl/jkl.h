#ifndef JKL_H
#define JKL_H

#include "types.h"

#define jkl_find_section_parser_ADDR (0x004D0E20)
#define jkl_set_section_parser_ADDR (0x004D0820)
#define jkl_init_parsers_ADDR (0x004CF6F0)

#define jkl_num_parsers (*(uint32_t*)0x8339D4)
#define some_integer_2 (*(uint32_t*)0x8339D8)
#define jkl_section_parsers ((sith_map_section_and_func*)0x833548)

typedef struct sith_jkl
{
    uint32_t a;
} sith_jkl;

typedef struct sith_map_section_and_func
{
    char section_name[32];
    int (*funcptr)(sith_jkl* ctx, int b);
} sith_map_section_and_func;

int jkl_find_section_parser(char *a1);
int jkl_set_section_parser(char *section_name, int (*funcptr)(sith_jkl *, int));
int jkl_init_parsers();

#endif // JKL_H
