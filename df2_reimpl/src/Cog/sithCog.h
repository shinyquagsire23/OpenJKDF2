#ifndef COG_H
#define COG_H

#define cog_register_jk_verbs_ADDR (0x40A110)
#define cog_jk_init_ADDR (0x40A0C0)
#define cog_init_ADDR    (0x4DE070)
#define cog_math_verbs_init_ADDR (0x00505400)
#define cog_thing_verbs_init_ADDR (0x005014E0)
#define cog_ai_verbs_init_ADDR (0x00500B00)
#define cog_noise_verbs_init_ADDR (0x004FF060)
#define cog_player_verbs_init_ADDR (0x004E0780)
#define cog_sector_verbs_init_ADDR (0x004FE680)
#define cog_surface_verbs_init_ADDR (0x004FFB50)

#define sithCogYACC_yyparse_ADDR (0x50BF50)

void cog_register_jk_verbs();
int cog_jk_init();
int cog_init();

void cog_math_verbs_init(void* a1);
void cog_thing_verbs_init(void* a1);
void cog_ai_verbs_init(void* a1);
void cog_noise_verbs_init(void* a1);
void cog_player_verbs_init(void* a1);
void cog_sector_verbs_init(void* a1);
void cog_surface_verbs_init(void* a1);

#endif // COG_H
