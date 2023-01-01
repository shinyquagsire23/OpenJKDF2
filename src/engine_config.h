#ifndef _OPENJKDF2_ENGINE_CONFIG_H
#define _OPENJKDF2_ENGINE_CONFIG_H

// If I ever do demo recording, add it here
#define NEEDS_STEPPED_PHYS (!jkPlayer_bJankyPhysics || sithNet_isMulti)

// Settings for stepped physics
#define TARGET_PHYSTICK_FPS (sithNet_isMulti ? (sithNet_tickrate < 100 ? 150.0 : 50.0) : 150.0)
#define DELTA_PHYSTICK_FPS (1.0/TARGET_PHYSTICK_FPS)

// Settings for the old stepped physics
#define OLDSTEP_TARGET_FPS (sithNet_isMulti ? (sithNet_tickrate < 100 ? 150.0 : 50.0) : 150.0)
#define OLDSTEP_DELTA_50FPS (1.0/OLDSTEP_TARGET_FPS)

// Use microsecond timing to calculate sithTime_deltaSecs/etc
#ifdef PLATFORM_POSIX
#define MICROSECOND_TIME
#endif

// Original game will speed up if framerate is over 100?
#ifndef QOL_IMPROVEMENTS
#define SITHTIME_MINDELTA (10)
#define SITHTIME_MAXDELTA (500)
#else
#define SITHTIME_MINDELTA (1)
#define SITHTIME_MAXDELTA (500)
#endif

#ifdef QOL_IMPROVEMENTS
#define MULTI_NEXTLEVEL_DELAY_MS (2000)
#define MULTI_LEAVEJOIN_DELAY_MS (1000)
#define MULTI_TIMEOUT_MS (30000)
#define MULTI_SCORE_UPDATE_INTERVAL_MS (5000)
#define MULTI_BIG_UPDATE_INTERVAL_MS (30)
#else // !QOL_IMPROVEMENTS
#define MULTI_NEXTLEVEL_DELAY_MS (10000)
#define MULTI_LEAVEJOIN_DELAY_MS (5000)
#define MULTI_TIMEOUT_MS (45000)
#define MULTI_SCORE_UPDATE_INTERVAL_MS (10000)
#define MULTI_BIG_UPDATE_INTERVAL_MS (60)
#endif

// World limits
#ifndef QOL_IMPROVEMENTS
#define SITH_MAX_THINGS (641)
#define SITH_MAX_VISIBLE_SECTORS (0x80)
#define SITH_MAX_VISIBLE_SECTORS_2 (0xA0)
#define SITH_MAX_VISIBLE_ALPHA_SURFACES (32)
#else // QOL_IMPROVEMENTS
#define SITH_MAX_THINGS (32000)
#define SITH_MAX_VISIBLE_SECTORS (1024)
#define SITH_MAX_VISIBLE_SECTORS_2 (1280)
#define SITH_MAX_VISIBLE_ALPHA_SURFACES (1024)
#endif // QOL_IMPROVEMENTS

// COG resource limits
#ifdef QOL_IMPROVEMENTS
#define SITHCOGVM_MAX_STACKSIZE (0x10000)
#define SITHCOG_SYMBOL_LIMIT (2048) // JK was 512, MoTS/DW are 1024
#define SITHCOG_LINKED_SYMBOL_LIMIT (2048)
#else // !QOL_IMPROVEMENTS
#define SITHCOGVM_MAX_STACKSIZE (64)
#define SITHCOG_SYMBOL_LIMIT (1024) // JK was 512, MoTS/DW are 1024
#define SITHCOG_LINKED_SYMBOL_LIMIT (256)
#endif // QOL_IMPROVEMENTS

#define RDCACHE_MAX_TRIS (0x400)
#define RDCACHE_MAX_VERTICES (0x8000)

#define STD3D_MAX_TEXTURES (4096)

// jkGuiMultiTally delay between maps
#define SCORE_DELAY_MS ((jkGuiNetHost_bIsDedicated && stdComm_bIsServer) ? 0 : 30000)

// UI tickrate limits
#ifdef QOL_IMPROVEMENTS
#define TICKRATE_MIN (1)
#define TICKRATE_MAX (1000)
#else
#define TICKRATE_MIN (100)
#define TICKRATE_MAX (300)
#endif

// Run game physics at a fixed timestep
#define FIXED_TIMESTEP_PHYS

// Backport MOTS RGB lighting and bone changes
#ifdef QOL_IMPROVEMENTS
#define JKM_LIGHTING
#define JKM_BONES
#define JKM_PARAMS
#define JKM_AI
#define JKM_SABER
#define JKM_DSS
#define JKM_CAMERA
#endif

// Backport Droidworks misc
#ifdef QOL_IMPROVEMENTS
#define DW_CAMERA
#endif

#ifdef JKM_DSS
#define NUM_JKPLAYER_THINGS (64)
#else
#define NUM_JKPLAYER_THINGS (16)
#endif

// Droidworks cameras
#ifdef DW_CAMERA
#define SITHCAMERA_NUMCAMERAS (8)
#else
#define SITHCAMERA_NUMCAMERAS (7)
#endif

//
// Resource configuration
//
#define JKRES_GOB_EXT (Main_bMotsCompat ? "goo" : "gob")

#define JKRES_DF2_MAGIC_0 0x69973284
#define JKRES_DF2_MAGIC_1 0x699232C4
#define JKRES_DF2_MAGIC_2 0x69923384
#define JKRES_DF2_MAGIC_3 0x69923284

#define JKRES_MOTS_MAGIC_0 0x3B426929
#define JKRES_MOTS_MAGIC_1 0x3B426929
#define JKRES_MOTS_MAGIC_2 0x3B426929
#define JKRES_MOTS_MAGIC_3 0x3B426929

#define JKRES_MAGIC_0 (Main_bMotsCompat ? JKRES_MOTS_MAGIC_0 : JKRES_DF2_MAGIC_0)
#define JKRES_MAGIC_1 (Main_bMotsCompat ? JKRES_MOTS_MAGIC_1 : JKRES_DF2_MAGIC_1)
#define JKRES_MAGIC_2 (Main_bMotsCompat ? JKRES_MOTS_MAGIC_2 : JKRES_DF2_MAGIC_2)
#define JKRES_MAGIC_3 (Main_bMotsCompat ? JKRES_MOTS_MAGIC_3 : JKRES_DF2_MAGIC_3)

#define JKRES_IS_MOTS_MAGIC(kval) ((kval == JKRES_MOTS_MAGIC_0) || (kval == JKRES_MOTS_MAGIC_1) || (kval == JKRES_MOTS_MAGIC_2) || (kval == JKRES_MOTS_MAGIC_3))
#define JKRES_IS_DF2_MAGIC(kval) ((kval == JKRES_DF2_MAGIC_0) || (kval == JKRES_DF2_MAGIC_1) || (kval == JKRES_DF2_MAGIC_2) || (kval == JKRES_DF2_MAGIC_3))

#ifndef JKM_PARAMS
#define STDCONF_LINEBUFFER_LEN (1024)
#else
#define STDCONF_LINEBUFFER_LEN (2048)
#endif

#define SITHAI_MAX_ACTORS (256)

// Disable warnings for Vegetable Studio
#if 1 && defined _MSC_VER
#pragma warning(disable: 4003) // not enough arguments for function-like macro invocation
#pragma warning(disable: 4005) // 'blahblah': macro redefinition
#pragma warning(disable: 4022) // pointer mismatch for actual parameter
#pragma warning(disable: 4024) // different types for formal and actual parameter
#pragma warning(disable: 4047) // 'blahblah *' differs in levels of indirection from 'blahblah (*)[blah]'
#pragma warning(disable: 4090) // different 'const' qualifiers
#pragma warning(disable: 4098) // 'void' function returning a value
#pragma warning(disable: 4113) // 'FARPROC' differs in parameter lists from 'blahblah'
#pragma warning(disable: 4133) // 'function': incompatible types - from 'blahblah [blah]' to 'const blah *'
#pragma warning(disable: 4190) // 'blahblah' has C-linkage specified, but returns UDT 'blahblahblahhhhh' which is incompatible with C
#pragma warning(disable: 4229) // anachronism used: modifiers on data are ignored
#pragma warning(disable: 4311) // 'type cast': pointer truncation from 'blah *' to 'blah'
#pragma warning(disable: 4312) // 'type cast': conversion from 'blah' to 'blah *' of greater size
#pragma warning(disable: 4700) // uninitialized local variable 'blahblah' used
#pragma warning(disable: 4715) // not all control paths return a value
#pragma warning(disable: 4716) // 'blahblah': must return a value
#pragma warning(disable: 5105) // macro expansion producing 'defined' has undefined behavior
#endif

#endif // _OPENJKDF2_ENGINE_CONFIG_H