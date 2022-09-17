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

// Run game physics at a fixed timestep
#define FIXED_TIMESTEP_PHYS

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