/* Synthetic engine dependencies; production parser and startup are included below. */
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <uchar.h>
#include "Main/stdAutostartCharacter.h"
#define QOL_IMPROVEMENTS
#define JK_GAMEMODE_TITLE 1
#define SESSIONFLAG_PASSWORD 2
#define SESSIONFLAG_ISDEDICATED 4
#define _strtok strtok
#define __strcmpi strcasecmp
#define _atoi atoi
static jmp_buf jump;
static int exitCode;
static void test_exit(int code) { exitCode=code; longjmp(jump,1); }
#define exit test_exit
static char Main_strAutostartCharacter[32], Main_path[128], Main_strEpisode[129], Main_strMap[132];
static int Main_bMotsCompat, Main_bAutostartSp, Main_bAutostart, Main_bDedicatedServer, Main_bHeadless;
static int Main_bDevMode, Main_bDisplayConfig, Main_bDispStats, Main_bFrameRate, Main_bWindowGUI;
static int Main_logLevel, Main_verboseLevel, Main_bNoHUD, Main_bVerboseNetworking, Main_bEnhancedCogVerbs, Main_bDwCompat, Main_bDwCogVerbs;
static int jkSmack_stopTick, jkSmack_nextGuiState, jkGuiNetHost_bIsDedicated;
static int jkGuiNetHost_maxRank=4, jkGuiNetHost_tickRate, jkGuiNetHost_maxPlayers, jkGuiNetHost_sessionFlags, jkGuiNetHost_gameFlags, jkGuiNetHost_scoreLimit, jkGuiNetHost_timeLimit;
static int sithNet_scorelimit, sithNet_multiplayer_timelimit;
static char16_t jkPlayer_playerShortName[32];
typedef struct {char16_t name[32]; char model[32],soundClass[32],sideMat[32],tipMat[32]; int jediRank;} Mpc;
static Mpc jkGuiMultiplayer_mpcInfo;
typedef struct {char16_t serverName[32],wPassword[32]; char episodeGobName[32],mapJklFname[32]; int tickRateMs,maxPlayers,sessionFlags,multiModeFlags,maxRank,scoreLimit,timeLimit;} jkMultiEntry3;
static void noop_error(const char* s, ...) {}
static struct {void (*errorPrint)(const char*,...);} services={noop_error}, *pHS=&services;
static void Main_ShowHelp(void) {test_exit(3);}
static void stdString_SafeStrCopy(char* out,const char* in,size_t n) {snprintf(out,n,"%s",in);}
static void stdString_CharToWchar(char16_t* out,const char* in,size_t n) {size_t i;for(i=0;i<n&&in[i];i++)out[i]=(unsigned char)in[i];out[i]=0;}
static void stdString_SafeWStrCopy(char16_t* out,const char16_t* in,size_t n) {size_t i;for(i=0;i+1<n&&in[i];i++)out[i]=in[i];out[i]=0;}
static size_t _wcslen(const char16_t* s) {size_t n=0;while(s[n])n++;return n;}
#define stdPlatform_Printf(...) ((void)0)
#define stdDisplay_DrawAndFlipGdi 0
#define stdDisplay_SetCooperativeLevel 0
#define Window_SetDrawHandlers(a,b) ((void)0)
static const char* profile="";
static int initialized, parseCalls, rank=3, parseResult=1, sceneStarts, sceneEnds, staticOpens, hostCalls, confCalls;
static void wuRegistry_GetStr(const char* key,char* out,size_t n,const char* def) {stdString_SafeStrCopy(out,strcmp(key,"playerShortName")?def:profile,n);}
static void wuRegistry_GetWString(const char* k,char16_t* out,size_t n,const char16_t* def) {stdString_SafeWStrCopy(out,def,n);}
#define wuRegistry_SaveStr(a,b) ((void)0)
static void jkPlayer_CreateConf(const char16_t* name) {assert(name[0]);assert(!initialized);confCalls++;}
#define jkGuiNetHost_SaveSettings() ((void)0)
#define jkGuiNetHost_LoadSettings() ((void)0)
static int createHost(void) {
    if (Main_strAutostartCharacter[0]) {assert(initialized);assert(parseCalls==1);}
    else {assert(!initialized);assert(!parseCalls);}
    hostCalls++;
    return 0;
}
#define sithMulti_CreatePlayer(...) createHost()
#define jkStrings_GetUniStringWithFallback(s) (s)
#define jkGuiDialog_ErrorDialog(a,b) ((void)0)
static void std3D_StartScene(void) {sceneStarts++;}
#define std3D_EndScene() (++sceneEnds)
#define sithOpenStatic(s) (++staticOpens)
static void jkHudInv_InitItems(void) {assert(sceneStarts==1 && sceneEnds==1 && staticOpens==1);assert(!initialized);initialized=1;}
static int jkPlayer_MPCParse(Mpc* info,void* unused,char16_t* profileName,char16_t* character,int bins) {
    assert(initialized);assert(!hostCalls);assert(info==&jkGuiMultiplayer_mpcInfo);assert(profileName==jkPlayer_playerShortName);assert(bins==1);
    assert(character[0]=='P');parseCalls++;info->jediRank=rank;strcpy(info->model,"selected.3do");return parseResult;
}
static int jkMain_loadFile2(const char* ep,const char* map) {assert(initialized);return 1;}
#define jkMain_LoadLevelSingleplayer(a,b) 1
#include "production.inc"
static void reset(void) {Main_strAutostartCharacter[0]=0;Main_bAutostart=Main_bAutostartSp=0;Main_strEpisode[0]=Main_strMap[0]=0;initialized=parseCalls=sceneStarts=sceneEnds=staticOpens=hostCalls=confCalls=exitCode=0;rank=3;parseResult=1;profile="";}
static void parse(const char* text,int expected) {char line[256];strcpy(line,text);if(!setjmp(jump))Main_ParseCmdLine(line);assert(exitCode==expected);}
static void startup(int dedicated,int expected) {if(!setjmp(jump))assert(Main_StartupDedicated(dedicated)==1);assert(exitCode==expected);assert(hostCalls==((expected || Main_bAutostartSp) ? 0 : 1));assert(sceneStarts==1 && sceneEnds==1 && staticOpens==1);}
int main(void) {
    assert(stdAutostart_CharacterNameValid("ABCDEFGHIJKLMNOPQRSTUVWXYZ_12-3"));
    assert(!stdAutostart_CharacterNameValid("ABCDEFGHIJKLMNOPQRSTUVWXYZ_12-34"));
    assert(!stdAutostart_CharacterNameValid(NULL));assert(!stdAutostart_CharacterNameValid(""));
    assert(!stdAutostart_CharacterNameValid("a/b"));assert(!stdAutostart_CharacterNameValid("a.b"));assert(!stdAutostart_CharacterNameValid("\xc3\xa9"));
    reset();parse("-autostart -character Pilot_2",0);startup(0,0);assert(parseCalls==1);assert(!strcmp(jkGuiMultiplayer_mpcInfo.model,"selected.3do"));assert(jkPlayer_playerShortName[0]=='S');
    reset();profile="Existing";parse("-autostart",0);startup(0,0);assert(!parseCalls);assert(jkPlayer_playerShortName[0]=='E');
    reset();startup(1,0);assert(jkPlayer_playerShortName[0]=='S');
    reset();parse("-autostart -sp",0);startup(0,0);assert(!parseCalls && !hostCalls);
    reset();parse("-autostart -character Pilot -character Pilot",6);
    reset();parse("-autostart -character",6);
    reset();parse("-character Pilot",6);
    reset();parse("-autostart -sp -character Pilot",6);
    reset();parse("-dedicatedServer -character Pilot",6);
    reset();parse("-character Pilot -autostart",0);rank=5;startup(0,6);
    reset();parse("-autostart -character Pilot",0);rank=-1;startup(0,6);
    reset();parse("-autostart -character Pilot",0);parseResult=0;startup(0,6);
    reset();parse("-autostart -character Pilot",0);rank=4;startup(0,0);
    puts("PASS: production autostart parse, selection, rank, inventory order, profile fallback, host side-effect gating");
    return 0;
}
