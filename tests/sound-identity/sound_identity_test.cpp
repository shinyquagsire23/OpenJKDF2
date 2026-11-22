#include <cstdio>
#include <cstdint>
#include <initializer_list>
#include <cstdlib>
#include <cstring>
struct sithSound { const char *name; } intended={"fire.wav"}, wrong={"wrong.wav"}, staticSound={"static.wav"};
struct SithMessage { struct { unsigned int msg_size; } netMsg; uint32_t pktData[32]; };
static int indexCalls,loadCalls;
static sithSound *sithSound_GetFromIdx(int index) { ++indexCalls; return index==0x8001?&staticSound:&wrong; }
static sithSound *sithSound_Load(char *name,int) { ++loadCalls; return !strcmp(name,"fire.wav")?&intended:nullptr; }
#include "../../src/Dss/sithDSSSoundIdentity.h"
#define CHECK(x) do { if(!(x)){fprintf(stderr,"Failed line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
int main() {
    // Global, attached, positional, weapon fire and MoTS weapon fire layouts.
    for(unsigned size:{18u,22u,30u,48u,52u}) {
        SithMessage m={};m.netMsg.msg_size=size+32;
        strcpy((char*)(unsigned char*)m.pktData+size,"fire.wav");
        indexCalls=0;
        CHECK(sithDSSSound_Resolve(&m,size,7)==&intended);
        CHECK(indexCalls==0); // Slot 7 is a different sound on this peer.
        strcpy((char*)(unsigned char*)m.pktData+size,"missing.wav");
        CHECK(!sithDSSSound_Resolve(&m,size,7));CHECK(indexCalls==0);
        ((unsigned char*)m.pktData)[size]=0;CHECK(!sithDSSSound_Resolve(&m,size,0xffff));
        memset((unsigned char*)m.pktData+size,'x',32);CHECK(!sithDSSSound_Resolve(&m,size,7));
        strcpy((char*)(unsigned char*)m.pktData+size,"../fire.wav");loadCalls=0;
        CHECK(!sithDSSSound_Resolve(&m,size,7));CHECK(loadCalls==0);
        for(unsigned n=0;n<32;n++){m.netMsg.msg_size=size+n;if(n)CHECK(!sithDSSSound_Resolve(&m,size,7));}
        m.netMsg.msg_size=size;
        CHECK(sithDSSSound_Resolve(&m,size,0x8001)==&staticSound);
        CHECK(!sithDSSSound_Resolve(&m,size,0xffff));
        CHECK(sithDSSSound_Resolve(&m,size,7)==&wrong); // Legacy packet compatibility.
    }
    puts("PASS: sound identity survives different load order; missing/malformed names never use unrelated indices; legacy/static/silent sounds supported");
}
