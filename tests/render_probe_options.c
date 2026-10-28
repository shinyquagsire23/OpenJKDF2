#include <assert.h>
#include <stdio.h>
#include "Win95/RenderProbe.h"

int main(void)
{
    RenderProbeOptions o;
    char *normal[] = {"jk", "-autostart", "-sp"};
    assert(RenderProbe_Parse(3,normal,&o) && !o.enabled);
    char *valid[] = {"jk","-renderprobe","-autostart","-renderout","C:/Lab With Spaces/output","-renderwidth","1254","-renderheight","960","-renderframes","3","-renderbloom","1","-renderssao","1"};
    assert(RenderProbe_Parse(15,valid,&o) && o.enabled && o.width==1254 && o.height==960 && o.frames==3 && o.bloom && o.ssao);
    assert(!strcmp(o.output,"C:/Lab With Spaces/output"));
    assert(!RenderProbe_Parse(14,valid,&o));
    valid[6]="99999999999999999999999";assert(!RenderProbe_Parse(15,valid,&o));
    valid[6]="4097";assert(!RenderProbe_Parse(15,valid,&o));
    valid[6]="4096";assert(RenderProbe_Parse(15,valid,&o));
    valid[10]="2";assert(!RenderProbe_Parse(15,valid,&o));
    valid[10]="18001";assert(!RenderProbe_Parse(15,valid,&o));
    valid[10]="18000";assert(RenderProbe_Parse(15,valid,&o));
    valid[4]="C:/test/../other";assert(!RenderProbe_Parse(15,valid,&o));
    valid[4]="\\\\server\\share";assert(!RenderProbe_Parse(15,valid,&o));
    valid[4]="//server/share";assert(!RenderProbe_Parse(15,valid,&o));
    valid[4]="relative";assert(!RenderProbe_Parse(15,valid,&o));
    valid[4]="C:/good";valid[2]="-headless";assert(!RenderProbe_Parse(15,valid,&o));
    valid[2]="-sp";assert(!RenderProbe_Parse(15,valid,&o));
    valid[2]="-autostart";valid[1]="-sp";assert(!RenderProbe_Parse(15,valid,&o));
    assert(!RenderProbe_Number("-1",0,1,&o.ssao));
    assert(!RenderProbe_Number("1x",0,1,&o.ssao));
    assert(!RenderProbe_LocalPath("C:"));
    assert(!RenderProbe_LocalPath("C:/test\nfoo"));
    assert(RenderProbe_LocalPath("/tmp/test space"));
    puts("render probe argument boundaries: PASS");
    return 0;
}
