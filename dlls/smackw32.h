#ifndef SMACKW32_H
#define SMACKW32_H

#include <QObject>
#include <unicorn/unicorn.h>

class SmackW32 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE SmackW32() {}
    
    Q_INVOKABLE void SmackSoundUseDirectSound(void* lpDSound);
    Q_INVOKABLE void SmackNextFrame(void *smackInst);
    Q_INVOKABLE void SmackClose(void *smackInst);
    Q_INVOKABLE uint32_t SmackOpen(char* fname, uint32_t b, uint32_t c);
    Q_INVOKABLE void SmackGetTrackData(void *smackInst, uint32_t a, uint32_t b);
    Q_INVOKABLE void SmackDoFrame(void *smackInst);
    Q_INVOKABLE void SmackToBuffer(void *smackInst, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f);
    Q_INVOKABLE uint32_t SmackWait(void *smackInst);
    Q_INVOKABLE void SmackSoundOnOff(void *smackInst, bool on);

//    Q_INVOKABLE uint32_t ();
};

#endif // SMACKW32_H
