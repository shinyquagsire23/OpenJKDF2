#ifndef NMM_H
#define NMM_H

#include <QObject>
#include <unicorn/unicorn.h>

class Nmm : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE Nmm() {}
    
    Q_INVOKABLE uint32_t mciSendCommandA(uint32_t IDDevice, uint32_t uMsg, uint32_t fdwCommand, uint32_t dwParam)
    {
        return 0;
    }
    
    Q_INVOKABLE uint32_t auxGetNumDevs(void)
    {
        return 0;
    }
    
    Q_INVOKABLE uint32_t joyGetNumDevs(void)
    {
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

#endif // NMM_H
