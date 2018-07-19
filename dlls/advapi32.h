#ifndef ADVAPI32_H
#define ADVAPI32_H

#include <QObject>
#include <unicorn/unicorn.h>

class AdvApi32 : public QObject
{
Q_OBJECT

private:
    uint32_t hKeyCnt;

public:

    Q_INVOKABLE AdvApi32() : hKeyCnt(1) {}
    
    Q_INVOKABLE uint32_t RegCreateKeyExA(uint32_t a, char* subkey, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i);
    
    Q_INVOKABLE uint32_t RegOpenKeyExA(uint32_t keyHnd, char* subkey, uint32_t c, uint32_t d, uint32_t* phkResult);
    Q_INVOKABLE uint32_t RegQueryValueExA(uint32_t keyHnd, char* valuename, uint32_t c, uint32_t d, void* lpData, uint32_t* lpcbData);
    Q_INVOKABLE uint32_t RegCloseKey(uint32_t hnd);

//    Q_INVOKABLE uint32_t ();
};

extern AdvApi32 *advapi32;

#endif // ADVAPI32_H
