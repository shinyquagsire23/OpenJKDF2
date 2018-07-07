#ifndef ADVAPI32_H
#define ADVAPI32_H

#include <QObject>
#include <unicorn/unicorn.h>

class AdvApi32 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE AdvApi32() {}
    
    Q_INVOKABLE uint32_t RegCreateKeyExA(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i);
    
    Q_INVOKABLE uint32_t RegOpenKeyExA(uint32_t a, uint32_t subkey_ptr, uint32_t c, uint32_t d, uint32_t e);
    Q_INVOKABLE uint32_t RegQueryValueExA(uint32_t a, uint32_t valuename_ptr, uint32_t c, uint32_t d, uint32_t e, uint32_t f);
    Q_INVOKABLE uint32_t RegCloseKey(uint32_t hnd);

//    Q_INVOKABLE uint32_t ();
};

#endif // ADVAPI32_H
