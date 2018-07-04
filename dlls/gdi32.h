#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>

#define BITSPIXEL 12

class Gdi32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:

    Q_INVOKABLE Gdi32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t GetStockObject(uint32_t a);
    Q_INVOKABLE uint32_t GetDeviceCaps(uint32_t device, uint32_t index);

//    Q_INVOKABLE uint32_t ();
};

#endif // GDI32_H
