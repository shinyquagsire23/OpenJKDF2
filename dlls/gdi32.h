#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>

#define BITSPIXEL 12

class Gdi32 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE Gdi32() {}
    
    Q_INVOKABLE uint32_t GetStockObject(uint32_t a);
    Q_INVOKABLE uint32_t GetDeviceCaps(uint32_t device, uint32_t index);

//    Q_INVOKABLE uint32_t ();
};

#endif // GDI32_H
