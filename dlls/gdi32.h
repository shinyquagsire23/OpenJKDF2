#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>

class Gdi32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:

    Q_INVOKABLE Gdi32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t GetStockObject(uint32_t a);

//    Q_INVOKABLE uint32_t ();
};

#endif // GDI32_H
