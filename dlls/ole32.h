#ifndef OLE32_H
#define OLE32_H

#include <QObject>
#include <unicorn/unicorn.h>

class Ole32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:

    Q_INVOKABLE Ole32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t CoInitialize(uint32_t a);
    Q_INVOKABLE uint32_t CoCreateInstance(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);

//    Q_INVOKABLE uint32_t ();
};

#endif // OLE32_H
