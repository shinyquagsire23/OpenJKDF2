#ifndef OLE32_H
#define OLE32_H

#include <QObject>
#include <unicorn/unicorn.h>

class Ole32 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE Ole32() {}
    
    Q_INVOKABLE uint32_t CoInitialize(uint32_t a);
    Q_INVOKABLE uint32_t CoCreateInstance(uint8_t* rclsid, void* pUnkOuter, void* dwClsContext, uint8_t* riid, uint32_t* ppv);

//    Q_INVOKABLE uint32_t ();
};

#endif // OLE32_H
