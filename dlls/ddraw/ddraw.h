#ifndef DDRAW_H
#define DDRAW_H

#include <QObject>
#include <unicorn/unicorn.h>

class DDraw : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE DDraw() {}
    
    Q_INVOKABLE uint32_t DirectDrawEnumerateA(uint32_t callback, uint32_t context);
    Q_INVOKABLE uint32_t DirectDrawCreate(uint8_t* lpGUID, uint32_t* lplpDD, void* pUnkOuter);

//    Q_INVOKABLE uint32_t ();
};

extern DDraw *ddraw;

#endif // DDRAW_H
