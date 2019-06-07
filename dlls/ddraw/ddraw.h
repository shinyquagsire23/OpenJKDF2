#ifndef DDRAW_H
#define DDRAW_H

#include <QObject>
#include <unicorn/unicorn.h>

class DDraw : public QObject
{
Q_OBJECT

public:
    uint8_t force_error;

    Q_INVOKABLE DDraw() : force_error(0) {}
    
    Q_INVOKABLE uint32_t DirectDrawEnumerateA(uint32_t callback, uint32_t context);
    Q_INVOKABLE uint32_t DirectDrawCreate(uint8_t* lpGUID, uint32_t* lplpDD, void* pUnkOuter);

//    Q_INVOKABLE uint32_t ();
};

extern DDraw *ddraw;

#endif // DDRAW_H
