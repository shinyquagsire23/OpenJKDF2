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
    Q_INVOKABLE uint32_t DirectDrawCreate(uint32_t a, uint32_t b, uint32_t c);

//    Q_INVOKABLE uint32_t ();
};

#endif // DDRAW_H
