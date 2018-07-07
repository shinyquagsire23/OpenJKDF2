#ifndef COMCTL32_H
#define COMCTL32_H

#include <QObject>
#include <unicorn/unicorn.h>

class ComCtl32 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE ComCtl32() {}
    
    Q_INVOKABLE void InitCommonControls();

//    Q_INVOKABLE uint32_t ();
};

#endif // COMCTL32_H
