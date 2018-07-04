#ifndef USER32_H
#define USER32_H

#include <QObject>
#include <unicorn/unicorn.h>

class User32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:

    Q_INVOKABLE User32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t LoadIconA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t LoadCursorA(uint32_t a, uint32_t b);

//    Q_INVOKABLE uint32_t ();
};

#endif // USER32_H
