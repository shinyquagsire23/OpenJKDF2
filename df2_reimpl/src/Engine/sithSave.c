#include "sithSave.h"

void sithSave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5)
{
    sithSave_func1 = a1;
    sithSave_func2 = a2;
    sithSave_func3 = a3;
    sithSave_funcWrite = a4;
    sithSave_funcRead = a5;
}
