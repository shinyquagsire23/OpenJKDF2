/* Public Domain.
 *
 * A sample C++ program for Dr.MinGW.
 */

#include <stdio.h>
#include <stdlib.h>

#include "exchndl.h"

static void Function(int i, double j, const char * pszString) {
    sscanf("12345", "%i", (int *)1);
}

struct Class {
    static void StaticMethod(int i, float j) {
        Function(i * 2, j, "Hello");
    }

    void Method(void) {
        StaticMethod(4, 5.6f);
    }
};

int main() {
    ExcHndlInit();
    Class instance;
    instance.Method();
    return 0;
}
