#ifndef OPENJKDF2_STD3D_READBACK_H
#define OPENJKDF2_STD3D_READBACK_H
#include <stddef.h>

/* Tight RGB8 rows in OpenGL's bottom-up order. No mode-specific size cap. */
int std3D_ReadbackSize(int width, int height, size_t* bytes);

/* Call on the render thread before presentation. Storage remains caller-owned.
 * A pre-existing GL error is reported separately. Strict capture callers reject
 * it before state changes; ordinary screenshots retain their permissive policy.
 * GL errors are consumed, not restored. Both error outputs may be NULL.
 * All touched framebuffer/pack state is restored on read failure. */
int std3D_ReadbackRgb(unsigned int framebuffer, int width, int height,
    unsigned char* pixels, size_t capacity, int rejectPriorError,
    unsigned int* priorError, unsigned int* captureError);
#endif
