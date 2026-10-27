#ifndef OPENJKDF2_JKGM_PIXEL_UNPACK_HPP
#define OPENJKDF2_JKGM_PIXEL_UNPACK_HPP

// Include after the platform GL declarations. loadPngImage produces tightly
// packed unsigned-byte rows, regardless of the caller's pixel-store state.
// Restore that state even when a later load fails and returns early.
// Ported from OpenJKDF2-MotS-Fixes by Andrei Kiralv/Darkahn and Coda Lilitari.
class JkgmScopedPixelUnpack
{
public:
    JkgmScopedPixelUnpack()
    {
        glGetIntegerv(GL_UNPACK_ALIGNMENT, &alignment_);
        glGetIntegerv(GL_UNPACK_ROW_LENGTH, &row_length_);
        glGetIntegerv(GL_UNPACK_SKIP_PIXELS, &skip_pixels_);
        glGetIntegerv(GL_UNPACK_SKIP_ROWS, &skip_rows_);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
        glPixelStorei(GL_UNPACK_SKIP_PIXELS, 0);
        glPixelStorei(GL_UNPACK_SKIP_ROWS, 0);
    }

    ~JkgmScopedPixelUnpack()
    {
        glPixelStorei(GL_UNPACK_ALIGNMENT, alignment_);
        glPixelStorei(GL_UNPACK_ROW_LENGTH, row_length_);
        glPixelStorei(GL_UNPACK_SKIP_PIXELS, skip_pixels_);
        glPixelStorei(GL_UNPACK_SKIP_ROWS, skip_rows_);
    }

    JkgmScopedPixelUnpack(const JkgmScopedPixelUnpack&) = delete;
    JkgmScopedPixelUnpack& operator=(const JkgmScopedPixelUnpack&) = delete;

private:
    GLint alignment_ = 4;
    GLint row_length_ = 0;
    GLint skip_pixels_ = 0;
    GLint skip_rows_ = 0;
};

#endif
