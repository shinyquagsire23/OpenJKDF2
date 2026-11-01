#ifndef OPENJKDF2_JKGM_TEXTURE_UPLOAD_HPP
#define OPENJKDF2_JKGM_TEXTURE_UPLOAD_HPP

// Include after the platform GL declarations. Upload tightly packed PNG pixels
// to the currently bound texture, preserving the caller's unpack state.
void jkgm_upload_texture_2d(GLint internal_format, GLsizei width, GLsizei height,
                           GLenum format, const void* pixels);

#endif
