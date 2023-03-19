/**
 * From the OpenGL Programming wikibook: http://en.wikibooks.org/wiki/OpenGL_Programming
 * This file is in the public domain.
 * Contributors: Sylvain Beucler
 */
#ifdef SDL2_RENDER

#ifndef _CREATE_SHADER_H
#define _CREATE_SHADER_H
#include "SDL2_helper.h"
//#include <GL/glew.h>

extern void print_log(GLuint object);
GLuint load_shader_file(const char* filepath, GLenum type);
extern GLuint create_shader(const char* filename, GLenum type);

#endif
#endif // SDL2_RENDER
