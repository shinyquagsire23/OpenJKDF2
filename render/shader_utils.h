/**
 * From the OpenGL Programming wikibook: http://en.wikibooks.org/wiki/OpenGL_Programming
 * This file is in the public domain.
 * Contributors: Sylvain Beucler
 */
#ifndef _CREATE_SHADER_H
#define _CREATE_SHADER_H
#include <GL/glew.h>

extern void print_log(GLuint object);
extern GLuint create_shader(const char* filename, GLenum type);

#endif
