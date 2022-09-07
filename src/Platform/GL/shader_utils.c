/**
 * From the OpenGL Programming wikibook: http://en.wikibooks.org/wiki/OpenGL_Programming
 * This file is in the public domain.
 * Contributors: Sylvain Beucler
 */

#ifdef SDL2_RENDER

#include "shader_utils.h"
#include "globals.h"

#include <SDL.h>
#include <GL/glew.h>
#include <stdio.h>
#include <string.h>

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

/**
 * Display compilation errors from the OpenGL shader compiler
 */
void print_log(GLuint object) {
	GLint log_length = 0;
	if (glIsShader(object)) {
		glGetShaderiv(object, GL_INFO_LOG_LENGTH, &log_length);
	} else if (glIsProgram(object)) {
		glGetProgramiv(object, GL_INFO_LOG_LENGTH, &log_length);
	} else {
		SDL_LogMessage(SDL_LOG_CATEGORY_APPLICATION, SDL_LOG_PRIORITY_ERROR,
					   "printlog: Not a shader or a program");
		return;
	}

	char* log = (char*)malloc(log_length);
	
	if (glIsShader(object))
		glGetShaderInfoLog(object, log_length, NULL, log);
	else if (glIsProgram(object))
		glGetProgramInfoLog(object, log_length, NULL, log);
	
	SDL_LogMessage(SDL_LOG_CATEGORY_APPLICATION, SDL_LOG_PRIORITY_ERROR, "%s\n", log);
	
	SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", log, NULL);
	
	free(log);
}

GLuint load_shader_file(const char* filepath, GLenum type)
{
    char tmp_filepath[256];
    strncpy(tmp_filepath, filepath, 256);
    
#ifdef WIN32
for (int i = 0; i < strlen(tmp_filepath); i++)
{
    if (tmp_filepath[i] == '/') {
        tmp_filepath[i] = '\\';
    }
}
#endif

#ifdef LINUX
    char *r = malloc(strlen(tmp_filepath) + 16);
    if (casepath(tmp_filepath, r))
    {
        strcpy(tmp_filepath, r);
    }
    free(r);
#endif

    char* shader_contents = NULL;
    FILE* f = fopen(tmp_filepath, "r");
    if (f)
    {
retry_file:
	    fseek(f, 0, SEEK_END);
	    size_t len = ftell(f);
	    rewind(f);
	    
	    shader_contents = malloc(len+1);
	    
	    if (fread(shader_contents, 1, len, f) != len)
	    {
	        char errtmp[256];
	        snprintf(errtmp, 256, "Failed to read shader file `%s`!\n", filepath);
	        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", errtmp, NULL);
	        return -1;
	    }
	    shader_contents[len] = 0;
	    
	    fclose(f);
	}
	else
    {
#if defined(MACOS)
    	char* base_path = SDL_GetBasePath();
    	strncpy(tmp_filepath, base_path, 256);
    	strncat(tmp_filepath, "Contents/Resources/", 256);
    	strncat(tmp_filepath, filepath, 256);
    	SDL_free(base_path);

    	f = fopen(tmp_filepath, "r");
    	if (f)
    		goto retry_file;
#endif

	    strncpy(tmp_filepath, filepath, 256);
	    
		for (int i = 0; i < strlen(tmp_filepath); i++)
		{
		    if (tmp_filepath[i] == '\\') {
		        tmp_filepath[i] = '/';
		    }
		}

    	for (size_t i = 0; i < embeddedResource_aFiles_num; i++)
    	{
    		if (!strcmp(embeddedResource_aFiles[i].fpath, tmp_filepath)) {
    			shader_contents = malloc(embeddedResource_aFiles[i].data_len+1);
    			memcpy(shader_contents, embeddedResource_aFiles[i].data, embeddedResource_aFiles[i].data_len);
    			shader_contents[embeddedResource_aFiles[i].data_len] = 0;
    			break;
    		}
    	}
    }

    if (!shader_contents)
    {
    	char errtmp[256];
        snprintf(errtmp, 256, "Failed to load shader file `%s`!\n", filepath);
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", errtmp, NULL);
        return -1;
    }
    
    printf("Parse shader `%s`\n", filepath);
    
    GLuint ret = create_shader(shader_contents, type);
    free(shader_contents);
    
    return ret;
}

/**
 * Compile the shader from file 'filename', with error handling
 */
GLuint create_shader(const char* shader, GLenum type) {
	const GLchar* source = (const GLchar*)shader;
	GLuint res = glCreateShader(type);

	// GLSL version
	const char* version;
	int profile;
	SDL_GL_GetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, &profile);
	//if (profile == SDL_GL_CONTEXT_PROFILE_ES)
	//	version = "#version 100\n";  // OpenGL ES 2.0
	//else
    //version = "#version 330 core\n";  // OpenGL 3.3
#ifdef MACOS
	version = "#version 330\n#define CAN_BILINEAR_FILTER\n#define HAS_MIPS\n";
#else
    version = "#version 330\n#define CAN_BILINEAR_FILTER\n#define HAS_MIPS\n";  // OpenGL ES 2.0
#endif

#if defined(WIN64_STANDALONE)
    version = "#version 330\n#define CAN_BILINEAR_FILTER\n#define HAS_MIPS\n";
#endif

#if defined(ARCH_WASM)
    version = "#version 300 es\n";
#endif

	// GLES2 precision specifiers
	const char* precision;
	precision =
		"#ifdef GL_ES                        \n"
		"#  ifdef GL_FRAGMENT_PRECISION_HIGH \n"
		"     precision highp float;         \n"
		"#  else                             \n"
		"     precision mediump float;       \n"
		"#  endif                            \n"
		"#else                               \n"
		// Ignore unsupported precision specifiers
		"#  define lowp                      \n"
		"#  define mediump                   \n"
		"#  define highp                     \n"
		"#endif                              \n";

	const GLchar* sources[] = {
		version,
		precision,
		source
	};
	glShaderSource(res, 3, sources, NULL);
	
	glCompileShader(res);
	GLint compile_ok = GL_FALSE;
	glGetShaderiv(res, GL_COMPILE_STATUS, &compile_ok);
	if (compile_ok == GL_FALSE) {
		print_log(res);
		glDeleteShader(res);
		return 0;
	}
	
	return res;
}
#endif // LINUX
