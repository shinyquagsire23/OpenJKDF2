#include "stdEmbeddedRes.h"

#include "globals.h"
#include "stdPlatform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

#ifdef SDL2_RENDER
#include "SDL2_helper.h"

#define stdEmbeddedRes_errmsg(_msg) SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", _msg, NULL)
#else
#define stdEmbeddedRes_errmsg(_msg) stdPlatform_Printf("Critical Error: %s\n", _msg)
#endif

char* stdEmbeddedRes_LoadOnlyInternal(const char* filepath, size_t* pOutSz)
{
    char tmp_filepath[256];
    strncpy(tmp_filepath, "resource/", 256);
    strncat(tmp_filepath, filepath, 256);

    if (pOutSz) {
        *pOutSz = 0;
    }
    
#ifdef WIN32
for (int i = 0; i < strlen(tmp_filepath); i++)
{
    if (tmp_filepath[i] == '/') {
        tmp_filepath[i] = '\\';
    }
}
#endif

    char* file_contents = NULL;
    FILE* f = fopen(tmp_filepath, "r");
    
#if defined(MACOS) && defined(SDL2_RENDER)
    char* base_path = SDL_GetBasePath();
    strncpy(tmp_filepath, base_path, 256);
    strncat(tmp_filepath, "Contents/Resources/", 256);
    strncat(tmp_filepath, filepath, 256);
    SDL_free(base_path);

    f = fopen(tmp_filepath, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t len = ftell(f);
        rewind(f);
        
        file_contents = malloc(len+1);
        
        if (fread(file_contents, 1, len, f) != len)
        {
            char errtmp[256];
            snprintf(errtmp, 256, "Failed to read file `%s`!\n", filepath);
            stdEmbeddedRes_errmsg(errtmp);
            return NULL;
        }
        file_contents[len] = 0;
        
        fclose(f);

        if (pOutSz) {
            *pOutSz = len+1;
        }
        return file_contents;
    }
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
            file_contents = malloc(embeddedResource_aFiles[i].data_len+1);
            memcpy(file_contents, embeddedResource_aFiles[i].data, embeddedResource_aFiles[i].data_len);
            file_contents[embeddedResource_aFiles[i].data_len] = 0;

            if (pOutSz) {
                *pOutSz = embeddedResource_aFiles[i].data_len+1;
            }

            break;
        }
    }

    return file_contents;
}

char* stdEmbeddedRes_Load(const char* filepath, size_t* pOutSz)
{
    char tmp_filepath[256];
    strncpy(tmp_filepath, "resource/", 256);
    strncat(tmp_filepath, filepath, 256);

    if (pOutSz) {
        *pOutSz = 0;
    }
    
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

    char* file_contents = NULL;
    FILE* f = fopen(tmp_filepath, "r");
    if (f)
    {
retry_file:
        fseek(f, 0, SEEK_END);
        size_t len = ftell(f);
        rewind(f);
        
        file_contents = malloc(len+1);
        
        if (fread(file_contents, 1, len, f) != len)
        {
            char errtmp[256];
            snprintf(errtmp, 256, "Failed to read file `%s`!\n", filepath);
            stdEmbeddedRes_errmsg(errtmp);
            return NULL;
        }
        file_contents[len] = 0;
        
        fclose(f);

        if (pOutSz) {
            *pOutSz = len+1;
        }
    }
    else
    {
#if defined(MACOS) && defined(SDL2_RENDER)
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
                file_contents = malloc(embeddedResource_aFiles[i].data_len+1);
                memcpy(file_contents, embeddedResource_aFiles[i].data, embeddedResource_aFiles[i].data_len);
                file_contents[embeddedResource_aFiles[i].data_len] = 0;

                if (pOutSz) {
                    *pOutSz = embeddedResource_aFiles[i].data_len+1;
                }

                break;
            }
        }
    }

    return file_contents;
}