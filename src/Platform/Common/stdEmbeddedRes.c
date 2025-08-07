#include "stdEmbeddedRes.h"

#include "globals.h"
#include "stdPlatform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FS_POSIX
#include "external/fcaseopen/fcaseopen.h"
#endif

#ifdef SDL2_RENDER
#include "SDL2_helper.h"

#define stdEmbeddedRes_errmsg(_msg) SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", _msg, NULL)
#else
#define stdEmbeddedRes_errmsg(_msg) stdPlatform_Printf("Critical Error: %s\n", _msg)
#endif

#ifdef TARGET_TWL
#include <nds.h>
#include <sys/stat.h>
#endif

char* stdEmbeddedRes_LoadOnlyInternal(const char* filepath, size_t* pOutSz)
{
    stdPlatform_Printf("OpenJKDF2: %s - Loading embedded resource: %s\n", __func__, filepath);
    int exists = 0;
#ifdef TARGET_TWL 
    struct stat statstuff;
    int exists = 0;
#endif
    FILE* f = NULL;
    char* base_path = NULL;
    char* file_contents = NULL;
    char tmp_filepath[256];
 
    strncpy(tmp_filepath, "resource/", 256);
    strncat(tmp_filepath, filepath, 256);
    #if defined(TARGET_SWITCH) || defined(LINUX)
    for (int i = 0; i < strlen(tmp_filepath); i++)
    {
        if (tmp_filepath[i] == '\\') {
            tmp_filepath[i] = '/';
        }
    }
#endif   
    stdPlatform_Printf("OpenJKDF2: %s - Loading embedded resource fullpath: %s\n", __func__, tmp_filepath);
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

#ifdef TARGET_TWL
    exists = stat(tmp_filepath, &statstuff) >= 0;
    if (!exists) {
        goto skip_fopen;
    }
#endif
    
#if defined(MACOS) && defined(SDL2_RENDER)
    base_path = SDL_GetBasePath();
    strncpy(tmp_filepath, base_path, 256);
    strncat(tmp_filepath, "Contents/Resources/", 256);
    strncat(tmp_filepath, filepath, 256);
    SDL_free(base_path);
#endif
#if defined(TARGET_SWITCH) && defined(SDL2_RENDER)

#endif

    f = fopen(tmp_filepath, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t len = ftell(f);
        rewind(f);
        
        file_contents = (char*)malloc(len+1);
        if (!file_contents) {
            if (pOutSz) {
                *pOutSz = 0;
            }
            fclose(f);
            return NULL;
        }
        
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

skip_fopen:
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
            file_contents = (char*)malloc(embeddedResource_aFiles[i].data_len+1);
            if (!file_contents) {
                if (pOutSz) {
                    *pOutSz = 0;
                }
                return NULL;
            }
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
#ifdef TARGET_TWL
    struct stat statstuff;
    int exists = 0;
#endif
    FILE* f = NULL;
    char* base_path = NULL;
    char* file_contents = NULL;
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

#ifdef FS_POSIX
    char *r = (char*)malloc(strlen(tmp_filepath) + 16);
    if (casepath(tmp_filepath, r))
    {
        strcpy(tmp_filepath, r);
    }
    free(r);
#endif


#ifdef TARGET_TWL
    exists = stat(tmp_filepath, &statstuff) >= 0;
    if (!exists) {
        goto skip_fopen;
    }
#endif

    f = fopen(tmp_filepath, "r");
    if (f)
    {
retry_file:
        fseek(f, 0, SEEK_END);
        size_t len = ftell(f);
        rewind(f);
        
        file_contents = (char*)malloc(len+1);
        if (!file_contents) {
            if (pOutSz) {
                *pOutSz = 0;
            }
            fclose(f);
            return NULL;
        }
        
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
        base_path = SDL_GetBasePath();
        strncpy(tmp_filepath, base_path, 256);
        strncat(tmp_filepath, "Contents/Resources/", 256);
        strncat(tmp_filepath, filepath, 256);
        SDL_free(base_path);

        f = fopen(tmp_filepath, "r");
        if (f)
            goto retry_file;
#endif

skip_fopen:
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
                file_contents = (char*)malloc(embeddedResource_aFiles[i].data_len+1);
                if (!file_contents) {
                    if (pOutSz) {
                        *pOutSz = 0;
                    }
                    return NULL;
                }
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