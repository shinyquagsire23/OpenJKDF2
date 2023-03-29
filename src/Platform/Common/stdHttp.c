#include "stdHttp.h"

#include <stdlib.h>
#include "stdPlatform.h"

#if defined(PLATFORM_CURL)

#include "Platform/Common/stdEmbeddedRes.h"
#ifdef LINUX
#include <curl/curl.h>
#else // !LINUX
#include "curl/curl.h"
#endif // !LINUX

char* stdHttp_pDlBuffer = NULL;
size_t stdHttp_dlBufferMax = 0;
int32_t stdHttp_dlBufferWritten = 0;

static void* stdHttp_pCaCertBlob = "";

static void stdHttp_reset()
{
    if (stdHttp_pDlBuffer) {
        free(stdHttp_pDlBuffer);
    }

    stdHttp_pDlBuffer = NULL;
    stdHttp_dlBufferWritten = 0;
    stdHttp_dlBufferMax = 0;
}

static void* stdHttp_export()
{
    void* data_out = stdHttp_pDlBuffer;
    stdHttp_pDlBuffer = NULL;

    stdHttp_reset();

    return data_out;
}

static size_t stdHttp_write_to_buffer(void *contents, size_t size, size_t nmemb, void *userp)
{
    int32_t actual_recv = size*nmemb;
    int32_t to_write = actual_recv;

    if (!stdHttp_pDlBuffer) {
        stdHttp_pDlBuffer = malloc(to_write*2);
        memset(stdHttp_pDlBuffer, 0, to_write*2);
        stdHttp_dlBufferMax = to_write*2;
    }

    if (stdHttp_dlBufferWritten+to_write >= stdHttp_dlBufferMax) {
        void* tmp = malloc(stdHttp_dlBufferMax*2);
        memset(tmp, 0, stdHttp_dlBufferMax*2);
        memcpy(tmp, stdHttp_pDlBuffer, stdHttp_dlBufferWritten);
        free(stdHttp_pDlBuffer);

        stdHttp_pDlBuffer = tmp;
        stdHttp_dlBufferMax = stdHttp_dlBufferMax*2;
    }

    void* out_ptr = stdHttp_pDlBuffer + stdHttp_dlBufferWritten;

    if (to_write > 0) {
        memcpy(out_ptr, contents, to_write);
    }

    stdHttp_dlBufferWritten += to_write;
    return actual_recv;
}

static size_t stdHttp_write_to_file(void *contents, size_t size, size_t nmemb, void *userp)
{
    return fwrite(contents, size, nmemb, (FILE*)userp);
}

void stdHttp_Startup()
{
    stdHttp_pCaCertBlob = stdEmbeddedRes_Load("ssl/cacert.pem", NULL);
}

void stdHttp_Shutdown()
{
    stdHttp_reset();

    free(stdHttp_pCaCertBlob);
}

void* stdHttp_Fetch(const char* pUrl)
{
    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }
    stdHttp_reset();

#ifndef PLATFORM_NO_CACERT_BLOB
    struct curl_blob blob;
    blob.data = stdHttp_pCaCertBlob;
    blob.len = strlen(blob.data);
    blob.flags = CURL_BLOB_COPY;
#endif

    curl_easy_setopt(curl, CURLOPT_URL, pUrl);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OpenJKDF2-stdHttp");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stdHttp_write_to_buffer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdHttp_pDlBuffer);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

#ifndef PLATFORM_NO_CACERT_BLOB
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
#endif

    res = curl_easy_perform(curl);
    /* always cleanup */

    if (res) {
        stdPlatform_Printf("stdHttp: Failed to fetch `%s`, cURL error: %s\n", pUrl, curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);

    return stdHttp_export();
}

int stdHttp_DownloadToPath(const char* pUrl, const char* pFpath)
{
    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0;
    }
    stdHttp_reset();

#ifndef PLATFORM_NO_CACERT_BLOB
    struct curl_blob blob;
    blob.data = stdHttp_pCaCertBlob;
    blob.len = strlen(blob.data);
    blob.flags = CURL_BLOB_COPY;
#endif

    FILE* pFile = fopen(pFpath, "wb");
    if (!pFile) {
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_URL, pUrl);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OpenJKDF2-stdHttp");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stdHttp_write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pFile);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

#ifndef PLATFORM_NO_CACERT_BLOB
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
#endif

    res = curl_easy_perform(curl);
    /* always cleanup */

    if (res) {
        stdPlatform_Printf("stdHttp: Failed to download `%s`, cURL error: %s\n", pUrl, curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    fclose(pFile);
    stdHttp_reset();

    return 1;
}
#else
void stdHttp_Startup()
{

}

void stdHttp_Shutdown()
{
    
}

void* stdHttp_Fetch(const char* pUrl)
{
    return NULL;
}

int stdHttp_DownloadToPath(const char* pUrl, const char* pFpath)
{
    return 0;
}
#endif