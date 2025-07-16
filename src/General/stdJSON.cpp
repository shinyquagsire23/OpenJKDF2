#include "stdJSON.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <nlohmann/json.hpp>
#include <filesystem>
#include <unordered_map>
#include <locale> 
#include <codecvt> 
#include "jk.h"
#include "stdPlatform.h"

namespace fs = std::filesystem;

// string (utf8) -> u16string
static std::u16string utf8_to_utf16(const std::string& utf8)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert; 
    std::u16string utf16 = convert.from_bytes(utf8);
    return utf16;
}
// u16string -> string (utf8)
static std::string utf16_to_utf8(const std::u16string& utf16) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert; 
    std::string utf8 = convert.to_bytes(utf16);
    return utf8;
}

extern "C"
{

#define CHECK_COMMON(pFpath, pKey) \
    if (!pFpath) { \
        stdJSON_PrintNullWarning();  \
        return 0;  \
    }  \
    if (!pKey) {  \
        stdJSON_PrintNullKeyWarning();  \
        return 0;  \
    } \
    ; \

#define CHECK_COMMON_GET(pFpath, pKey, val) \
    if (!pFpath) { \
        stdJSON_PrintNullWarning();  \
        return val;  \
    }  \
    if (!pKey) {  \
        stdJSON_PrintNullKeyWarning();  \
        return val;  \
    } \
    ; \

#define CHECK_ARGPTR(pPtr) \
    if (!pPtr) { \
        stdJSON_PrintNullPtrWarning();  \
        return 0;  \
    }  \
    ; \

static inline void stdJSON_PrintNullWarning() {
    stdPlatform_Printf("WARN: stdJSON was passed a NULL pFpath.\n");
}

static inline void stdJSON_PrintNullKeyWarning() {
    stdPlatform_Printf("WARN: stdJSON was passed a NULL key.\n");
}

static inline void stdJSON_PrintNullPtrWarning() {
    stdPlatform_Printf("WARN: stdJSON was passed a NULL ptr value.\n");
}

static nlohmann::json stdJSON_OpenAndReadFile(const char* pFpath)
{
    fs::path json_path = {pFpath};
    nlohmann::json json_file(nlohmann::json::value_t::object);
    if (!fs::exists(json_path)) {
        return json_file;
    }

    std::ifstream i(json_path);
    i >> json_file;
    i.close();

    return json_file;
}

#if 0
static int stdJSON_WriteToFile(const char* pFpath, nlohmann::json& json_file)
{
    if (!pFpath)
    {
        stdPlatform_Printf("ERROR: Failed to open `(NULL)`!\n");
        return 0;
    }

    printf("asdf %s\n", pFpath);

    FILE* f = fopen("sd:/test_idk.json", "w");
    if (!f) {
        stdPlatform_Printf("ERROR: Failed to open `%s`!\n", pFpath);
        return 0;
    }

    std::string s = json_file.dump(4, ' ', true);
    size_t sz_expect = strlen(s.c_str());
    size_t sz = fwrite(s.c_str(), 1, sz_expect, f);
    if (sz != sz_expect)
    {
        stdPlatform_Printf("ERROR: Failed to write `%s`!\n", pFpath);
        return 0;
    }
    return 1;
}
#endif

static int stdJSON_WriteToFile(const char* pFpath, nlohmann::json& json_file)
{
    if (!pFpath)
    {
        stdPlatform_Printf("ERROR: Failed to open `(NULL)`!\n");
        return 0;
    }
#ifdef TARGET_TWL
    return 1;
#endif

    fs::path json_path = {pFpath};
    std::ofstream o(json_path);
    if (!o)
    {
        stdPlatform_Printf("ERROR: Failed to open `%s`!\n", pFpath);
        return 0;
    }
    o << json_file.dump(4, ' ', true);
    if (!o)
    {
        stdPlatform_Printf("ERROR: Failed to write `%s`!\n", pFpath);
        return 0;
    }
    return 1;
}

int stdJSON_SaveInt(const char* pFpath, const char* pKey, int val)
{
    CHECK_COMMON(pFpath, pKey);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = val;
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_SaveFloat(const char* pFpath, const char* pKey, flex_t val)
{
    CHECK_COMMON(pFpath, pKey);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = (double)val; // FLEXTODO
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_GetInt(const char* pFpath, const char* pKey, int valDefault)
{
    CHECK_COMMON_GET(pFpath, pKey, valDefault);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    if (!json_file.contains(pKey)) {
        stdJSON_SaveInt(pFpath, pKey, valDefault);
        return valDefault;
    }

    auto ret = json_file[pKey];
    if (ret.is_boolean()) {
        return ret.get<bool>() ? 1 : 0;
    }

    if (!ret.is_number()) {
        stdJSON_SaveInt(pFpath, pKey, valDefault);
        return valDefault;
    }

    return ret.get<int>();
}

flex_t stdJSON_GetFloat(const char* pFpath, const char* pKey, flex_t valDefault)
{
    CHECK_COMMON_GET(pFpath, pKey, valDefault);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);

    if (!json_file.contains(pKey)) {
        stdJSON_SaveFloat(pFpath, pKey, valDefault);
        return valDefault;
    }

    auto ret = json_file[pKey];
    if (!ret.is_number()) {
        stdJSON_SaveFloat(pFpath, pKey, valDefault);
        return valDefault;
    }

    return ret.get<double>(); // FLEXTODO
}

int stdJSON_SaveBool(const char* pFpath, const char* pKey, int bVal)
{
    CHECK_COMMON(pFpath, pKey);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = !!bVal;
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_GetBool(const char* pFpath, const char* pKey, int bValDefault)
{
    CHECK_COMMON_GET(pFpath, pKey, bValDefault);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    if (!json_file.contains(pKey)) {
        stdJSON_SaveBool(pFpath, pKey, !!bValDefault);
        return bValDefault;
    }

    auto ret = json_file[pKey];
    if (ret.is_number()) {
        return ret.get<int>() != 0 ? 1 : 0;
    }

    if (!ret.is_boolean()) {
        stdJSON_SaveBool(pFpath, pKey, !!bValDefault);
        return bValDefault;
    }

    return ret.get<bool>() ? 1 : 0;
}

int stdJSON_SaveBytes(const char* pFpath, const char* pKey, uint8_t *pData, uint32_t dataLen)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pData);

    std::vector<uint8_t> data(pData, pData+dataLen);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = data;
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_GetBytes(const char* pFpath, const char* pKey, uint8_t* pData, uint32_t dataLen)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pData);

    std::vector<uint8_t> out(pData, pData+dataLen);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    auto ret = json_file[pKey];
    if (!ret.is_array()) {
        stdJSON_SaveBytes(pFpath, pKey, out.data(), dataLen);
    }
    else {
        out = json_file[pKey].get<std::vector<uint8_t>>();
    }

    std::copy_n(out.begin(), dataLen, pData);

    return 1;
}

int stdJSON_SetString(const char* pFpath, const char* pKey, const char *pVal)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pVal);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = std::string(pVal);
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_GetString(const char* pFpath, const char* pKey, char* pOut, int outSize, const char *pValDefault)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pOut);
    CHECK_ARGPTR(pValDefault);

    std::string out = "";

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    out = json_file.value(std::string(pKey), std::string(pValDefault));
    if (out == std::string(pValDefault)) {
        stdJSON_SetString(pFpath, pKey, pValDefault);
    }
    
    size_t readSize = strlen(out.c_str());
    if (readSize < outSize) {
        outSize = readSize;
    }
    _strncpy(pOut, out.c_str(), outSize);

    return 1;
}

/*
static std::string utf16_to_utf8( std::u16string&& utf16_string )
{
   std::wstring_convert<std::codecvt_utf8_utf16<int16_t>, int16_t> convert;
   auto p = reinterpret_cast<const int16_t *>( utf16_string.data() );
   return convert.to_bytes( p, p + utf16_string.size() );
}

static std::u16string utf8_to_utf16( std::string&& utf8_string )
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert; 
    std::u16string dest = convert.from_bytes(utf8_string);
}
*/

int stdJSON_SetWString(const char* pFpath, const char* pKey, const char16_t *pVal)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pVal);

    std::string val = utf16_to_utf8(std::u16string(pVal));

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file[pKey] = val;
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_GetWString(const char* pFpath, const char* pKey, char16_t* pOut, int outSize, const char16_t *pValDefault)
{
    CHECK_COMMON(pFpath, pKey);
    CHECK_ARGPTR(pOut);
    CHECK_ARGPTR(pValDefault);

    std::u16string out = std::u16string(pValDefault);
    std::string out_u8 = "";

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    auto ret = json_file[pKey];
    if (!ret.is_string()) {
        stdJSON_SetWString(pFpath, pKey, pValDefault);
    }
    else {
        out_u8 = ret.get<std::string>();
        out = utf8_to_utf16(out_u8);
    }
    
    size_t readSize = _wcslen((wchar_t*)out.data());
    if (readSize < outSize) {
        outSize = readSize;
    }
    _wcsncpy((wchar_t*)pOut, (wchar_t*)out.data(), outSize);

    return 1;
}

int stdJSON_IterateKeys(const char* pFpath, stdJSONCallback_t pCallbackFn, void* pCtx)
{
    CHECK_ARGPTR(pFpath);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);

    for (auto& el : json_file.items())
    {
        std::string out = json_file.value(std::string(el.key().c_str()), std::string(""));
        if (out == std::string("")) {
            stdJSON_SetString(pFpath, el.key().c_str(), "");
        }

        if (pCallbackFn) {
            pCallbackFn(el.key().c_str(), out.c_str(), pCtx);
        }
    }

    //[pKey] = std::string(pVal);
    //return stdJSON_WriteToFile(pFpath, json_file);
    return 1;
}

int stdJSON_EraseKey(const char* pFpath, const char* pKey)
{
    CHECK_COMMON(pFpath, pKey);

    nlohmann::json json_file = stdJSON_OpenAndReadFile(pFpath);
    json_file.erase(pKey);
    return stdJSON_WriteToFile(pFpath, json_file);
}

int stdJSON_EraseAll(const char* pFpath)
{
    CHECK_ARGPTR(pFpath);
    
    nlohmann::json json_file(nlohmann::json::value_t::object);
    return stdJSON_WriteToFile(pFpath, json_file);
}
}