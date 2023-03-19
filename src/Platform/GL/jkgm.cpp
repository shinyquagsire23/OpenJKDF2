#include "jkgm.h"

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
#include "General/md5.h"
#include "Engine/rdMaterial.h"
#include "Platform/std3D.h"
#include "stdPlatform.h"
#include "jk.h"

namespace fs = std::filesystem;

extern "C" {

void* jkgm_alloc_aligned(size_t amt)
{
    void *buffer = NULL;

#ifdef PLAT_MACOS
    int pagesize = getpagesize();

    if (posix_memalign((void **)&buffer, pagesize, amt) != 0) {
        return NULL;
    }
#elif defined(WIN64_MINGW)
    buffer = _aligned_malloc(amt, 0x1000);
#else
    buffer = malloc(amt);
#endif
    return buffer;
}

void jkgm_aligned_free(void* p)
{
    if (!p) return;

#ifdef PLAT_MACOS
    free(p);
#elif defined(WIN64_MINGW)
    _aligned_free(p);
#else
    free(p);
#endif
}

}

#ifdef SDL2_RENDER
#if defined(TARGET_CAN_JKGM)

extern "C" {

#include <png.h>

extern void* worldpal_data;
extern rdDDrawSurface* std3D_aLoadedSurfaces[1024];
extern GLuint std3D_aLoadedTextures[1024];
extern size_t std3D_loadedTexturesAmt;
extern int jkPlayer_enableTextureFilter;
extern int jkPlayer_bEnableJkgm;
extern int jkPlayer_bEnableTexturePrecache;
extern int Main_bHeadless;
extern int jkGuiBuildMulti_bRendering;
extern GLuint worldpal_texture;

int compare_hashstr(uint8_t *p, const char* str){
    char tmp[34];
    for(unsigned int i = 0; i < 16; ++i){
        snprintf(&tmp[i*2], 3, "%02x", p[i]);
    }
    tmp[32] = 0;

    return !strcmp(str, tmp);
}

void print_hash(uint8_t *p){
    for(unsigned int i = 0; i < 16; ++i){
        stdPlatform_Printf("%02x", p[i]);
    }
    stdPlatform_Printf("\n");
}

bool loadPngImage(const char *name, int* outWidth, int* outHeight, int* outHasAlpha, GLubyte **outData, int flip_bgr) {
    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;
    unsigned int sig_read = 0;
    int color_type = 0, interlace_type = 0;
    FILE *fp = NULL;
 
    if ((fp = fopen(name, "rb")) == NULL)
        return false;
 
    /* Create and initialize the png_struct
     * with the desired error handler
     * functions.  If you want to use the
     * default stderr and longjump method,
     * you can supply NULL for the last
     * three parameters.  We also supply the
     * the compiler header file version, so
     * that we know if the application
     * was compiled with a compatible version
     * of the library.  REQUIRED
     */
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                     NULL, NULL, NULL);
 
    if (png_ptr == NULL) {
        fclose(fp);
        return false;
    }
 
    /* Allocate/initialize the memory
     * for image information.  REQUIRED. */
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        stdPlatform_Printf("Failed in png_create_info_struct\n");
        fclose(fp);
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return false;
    }
 
    /* Set error handling if you are
     * using the setjmp/longjmp method
     * (this is the normal method of
     * doing things with libpng).
     * REQUIRED unless you  set up
     * your own error handlers in
     * the png_create_read_struct()
     * earlier.
     */
    if (setjmp(png_jmpbuf(png_ptr))) {
        stdPlatform_Printf("Failed to read `%s`\n", name);
        /* Free all of the memory associated
         * with the png_ptr and info_ptr */
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        /* If we get here, we had a
         * problem reading the file */
        return false;
    }
 
    /* Set up the output control if
     * you are using standard C streams */
    png_init_io(png_ptr, fp);
    //printf("png_init_io\n");
 
    /* If we have already
     * read some of the signature */
    png_set_sig_bytes(png_ptr, sig_read);
    //printf("png_set_sig_bytes\n");
 
    /*
     * If you have enough memory to read
     * in the entire image at once, and
     * you need to specify only
     * transforms that can be controlled
     * with one of the PNG_TRANSFORM_*
     * bits (this presently excludes
     * dithering, filling, setting
     * background, and doing gamma
     * adjustment), then you can read the
     * entire image (including pixels)
     * into the info structure with this
     * call
     *
     * PNG_TRANSFORM_STRIP_16 |
     * PNG_TRANSFORM_PACKING  forces 8 bit
     * PNG_TRANSFORM_EXPAND forces to
     *  expand a palette into RGB
     */
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_STRIP_16 | PNG_TRANSFORM_PACKING | PNG_TRANSFORM_EXPAND | (flip_bgr ? PNG_TRANSFORM_BGR : 0), NULL); // 
    //printf("png_read_png\n");

    png_uint_32 width = 0, height = 0;
    int bit_depth = 0;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type,
                 &interlace_type, NULL, NULL);
    //printf("png_get_IHDR\n");
    *outWidth = width;
    *outHeight = height;
    //printf("PNG color type %x %x\n", color_type, PNG_COLOR_MASK_ALPHA);
    *outHasAlpha = !!(color_type & PNG_COLOR_MASK_ALPHA);
 
    size_t row_bytes = png_get_rowbytes(png_ptr, info_ptr);
    *outData = (unsigned char*) jkgm_alloc_aligned(row_bytes * height);
    //intptr_t orig_ptr = (intptr_t)*outData;
    _memset(*outData, 0, row_bytes * height);
    //*outData = (GLubyte*)(((intptr_t)(*outData)) & ~0x1F); // TODO ehhh
    //intptr_t align_ptr = (intptr_t)*outData;
    //printf("png_get_rowbytes\n");

#if 0
    std::vector<std::uint8_t*> aRowPtrs(height);
    std::uint8_t* BuffPos = reinterpret_cast<std::uint8_t*>(*outData);

    for (size_t i = 0; i < height; ++i)
    {
        aRowPtrs[i] = *outData+(row_bytes * (height-1-i));
    }

    png_read_image(png_ptr, aRowPtrs.data());
    png_read_end(png_ptr, info_ptr);
#endif

#if 1
    png_bytepp row_pointers = png_get_rows(png_ptr, info_ptr);
    //printf("png_get_rows\n");
 
    for (int i = 0; i < height; i++) {
        // note that png is ordered top to
        // bottom, but OpenGL expect it bottom to top
        // so the order or swapped
        _memcpy(*outData+(row_bytes * i), row_pointers[i], row_bytes);
    }
#endif

#if 0
    for (int i = height/2; i < height; i++) {
        uint32_t* rowout = (uint32_t*)(*outData+(row_bytes * i));
        for (int j = 0; j < row_bytes/4; j++) {
            *rowout = (i&1) ? 0x00FF0088 : 0xFF008800;
            rowout++;
        }
    }
#endif

    /* Clean up after the read,
     * and free any memory allocated */
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    //printf("png_destroy_read_struct\n");
 
    /* Close the file */
    fclose(fp);

#if 0
    if (!*outHasAlpha)
    {
        GLubyte* outDataConv = (unsigned char*) jkgm_alloc_aligned(width * height * 4);
        _memset(outDataConv, 0, row_bytes * height);
        for (int i = 0; i < height; i++) {
            for (int j = 0; j < row_bytes/3; j++) {
                void* ptr = *outData+(row_bytes * i)+(j*3);
                void* ptrOut = outDataConv+(row_bytes * i)+(j*4);
                uint32_t* pDatIn = (uint32_t*)ptr;
                uint32_t* pDatOut = (uint32_t*)ptrOut;
                uint32_t val = *pDatIn & 0xFFFFFF;


                if (val) {
                    val |= 0xFF000000;
                }
                val &= ~0xFF000000;

                *pDatOut = val;
            }
        }

        jkgm_aligned_free(*outData);
        *outData = outDataConv;
        *outHasAlpha = 1;
    }
    else 
    {
        for (int i = 0; i < height; i++) {
            for (int j = 0; j < row_bytes/4; j++) {
                void* ptr = *outData+(row_bytes * i)+(j*4);
                void* ptrOut = *outData+(row_bytes * i)+(j*4);
                uint32_t* pDatIn = (uint32_t*)ptr;
                uint32_t* pDatOut = (uint32_t*)ptrOut;
                uint32_t val = *pDatIn;


                if (!(val & 0xFFFFFF)) {
                    val &= ~0xFF000000;
                }
                val &= ~0xFF000000;

                *pDatOut = val;
            }
        }
    }
#endif

    //memset(*outData, 0xFF, row_bytes * height);
 
    /* That's it */
    return true;
}
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
  std::vector<uint8_t> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

typedef struct jkgm_cache_entry_t
{
    std::string albedo_tex;
    std::string emissive_tex;
    std::string displacement_tex;
    float emissive_factor[3];
    float albedo_factor[4];
    float displacement_factor;

    void* albedo_data;
    void* emissive_data;
    void* displacement_data;

    int albedo_width;
    int albedo_height;
    int albedo_hasAlpha;

    int emissive_width;
    int emissive_height;
    int emissive_hasAlpha;

    int displacement_width;
    int displacement_height;
    int displacement_hasAlpha;
} jkgm_cache_entry_t;

static std::unordered_map<std::string, jkgm_cache_entry_t> jkgm_cache;
static std::unordered_map<std::string, jkgm_cache_entry_t> jkgm_cache_hash;
static bool jkgm_cache_once = false;
static bool jkgm_fastpath_disable = false;

void jkgm_startup()
{
    jkgm_cache_once = false;
    jkgm_fastpath_disable = false;

    for (auto i : jkgm_cache) {
        jkgm_free_cache_entry(&i.second);
    }
    for (auto i : jkgm_cache_hash) {
        jkgm_free_cache_entry(&i.second);
    }

    jkgm_cache.clear();
    jkgm_cache_hash.clear();
}

static std::string jkgm_hash_to_str(uint8_t *p) {
    char tmp[32+2];
    char* tmp_it = tmp;
    for(unsigned int i = 0; i < 16; ++i){
        snprintf(tmp_it, 3, "%02x", p[i]);
        tmp_it += 2;
    }
    *tmp_it = 0;
    return std::string(tmp);
}

const fs::path jkgm_materials_path{ "jkgm/materials/" };

void jkgm_populate_cache()
{
    if (jkgm_cache_once) return;

    if (!fs::exists(jkgm_materials_path)) {
        jkgm_fastpath_disable = true;
        return;
    }

    for (const auto& fs_entry : fs::directory_iterator(jkgm_materials_path)) {
        if (!fs_entry.is_directory()) {
            continue;
        }
        const auto dir_iter_str = fs_entry.path().filename().string();

        std::string base_path = "jkgm/materials/" + dir_iter_str + "/";
        std::string metadata_path = base_path + "metadata.json";

        try
        {
            std::ifstream i(metadata_path);
            nlohmann::json jkgm_metadata;
            i >> jkgm_metadata;
       
            for (auto it : jkgm_metadata["materials"])
            {
                jkgm_cache_entry_t entry;
                entry.emissive_tex = "";
                entry.albedo_tex = "";
                entry.displacement_tex = "";

                //TODO safety/bounds checks
                if (it["emissive_factor"].type() != nlohmann::json::value_t::null) {
                    auto json_emissive_factor = it["emissive_factor"];
                    entry.emissive_factor[0] = json_emissive_factor[0];
                    entry.emissive_factor[1] = json_emissive_factor[1];
                    entry.emissive_factor[2] = json_emissive_factor[2];
                }
                else
                {
                    entry.emissive_factor[0] = 0.0f;
                    entry.emissive_factor[1] = 0.0f;
                    entry.emissive_factor[2] = 0.0f;
                }

                entry.emissive_tex = it.value("emissive_map", "");
                if (entry.emissive_tex != "") {
                    entry.emissive_tex = base_path + entry.emissive_tex;
                }

                //TODO safety/bounds checks
                if (it["albedo_factor"].type() != nlohmann::json::value_t::null) {
                    auto json_albedo_factor = it["albedo_factor"];
                    entry.albedo_factor[0] = json_albedo_factor[0];
                    entry.albedo_factor[1] = json_albedo_factor[1];
                    entry.albedo_factor[2] = json_albedo_factor[2];
                    entry.albedo_factor[3] = json_albedo_factor[3];
                }
                else
                {
                    entry.albedo_factor[0] = 1.0f;
                    entry.albedo_factor[1] = 1.0f;
                    entry.albedo_factor[2] = 1.0f;
                    entry.albedo_factor[3] = 1.0f;
                }

                if (it["displacement_factor"].type() != nlohmann::json::value_t::null) {
                    auto json_displacement_factor = it["displacement_factor"];
                    entry.displacement_factor = json_displacement_factor;

                    entry.displacement_tex = it.value("displacement_map", "");
                    if (entry.displacement_tex != "") {
                        entry.displacement_tex = base_path + entry.displacement_tex;
                    }
                    //printf("%s %f\n", entry.displacement_tex.c_str(), entry.displacement_factor);
                }
                else
                {
                    entry.displacement_factor = 0.0f;
                    entry.displacement_tex = "";
                }
                    
                entry.albedo_tex = base_path + it.value("albedo_map", "");

                entry.albedo_data = NULL;
                entry.emissive_data = NULL;
                entry.displacement_data = NULL;

                entry.albedo_width = 0;
                entry.albedo_height = 0;
                entry.albedo_hasAlpha = 0;

                entry.emissive_width = 0;
                entry.emissive_height = 0;
                entry.emissive_hasAlpha = 0;

                entry.displacement_width = 0;
                entry.displacement_height = 0;
                entry.displacement_hasAlpha = 0;

                for (auto repl_it : it["replaces"]) {
                    int cel_idx = repl_it["cel"];
                    std::string name = repl_it["name"];

                    jkgm_cache[name + std::to_string(cel_idx)] = entry;
                }

                for (auto hash_it : it["replaces_signatures"]) {
                    //auto bytes = hex_to_bytes(hash_it);
                    
                    //print_hash(bytes.data());
                    //std::cout << hash_it << std::endl;
                    jkgm_cache_hash[hash_it] = entry;
                }
            }
        }
        catch(nlohmann::json::parse_error& e)
        {
            std::cout << "Parse error while reading metadata `" << metadata_path << "`:";
            std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n'
                  << "byte position of error: " << e.byte << std::endl;

            //found_replace = false;
        }
        catch(nlohmann::json::exception& e)
        {
            std::cout << "Exception while parsing metadata `" << metadata_path << "`:";
            std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n' << std::endl;

            //found_replace = false;
        }
    }
    jkgm_cache_once = true;
}

std::string jkgm_get_tex_hash(stdVBuffer *vbuf, rdDDrawSurface *texture, rdMaterial* material, int is_alpha_tex)
{
    if (!vbuf || !texture) return "AAAAAAAAAA";

    uint8_t* image_8bpp = (uint8_t*)vbuf->sdlSurface->pixels;
    uint16_t* image_16bpp = (uint16_t*)vbuf->sdlSurface->pixels;
    uint8_t* pal = (uint8_t*)vbuf->palette;
    
    uint32_t width, height;
    width = vbuf->format.width;
    height = vbuf->format.height;

    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, (uint8_t *)&width, sizeof(uint32_t));
    md5Update(&ctx, (uint8_t *)&height, sizeof(uint32_t));

    if (!vbuf->format.format.is16bit)
    {
        for (int i = 0; i < width*height; i++)
        {
            uint8_t val = image_8bpp[i];
            uint8_t b = ((uint8_t*)worldpal_data)[val*3];
            uint8_t g = ((uint8_t*)worldpal_data)[(val*3)+1];
            uint8_t r = ((uint8_t*)worldpal_data)[(val*3)+2];

            if (is_alpha_tex) {
                uint16_t rgb565 = (((b >> 3) & 0x1F)<<0) | (((g >> 2) & 0x3F)<<5) | (((r >> 3) & 0x1F) << (6+5));
                md5Update(&ctx, (uint8_t*)&rgb565, sizeof(rgb565));
            }
            else
            {
                uint16_t rgb1555 = (((b >> 3) & 0x1F)<<0) | (((g >> 3) & 0x1F)<<5) | (((r >> 3) & 0x1F) << (5+5)) | ((val == 0) ? 0 : 0x8000);
                md5Update(&ctx, (uint8_t*)&rgb1555, sizeof(rgb1555));
            }
        }
    }
    else
    {
        md5Update(&ctx, (uint8_t *)image_8bpp, width * height * sizeof(uint16_t));
    }
    //
    md5Finalize(&ctx);

    std::string hash = jkgm_hash_to_str(ctx.digest);
    return hash;
}

void jkgm_populate_shortcuts(stdVBuffer *vbuf, rdDDrawSurface *texture, rdMaterial* material, int is_alpha_tex, int mipmap_level, int cel)
{
    if (Main_bHeadless) return;
    if (texture && texture->texture_loaded) return;

    // Also preload even if we have no jkgm stuff
    if ((!jkGuiBuildMulti_bRendering && jkPlayer_bEnableTexturePrecache) && jkgm_fastpath_disable && vbuf && texture) {
        // Causes some texture confusion when returning from jkGuiBuildMulti?
        //printf("PreInit %s %x %x %p %x\n", material->mat_fpath, texture->texture_id, texture->texture_loaded, vbuf, std3D_loadedTexturesAmt);
        std3D_AddToTextureCache(vbuf, texture, is_alpha_tex, 0);
        //printf("Init %s %x %x\n", material->mat_fpath, texture->texture_id, std3D_loadedTexturesAmt);
        return;
    }

    if (!vbuf || !texture || jkgm_fastpath_disable) return;

    jkgm_populate_cache();

    std::string hash = jkgm_get_tex_hash(vbuf, texture, material, is_alpha_tex);

    std::string full_fpath_str = std::string(material->mat_full_fpath);
    std::string cache_key = full_fpath_str + std::to_string(cel);

    //printf("%s %s %s\n", full_fpath_str.c_str(), cache_key.c_str(), hash.c_str());

    texture->cache_entry = NULL;

    if (jkgm_cache.find(cache_key) != jkgm_cache.end()) {
        texture->skip_jkgm = 0;
    }
    else if (jkgm_cache_hash.find(hash) != jkgm_cache_hash.end()) {
        texture->skip_jkgm = 0;
    }
    else {
        texture->skip_jkgm = 1;
    }

    // Also preload non-PNG textures
    if (texture->skip_jkgm) {
        if (!jkGuiBuildMulti_bRendering && jkPlayer_bEnableTexturePrecache) {
            // Causes some texture confusion when returning from jkGuiBuildMulti?
            //printf("PreInit %s %x %x %p%x \n", material->mat_fpath, texture->texture_id, texture->texture_loaded, vbuf, std3D_loadedTexturesAmt);
            std3D_AddToTextureCache(vbuf, texture, is_alpha_tex, 0);
            //printf("Init %s %x %x\n", material->mat_fpath, texture->texture_id, std3D_loadedTexturesAmt);
        }
        return;
    }

    texture->cache_entry = &jkgm_cache[cache_key];

    rdTexture *pRdTexture = &material->textures[cel];
    //pRdTexture->has_jkgm_override = 1;

    //printf("Caching %s mipmap_level=%d, cel=%d\n", material->mat_full_fpath, mipmap_level, cel);

    if (!jkGuiBuildMulti_bRendering && jkPlayer_bEnableTexturePrecache) {
        //printf("PreInit %s %x %x %p %x\n", material->mat_fpath, texture->texture_id, texture->texture_loaded, vbuf, std3D_loadedTexturesAmt);
        if (!jkgm_std3D_AddToTextureCache(vbuf, texture, is_alpha_tex, 0, material, cel)) {
            //printf("PreInit2 %s %x %x %p %x\n", material->mat_fpath, texture->texture_id, texture->texture_loaded, vbuf, std3D_loadedTexturesAmt);
            std3D_AddToTextureCache(vbuf, texture, is_alpha_tex, 0);
        }
        //printf("Init %s %x %x\n", material->mat_fpath, texture->texture_id, std3D_loadedTexturesAmt);
    }
}

int jkgm_std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha, rdMaterial* material, int cel)
{
    if (Main_bHeadless) return 0;
    if (texture->texture_loaded) return 1;

    rdTexture *pRdTexture = &material->textures[cel];

    //printf("Cache %s\n", material->mat_full_fpath);

    texture->emissive_texture_id = 0;
    texture->emissive_factor[0] = 0.0f;
    texture->emissive_factor[1] = 0.0f;
    texture->emissive_factor[2] = 0.0f;
    texture->albedo_factor[0] = 1.0f;
    texture->albedo_factor[1] = 1.0f;
    texture->albedo_factor[2] = 1.0f;
    texture->albedo_factor[3] = 1.0f;
    texture->emissive_data = NULL;
    texture->displacement_texture_id = 0;
    texture->displacement_factor = 0.0;
    texture->displacement_data = NULL;
    texture->albedo_data = NULL;

    // If the player disabled Jkgm, free any textures that were loaded
    if (!jkPlayer_bEnableJkgm && texture->cache_entry) {
        pRdTexture->has_jkgm_override = 0;

        jkgm_free_cache_entry(texture->cache_entry);
        return 0;
    }

    if (!jkPlayer_bEnableJkgm || jkgm_fastpath_disable || texture->skip_jkgm) {
        return 0;
    }

    
    if (!jkgm_cache_once) {
        if (!fs::exists(jkgm_materials_path)) {
            jkgm_fastpath_disable = true;
            return 0;
        }
    }
    
    uint32_t width, height;
    width = vbuf->format.width;
    height = vbuf->format.height;

    //std::string hash = jkgm_get_tex_hash(vbuf, texture, material, is_alpha_tex);

    jkgm_cache_entry_t* entry = NULL;

    std::string full_fpath_str = std::string(material->mat_full_fpath);
    std::string cache_key = full_fpath_str + std::to_string(cel);
    std::string albedo_tex = "";
    std::string emissive_tex = "";
    std::string displacement_tex = "";
    float emissive_factor[3] = {0.0f, 0.0f, 0.0f};
    float albedo_factor[4] = {1.0f, 1.0f, 1.0f, 1.0f};
    float displacement_factor = 0.0;
    bool found_replace = false;
    bool has_emissive = false;
    bool has_displacement = false;

    jkgm_populate_cache();

    if (texture->cache_entry)
    {
        //printf("Path match!\n");
        entry = texture->cache_entry;
        albedo_tex = entry->albedo_tex;
        emissive_tex = entry->emissive_tex;
        emissive_factor[0] = entry->emissive_factor[0];
        emissive_factor[1] = entry->emissive_factor[1];
        emissive_factor[2] = entry->emissive_factor[2];
        albedo_factor[0] = entry->albedo_factor[0];
        albedo_factor[1] = entry->albedo_factor[1];
        albedo_factor[2] = entry->albedo_factor[2];
        albedo_factor[3] = entry->albedo_factor[3];
        has_emissive = (emissive_tex != "");
        displacement_tex = entry->displacement_tex;
        displacement_factor = entry->displacement_factor;
        has_displacement = (displacement_tex != "");
        found_replace = true;
    }

    if (found_replace) // saberpurple0.mat
    {
        GLuint image_texture;
        glGenTextures(1, &image_texture);
        glActiveTexture(GL_TEXTURE0);

        glBindTexture(GL_TEXTURE_2D, image_texture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
        glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
        //glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        //glPixelStorei(GL_PACK_ALIGNMENT, 1);

        if (jkPlayer_enableTextureFilter)
        {
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        }
        else
        {
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        }

        texture->emissive_texture_id = 0;
        texture->displacement_texture_id = 0;
        texture->texture_id = 0;

        {
            const char* path = albedo_tex.c_str();

            GLubyte* data = (GLubyte*)entry->albedo_data;

            if (data) {
                //printf("Using precached %s\n", path);
            }

            if (data || loadPngImage(path, &entry->albedo_width, &entry->albedo_height, &entry->albedo_hasAlpha, &data, 0))
            {
                //printf("Loaded %s %p\n", path, data);
                //glTexStorage2D(GL_TEXTURE_2D, 1, entry->albedo_hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, entry->albedo_hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, entry->albedo_hasAlpha ? GL_RGBA8 : GL_RGB8, entry->albedo_width, entry->albedo_height, 0,  entry->albedo_hasAlpha ?  GL_BGRA : GL_BGR,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, entry->albedo_hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->texture_id = image_texture;
                texture->albedo_data = data;
                entry->albedo_data = data;
            }
            else
            {
                texture->albedo_data = NULL;
                entry->albedo_data = NULL;
                glDeleteTextures(1, &image_texture);
                if (data) {
                    free(data);
                }

                texture->emissive_texture_id = 0;
                texture->emissive_factor[0] = 0.0f;
                texture->emissive_factor[1] = 0.0f;
                texture->emissive_factor[2] = 0.0f;
                texture->albedo_factor[0] = 1.0f;
                texture->albedo_factor[1] = 1.0f;
                texture->albedo_factor[2] = 1.0f;
                texture->albedo_factor[3] = 1.0f;
                texture->emissive_data = NULL;
                texture->displacement_texture_id = 0;
                texture->displacement_factor = 0.0;
                texture->displacement_data = NULL;
                texture->albedo_data = NULL;

                return 0;
            }
        }

        if (has_emissive)
        {
            GLuint emiss_texture;
            glGenTextures(1, &emiss_texture);
            glBindTexture(GL_TEXTURE_2D, emiss_texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
            glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
            //glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
            //glPixelStorei(GL_PACK_ALIGNMENT, 1);

            if (jkPlayer_enableTextureFilter)
            {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            }
            else
            {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
            }

            const char* path = emissive_tex.c_str();

            GLubyte* data = (GLubyte*)entry->emissive_data;

            if (data) {
                //printf("Using precached %s\n", path);
            }

            if (data || loadPngImage(path, &entry->emissive_width, &entry->emissive_height, &entry->emissive_hasAlpha, &data, 0))
            {
                //printf("Loaded %s\n", path);
                //glTexStorage2D(GL_TEXTURE_2D, 1, entry->emissive_hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, entry->emissive_hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, entry->emissive_hasAlpha ? GL_RGBA8 : GL_RGB8, entry->emissive_width, entry->emissive_height, 0,  entry->emissive_hasAlpha ? GL_RGBA : GL_RGB,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, entry->emissive_hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->emissive_texture_id = emiss_texture;
                texture->emissive_data = data;
                entry->emissive_data = data;
            }
            else
            {
                texture->emissive_data = NULL;
                entry->emissive_data = NULL;
                glDeleteTextures(1, &emiss_texture);
                if (data) {
                    free(data);
                }
            }
        }

        if (has_displacement)
        {
            //printf("%s\n", displacement_tex.c_str());
            GLuint displace_texture;
            glGenTextures(1, &displace_texture);
            glBindTexture(GL_TEXTURE_2D, displace_texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
            glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
            //glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
            //glPixelStorei(GL_PACK_ALIGNMENT, 1);

            if (jkPlayer_enableTextureFilter)
            {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            }
            else
            {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
            }

            const char* path = displacement_tex.c_str();

            GLubyte* data = (GLubyte*)entry->displacement_data;

            if (data) {
                //printf("Using precached %s\n", path);
            }

            if (data || loadPngImage(path, &entry->displacement_width, &entry->displacement_height, &entry->displacement_hasAlpha, &data, 0))
            {
                //printf("Loaded %s\n", path);
                //glTexStorage2D(GL_TEXTURE_2D, 1, entry->displacement_hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, entry->displacement_hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, entry->displacement_hasAlpha ? GL_RGBA8 : GL_RGB8, entry->displacement_width, entry->displacement_height, 0,  entry->displacement_hasAlpha ? GL_RGBA : GL_RGB,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, entry->displacement_hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->displacement_texture_id = displace_texture;
                texture->displacement_data = data;
                entry->displacement_data = data;
            }
            else
            {
                texture->displacement_data = NULL;
                entry->displacement_data = NULL;
                glDeleteTextures(1, &displace_texture);
                if (data) {
                    free(data);
                }
            }
        }

        texture->emissive_factor[0] = emissive_factor[0];
        texture->emissive_factor[1] = emissive_factor[1];
        texture->emissive_factor[2] = emissive_factor[2];
        texture->albedo_factor[0] = albedo_factor[0];
        texture->albedo_factor[1] = albedo_factor[1];
        texture->albedo_factor[2] = albedo_factor[2];
        texture->albedo_factor[3] = albedo_factor[3];
        texture->displacement_factor = displacement_factor;

        std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = texture;
        std3D_aLoadedTextures[std3D_loadedTexturesAmt++] = image_texture;

        texture->is_16bit = 1;
        texture->texture_loaded = 1;

        glBindTexture(GL_TEXTURE_2D, worldpal_texture);

        pRdTexture->has_jkgm_override = 1;
        return 1;
    }

    texture->skip_jkgm = 1;

    stdPlatform_Printf("Cache miss, %s\n", cache_key.c_str());

    return 0;
}

void jkgm_free_cache_entry(jkgm_cache_entry_t* entry)
{
    if (!entry) return;

    if (entry->albedo_data != NULL) {
        jkgm_aligned_free(entry->albedo_data);
        entry->albedo_data = NULL;
    }

    if (entry->emissive_data != NULL) {
        jkgm_aligned_free(entry->emissive_data);
        entry->emissive_data = NULL;
    }

    if (entry->displacement_data != NULL) {
        jkgm_aligned_free(entry->displacement_data);
        entry->displacement_data = NULL;
    }

    entry->albedo_width = 0;
    entry->albedo_height = 0;
    entry->albedo_hasAlpha = 0;

    entry->emissive_width = 0;
    entry->emissive_height = 0;
    entry->emissive_hasAlpha = 0;

    entry->displacement_width = 0;
    entry->displacement_height = 0;
    entry->displacement_hasAlpha = 0;
}

void jkgm_write_png(const char *pFname, int width, int height, uint8_t* paFramebuffer) 
{
    int y;

    FILE *fp = fopen(pFname, "wb");
    if(!fp) return;

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) return;

    png_infop info = png_create_info_struct(png);
    if (!info) return;

    if (setjmp(png_jmpbuf(png))) abort();

    png_init_io(png, fp);

    // Output is 8bit depth, RGBA format.
    png_set_IHDR(
        png,
        info,
        width, height,
        8,
        PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT
    );
    png_write_info(png, info);

    // To remove the alpha channel for PNG_COLOR_TYPE_RGB format,
    // Use png_set_filler().
    //png_set_filler(png, 0, PNG_FILLER_AFTER);

    for(int y = height-1; y >= 0; y--) {
        png_write_row(png, paFramebuffer+(y*width*3));
    }

    png_write_end(png, NULL);

    fclose(fp);

    png_destroy_write_struct(&png, &info);
}

#endif // TARGET_CAN_JKGM
#endif //SDL2_RENDER