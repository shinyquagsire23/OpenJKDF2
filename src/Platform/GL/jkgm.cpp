#include "jkgm.h"

#ifdef SDL2_RENDER

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <unordered_map>
#include "General/md5.h"
#include "jk.h"

namespace fs = std::filesystem;

extern "C" {

#include <png.h>

extern void* worldpal_data;
extern rdDDrawSurface* std3D_aLoadedSurfaces[1024];
extern GLuint std3D_aLoadedTextures[1024];
extern size_t std3D_loadedTexturesAmt;
extern int jkPlayer_enableTextureFilter;

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
        printf("%02x", p[i]);
    }
    printf("\n");
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
        printf("Failed in png_create_info_struct\n");
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
        printf("Failed to read `%s`\n", name);
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

typedef struct jkgm_cache_entry_t
{
    std::string albedo_tex;
    std::string emissive_tex;
    std::string displacement_tex;
    float emissive_factor[3];
    float displacement_factor;
} jkgm_cache_entry_t;

static std::unordered_map<std::string, jkgm_cache_entry_t> jkgm_cache;
static std::unordered_map<std::string, jkgm_cache_entry_t> jkgm_cache_hash;
static bool jkgm_cache_once = false;
static bool jkgm_fastpath_disable = false;

#if 0
static void jkgm_populate_cache()
{
    for (const auto& entry : fs::directory_iterator(jkgm_materials_path)) {
        if (!entry.is_directory()) {
            continue;
        }
        const auto dir_iter_str = entry.path().filename().string();

        std::string base_path = "jkgm/materials/" + dir_iter_str + "/";
        std::string metadata_path = base_path + "metadata.json";

        try
        {
            std::ifstream i(metadata_path);
            nlohmann::json jkgm_metadata;
            i >> jkgm_metadata;

        //std::cout << jkgm_metadata.dump(4) << std::endl;

       
            for (auto it : jkgm_metadata["materials"])
            {
                //TODO safety/bounds checks
                for (auto hash_it : it["replaces_signatures"]) {
                    auto bytes = hex_to_bytes(hash_it);
                    //print_hash(bytes.data());
                    //std::cout << hash_it << std::endl;
                    if (!memcmp(bytes.data(), ctx.digest, bytes.size())) {
                        found_replace = true;
                        break;
                    }
                }

                //TODO safety/bounds checks
                for (auto repl_it : it["replaces"]) {
                    int cel_idx = repl_it["cel"];
                    if (cel_idx != cel) continue;

                    std::string name = repl_it["name"];
                    const char* name_c = name.c_str();
                    if (!strcmp(name_c, material->mat_full_fpath)) {
                        printf("Hash match!\n");
                        found_replace = true;
                        break;
                    }
                }
                
                if (found_replace) {
                    printf("Found replace,\n");
                    //TODO safety/bounds checks
                    if (it["emissive_factor"].type() != nlohmann::json::value_t::null) {
                        auto json_emissive_factor = it["emissive_factor"];
                        emissive_factor[0] = json_emissive_factor[0];
                        emissive_factor[1] = json_emissive_factor[1];
                        emissive_factor[2] = json_emissive_factor[2];

                        emissive_tex = base_path + it.value("emissive_map", "");
                        if (emissive_tex != "")
                            has_emissive = true;
                    }
                    
                    albedo_tex = base_path + it.value("albedo_map", "");
                    printf("Found replace done\n");

                    //std::cout << it.dump(4) << std::endl;
                    break;
                }
            }

            if (found_replace) {
                break;
            }
        }
        catch(nlohmann::json::parse_error& e)
        {
            std::cout << "Parse error while reading metadata `" << metadata_path << "`:";
            std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n'
                  << "byte position of error: " << e.byte << std::endl;

            found_replace = false;
        }
        catch(nlohmann::json::exception& e)
        {
            std::cout << "Exception while parsing metadata `" << metadata_path << "`:";
            std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n' << std::endl;

            found_replace = false;
        }
    }
}
#endif

static std::string jkgm_hash_to_str(uint8_t *p){
    char tmp[32+2];
    char* tmp_it = tmp;
    for(unsigned int i = 0; i < 16; ++i){
        sprintf(tmp_it, "%02x", p[i]);
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

                    entry.emissive_tex = it.value("emissive_map", "");
                    if (entry.emissive_tex != "") {
                        entry.emissive_tex = base_path + entry.emissive_tex;
                    }
                }
                else
                {
                    entry.emissive_factor[0] = 0.0f;
                    entry.emissive_factor[1] = 0.0f;
                    entry.emissive_factor[2] = 0.0f;
                    entry.emissive_tex = "";
                }

                if (it["displacement_factor"].type() != nlohmann::json::value_t::null) {
                    auto json_displacement_factor = it["displacement_factor"];
                    entry.displacement_factor = json_displacement_factor;

                    entry.displacement_tex = it.value("displacement_map", "");
                    if (entry.displacement_tex != "") {
                        entry.displacement_tex = base_path + entry.displacement_tex;
                    }
                    printf("%s %f\n", entry.displacement_tex.c_str(), entry.displacement_factor);
                }
                else
                {
                    entry.displacement_factor = 0.0f;
                    entry.displacement_tex = "";
                }
                    
                entry.albedo_tex = base_path + it.value("albedo_map", "");

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
    //if (ctx.digest[0] == 0x35 && ctx.digest[1] == 0x8F)
    //print_hash(ctx.digest);

    std::string hash = jkgm_hash_to_str(ctx.digest);
    return hash;
}

void jkgm_populate_shortcuts(stdVBuffer *vbuf, rdDDrawSurface *texture, rdMaterial* material, int is_alpha_tex, int cel)
{
    if (!vbuf || !texture || jkgm_fastpath_disable) return;

    jkgm_populate_cache();

    std::string hash = jkgm_get_tex_hash(vbuf, texture, material, is_alpha_tex);

    std::string full_fpath_str = std::string(material->mat_full_fpath);
    std::string cache_key = full_fpath_str + std::to_string(cel);

    //printf("%s %s %s\n", full_fpath_str.c_str(), cache_key.c_str(), hash.c_str());

    if (jkgm_cache.find(cache_key) != jkgm_cache.end()) {
        texture->skip_jkgm = 0;
        return;
    }

    if (jkgm_cache_hash.find(hash) != jkgm_cache_hash.end()) {
        texture->skip_jkgm = 0;
        return;
    }

    texture->skip_jkgm = 1;
}

int jkgm_std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha, rdMaterial* material, int cel)
{
    texture->emissive_texture_id = 0;
    texture->emissive_factor[0] = 0.0f;
    texture->emissive_factor[1] = 0.0f;
    texture->emissive_factor[2] = 0.0f;
    texture->emissive_data = NULL;
    texture->displacement_texture_id = 0;
    texture->displacement_factor = 0.0;
    texture->displacement_data = NULL;
    texture->albedo_data = NULL;

    if (jkgm_fastpath_disable || texture->skip_jkgm) {
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

    std::string hash = jkgm_get_tex_hash(vbuf, texture, material, is_alpha_tex);

    std::string full_fpath_str = std::string(material->mat_full_fpath);
    std::string cache_key = full_fpath_str + std::to_string(cel);
    std::string albedo_tex = "";
    std::string emissive_tex = "";
    std::string displacement_tex = "";
    float emissive_factor[3] = {0.0f, 0.0f, 0.0f};
    float displacement_factor = 0.0;
    bool found_replace = false;
    bool has_emissive = false;
    bool has_displacement = false;
    
    jkgm_populate_cache();

    if (jkgm_cache.find(cache_key) != jkgm_cache.end()) {
        //printf("Path match!\n");
        jkgm_cache_entry_t entry = jkgm_cache[cache_key];
        albedo_tex = entry.albedo_tex;
        emissive_tex = entry.emissive_tex;
        emissive_factor[0] = entry.emissive_factor[0];
        emissive_factor[1] = entry.emissive_factor[1];
        emissive_factor[2] = entry.emissive_factor[2];
        has_emissive = (emissive_tex != "");
        displacement_tex = entry.displacement_tex;
        displacement_factor = entry.displacement_factor;
        has_displacement = (displacement_tex != "");
        found_replace = true;
        goto found_cached;
    }

    if (jkgm_cache_hash.find(hash) != jkgm_cache_hash.end()) {
        //printf("Hash match!\n");
        jkgm_cache_entry_t entry = jkgm_cache_hash[hash];
        albedo_tex = entry.albedo_tex;
        emissive_tex = entry.emissive_tex;
        emissive_factor[0] = entry.emissive_factor[0];
        emissive_factor[1] = entry.emissive_factor[1];
        emissive_factor[2] = entry.emissive_factor[2];
        has_emissive = (emissive_tex != "");
        displacement_tex = entry.displacement_tex;
        displacement_factor = entry.displacement_factor;
        has_displacement = (displacement_tex != "");
        found_replace = true;
        goto found_cached;
    }

#if 0
    if (found_replace) {
        jkgm_cache_entry_t entry;
        entry.albedo_tex = albedo_tex;
        entry.emissive_tex = emissive_tex;
        entry.emissive_factor[0] = emissive_factor[0];
        entry.emissive_factor[1] = emissive_factor[1];
        entry.emissive_factor[2] = emissive_factor[2];
        jkgm_cache[full_fpath_str] = entry;
    }
#endif

found_cached:
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

            GLubyte* data = NULL;
            int width = 0;
            int height = 0;
            int hasAlpha = 0;

            if (loadPngImage(path, &width, &height, &hasAlpha, &data, 0))
            {
                //printf("Loaded %s %p\n", path, data);
                //glTexStorage2D(GL_TEXTURE_2D, 1, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height, 0,  hasAlpha ?  GL_BGRA : GL_BGR,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->texture_id = image_texture;
                texture->albedo_data = data;
            }
            else
            {
                texture->albedo_data = NULL;
                glDeleteTextures(1, &image_texture);
                if (data) {
                    free(data);
                }
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

            GLubyte* data = NULL;
            int width = 0;
            int height = 0;
            int hasAlpha = 0;

            if (loadPngImage(path, &width, &height, &hasAlpha, &data, 0))
            {
                //printf("Loaded %s\n", path);
                //glTexStorage2D(GL_TEXTURE_2D, 1, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height, 0,  hasAlpha ? GL_RGBA : GL_RGB,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->emissive_texture_id = emiss_texture;
                texture->emissive_data = data;;
            }
            else
            {
                texture->emissive_data = NULL;
                glDeleteTextures(1, &emiss_texture);
                if (data) {
                    free(data);
                }
            }
        }

        if (has_displacement)
        {
            printf("%s\n", displacement_tex.c_str());
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

            GLubyte* data = NULL;
            int width = 0;
            int height = 0;
            int hasAlpha = 0;

            if (loadPngImage(path, &width, &height, &hasAlpha, &data, 0))
            {
                //printf("Loaded %s\n", path);
                //glTexStorage2D(GL_TEXTURE_2D, 1, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height);
                //glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, hasAlpha ? GL_RGBA : GL_RGB, GL_UNSIGNED_INT_8_8_8_8_REV, data);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
                glTexImage2D(GL_TEXTURE_2D, 0, hasAlpha ? GL_RGBA8 : GL_RGB8, width, height, 0,  hasAlpha ? GL_RGBA : GL_RGB,     GL_UNSIGNED_BYTE, data);
                //glGetTexImage(GL_TEXTURE_2D, 0, hasAlpha ? GL_BGRA : GL_BGR, GL_UNSIGNED_BYTE, data);
                //printf("%x\n", *(uint32_t*)data);
                texture->displacement_texture_id = displace_texture;
                texture->displacement_data = data;;
            }
            else
            {
                texture->displacement_data = NULL;
                glDeleteTextures(1, &displace_texture);
                if (data) {
                    free(data);
                }
            }
        }

        texture->emissive_factor[0] = emissive_factor[0];
        texture->emissive_factor[1] = emissive_factor[1];
        texture->emissive_factor[2] = emissive_factor[2];
        texture->displacement_factor = displacement_factor;

        std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = texture;
        std3D_aLoadedTextures[std3D_loadedTexturesAmt++] = image_texture;

        texture->is_16bit = 1;
        texture->texture_loaded = 1;
        return 1;
    }

    texture->skip_jkgm = 1;

    printf("Cache miss, %s\n", cache_key.c_str());

    return 0;
}

#endif //SDL2_RENDER