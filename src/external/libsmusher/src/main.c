#include <stdlib.h>
#include <stdio.h>

#include "smush.h"
#include "endian.h"

#include <SDL.h>

void my_audio_callback(void *userdata, Uint8 *stream, int len);
void smush_audio_callback(const uint8_t* data, size_t len);

#define AUDIO_QUEUE_DEPTH (64)

static uint8_t* audio_buf;
static uint8_t* audio_pos;
static uint32_t audio_len;

static uint8_t* audio_queue[AUDIO_QUEUE_DEPTH] = {0};
static size_t audio_queue_lens[AUDIO_QUEUE_DEPTH] = {0};
static int audio_queue_read_idx = 0;
static int audio_queue_write_idx = 0;

int main(int argc, char** argv)
{
    SDL_AudioSpec spec_want, spec_have;

    if (argc <= 1) {
        printf("Usage: %s <movie.san>\n", argv[0]);
        return -1;
    }

    smush_ctx* ctx = smush_from_fpath(argv[1]);
    if (!ctx) {
        printf("Failed to open file `%s`!\n", argv[1]);
        return -1;
    }
    smush_set_debug(ctx, 0);
    smush_set_audio_callback(ctx, smush_audio_callback);
    smush_frame(ctx);

    if(SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) != 0) {
        fprintf(stderr, "Could not init SDL: %s\n", SDL_GetError());
        return 1;
    }
    SDL_Window *window = SDL_CreateWindow("libsmusher tester",
            0,
            0,
            640, 480,
            SDL_WINDOW_SHOWN);
    if(!window) 
    {
        fprintf(stderr, "Could not create window\n");
        return 1;
    }

    SDL_memset(&spec_want, 0, sizeof(spec_want));
    SDL_memset(&spec_have, 0, sizeof(spec_have));
    spec_want.freq = 22050;
    spec_want.format = AUDIO_S16MSB;
    spec_want.channels = 2;
    spec_want.samples = 1024;
    spec_want.callback = my_audio_callback; 
    spec_want.userdata = NULL;
    SDL_AudioDeviceID* dev = SDL_OpenAudioDevice(NULL, 0, &spec_want, &spec_have, 0); // SDL_AUDIO_ALLOW_FORMAT_CHANGE

    audio_pos = NULL;
    audio_len = 0;

    SDL_Color sdl_pal[256];

    //Get window surface
    SDL_Surface* screen_surface = SDL_GetWindowSurface(window);
    SDL_Surface* smush_surface = SDL_CreateRGBSurfaceFrom(ctx->framebuffer, 640, 480, 8, 640, 0,0,0,0);
    
    //smush_print(ctx);

    SDL_PauseAudioDevice(dev, 0);

    int every_third = 0;
    int every_third_ticks = 0;
    SDL_Event e;
    int quit = 0;

    int wait_ticks = 83;
    int last_ticks = SDL_GetTicks();
    while (!quit)
    {
        while (SDL_PollEvent(&e)){
            if (e.type == SDL_QUIT){
                quit = 1;
            }
            if (e.type == SDL_KEYDOWN){
                //quit = 1;
            }
            if (e.type == SDL_MOUSEBUTTONDOWN){
                //quit = 1;
            }
        }

        smush_frame(ctx);

        for(int i = 0; i < 256; i++)
        {
            sdl_pal[i].r = ctx->palette[(i*3)+0];
            sdl_pal[i].g = ctx->palette[(i*3)+1];
            sdl_pal[i].b = ctx->palette[(i*3)+2];
            sdl_pal[i].a = 255;
        }
        SDL_SetPaletteColors(smush_surface->format->palette, sdl_pal, 0, 256);

        SDL_Rect all = {0,0,640,480};
        SDL_BlitSurface(smush_surface, &all, screen_surface, &all);

        SDL_UpdateWindowSurface(window);

        //printf("%u\n", SDL_GetTicks() - last_ticks);
        every_third_ticks += SDL_GetTicks() - last_ticks;
        if (SDL_GetTicks() - last_ticks > 83) {
            wait_ticks--;
        }
        else if (SDL_GetTicks() - last_ticks < 83) {
            wait_ticks++;
        }
        last_ticks = SDL_GetTicks();

        SDL_Delay(wait_ticks);
        every_third++;
        if (every_third >= 3) {
            if (every_third_ticks < 250) {
                SDL_Delay(250 - every_third_ticks);
            }
            
            every_third = 0;
            every_third_ticks = 0;
        }



        //printf("%u %u\n", smush_cur_frame(ctx), smush_num_frames(ctx));
        if (smush_done(ctx)) break;
    }

    SDL_CloseAudio();
    SDL_DestroyWindow(window);
    SDL_Quit();

    smush_destroy(ctx);

    return 0;
}

void smush_audio_callback(const uint8_t* data, size_t len)
{
    audio_queue[audio_queue_write_idx] = data;
    audio_queue_lens[audio_queue_write_idx++] = len;
    audio_queue_write_idx = audio_queue_write_idx % AUDIO_QUEUE_DEPTH;
}

void my_audio_callback(void *userdata, Uint8 *stream, int len) 
{
    if (audio_len <= 0) {
        if (audio_buf) {
            free(audio_buf);
        }
        audio_buf = audio_queue[audio_queue_read_idx];
        audio_len = audio_queue_lens[audio_queue_read_idx];
        audio_pos = audio_buf;

        audio_queue[audio_queue_read_idx] = NULL;
        audio_queue_lens[audio_queue_read_idx++] = 0;
        audio_queue_read_idx = audio_queue_read_idx % AUDIO_QUEUE_DEPTH;
    }
    
    int written_len = 0;
    while (written_len < len) {
        memset(stream, 0, len);
        int to_write = (len > audio_len ? audio_len : len);
        if (to_write && audio_pos) {
            SDL_memcpy(stream, audio_pos, to_write);
        }
        //SDL_MixAudio(stream, audio_pos, len, SDL_MIX_MAXVOLUME);// mix from one buffer into another
        
        written_len += to_write;
        audio_pos += to_write;
        audio_len -= to_write;

        if (audio_len <= 0) {
            if (audio_buf) {
                free(audio_buf);
            }
            audio_buf = audio_queue[audio_queue_read_idx];
            audio_len = audio_queue_lens[audio_queue_read_idx];
            audio_pos = audio_buf;

            audio_queue[audio_queue_read_idx] = NULL;
            audio_queue_lens[audio_queue_read_idx++] = 0;
            audio_queue_read_idx = audio_queue_read_idx % AUDIO_QUEUE_DEPTH;
        }

        if (!audio_pos || !audio_len) {
            break;
        }
    }
    
}