#include "types.h"

#include <stdlib.h>
#include <stdio.h>

#include "General/stdBitmapRle.h"
#include "General/stdFnames.h"
#include "Engine/rdColormap.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "Platform/GL/jkgm.h"
#include "Win95/std.h"

static HostServices hs;

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#if defined(SDL2_RENDER)
#include "SDL2_helper.h"
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <stdbool.h>
#if defined(LINUX) || defined(MACOS)
#include <pwd.h>
#endif
#include "nfd.h"
#endif

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif


void RLE_decompress_type1(uint8_t* out_data, uint32_t out_data_stride, uint8_t *data, bitmapExtent *pDstExtent, bitmapExtent *pSrcExtent)
{
  uint8_t bVar1;
  short sVar2;
  short dst_x;
  uint uVar3;
  uint uVar4;
  ushort uVar5;
  uint8_t *pbVar6;
  uint8_t *op_data;
  short sVar7;
  int pbVar15;
  short sVar8;
  int op2;
  ushort op1;
  short src_height;
  short src_width;
  short src_x;
  ushort src_y;
  
  dst_x = pDstExtent->x;
  src_width = pSrcExtent->width;
  src_y = pSrcExtent->y;
  src_x = pSrcExtent->x;
  src_height = pSrcExtent->height;
  op1 = pDstExtent->height - 1;
  pbVar15 = (int)op1;
  int tmp_idk = pbVar15;
  while ((short)src_y <= (short)op1) 
  {
    op1 = (ushort)*data;
    sVar7 = (short)pbVar15;
    if (op1 == 0) 
    {
      op1 = (ushort)data[1];
      op2 = (int)(short)op1;
      op_data = data + 2;
      if (op2 == 0) 
      {
        tmp_idk = pbVar15 - 1;
        dst_x = pDstExtent->x;
        pbVar15 = tmp_idk;
      }
      else if (op2 == 1) 
      {
        tmp_idk = src_y - 1;
        pbVar15 = tmp_idk;
      }
      else if (op2 == 2)
      {
        bVar1 = *op_data;
        op_data = data + 4;
        dst_x = dst_x + (ushort)bVar1;
        tmp_idk = pbVar15 - (uint)data[3];
        pbVar15 = tmp_idk;
      }
      else 
      {
        if (sVar7 < src_height) 
        {
          sVar2 = dst_x;
          if (dst_x < src_x) 
          {
            sVar2 = src_x - dst_x;
            if (sVar2 < (short)op1) {
              op_data = op_data + sVar2;
              op1 = op1 - sVar2;
              sVar2 = src_x;
            }
            else {
              sVar2 = dst_x + op1;
              op_data = op_data + op2;
              op1 = 0;
            }
          }
          if (src_width <= sVar2) {
            sVar2 = sVar2 + op1;
            op_data = op_data + (short)op1;
            op1 = 0;
          }
          dst_x = sVar2;
          if (0 < (short)op1) {
            dst_x = op1 + sVar2;
            sVar8 = 0;
            uVar5 = op1;
            if (src_width <= dst_x) {
              uVar5 = src_width - sVar2;
              sVar8 = op1 - uVar5;
            }
            pbVar6 = (uint8_t *)(out_data_stride * (int)sVar7 + out_data + (int)sVar2);
            if (uVar5 != 0) {
              op2 = (short)(uVar5 - 1) + 1;
              do {
                if (*op_data != 0) {
                  *pbVar6 = *op_data;
                }
                pbVar6 = pbVar6 + 1;
                op_data = op_data + 1;
                op2 = op2 + -1;
              } while (op2 != 0);
            }
            op_data = op_data + sVar8;
            pbVar15 = tmp_idk;
          }
        }
        else {
          op_data = op_data + op2;
          dst_x = dst_x + op1;
        }
        if (((intptr_t)op_data & 1) != 0) {
          op_data = op_data + 1;
        }
      }
    }
    else 
    {
      bVar1 = data[1];
      op_data = data + 2;
      if ((sVar7 < src_height) && (bVar1 != 0)) {
        sVar2 = dst_x;
        if (dst_x < src_x) {
          if ((short)(src_x - dst_x) < (short)op1) {
            op1 = op1 - (src_x - dst_x);
            sVar2 = src_x;
          }
          else {
            sVar2 = dst_x + op1;
            op1 = 0;
          }
        }
        if (src_width <= sVar2) {
          sVar2 = sVar2 + op1;
          op1 = 0;
        }
        dst_x = sVar2;
        if (0 < (short)op1) {
          dst_x = op1 + sVar2;
          if (src_width <= dst_x) {
            op1 = src_width - sVar2;
          }
          pbVar15 = tmp_idk;
          if (op1 != 0) {
            uVar3 = (int)(short)(op1 - 1) + 1;
            uint8_t* puVar9 = (out_data_stride * (int)sVar7 + out_data + (int)sVar2);
            for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
              puVar9[0] = bVar1;
              puVar9[1] = bVar1;
              puVar9[2] = bVar1;
              puVar9[3] = bVar1;
              puVar9 = puVar9 + 4;
            }
            for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
              puVar9[0] = bVar1;
              puVar9 = puVar9 + 1;
            }
          }
        }
      }
      else {
        dst_x = dst_x + op1;
      }
    }
    data = op_data;
    op1 = (ushort)pbVar15;
  }
  return;
}

//for i in /Users/maxamillion/workspace/OpenJKDF2/DW_res/dwCD/images/*.rle; do ../build_darwin64/rle_test "$i"; done


int main(int argc, char** argv)
{
    rleBitmapHeader header;
    rleBitmapHeaderExt header_ext;
    rdColormap colormap;
    uint8_t pal_stored[0x400];

    printf("RLE test!\n");

    if (argc < 2) {
        printf("Usage: %s <file.rle> [palette.cmp]\n", argv[0]);
        return -1;
    }
    char* fpath = argv[1];
    printf("Read %s\n", fpath);

#if defined(PLATFORM_POSIX)
    // Make sure floating point stuff is using . and not ,
    setlocale(LC_ALL, "C");
#endif

    stdInitServices(&hs); 
    stdPlatform_Printf("%s\n", Main_path);

    hs.debugPrint = stdConsolePrintf;
    hs.messagePrint = stdConsolePrintf;
    hs.errorPrint = stdConsolePrintf;
    pHS = &hs;
    std_pHS = &hs;
    rdroid_pHS = &hs;

    stdStartup(&hs); // Added
    //InstallHelper_SetCwd(); // Added

    stdFile_t fp = (stdFile_t)fopen(fpath, "rb");
    int has_pal = argc <= 2 ? 0 : rdColormap_LoadEntry(argv[2], &colormap);
    
    printf("%lx %lx %lx\n", fp, sizeof(header), sizeof(header_ext));
    std_pHS->fileRead(fp, &header, sizeof(header));
    std_pHS->fileRead(fp, &header_ext, sizeof(header_ext));
    std_pHS->fileRead(fp, pal_stored, sizeof(pal_stored));

    if (!header_ext.data_length)
    {
        header_ext.data_length = header.total_size - header.data_start;
    }
    void* pAlloc = std_pHS->alloc(header_ext.data_length);
    std_pHS->fseek(fp, header.data_start, SEEK_SET);
    std_pHS->fileRead(fp, pAlloc, header_ext.data_length);

    printf("Header:\n");
    printf("magic:      %02x\n", header.magic);
    printf("total_size: %04x\n", header.total_size);
    printf("field_6:    %04x\n", header.field_6);
    printf("data_start: %04x\n", header.data_start);

    printf("\nExt header:\n");
    printf("ext_length:  %04x\n", header_ext.ext_length);
    printf("width:       %04x\n", header_ext.width);
    printf("height:      %04x\n", header_ext.height);
    printf("field_C:     %02x\n", header_ext.field_C);
    printf("bpp:         %02x\n", header_ext.bpp);

    printf("format:      %04x\n", header_ext.format);
    printf("data_length: %04x\n", header_ext.data_length);
    printf("field_18:    %04x\n", header_ext.field_18);
    printf("field_1C:    %04x\n", header_ext.field_1C);

    printf("field_20:    %04x\n", header_ext.field_20);
    printf("field_24:    %04x\n", header_ext.field_24);

    printf("\nMisc:\n");
    printf("Decompressed size: %04x\n", header_ext.width * header_ext.height);

    fclose((FILE*)fp);

    bitmapExtent dstExtent = {0,0, header_ext.width, header_ext.height};
    bitmapExtent srcExtent = {0,0, header_ext.width, header_ext.height};

    uint8_t* out_data = std_pHS->alloc(header_ext.width * header_ext.height);
    uint8_t* out_data_converted = std_pHS->alloc(header_ext.width * header_ext.height * 3);
    memset(out_data, 0, header_ext.width * header_ext.height);
    memset(out_data_converted, 0, header_ext.width * header_ext.height * 3);
    RLE_decompress_type1(out_data, header_ext.width, pAlloc, &dstExtent, &srcExtent);

    char tmp[1024];
    char tmp2[1024];
    //FILE* f_out = fopen("test.rle_dec", "wb");
    //fwrite(out_data, 1, header_ext.width * header_ext.height, f_out);
    //fclose(f_out);

    for (int i = 0; i < header_ext.width; i++)
    {
        for (int j = 0; j < header_ext.height; j++)
        {
            int idx = i+(j*header_ext.width);
            int idx_out = i+((header_ext.height-j-1)*header_ext.width);
            uint8_t val = out_data[idx];
            
            out_data_converted[(idx_out*3)+0] = pal_stored[(val*4)+2];
            out_data_converted[(idx_out*3)+1] = pal_stored[(val*4)+1];
            out_data_converted[(idx_out*3)+2] = pal_stored[(val*4)+0];
        }
    }

    stdFnames_CopyMedName(tmp, sizeof(tmp), fpath);
    strcat(tmp, ".png");

    jkgm_write_png(tmp, header_ext.width, header_ext.height, out_data_converted);

    if (!has_pal) return 0;

    for (int i = 0; i < header_ext.width; i++)
    {
        for (int j = 0; j < header_ext.height; j++)
        {
            int idx = i+(j*header_ext.width);
            int idx_out = i+((header_ext.height-j-1)*header_ext.width);
            uint8_t val = out_data[idx];
            
            out_data_converted[(idx_out*3)+0] = colormap.colors[val].b;
            out_data_converted[(idx_out*3)+1] = colormap.colors[val].g;
            out_data_converted[(idx_out*3)+2] = colormap.colors[val].r;
        }
    }

    stdFnames_CopyMedName(tmp, sizeof(tmp), fpath);
    stdFnames_CopyMedName(tmp2, sizeof(tmp2), argv[2]);
    strcat(tmp, "_");
    strcat(tmp, tmp2);
    strcat(tmp, ".png");

    jkgm_write_png(tmp, header_ext.width, header_ext.height, out_data_converted);
}