#include "rdCache.h"

#include "Engine/rdroid.h"
#include "Engine/rdActive.h"
#include "Win95/std3D.h"
#include "Engine/rdColormap.h"

#include <math.h>

int rdCache_Startup()
{
    return 1;
}

void rdCache_AdvanceFrame()
{
    if ( rdroid_curAcceleration > 0 )
        std3D_StartScene();
}

void rdCache_FinishFrame()
{
    if ( rdroid_curAcceleration > 0 )
        std3D_EndScene();
}

void rdCache_Reset()
{
    rdCache_numProcFaces = 0;
    rdCache_numUsedVertices = 0;
    rdCache_numUsedTexVertices = 0;
    rdCache_numUsedIntensities = 0;
    rdCache_ulcExtent.x = 0x7FFFFFFF;
    rdCache_ulcExtent.y = 0x7FFFFFFF;
    rdCache_lrcExtent.x = 0;
    rdCache_lrcExtent.y = 0;
}

void rdCache_ClearFrameCounters()
{
    rdCache_drawnFaces = 0;
}

rdProcEntry *rdCache_GetProcEntry()
{
    size_t idx;
    rdProcEntry *out_procEntry;

    idx = rdCache_numProcFaces;
    if ( rdCache_numProcFaces >= 0x400 )
    {
        rdCache_Flush();
        idx = rdCache_numProcFaces;
    }

    if ( (unsigned int)(0x8000 - rdCache_numUsedVertices) < 0x20 )
        return 0;

    if ( (unsigned int)(0x8000 - rdCache_numUsedTexVertices) < 0x20 )
        return 0;

    if ( (unsigned int)(0x8000 - rdCache_numUsedIntensities) < 0x20 )
        return 0;

    out_procEntry = &rdCache_aProcFaces[idx];
    out_procEntry->vertices = &rdCache_aVertices[rdCache_numUsedVertices];
    out_procEntry->vertexUVs = &rdCache_aTexVertices[rdCache_numUsedTexVertices];
    out_procEntry->vertexIntensities = &rdCache_aIntensities[rdCache_numUsedIntensities];
    return out_procEntry;
}

void rdCache_Flush()
{
    size_t v0; // eax
    size_t v1; // edi
    rdProcEntry *face_; // esi
    size_t v3; // edi
    rdProcEntry *face; // esi

    if ( rdCache_numProcFaces )
    {
        if ( rdroid_curSortingMethod == 2 )
        {
            _qsort(rdCache_aProcFaces, rdCache_numProcFaces, sizeof(rdProcEntry), (int (__cdecl *)(const void *, const void *))rdCache_ProcFaceCompare);
        }
        if ( rdroid_curAcceleration <= 0 )
        {
            if ( rdroid_curOcclusionMethod )
            {
                if ( rdroid_curOcclusionMethod == 1 )
                {
                    rdActive_AdvanceFrame();
                    rdActive_DrawScene();
                }
            }
            else if ( rdroid_curZBufferMethod )
            {
                if ( rdroid_curZBufferMethod == 2 )
                {
                    v1 = 0;
                    face_ = rdCache_aProcFaces;
                    if ( rdCache_numProcFaces )
                    {
                        do
                        {
                            if ( (face_->extraData & 1) != 0 )
                                rdCache_DrawFaceUser(face_);
                            else
                                rdCache_DrawFaceZ(face_);
                            ++face_;
                            ++v1;
                        }
                        while ( v1 < rdCache_numProcFaces );
                    }
                }
            }
            else
            {
                v3 = 0;
                face = rdCache_aProcFaces;
                if ( rdCache_numProcFaces )
                {
                    do
                    {
                        if ( (face->extraData & 1) != 0 )
                            rdCache_DrawFaceUser(face);
                        else
                            rdCache_DrawFaceN(face);
                        ++face;
                        ++v3;
                    }
                    while ( v3 < rdCache_numProcFaces );
                }
            }
        }
        else
        {
            rdCache_SendFaceListToHardware();
        }
        rdCache_drawnFaces += rdCache_numProcFaces;
        rdCache_Reset();
    }
}

#if 1

int rdCache_SendFaceListToHardware()
{
    int v0; // ecx
    int v1; // edx
    double v2; // st7
    double v3; // st6
    double v4; // st5
    int vertices_to_add; // eax
    rdClipFrustum *v7; // edx
    double v8; // st7
    int mipmap_level; // edi
    rdProcEntry *active_6c; // esi
    v11_struct v11; // edx
    int expected_alpha; // ecx
    int v14; // eax
    rdTexinfo *v15; // eax
    rdTexture *sith_tex_sel; // esi
    sith_tex_2 *tex2_arr_sel; // eax
    float *vert_lights_iter; // ecx
    int vert_lights_iter_cnt; // edx
    double v21; // st7
    double v22; // st7
    double v23; // st7
    double v24; // st7
    double v25; // st7
    double v26; // st7
    double v27; // st7
    int vertex_cnt; // eax
    rdProcEntry *v31; // eax
    rdVector3 *iterating_6c_vtxs_; // esi
    int v35; // ecx
    double v36; // st7
    double d3dvtx_zval; // st7
    double v38; // st6
    int v39; // eax
    int normals_related; // zf
    double light_level; // st7
    int vertex_b_; // esi
    int vertex_g; // ebx
    int vertex_r; // edi
    rdColormap *v45; // eax
    int v46; // esi
    double v47; // st7
    __int64 v48; // rax
    double v49; // st7
    uint8_t vertex_b; // cl
    rdProcEntry *v52; // esi
    int final_vertex_color; // eax
    rdVector2 *uvs_in_pixels; // eax
    double tex_u_pixels; // st7
    rdVector2 *tex_v_pixels; // eax
    double tex_v; // st7
    unsigned int vtx_idx_inc_max; // eax
    unsigned int iter_6c_vtx_num; // edi
    int v61; // ecx
    int lighting_maybe_2; // edx
    unsigned int v63; // edi
    int pushed_tris; // esi
    size_t v65; // eax
    int tri; // eax
    int lighting_maybe; // ebx
    size_t tri_idx_; // edx
    size_t tri_idx; // eax
    float *v70; // ecx
    int v71; // edx
    double v72; // st7
    double v73; // st7
    double v74; // st7
    double v75; // st7
    double v76; // st7
    double v77; // st7
    double v78; // st7
    int v79; // eax
    sith_tex_2 *v80; // edx
    double v87; // st7
    double v88; // st7
    double v89; // st6
    int v90; // eax
    rdColormap *v91; // esi
    double v92; // st7
    int v93; // eax
    int v94; // ebx
    int v95; // edx
    int v96; // edi
    int v97; // eax
    int v98; // ecx
    double v99; // st7
    __int64 v100; // rax
    double v101; // st7
    uint8_t v103; // cl
    int v104; // eax
    float v105; // ecx
    int v106; // edi
    int v107; // eax
    unsigned int v108; // edi
    int v109; // ecx
    int v110; // edx
    unsigned int v111; // edi
    int v112; // esi
    unsigned int v113; // eax
    rdTri *v114; // eax
    int v115; // ebx
    unsigned int v116; // edx
    unsigned int v117; // eax
    float actual_width; // [esp+1Ch] [ebp-84h]
    float actual_height; // [esp+20h] [ebp-80h]
    float v121; // [esp+24h] [ebp-7Ch]
    float vert_y_int; // [esp+28h] [ebp-78h]
    float vert_x_int; // [esp+30h] [ebp-70h]
    float green_scalar; // [esp+34h] [ebp-6Ch]
    float blue_scalar; // [esp+38h] [ebp-68h]
    int rend_6c_current_idx; // [esp+3Ch] [ebp-64h]
    float red_scalar; // [esp+40h] [ebp-60h]
    int v129; // [esp+44h] [ebp-5Ch]
    int v130; // [esp+48h] [ebp-58h]
    int vertex_a; // [esp+4Ch] [ebp-54h]
    int alpha_upshifta; // [esp+4Ch] [ebp-54h]
    int alpha_is_opaque; // [esp+50h] [ebp-50h]
    float v134; // [esp+54h] [ebp-4Ch]
    int tri_vert_idx; // [esp+58h] [ebp-48h]
    int flags_idk; // [esp+60h] [ebp-40h]
    rdTexinfo *v137; // [esp+64h] [ebp-3Ch]
    int iterating_6c_vtx_idx; // [esp+64h] [ebp-3Ch]
    int mipmap_related; // [esp+68h] [ebp-38h]
    rdVector3 *iterating_6c_vtxs; // [esp+68h] [ebp-38h]
    int mipmap_relatedb; // [esp+68h] [ebp-38h]
    unsigned int out_width; // [esp+6Ch] [ebp-34h] BYREF
    sith_tex_2 *tex2_arr_sel_; // [esp+70h] [ebp-30h]
    unsigned int out_height; // [esp+74h] [ebp-2Ch] BYREF
    int flags_idk_; // [esp+78h] [ebp-28h]
    int a3; // [esp+7Ch] [ebp-24h]
    int lighting_capability; // [esp+80h] [ebp-20h]
    float v148; // [esp+84h] [ebp-1Ch]
    float tris_to_push; // [esp+88h] [ebp-18h]
    int blue; // [esp+8Ch] [ebp-14h]
    rdProcEntry *iterating_6c; // [esp+90h] [ebp-10h]
    int vtx_idx; // [esp+94h] [ebp-Ch]
    int red_and_alpha; // [esp+98h] [ebp-8h]
    int green; // [esp+9Ch] [ebp-4h]

    a3 = 0; // added? aaaaaaa undefined
    v0 = 0;
    v1 = 0;
    v130 = 0;
    v129 = 0;
    alpha_is_opaque = 0;
    flags_idk = 0x33;
    switch ( rdroid_curZBufferMethod )
    {
        case 1:
            flags_idk = 0x1033;
            break;
        case 2:
            flags_idk = 0x1833;
            break;
        case 3:
            flags_idk = 0x833;
            break;
    }
    if ( rdroid_curColorEffects.tint.x > 0.0 || rdroid_curColorEffects.tint.y > 0.0 || rdroid_curColorEffects.tint.z > 0.0 )
    {
        v2 = rdroid_curColorEffects.tint.y * 0.5;
        v3 = rdroid_curColorEffects.tint.z * 0.5;
        v0 = 1;
        v130 = 1;
        red_scalar = rdroid_curColorEffects.tint.x - (v3 + v2);
        v4 = rdroid_curColorEffects.tint.x * 0.5;
        tris_to_push = v4;
        green_scalar = rdroid_curColorEffects.tint.y - (v4 + v3);
        blue_scalar = rdroid_curColorEffects.tint.z - (tris_to_push + v2);
    }
    if ( rdroid_curColorEffects.filter.x || rdroid_curColorEffects.filter.y || rdroid_curColorEffects.filter.z )
    {
        v1 = 1;
        v129 = 1;
    }
    if ( v0 || v1 )
    {
        flags_idk |= 0x8000;
    }
    std3D_ResetRenderList();
    vertices_to_add = 0;
    rdCache_totalNormalTris = 0;
    rdCache_totalSolidTris = 0;
    v7 = rdCamera_pCurCamera->cameraClipFrustum;
    rdCache_totalVerts = 0;
    v8 = 1.0 / v7->field_0.z;
    iterating_6c = rdCache_aProcFaces;
    rend_6c_current_idx = 0;
    v134 = v8;
    
    if ( rdCache_numProcFaces )
    {
        mipmap_level = a3;
        active_6c = iterating_6c;
        while ( 1 )
        {
            flags_idk_ = flags_idk;
            if ( (rdroid_curRenderOptions & 2) != 0 )
                v148 = active_6c->ambientLight;
            else
                v148 = 0.0;

            if ( active_6c->numVertices + vertices_to_add >= d3d_maxVertices )
            {
                if ( vertices_to_add )
                {
                    if ( !std3D_AddRenderListVertices(rdCache_aHWVertices, vertices_to_add) )
                    {
                        std3D_DrawRenderList();
                        std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts);
                    }
                    std3D_RenderListVerticesFinish();
                    if ( rdroid_curZBufferMethod == 2 )
                        _qsort(rdCache_aHWNormalTris, rdCache_totalNormalTris, sizeof(rdTri), rdCache_TriCompare);
                    if ( rdCache_totalSolidTris )
                        std3D_AddRenderListTris(rdCache_aHWSolidTris, rdCache_totalSolidTris);
                    if ( rdCache_totalNormalTris )
                        std3D_AddRenderListTris(rdCache_aHWNormalTris, rdCache_totalNormalTris);
                    std3D_DrawRenderList();
                }
                std3D_ResetRenderList();
                vertices_to_add = 0;
                rdCache_totalNormalTris = 0;
                rdCache_totalSolidTris = 0;
                rdCache_totalVerts = 0;
            }

            v11.mipmap_related = rdroid_curGeometryMode;
            tri_vert_idx = vertices_to_add;

            if ( active_6c->geometryMode < rdroid_curGeometryMode )
                v11.mipmap_related = active_6c->geometryMode;

            mipmap_related = v11.mipmap_related;
            lighting_capability = active_6c->lightingMode;

            if ( lighting_capability >= rdroid_curLightingMode )
                lighting_capability = rdroid_curLightingMode;

            if ( (active_6c->type & 2) != 0 )
            {
                expected_alpha = 90;
                flags_idk_ |= 0x200;
                red_and_alpha = 90;
            }
            else
            {
                expected_alpha = 255;
                red_and_alpha = 255;
            }

            if ( expected_alpha != 255 && !d3d_device_ptr->hasModulateAlpha && !d3d_device_ptr->hasAlphaFlatStippled )
            {
                red_and_alpha = 255;
                alpha_is_opaque = 1;
            }

            v11.material = active_6c->material;
            if ( v11.material )
                break;
LABEL_280:
            active_6c = ++iterating_6c;
            if ( ++rend_6c_current_idx >= rdCache_numProcFaces )
            {
                vertices_to_add = rdCache_totalVerts;
                goto LABEL_282;
            }
            mipmap_level = a3;
            vertices_to_add = rdCache_totalVerts;
        }
        v14 = active_6c->wallCel;
        if ( v14 == -1 )
        {
            v14 = v11.material->celIdx;
            if ( v14 >= 0 )
            {
                if ( v14 > v11.material->num_texinfo - 1 )
                    v14 = v11.material->num_texinfo - 1;
                goto LABEL_56;
            }
        }
        else if ( v14 >= 0 )
        {
            if ( v14 > v11.material->num_texinfo - 1 )
                v14 = v11.material->num_texinfo - 1;
LABEL_56:
            v15 = v11.material->texinfos[v14];
            v137 = v15;
            if ( v11.mipmap_related == 4 && (v15->header.texture_type & 8) == 0 )
            {
                v11.mipmap_related = 3;
                mipmap_related = 3;
            }
            if ( !v15 || (v15->header.texture_type & 8) == 0 )
            {
                tex2_arr_sel_ = 0;
                goto LABEL_99;
            }
            sith_tex_sel = v15->texture_ptr;
            switch ( sith_tex_sel->num_mipmaps )
            {
                case 1:
                    mipmap_level = 0;
LABEL_79:
                    a3 = mipmap_level;
LABEL_80:
                    if ( (sith_tex_sel->alpha_en & 1) != 0 && d3d_device_ptr->hasAlpha )
                    {
                        flags_idk_ |= 0x400;
                    }

                    if ( !rdMaterial_AddToTextureCache(v11.material, sith_tex_sel, mipmap_level, alpha_is_opaque) )
                    {
                        if ( rdCache_totalVerts )
                        {
                            if ( !std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts) )
                            {
                                std3D_DrawRenderList();
                                std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts);
                            }
                            std3D_RenderListVerticesFinish();
                            if ( rdroid_curZBufferMethod == 2 )
                                _qsort(
                                    rdCache_aHWNormalTris,
                                    rdCache_totalNormalTris,
                                    sizeof(rdTri),
                                    rdCache_TriCompare);

                            if ( rdCache_totalSolidTris )
                                std3D_AddRenderListTris(rdCache_aHWSolidTris, rdCache_totalSolidTris);

                            if ( rdCache_totalNormalTris )
                                std3D_AddRenderListTris(rdCache_aHWNormalTris, rdCache_totalNormalTris);

                            std3D_DrawRenderList();
                        }
                        std3D_ResetRenderList();
                        rdCache_totalNormalTris = 0;
                        rdCache_totalSolidTris = 0;
                        rdCache_totalVerts = 0;
                        if ( !rdMaterial_AddToTextureCache(v11.material, sith_tex_sel, mipmap_level, alpha_is_opaque) )
                            return 0;
                    }

                    tex2_arr_sel = &sith_tex_sel->alphaMats[mipmap_level];

                    if ( alpha_is_opaque )
                        tex2_arr_sel = &sith_tex_sel->opaqueMats[mipmap_level];

                    std3D_GetValidDimension(
                        sith_tex_sel->texture_struct[mipmap_level]->format.width,
                        sith_tex_sel->texture_struct[mipmap_level]->format.height,
                        &out_width,
                        &out_height);
                    active_6c = iterating_6c;
                    v11.mipmap_related = mipmap_related;
                    actual_width = (float)(out_width << mipmap_level);
                    actual_height = (float)(out_height << mipmap_level);
LABEL_99:
                    if ( v11.mipmap_related != 3 )
                    {
                        if ( v11.mipmap_related != 4 )
                            goto LABEL_280;
                        if ( lighting_capability == 1 )
                        {
                            if ( active_6c->extralight < 0.0 )
                            {
                                v27 = 0.0;
                            }
                            else if ( active_6c->extralight > 1.0 )
                            {
                                v27 = 1.0;
                            }
                            else
                            {
                                v27 = active_6c->extralight;
                            }
                            if ( v27 > v148 )
                            {
                                if ( active_6c->extralight >= 0.0 )
                                {
                                    if ( active_6c->extralight <= 1.0 )
                                    {
                                        v26 = active_6c->extralight;
                                        goto LABEL_141;
                                    }
LABEL_138:
                                    v26 = 1.0;
                                    goto LABEL_141;
                                }
LABEL_139:
                                v26 = 0.0;
                                goto LABEL_141;
                            }
                        }
                        else
                        {
                            if ( lighting_capability != 2 )
                            {
                                if ( lighting_capability == 3 && active_6c->numVertices )
                                {
                                    vert_lights_iter = active_6c->vertexIntensities;
                                    vert_lights_iter_cnt = active_6c->numVertices;
                                    do
                                    {
                                        v21 = *vert_lights_iter + active_6c->extralight;

                                        if ( v21 < 0.0 )
                                        {
                                            v22 = 0.0;
                                        }
                                        else if ( v21 > 1.0 )
                                        {
                                            v22 = 1.0;
                                        }
                                        else
                                        {
                                            v22 = v21;
                                        }
                                        if ( v22 <= v148 )
                                        {
                                            v23 = v148;
                                        }
                                        else if ( v21 < 0.0 )
                                        {
                                            v23 = 0.0;
                                        }
                                        else if ( v21 > 1.0 )
                                        {
                                            v23 = 1.0;
                                        }
                                        else
                                        {
                                            v23 = v21;
                                        }

                                        *vert_lights_iter = v23 * 255.0;
                                        ++vert_lights_iter;
                                        --vert_lights_iter_cnt;
                                    }
                                    while ( vert_lights_iter_cnt );
                                }
                                goto LABEL_142;
                            }
                            v24 = active_6c->extralight + active_6c->light_level_static;

                            if ( v24 < 0.0 )
                            {
                                v25 = 0.0;
                            }
                            else if ( v24 > 1.0 )
                            {
                                v25 = 1.0;
                            }
                            else
                            {
                                v25 = v24;
                            }
                            if ( v25 > v148 )
                            {
                                if ( v24 >= 0.0 )
                                {
                                    if ( v24 <= 1.0 )
                                    {
                                        v26 = v24;
LABEL_141:
                                        active_6c->light_level_static = v26 * 255.0;
LABEL_142:
                                        vertex_cnt = active_6c->numVertices;
                                        *(float *)&vtx_idx = 0.0;
                                        if ( vertex_cnt )
                                        {
                                            iterating_6c_vtx_idx = 0;
                                            iterating_6c_vtxs = iterating_6c->vertices;
                                            vertex_a = red_and_alpha << 8;
                                            do
                                            {
                                                vert_x_int = round(iterating_6c_vtxs[iterating_6c_vtx_idx].x);
                                                v31 = iterating_6c;
                                                rdCache_aHWVertices[rdCache_totalVerts].x = vert_x_int;
                                                vert_y_int = round(v31->vertices[iterating_6c_vtx_idx].y);
                                                iterating_6c_vtxs_ = v31->vertices;
                                                rdCache_aHWVertices[rdCache_totalVerts].y = vert_y_int;
                                                v36 = iterating_6c_vtxs_[iterating_6c_vtx_idx].z;
                                                iterating_6c_vtxs = iterating_6c_vtxs_;
                                                if ( v36 == 0.0 )
                                                    d3dvtx_zval = 0.0;
                                                else
                                                    d3dvtx_zval = 1.0 / iterating_6c_vtxs_[iterating_6c_vtx_idx].z;
                                                v38 = d3dvtx_zval * v134;
                                                if ( dword_865258 != 16 )
                                                    v38 = 1.0 - v38;
                                                rdCache_aHWVertices[rdCache_totalVerts].z = v38;
                                                v39 = lighting_capability;
                                                normals_related = lighting_capability == 0;
                                                rdCache_aHWVertices[rdCache_totalVerts].nx = d3dvtx_zval * 0.03125;
                                                rdCache_aHWVertices[rdCache_totalVerts].nz = 0.0;
                                                if ( normals_related )
                                                {
                                                    vertex_b_ = 255;
                                                    vertex_g = 255;
                                                    blue = 255;
                                                    green = 255;
                                                    vertex_r = 255;
                                                }
                                                else
                                                {
                                                    if ( v39 == 3 )
                                                        light_level = iterating_6c->vertexIntensities[vtx_idx];
                                                    else
                                                        light_level = iterating_6c->light_level_static;
                                                    vertex_b_ = (__int64)light_level;
                                                    vertex_g = vertex_b_;
                                                    blue = vertex_b_;
                                                    green = vertex_b_;
                                                    vertex_r = vertex_b_;
                                                }
                                                red_and_alpha = vertex_r;
                                                v45 = (rdColormap *)iterating_6c->colormap;
                                                if ( v45 != rdColormap_pIdentityMap )
                                                {
                                                    v46 = iterating_6c->colormap;
                                                    v47 = v45->tint.y * (double)green;
                                                    vertex_r = (uint8_t)(__int64)(v45->tint.x * (double)red_and_alpha);
                                                    red_and_alpha = vertex_r;
                                                    v48 = (__int64)v47;
                                                    v49 = *(float *)(v46 + 44) * (double)blue;
                                                    vertex_g = (uint8_t)v48;
                                                    green = (uint8_t)v48;
                                                    vertex_b_ = (uint8_t)(__int64)v49;
                                                    flags_idk_ |= 0x8000;
                                                    blue = vertex_b_;
                                                }
                                                if ( v129 )
                                                {
                                                    if ( !rdroid_curColorEffects.filter.x )
                                                    {
                                                        vertex_r = 0;
                                                        red_and_alpha = 0;
                                                    }
                                                    if ( !rdroid_curColorEffects.filter.y )
                                                    {
                                                        vertex_g = 0;
                                                        green = 0;
                                                    }
                                                    if ( !rdroid_curColorEffects.filter.z )
                                                    {
                                                        vertex_b_ = 0;
                                                        blue = 0;
                                                    }
                                                }
                                                if ( v130 )
                                                {
                                                    vertex_r += (__int64)((double)red_and_alpha * red_scalar);
                                                    red_and_alpha = vertex_r;
                                                    vertex_g += (__int64)((double)green * green_scalar);
                                                    green = vertex_g;
                                                    vertex_b_ += (__int64)((double)blue * blue_scalar);
                                                    blue = vertex_b_;
                                                }
                                                if ( rdroid_curColorEffects.fade < 1.0 )
                                                {
                                                    vertex_r = (__int64)((double)red_and_alpha * rdroid_curColorEffects.fade);
                                                    vertex_g = (__int64)((double)green * rdroid_curColorEffects.fade);
                                                    vertex_b_ = (__int64)((double)blue * rdroid_curColorEffects.fade);
                                                }
                                                if ( vertex_r < 0 )
                                                {
                                                    vertex_r = (vertex_r & ~0xFF) | 0;
                                                }
                                                else if ( vertex_r > 255 )
                                                {
                                                    vertex_r = (vertex_r & ~0xFF) | 0xFF;
                                                }
                                                if ( vertex_g < 0 )
                                                {
                                                    vertex_g = (vertex_g & ~0xFF) | 0;
                                                }
                                                else if ( vertex_g > 255 )
                                                {
                                                    vertex_g = (vertex_g & ~0xFF) | 0xFF;
                                                }
                                                if ( vertex_b_ < 0 )
                                                {
                                                    vertex_b = (vertex_b & ~0xFF) | 0;
                                                }
                                                else if ( vertex_b_ > 255 )
                                                {
                                                    vertex_b = (vertex_b & ~0xFF) | 0xFF;
                                                }
                                                else
                                                {
                                                    vertex_b = vertex_b_;
                                                }
                                                v52 = iterating_6c;
                                                final_vertex_color = vertex_b | (((uint8_t)vertex_g | ((vertex_a | (uint8_t)vertex_r) << 8)) << 8);
                                                
                                                // For some reason, ny holds the vertex color.
                                                *(uint32_t*)&rdCache_aHWVertices[rdCache_totalVerts].ny = final_vertex_color;
                                                uvs_in_pixels = v52->vertexUVs;
                                                tex_u_pixels = uvs_in_pixels[vtx_idx].x;
                                                tex_v_pixels = &uvs_in_pixels[vtx_idx++];
                                                
                                                rdCache_aHWVertices[rdCache_totalVerts].tu = tex_u_pixels / actual_width;
                                                rdCache_aHWVertices[rdCache_totalVerts].tv = tex_v_pixels->y / actual_height;
                                                
                                                vtx_idx_inc_max = v52->numVertices;
                                                ++rdCache_totalVerts;
                                                ++iterating_6c_vtx_idx;
                                            }
                                            while ( vtx_idx < vtx_idx_inc_max );
                                        }
                                        iter_6c_vtx_num = iterating_6c->numVertices;
                                        if ( iter_6c_vtx_num <= 3 )
                                        {
                                            tri_idx_ = rdCache_totalNormalTris;
                                            tri_idx = rdCache_totalNormalTris;
                                            rdCache_aHWNormalTris[tri_idx].v3 = tri_vert_idx;
                                            rdCache_aHWNormalTris[tri_idx].v2 = tri_vert_idx + 1;
                                            rdCache_aHWNormalTris[tri_idx].v1 = tri_vert_idx + 2;
                                            rdCache_aHWNormalTris[tri_idx].flags = flags_idk_;
                                            rdCache_aHWNormalTris[tri_idx].texture = tex2_arr_sel;
                                            rdCache_totalNormalTris = tri_idx_ + 1;
                                        }
                                        else
                                        {
                                            v61 = iter_6c_vtx_num - 2;
                                            lighting_maybe_2 = 0;
                                            v63 = iter_6c_vtx_num - 1;
                                            pushed_tris = 0;
                                            lighting_capability = 1;
                                            if ( v61 > 0 )
                                            {
                                                v65 = rdCache_totalNormalTris;
                                                rdCache_totalNormalTris += v61;
                                                do
                                                {
                                                    lighting_maybe = lighting_capability;
                                                    rdCache_aHWNormalTris[v65+pushed_tris].v3 = tri_vert_idx + lighting_maybe_2;
                                                    rdCache_aHWNormalTris[v65+pushed_tris].v2 = lighting_maybe + tri_vert_idx;
                                                    rdCache_aHWNormalTris[v65+pushed_tris].v1 = v63 + tri_vert_idx;
                                                    rdCache_aHWNormalTris[v65+pushed_tris].flags = flags_idk_;
                                                    rdCache_aHWNormalTris[v65+pushed_tris].texture = tex2_arr_sel;
                                                    if ( (pushed_tris & 1) != 0 )
                                                    {
                                                        lighting_maybe_2 = v63--;
                                                    }
                                                    else
                                                    {
                                                        lighting_maybe_2 = lighting_maybe;
                                                        lighting_capability = lighting_maybe + 1;
                                                    }
                                                    ++pushed_tris;
                                                }
                                                while ( pushed_tris < v61 );
                                            }
                                        }
                                        goto LABEL_280;
                                    }
                                    goto LABEL_138;
                                }
                                goto LABEL_139;
                            }
                        }
                        v26 = v148;
                        goto LABEL_141;
                    }
                    if ( lighting_capability == 1 )
                    {
                        if ( active_6c->extralight < 0.0 )
                        {
                            v78 = 0.0;
                        }
                        else if ( active_6c->extralight > 1.0 )
                        {
                            v78 = 1.0;
                        }
                        else
                        {
                            v78 = active_6c->extralight;
                        }
                        if ( v78 > v148 )
                        {
                            if ( active_6c->extralight >= 0.0 )
                            {
                                if ( active_6c->extralight <= 1.0 )
                                {
                                    v77 = active_6c->extralight;
                                    goto LABEL_231;
                                }
LABEL_228:
                                v77 = 1.0;
                                goto LABEL_231;
                            }
LABEL_229:
                            v77 = 0.0;
                            goto LABEL_231;
                        }
                    }
                    else
                    {
                        if ( lighting_capability != 2 )
                        {
                            if ( lighting_capability == 3 && active_6c->numVertices )
                            {
                                v70 = active_6c->vertexIntensities;
                                v71 = active_6c->numVertices;
                                do
                                {
                                    v72 = *v70 + active_6c->extralight;

                                    if ( v72 < 0.0 )
                                    {
                                        v73 = 0.0;
                                    }
                                    else if ( v72 > 1.0 )
                                    {
                                        v73 = 1.0;
                                    }
                                    else
                                    {
                                        v73 = v72;
                                    }
                                    if ( v73 <= v148 )
                                    {
                                        v74 = v148;
                                    }
                                    else if ( v72 < 0.0 )
                                    {
                                        v74 = 0.0;
                                    }
                                    else if ( v72 > 1.0 )
                                    {
                                        v74 = 1.0;
                                    }
                                    else
                                    {
                                        v74 = v72;
                                    }

                                    *v70 = v74 * 63.0;
                                    ++v70;
                                    --v71;
                                }
                                while ( v71 );
                            }
                            goto LABEL_232;
                        }
                        v75 = active_6c->extralight + active_6c->light_level_static;

                        if ( v75 < 0.0 )
                        {
                            v76 = 0.0;
                        }
                        else if ( v75 > 1.0 )
                        {
                            v76 = 1.0;
                        }
                        else
                        {
                            v76 = v75;
                        }
                        if ( v76 > v148 )
                        {
                            if ( v75 >= 0.0 )
                            {
                                if ( v75 <= 1.0 )
                                {
                                    v77 = v75;
LABEL_231:
                                    active_6c->light_level_static = v77 * 63.0;
LABEL_232:
                                    v79 = active_6c->numVertices;
                                    *(float *)&vtx_idx = 0.0;
                                    if ( v79 )
                                    {
                                        int tmpiter = 0;
                                        mipmap_relatedb = (int)iterating_6c->vertices;
                                        alpha_upshifta = red_and_alpha << 8;
                                        do
                                        {
                                            rdCache_aHWVertices[rdCache_totalVerts].x = round(iterating_6c->vertices[tmpiter].x);
                                            rdCache_aHWVertices[rdCache_totalVerts].y = round(iterating_6c->vertices[tmpiter].y);
                                            v87 = iterating_6c->vertices[tmpiter].z;

                                            if ( v87 == 0.0 )
                                                v88 = 0.0;
                                            else
                                                v88 = 1.0 / iterating_6c->vertices[tmpiter].z;
                                            v89 = v88 * v134;
                                            if ( dword_865258 != 16 )
                                                v89 = 1.0 - v89;
                                            rdCache_aHWVertices[rdCache_totalVerts].z = v89;
                                            v90 = lighting_capability;
                                            normals_related = lighting_capability == 0;
                                            rdCache_aHWVertices[rdCache_totalVerts].nx = v88 * 0.03125;
                                            rdCache_aHWVertices[rdCache_totalVerts].nz = 0.0;
                                            if ( normals_related )
                                            {
                                                v91 = (rdColormap *)iterating_6c->colormap;
                                                v97 = v137->header.field_4;
                                                v94 = (uint8_t)v91->colors[v97].g;
                                                v98 = (uint8_t)v91->colors[v97].b;
                                                v96 = (uint8_t)v91->colors[v97].r;
                                                red_and_alpha = v96;
                                                green = v94;
                                                blue = v98;
                                            }
                                            else
                                            {
                                                v91 = (rdColormap *)iterating_6c->colormap;
                                                if ( v90 == 3 )
                                                    v92 = iterating_6c->vertexIntensities[vtx_idx];
                                                else
                                                    v92 = iterating_6c->light_level_static;
                                                v93 = *((uint8_t *)v91->lightlevel + 256 * ((__int64)v92 & 0x3F) + v137->header.field_4);
                                                v94 = (uint8_t)v91->colors[v93].g;
                                                v95 = (uint8_t)v91->colors[v93].b;
                                                v96 = (uint8_t)v91->colors[v93].r;
                                                red_and_alpha = v96;
                                                green = v94;
                                                blue = v95;
                                            }
                                            if ( v91 != rdColormap_pIdentityMap )
                                            {
                                                v99 = v91->tint.y * (double)green;
                                                v96 = (uint8_t)(__int64)(v91->tint.x * (double)red_and_alpha);
                                                red_and_alpha = v96;
                                                v100 = (__int64)v99;
                                                v101 = v91->tint.z * (double)blue;
                                                v94 = (uint8_t)v100;
                                                green = (uint8_t)v100;
                                                blue = (uint8_t)(__int64)v101;
                                            }
                                            flags_idk_ |= 0x8000;
                                            if ( v129 )
                                            {
                                                if ( !(*(uint32_t*)&rdroid_curColorEffects.filter.x) )
                                                {
                                                    v96 = 0;
                                                    red_and_alpha = 0;
                                                }
                                                if ( !(*(uint32_t*)&rdroid_curColorEffects.filter.y) )
                                                {
                                                    v94 = 0;
                                                    green = 0;
                                                }
                                                if ( !(*(uint32_t*)&rdroid_curColorEffects.filter.z) )
                                                    blue = 0;
                                            }
                                            if ( v130 )
                                            {
                                                v96 += (__int64)((double)red_and_alpha * red_scalar);
                                                red_and_alpha = v96;
                                                v94 += (__int64)((double)green * green_scalar);
                                                green = v94;
                                                blue += (__int64)((double)blue * blue_scalar);
                                            }
                                            if ( rdroid_curColorEffects.fade < 1.0 )
                                            {
                                                v96 = (__int64)((double)red_and_alpha * rdroid_curColorEffects.fade);
                                                v94 = (__int64)((double)green * rdroid_curColorEffects.fade);
                                                blue = (__int64)((double)blue * rdroid_curColorEffects.fade);
                                            }
                                            if ( v96 < 0 )
                                            {
                                                v96 = (v96 & ~0xFF) | 0;
                                            }
                                            else if ( v96 > 255 )
                                            {
                                                v96 = (v96 & ~0xFF) | 0xff;
                                            }
                                            if ( v94 < 0 )
                                            {
                                                v94 = (v94 & ~0xFF) | 0;
                                            }
                                            else if ( v94 > 255 )
                                            {
                                                v94 = (v94 & ~0xFF) | 0xff;
                                            }
                                            v103 = blue;
                                            if ( blue < 0 )
                                            {
                                                v103 = 0;
                                            }
                                            else if ( blue > 255 )
                                            {
                                                v103 = -1;
                                            }
                                            v104 = v103 | (((uint8_t)v94 | ((alpha_upshifta | (uint8_t)v96) << 8)) << 8);
                                            v105 = tris_to_push;
                                            v106 = rdCache_totalVerts + 1;
                                            *(uint32_t *)&rdCache_aHWVertices[rdCache_totalVerts].ny = v104;
                                            rdCache_aHWVertices[rdCache_totalVerts].tu = 0.0;
                                            v107 = vtx_idx;
                                            rdCache_aHWVertices[rdCache_totalVerts].tv = 0.0;
                                            rdCache_totalVerts = v106;
                                            tmpiter++;
                                            vtx_idx = v107 + 1;
                                        }
                                        while ( (unsigned int)(v107 + 1) < iterating_6c->numVertices );
                                    }
                                    v108 = iterating_6c->numVertices;
                                    if ( v108 <= 3 )
                                    {
                                        v116 = rdCache_totalSolidTris;
                                        v117 = rdCache_totalSolidTris;
                                        rdCache_aHWSolidTris[v117].v3 = tri_vert_idx;
                                        rdCache_aHWSolidTris[v117].v2 = tri_vert_idx + 1;
                                        rdCache_aHWSolidTris[v117].v1 = tri_vert_idx + 2;
                                        rdCache_aHWSolidTris[v117].flags = flags_idk_;
                                        rdCache_aHWSolidTris[v117].texture = 0;
                                        rdCache_totalSolidTris = v116 + 1;
                                    }
                                    else
                                    {
                                        v109 = v108 - 2;
                                        v110 = 0;
                                        v111 = v108 - 1;
                                        v112 = 0;
                                        lighting_capability = 1;
                                        if ( v109 > 0 )
                                        {
                                            v113 = rdCache_totalSolidTris;
                                            rdCache_totalSolidTris += v109;
                                            do
                                            {
                                                v115 = lighting_capability;
                                                rdCache_aHWSolidTris[v113+v112].v3 = tri_vert_idx + v110;
                                                rdCache_aHWSolidTris[v113+v112].v2 = v115 + tri_vert_idx;
                                                rdCache_aHWSolidTris[v113+v112].v1 = v111 + tri_vert_idx;
                                                rdCache_aHWSolidTris[v113+v112].flags = flags_idk_;
                                                rdCache_aHWSolidTris[v113+v112].texture = 0;
                                                if ( (v112 & 1) != 0 )
                                                {
                                                    v110 = v111--;
                                                }
                                                else
                                                {
                                                    v110 = v115;
                                                    lighting_capability = v115 + 1;
                                                }
                                                ++v112;
                                            }
                                            while ( v112 < v109 );
                                        }
                                    }
                                    goto LABEL_280;
                                }
                                goto LABEL_228;
                            }
                            goto LABEL_229;
                        }
                    }
                    v77 = v148;
                    goto LABEL_231;
                case 2:
                    if ( iterating_6c->z_min <= (double)rdroid_aMipDistances.y )
                    {
                        mipmap_level = 0;
                        goto LABEL_79;
                    }
                    break;
                case 3:
                    if ( iterating_6c->z_min <= (double)rdroid_aMipDistances.x )
                    {
                        mipmap_level = 0;
                        goto LABEL_79;
                    }
                    if ( iterating_6c->z_min > (double)rdroid_aMipDistances.y )
                    {
                        mipmap_level = 2;
                        goto LABEL_79;
                    }
                    break;
                case 4:
                    if ( iterating_6c->z_min <= (double)rdroid_aMipDistances.x )
                    {
                        mipmap_level = 0;
                        goto LABEL_79;
                    }
                    if ( iterating_6c->z_min > (double)rdroid_aMipDistances.y )
                    {
                        if ( iterating_6c->z_min > (double)rdroid_aMipDistances.z )
                            mipmap_level = 3;
                        else
                            mipmap_level = 2;
                        goto LABEL_79;
                    }
                    break;
                default:
                    goto LABEL_80;
            }
            mipmap_level = 1;
            goto LABEL_79;
        }
        v14 = 0;
        goto LABEL_56;
    }
LABEL_282:
    if ( vertices_to_add )
    {
        if ( !std3D_AddRenderListVertices(rdCache_aHWVertices, vertices_to_add) )
        {
            std3D_DrawRenderList();
            std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts);
        }
        std3D_RenderListVerticesFinish();
        if ( rdroid_curZBufferMethod == 2 )
            _qsort(rdCache_aHWNormalTris, rdCache_totalNormalTris, sizeof(rdTri), rdCache_TriCompare);
        if ( rdCache_totalSolidTris )
            std3D_AddRenderListTris(rdCache_aHWSolidTris, rdCache_totalSolidTris);
        if ( rdCache_totalNormalTris )
            std3D_AddRenderListTris(rdCache_aHWNormalTris, rdCache_totalNormalTris);
        std3D_DrawRenderList();
    }
    return 1;
}


#endif

void rdCache_ResetRenderList()
{
    std3D_ResetRenderList();
    rdCache_totalNormalTris = 0;
    rdCache_totalSolidTris = 0;
    rdCache_totalVerts = 0;
}

void rdCache_DrawRenderList()
{
    if ( rdCache_totalVerts )
    {
        if ( !std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts) )
        {
            std3D_DrawRenderList();
            std3D_AddRenderListVertices(rdCache_aHWVertices, rdCache_totalVerts);
        }
        std3D_RenderListVerticesFinish();
        if ( rdroid_curZBufferMethod == 2 )
            _qsort(rdCache_aHWNormalTris, rdCache_totalNormalTris, sizeof(rdTri), rdCache_TriCompare);
        if ( rdCache_totalSolidTris )
            std3D_AddRenderListTris(rdCache_aHWSolidTris, rdCache_totalSolidTris);
        if ( rdCache_totalNormalTris )
            std3D_AddRenderListTris(rdCache_aHWNormalTris, rdCache_totalNormalTris);
        std3D_DrawRenderList();
    }
}

int rdCache_TriCompare(rdTri *a, rdTri *b)
{
    sith_tex_2 *tex_b;
    sith_tex_2 *tex_a;

    tex_b = b->texture;
    tex_a = a->texture;

    if ( tex_a->is_16bit == tex_b->is_16bit )
        return tex_a - tex_b;
    else
        return tex_a->is_16bit != 0 ? 1 : -1;
}

int rdCache_ProcFaceCompare(rdProcEntry *a, rdProcEntry *b)
{
    if ( a->z_min == b->z_min )
        return 0;

    if ( a->z_min >= b->z_min )
        return -1;

    return 1;
}
