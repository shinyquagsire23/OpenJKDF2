#include "rdModel3.h"

#include "Engine/rdroid.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"

void rdModel3_RegisterLoader(model3Loader_t loader)
{
    pModel3Loader = loader;
}

void rdModel3_RegisterUnloader(model3Unloader_t unloader)
{
    pModel3Unloader = unloader;
}

void rdModel3_ClearFrameCounters()
{
    rdModel3_numDrawnModels = 0;
}

int rdModel3_NewEntry(rdModel3 *model)
{
    _memset(model, 0, sizeof(rdModel3));
    _strncpy(model->filename, "UNKNOWN", 0x1Fu);
    model->filename[31] = 0;
    model->field_50 = 0;
    return 0;
}

rdModel3* rdModel3_New(char *path)
{
    rdModel3 *model; // esi

    if ( pModel3Loader )
        return (rdModel3 *)pModel3Loader(path, 0);
    model = (rdModel3 *)rdroid_pHS->alloc(sizeof(rdModel3));
    if ( model )
    {
        if ( rdModel3_Load(path, model) )
            return model;
        if ( model )
        {
            if ( pModel3Unloader )
            {
                pModel3Unloader(model);
                return 0;
            }
            rdModel3_FreeEntry((int)model);
            rdroid_pHS->free(model);
        }
    }
    return 0;
}

int rdModel3_Load(char *model_fpath, rdModel3 *model)
{
    rdMesh *mesh; // ebx
    int vertex_num; // edi
    int v25; // edi
    int v29; // edi
    rdVector3 *vertex_normal; // eax
    char *v35; // eax
    int v36; // eax
    char *to_num_verts; // eax
    unsigned int v49; // ebp
    unsigned int v52; // ebp
    int v55; // edi
    unsigned int idx; // edi
    rdHierarchyNode *node; // esi
    float v_z; // [esp+14h] [ebp-80h]
    float v_y; // [esp+18h] [ebp-7Ch]
    float v_x; // [esp+1Ch] [ebp-78h]
    rdFace *face; // [esp+34h] [ebp-60h]
    int v78; // [esp+50h] [ebp-44h]
    int sibling; // [esp+54h] [ebp-40h]
    float pitch; // [esp+58h] [ebp-3Ch]
    float v_i; // [esp+5Ch] [ebp-38h]
    float yaw; // [esp+60h] [ebp-34h]
    float v_v; // [esp+64h] [ebp-30h]
    float roll; // [esp+68h] [ebp-2Ch]
    int parent; // [esp+6Ch] [ebp-28h]
    float pivot_x; // [esp+70h] [ebp-24h]
    float radius; // [esp+74h] [ebp-20h]
    float pivot_y; // [esp+78h] [ebp-1Ch]
    int extralight; // [esp+7Ch] [ebp-18h]
    float pivot_z; // [esp+80h] [ebp-14h]
    float v_u; // [esp+84h] [ebp-10h]
    int child; // [esp+88h] [ebp-Ch]
    char version_minor; // [esp+8Ch] [ebp-8h]
    char version_major; // [esp+90h] [ebp-4h]
    int geoset_num;

    rdModel3_NewEntry(model);
    _strncpy(model->filename, stdFileFromPath(model_fpath), 0x1Fu);
    model->filename[31] = 0;
    if ( !stdConffile_OpenRead(model_fpath) )
        return 0;

    if (!stdConffile_ReadLine())
        return 0;

    if ( _sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1 )
        return 0;

    if (!stdConffile_ReadLine())
        return 0;

    _sscanf(stdConffile_aLine, " 3do %d.%d", &version_major, &version_minor);
    if (!stdConffile_ReadLine())
        return 0;

    if ( _sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1
      || !stdConffile_ReadLine()
      || _sscanf(stdConffile_aLine, " materials %d", &model->numMaterials) != 1 )
        return 0;

    if ( model->numMaterials)
    {
        model->materials = (rdMaterial **)rdroid_pHS->alloc(sizeof(rdMaterial*) * model->numMaterials);
        if (!model->materials)
            return 0;
    }
    for (int i = 0; i < model->numMaterials; i++)
    {
        if (!stdConffile_ReadLine())
            goto fail;

        if ( _sscanf(stdConffile_aLine, " %d: %s", &geoset_num, std_genBuffer) != 2 )
            goto fail;

        model->materials[i] = rdMaterial_Load(std_genBuffer, 0, 0);

        if ( !model->materials[i] )
            goto fail;
    }

    if (!stdConffile_ReadLine())
        goto fail;

    if ( _sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1 )
        goto fail;

    if (!stdConffile_ReadLine())
        goto fail;

    if ( _sscanf(stdConffile_aLine, " radius %f", &radius) != 1 )
        goto fail;

    model->radius = radius;
    if (!stdConffile_ReadLine())
        goto fail;

    if ( _sscanf(stdConffile_aLine, " insert offset %f %f %f", &v_x, &v_y, &v_z) != 3 )
        goto fail;

    model->insertOffset.x = v_x;
    model->insertOffset.y = v_y;
    model->insertOffset.z = v_z;
    if (!stdConffile_ReadLine())
        goto fail;

    if ( _sscanf(stdConffile_aLine, " geosets %d", &model->numGeosets) != 1 )
        goto fail;
    for (v78 = 0; v78 < model->numGeosets; v78++)
    {
        if (!stdConffile_ReadLine())
            goto fail;
            
        if ( _sscanf(stdConffile_aLine, " geoset %d", &geoset_num) != 1 )
            goto fail;
            
        if ( !stdConffile_ReadLine() )
            goto fail;
            
        if ( _sscanf(stdConffile_aLine, " meshes %d", &model->geosets[v78].numMeshes) != 1 )
            goto fail;

        model->geosets[v78].meshes = (rdMesh *)rdroid_pHS->alloc(sizeof(rdMesh) * model->geosets[v78].numMeshes);
        if ( !model->geosets[v78].meshes )
            goto fail;
        
        for (int i = 0; i < model->geosets[v78].numMeshes; i++)
        {
            mesh = &model->geosets[v78].meshes[i];
            mesh->mesh_num = i;
            if ( !stdConffile_ReadLine() )
                goto fail;
            if ( _sscanf(stdConffile_aLine, " mesh %d", std_genBuffer) != 1 )
                goto fail;
            if ( !stdConffile_ReadLine() )
                goto fail;
            if ( _sscanf(stdConffile_aLine, " name %s", std_genBuffer) != 1 )
                goto fail;

            _strncpy(mesh->name, std_genBuffer, 0x1Fu);
            mesh->name[31] = 0;

            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " radius %f", &mesh->radius) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " geometrymode %d", &mesh->lightingMode) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " lightingmode %d", &mesh->textureMode) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " texturemode %d", &mesh->sortingMethod) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " vertices %d", &mesh->numVertices) != 1
              || mesh->numVertices > 0x200 )
            {
                goto fail;
            }
            
            mesh->vertices = 0;
            mesh->vertices_i = 0;
            mesh->vertices_unk = 0;
            if ( mesh->numVertices)
            {
                mesh->vertices = (rdVector3 *)rdroid_pHS->alloc(sizeof(rdVector3) * mesh->numVertices);
                if ( !mesh->vertices )
                    goto fail;
                mesh->vertices_i = (float *)rdroid_pHS->alloc(sizeof(float) * mesh->numVertices);
                if ( !mesh->vertices_i )
                    goto fail;
                mesh->vertices_unk  = (float *)rdroid_pHS->alloc(sizeof(float) * mesh->numVertices);
                if ( !mesh->vertices_unk  )
                    goto fail;
                _memset(mesh->vertices_unk, 0, mesh->numVertices); // bug?
            }
            for (vertex_num = 0; vertex_num < mesh->numVertices; vertex_num++)
            {
                if ( !stdConffile_ReadLine()
                     || _sscanf(
                            stdConffile_aLine,
                            " %d: %f %f %f %f",
                            &geoset_num,
                            &v_x,
                            &v_y,
                            &v_z,
                            &v_i) != 5 )
                    goto fail;

                mesh->vertices[vertex_num].x = v_x;
                mesh->vertices[vertex_num].y = v_y;
                mesh->vertices[vertex_num].z = v_z;
                mesh->vertices_i[vertex_num] = v_i;
            }

            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " texture vertices %d", &mesh->numUVs) != 1
              || mesh->numUVs > 0x300 )
            {
                goto fail;
            }
            
            mesh->vertexUVs = 0;
            if ( mesh->numUVs )
            {
                mesh->vertexUVs = (rdVector2 *)rdroid_pHS->alloc(sizeof(rdVector2) * mesh->numUVs);
                if ( !mesh->vertexUVs )
                    goto fail;
                for (v25 = 0; v25 < mesh->numUVs; v25++)
                {
                    if ( !stdConffile_ReadLine()
                         || _sscanf(stdConffile_aLine, " %d: %f %f", &geoset_num, &v_u, &v_v) != 3 )
                         goto fail;

                        mesh->vertexUVs[v25].x = v_u;
                        mesh->vertexUVs[v25].y = v_v;
                }
            }

            if ( !stdConffile_ReadLine() )
                goto fail;
            mesh->vertexNormals = 0;
            if ( mesh->numVertices)
            {
                mesh->vertexNormals = (rdVector3 *)rdroid_pHS->alloc(sizeof(rdVector3) * mesh->numVertices);
                if ( !mesh->vertexNormals )
                    goto fail;
            }
            for (v29 = 0; v29 < mesh->numVertices; v29++ )
            {
                
                if ( !stdConffile_ReadLine()
                     || _sscanf(
                            stdConffile_aLine,
                            " %d: %f %f %f",
                            &geoset_num,
                            &v_x,
                            &v_y,
                            &v_z) != 4 )
                    goto fail;

                vertex_normal = &mesh->vertexNormals[v29];
                vertex_normal->x = v_x;
                vertex_normal->y = v_y;
                vertex_normal->z = v_z;                    
            }

            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " faces %d", &mesh->numFaces) != 1
              || mesh->numFaces > 0x200 )
            {
                goto fail;
            }
            mesh->faces = 0;
            if ( mesh->numFaces)
            {
                mesh->faces = (rdFace *)rdroid_pHS->alloc(sizeof(rdFace) * mesh->numFaces);
                if ( !mesh->faces )
                    goto fail;
            }
            
            for (int j = 0; j < mesh->numFaces; j++)
            {
                
                if (!stdConffile_ReadLine())
                    goto fail;

                face = &mesh->faces[j];
                rdFace_NewEntry(face);
                _strtok(stdConffile_aLine, " \t");
                v35 = _strtok(0, " \t");
                v36 = atoi(v35);
                face->num = j;
                face->material = (v36 == -1) ? 0 : model->materials[v36];
                v35 = _strtok(0, " \t");
                if ( _sscanf(v35, "%x", &face->type) != 1 )
                    goto fail;
                v35 = _strtok(0, " \t");
                if ( _sscanf(v35, "%d", &face->lightingMode) != 1 )
                    goto fail;
                v35 = _strtok(0, " \t");
                if ( _sscanf(v35, "%d", &face->textureMode) != 1 )
                    goto fail;
                v35 = _strtok(0, " \t");
                if ( _sscanf(v35, "%d", &face->sortingMethod) != 1 )
                    goto fail;
                v35 = _strtok(0, " \t");
                if ( _sscanf(v35, "%f", &face->extralight) != 1 )
                    goto fail;
                to_num_verts = _strtok(0, " \t");
                face->numVertices = atoi(to_num_verts);
                if ( !face->numVertices )
                    goto fail;
                if ( face->numVertices > 24 )
                    goto fail;
                face->vertexPosIdx = (int*)rdroid_pHS->alloc(sizeof(int) * face->numVertices);
                if ( !face->vertexPosIdx )
                    goto fail;
                if ( face->material && face->material->tex_type & 2 )
                {
                    face->vertexUVIdx = (int*)rdroid_pHS->alloc(sizeof(int) * face->numVertices);
                    if ( !face->vertexUVIdx )
                        goto fail;
                    for (v49 = 0; v49 < face->numVertices; v49++)
                    {
                        v35 = _strtok(0, " \t,");
                        face->vertexPosIdx[v49] = atoi(v35);
                        
                        v35 = _strtok(0, " \t,");
                        face->vertexUVIdx[v49] = atoi(v35);
                    }
                }
                else
                {
                    
                    for (v52 = 0; v52 < face->numVertices; v52++)
                    {
                        v35 = _strtok(0, " \t,");
                        face->vertexPosIdx[v52] = atoi(v35);
                        _strtok(0, " \t,");
                    }
                }
                face++;
            }

            if ( !stdConffile_ReadLine() )
                goto fail;
            for (v55 = 0; v55 < mesh->numFaces; v55++)
            {
                if ( !stdConffile_ReadLine()
                     || _sscanf(
                            stdConffile_aLine,
                            " %d: %f %f %f",
                            &geoset_num,
                            &v_x,
                            &v_y,
                            &v_z) != 4 )
                    goto fail;


                mesh->faces[v55].normal.x = v_x;
                mesh->faces[v55].normal.y = v_y;
                mesh->faces[v55].normal.z = v_z;
            }
        }
    }
    
    if (!stdConffile_ReadLine() )
        goto fail;

    if ( _sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1 )
        goto fail;

    if (!stdConffile_ReadLine())
        goto fail;

    if ( _sscanf(stdConffile_aLine, " hierarchy nodes %d", &model->numHierarchyNodes) != 1 )
        goto fail;

    model->hierarchyNodes = (rdHierarchyNode *)rdroid_pHS->alloc(sizeof(rdHierarchyNode) * model->numHierarchyNodes);
    if (!model->hierarchyNodes)
        goto fail;

    for (idx = 0; idx < model->numHierarchyNodes; idx++)
    {
        node = &model->hierarchyNodes[idx];
        node->idx = idx;
        if ( !stdConffile_ReadLine()
          || _sscanf(
                 stdConffile_aLine,
                 " %d: %x %x %d %d %d %d %d %f %f %f %f %f %f %f %f %f %s",
                 &geoset_num,
                 &node->flags,
                 &node->type,
                 &node->mesh,
                 &parent,
                 &child,
                 &sibling,
                 &node->numChildren,
                 &v_x,
                 &v_y,
                 &v_z,
                 &pitch,
                 &yaw,
                 &roll,
                 &pivot_x,
                 &pivot_y,
                 &pivot_z,
                 node) != 18 )
        {
            goto fail;
        }
        
        if ( parent == -1 )
        {
            node->parent = 0;
        }
        else
        {
            node->parent = &model->hierarchyNodes[parent];
        }

        if ( child == -1 )
            node->child = 0;
        else
            node->child = &model->hierarchyNodes[child];

        if ( sibling == -1 )
            node->nextSibling = 0;
        else
            node->nextSibling = &model->hierarchyNodes[sibling];

        node->pos.x = v_x;
        node->pos.y = v_y;
        node->pos.z = v_z;
        node->rot.x = pitch;
        node->rot.y = yaw;
        node->rot.z = roll;
        node->pivot.x = pivot_x;
        node->pivot.y = pivot_y;
        node->pivot.z = pivot_z;
    }
    stdConffile_Close();
    return 1;

fail:
    stdConffile_Close();
    return 0;
}

void rdModel3_Free(rdModel3 *model)
{
    if ( model )
    {
        if ( pModel3Unloader )
        {
            pModel3Unloader(model);
        }
        else
        {
            rdModel3_FreeEntry(model);
            rdroid_pHS->free(model);
        }
    }
}
