#include "rdModel3.h"

#include "Engine/rdroid.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdMath.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdClip.h"
#include "Win95/std.h"
#include "Engine/rdCache.h"
#include "Engine/rdColormap.h"
#include "Primitives/rdPrimit3.h"
#include "Primitives/rdDebug.h"

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
    model->geosetSelect = 0;
    return 0;
}

rdModel3* rdModel3_New(char *path)
{
    rdModel3 *model;

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
            rdModel3_FreeEntry(model);
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
    char *tmpTxt; // eax
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
    int version_minor; // [esp+8Ch] [ebp-8h]
    int version_major; // [esp+90h] [ebp-4h]
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
              || _sscanf(stdConffile_aLine, " geometrymode %d", &mesh->geometryMode) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " lightingmode %d", &mesh->lightingMode) != 1
              || !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " texturemode %d", &mesh->textureMode) != 1
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
                tmpTxt = _strtok(0, " \t");
                v36 = _atoi(tmpTxt);
                face->num = j;
                face->material = (v36 == -1) ? 0 : model->materials[v36];
                tmpTxt = _strtok(0, " \t");
                if ( _sscanf(tmpTxt, "%x", &face->type) != 1 )
                    goto fail;
                tmpTxt = _strtok(0, " \t");
                if ( _sscanf(tmpTxt, "%d", &face->geometryMode) != 1 )
                    goto fail;
                tmpTxt = _strtok(0, " \t");
                if ( _sscanf(tmpTxt, "%d", &face->lightingMode) != 1 )
                    goto fail;
                tmpTxt = _strtok(0, " \t");
                if ( _sscanf(tmpTxt, "%d", &face->textureMode) != 1 )
                    goto fail;
                tmpTxt = _strtok(0, " \t");
                if ( _sscanf(tmpTxt, "%f", &face->extraLight) != 1 )
                    goto fail;
                to_num_verts = _strtok(0, " \t");
                face->numVertices = _atoi(to_num_verts);
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
                        tmpTxt = _strtok(0, " \t,");
                        face->vertexPosIdx[v49] = _atoi(tmpTxt);
                        
                        tmpTxt = _strtok(0, " \t,");
                        face->vertexUVIdx[v49] = _atoi(tmpTxt);
                    }
                }
                else
                {
                    
                    for (v52 = 0; v52 < face->numVertices; v52++)
                    {
                        tmpTxt = _strtok(0, " \t,");
                        face->vertexPosIdx[v52] = _atoi(tmpTxt);
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
                 &node->meshIdx,
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

// from editor?
void rdModel3_LoadPostProcess(rdModel3 *model)
{
    rdModel3_CalcBoundingBoxes(model);
    rdModel3_CalcFaceNormals(model);
    rdModel3_CalcVertexNormals(model);
}

// from editors?
int rdModel3_WriteText(char *fout, rdModel3 *model, char *createdfrom)
{
    rdGeoset* geoset;
    int siblingIdx;
    int parentIdx;
    int childIdx;
    int fd;

    fd = rdroid_pHS->fileOpen(fout, "wt+");
    if (!fd)
        return 0;

    rdroid_pHS->filePrintf(fd, "# MODEL '%s' created from '%s'\n\n", model, createdfrom);
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: HEADER\n\n");
    rdroid_pHS->filePrintf(fd, "3DO %d.%d\n\n", 2, 1);
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: MODELRESOURCE\n\n");
    rdroid_pHS->filePrintf(fd, "# Materials list\n");
    rdroid_pHS->filePrintf(fd, "MATERIALS %d\n\n", model->numMaterials);
    for (int i = 0; i < model->numMaterials; i++)
    {
            rdroid_pHS->filePrintf(fd, "%10d:%15s\n", i, model->materials[i]->mat_fpath);
    }
    rdroid_pHS->filePrintf(fd, "\n\n");
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: GEOMETRYDEF\n\n");
    rdroid_pHS->filePrintf(fd, "# Object radius\n");
    rdroid_pHS->filePrintf(fd, "RADIUS %10.6f\n\n", model->radius);
    rdroid_pHS->filePrintf(fd, "# Insertion offset\n");
    rdroid_pHS->filePrintf(fd, "INSERT OFFSET %10.6f %10.6f %10.6f\n\n", model->insertOffset.x, model->insertOffset.y, model->insertOffset.z);
    rdroid_pHS->filePrintf(fd, "# Number of Geometry Sets\n");
    rdroid_pHS->filePrintf(fd, "GEOSETS %d\n\n", model->numGeosets);

    geoset = model->geosets;
    for (int geosetNum = 0; geosetNum < model->numGeosets; geosetNum++)
    {
        rdroid_pHS->filePrintf(fd, "# Geometry Set definition\n");
        rdroid_pHS->filePrintf(fd, "GEOSET %d\n\n", geosetNum);
        rdroid_pHS->filePrintf(fd, "# Number of Meshes\n");
        rdroid_pHS->filePrintf(fd, "MESHES %d\n\n\n", geoset->numMeshes);

        for (int meshNum = 0; meshNum < geoset->numMeshes; meshNum++)
        {
            rdroid_pHS->filePrintf(fd, "# Mesh definition\n");
            rdroid_pHS->filePrintf(fd, "MESH %d\n\n", meshNum);
            rdroid_pHS->filePrintf(fd, "NAME %s\n\n", geoset->meshes[meshNum].name);
            rdroid_pHS->filePrintf(fd, "RADIUS %10.6f\n\n", geoset->meshes[meshNum].radius);
            rdroid_pHS->filePrintf(fd, "GEOMETRYMODE\t%d\n", geoset->meshes[meshNum].geometryMode);
            rdroid_pHS->filePrintf(fd, "LIGHTINGMODE\t%d\n", geoset->meshes[meshNum].lightingMode);
            rdroid_pHS->filePrintf(fd, "TEXTUREMODE\t%d\n", geoset->meshes[meshNum].textureMode);
            rdroid_pHS->filePrintf(fd, "\n\n");
            rdroid_pHS->filePrintf(fd, "VERTICES %d\n\n", geoset->meshes[meshNum].numVertices);
            rdroid_pHS->filePrintf(fd, "# num:     x:         y:         z:         i: \n");
            for (int vertexNum = 0; vertexNum < geoset->meshes[meshNum].numVertices; vertexNum++)
            {
                rdVector3* vertex = &geoset->meshes[meshNum].vertices[vertexNum];
                rdroid_pHS->filePrintf(
                    fd,
                    "  %3d: %10.6f %10.6f %10.6f %10.6f\n",
                    vertexNum,
                    vertex->x,
                    vertex->y,
                    vertex->z,
                    geoset->meshes[meshNum].vertices_i[vertexNum]);
            }
            rdroid_pHS->filePrintf(fd, "\n\n");
            rdroid_pHS->filePrintf(fd, "TEXTURE VERTICES %d\n\n", geoset->meshes[meshNum].numVertices);
            for (int vertexNum = 0; vertexNum < geoset->meshes[meshNum].numUVs; vertexNum++)
            {
                rdVector2* uv = &geoset->meshes[meshNum].vertexUVs[vertexNum];
                rdroid_pHS->filePrintf(fd, "  %3d: %10.6f %10.6f\n", vertexNum, uv->x, uv->y);
            }
            rdroid_pHS->filePrintf(fd, "\n\n");
            rdroid_pHS->filePrintf(fd, "VERTEX NORMALS\n\n");
            rdroid_pHS->filePrintf(fd, "# num:     x:         y:         z:\n");
            for (int vertexNum = 0; vertexNum < geoset->meshes[meshNum].numVertices; vertexNum++)
            {
                rdVector3* norm = &geoset->meshes[meshNum].vertexNormals[vertexNum];
                rdroid_pHS->filePrintf(
                    fd,
                    "  %3d: %10.6f %10.6f %10.6f\n",
                    vertexNum,
                    norm->x,
                    norm->y,
                    norm->z);
            }
            rdroid_pHS->filePrintf(fd, "\n\n");
            rdroid_pHS->filePrintf(fd, "FACES %d\n\n", geoset->meshes[meshNum].numFaces);
            rdroid_pHS->filePrintf(fd, "#  num:  material:   type:  geo:  light:   tex:  extralight:  verts:\n");
            rdFace* face = geoset->meshes[meshNum].faces;
            for (int faceNum = 0; faceNum < geoset->meshes[meshNum].numFaces; faceNum++)
            {
                int materialIdx = -1;
                for (int j = 0; j < model->numMaterials; j++)
                {
                    if (!face->material)
                        break;

                    if ( face->material == model->materials[j] )
                        materialIdx = j;
                }

                rdroid_pHS->filePrintf(
                    fd,
                    "   %3d: %9d  0x%04x  %4d %7d %6d %12.4f %7d  ",
                    faceNum,
                    materialIdx,
                    face->type,
                    face->geometryMode,
                    face->lightingMode,
                    face->textureMode,
                    face->extraLight,
                    face->numVertices);

                if (face->material && face->material->tex_type & 2)
                {
                    for (int j = 0; j < face->numVertices; j++)
                    {
                        rdroid_pHS->filePrintf(
                            fd,
                            "%3d,%3d ",
                            face->vertexPosIdx[j],
                            face->vertexUVIdx[j]);
                    }
                }
                else
                {
                    for (int j = 0; j < face->numVertices; j++)
                    {
                        rdroid_pHS->filePrintf(fd, "%3d, 0 ", face->vertexPosIdx[j]);
                    }
                }
                rdroid_pHS->filePrintf(fd, "\n");
            }
            rdroid_pHS->filePrintf(fd, "\n\n");
            rdroid_pHS->filePrintf(fd, "FACE NORMALS\n\n");
            rdroid_pHS->filePrintf(fd, "# num:     x:         y:         z:\n");
            for (int j = 0; j < geoset->meshes[meshNum].numFaces; j++)
            {
                rdVector3* norm = &geoset->meshes[meshNum].faces[j].normal;
                rdroid_pHS->filePrintf(fd, "  %3d: %10.6f %10.6f %10.6f\n", j, norm->x, norm->y, norm->z);
            }
            rdroid_pHS->filePrintf(fd, "\n\n");
        }
        ++geoset;
    }
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: HIERARCHYDEF\n\n");
    rdroid_pHS->filePrintf(fd, "# Hierarchy node list\n");
    rdroid_pHS->filePrintf(fd, "HIERARCHY NODES %d\n\n", model->numHierarchyNodes);
    rdroid_pHS->filePrintf(fd, 
        "#  num:   flags:   type:    mesh:  parent:  child:  sibling:  numChildren:        x:         y:         z:     pitch:       yaw:      roll:    pivot"
        "x:    pivoty:    pivotz:  hnodename:\n");

    for (int nodeIdx = 0; nodeIdx < model->numHierarchyNodes; nodeIdx++ )
    {
        rdHierarchyNode* node = &model->hierarchyNodes[nodeIdx];

        if ( node->parent )
            parentIdx = node->parent->idx;
        else
            parentIdx = -1;

        if ( node->child )
            childIdx = node->child->idx;
        else
            childIdx = -1;

        if ( node->nextSibling )
            siblingIdx = node->nextSibling->idx;
        else
            siblingIdx = -1;

        rdroid_pHS->filePrintf(
            fd,
            "   %3d:  0x%04x 0x%05X %8d %8d %7d %9d %13d %10.6f %10.6f %10.6f %10.6f %10.6f %10.6f %10.6f %10.6f %10.6f  %s\n",
            nodeIdx,
            node->flags,
            node->type,
            node->meshIdx,
            parentIdx,
            childIdx,
            siblingIdx,
            node->numChildren,
            node->pos.x,
            node->pos.y,
            node->pos.z,
            node->rot.x,
            node->rot.y,
            node->rot.z,
            node->pivot.x,
            node->pivot.y,
            node->pivot.z,
            node->name);
    }
    rdroid_pHS->fileClose(fd);
    return 1;
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

void rdModel3_FreeEntry(rdModel3 *model)
{
    if (!model)
        return;

    rdGeoset* geoset = model->geosets;
    for (int geosetNum = 0; geosetNum < model->numGeosets; geosetNum++ )
    {
        for (int meshNum = 0; meshNum < geoset->numMeshes; meshNum++)
        {
            rdMesh* mesh = &geoset->meshes[meshNum];
            
            if (mesh->vertices)
                rdroid_pHS->free(mesh->vertices);
            
            if (mesh->vertexUVs)
                rdroid_pHS->free(mesh->vertexUVs);
            
            if ( mesh->faces )
            {
                for (int faceIdx = 0; faceIdx < mesh->numFaces; faceIdx++)
                {
                    rdFace_FreeEntry(&mesh->faces[faceIdx]);
                }
                rdroid_pHS->free(mesh->faces);
            }
            if (mesh->vertices_i)
                rdroid_pHS->free(mesh->vertices_i);
            if (mesh->vertices_unk)
                rdroid_pHS->free(mesh->vertices_unk);
            if (mesh->vertexNormals)
                rdroid_pHS->free(mesh->vertexNormals);
        }
        if ( geoset->meshes )
            rdroid_pHS->free(geoset->meshes);
        ++geoset;
    }

    if ( model->hierarchyNodes )
        rdroid_pHS->free(model->hierarchyNodes);

    if ( model->numMaterials )
    {
        for (int i = 0; i < model->numMaterials; i++)
        {
            rdMaterial_Free(model->materials[i]);
        }
    }
    if (model->materials )
        rdroid_pHS->free(model->materials);
}

void rdModel3_FreeEntryGeometryOnly(rdModel3 *model)
{
    if (!model)
        return;

    rdGeoset* geoset = model->geosets;
    for (int geosetNum = 0; geosetNum < model->numGeosets; geosetNum++ )
    {
        for (int meshNum = 0; meshNum < geoset->numMeshes; meshNum++)
        {
            rdMesh* mesh = &geoset->meshes[meshNum];
            
            if (mesh->vertices)
                rdroid_pHS->free(mesh->vertices);
            
            if (mesh->vertexUVs)
                rdroid_pHS->free(mesh->vertexUVs);
            
            if ( mesh->faces )
            {
                for (int faceIdx = 0; faceIdx < mesh->numFaces; faceIdx++)
                {
                    rdFace_FreeEntry(&mesh->faces[faceIdx]);
                }
                rdroid_pHS->free(mesh->faces);
            }
            if (mesh->vertices_i)
                rdroid_pHS->free(mesh->vertices_i);
            if (mesh->vertices_unk)
                rdroid_pHS->free(mesh->vertices_unk);
            if (mesh->vertexNormals)
                rdroid_pHS->free(mesh->vertexNormals);
        }
        if ( geoset->meshes )
            rdroid_pHS->free(geoset->meshes);
        ++geoset;
    }

    if ( model->hierarchyNodes )
        rdroid_pHS->free(model->hierarchyNodes);

    if (model->materials )
        rdroid_pHS->free(model->materials);
}

#if 0
int __cdecl rdModel3_Validate(rdModel3 *model)
{
    int result; // eax
    unsigned int v2; // edx
    rdGeoset *v3; // ecx
    int geoset; // ebp
    unsigned int v5; // ebx
    int *v6; // edi
    unsigned int v7; // edx
    void *v8; // eax
    _BYTE *v9; // ecx
    unsigned int v10; // [esp+10h] [ebp-8h]
    unsigned int v11; // [esp+14h] [ebp-4h]
    rdGeoset *modela; // [esp+1Ch] [ebp+4h]

    result = (int)model;
    v2 = model->numGeosets;
    v3 = model->geosets;
    modela = model->geosets;
    v10 = 0;
    v11 = v2;
    if ( v2 )
    {
        do
        {
            geoset = v3->numMeshes;
            v5 = 0;
            if ( v3->numMeshes )
            {
                v6 = &v3->meshes->numFaces;
                do
                {
                    v7 = 0;
                    if ( *v6 )
                    {
                        v8 = (void *)(*(v6 - 4) + 8);// faces+8
                        do
                        {
                            v9 = (_BYTE *)*((_DWORD *)v8 + 6);
                            if ( v9 )
                            {
                                if ( !(*v9 & 2) && *(_DWORD *)v8 > 3 )
                                    return 0;
                            }
                            else if ( *(_DWORD *)v8 > 0 )
                            {
                                return 0;
                            }
                            v8 = (char *)v8 + 64;
                            ++v7;
                        }
                        while ( v7 < *v6 );
                    }
                    v6 += 28;
                    ++v5;
                }
                while ( v5 < geoset );
                v3 = modela;
                v2 = v11;
            }
            ++v3;
            result = v10 + 1;
            modela = v3;
            ++v10;
        }
        while ( v10 < v2 );
    }
    return result;
}
#endif

rdModel3* rdModel3_Validate(rdModel3 *model)
{
    return model;
}

void rdModel3_CalcBoundingBoxes(rdModel3 *model)
{
    float maxDist;

    for (int i = 0; i < model->geosets[0].numMeshes; i++)
    {
        rdMesh* mesh = &model->geosets[0].meshes[i];
        maxDist = 0.0;
        for (int j = 0; j < mesh->numVertices; j++)
        {
            rdVector3* vtx = &mesh->vertices[j];
            float dist = rdVector_Len3(vtx);
            if ( dist > maxDist )
            {
                maxDist = dist;
            }
        }
        mesh->field_64 = (maxDist * 0.1) + maxDist;
    }
    rdModel3_fRadius = 0.0;
    rdModel3_BuildExpandedRadius(model, model->hierarchyNodes, &rdroid_identMatrix34);
    model->radius = rdModel3_fRadius * 0.1 + rdModel3_fRadius;
}

void rdModel3_BuildExpandedRadius(rdModel3 *model, rdHierarchyNode *node, const rdMatrix34 *matrix)
{
    rdVector3 vertex_out;
    rdVector3 vecTmp;
    rdMatrix34 matPivotTranslate;
    rdMatrix34 out;
    rdMatrix34 matTmp;

    rdMatrix_Build34(&matTmp, &node->rot, &node->pos);
    rdMatrix_BuildTranslate34(&matPivotTranslate, &node->pivot);
    rdMatrix_PostMultiply34(&matPivotTranslate, &matTmp);
    
    if (node->parent)
    {
        rdVector_Neg3(&vecTmp, &node->parent->pivot);
        rdMatrix_PostTranslate34(&matPivotTranslate, &vecTmp);
    }
    
    rdMatrix_Multiply34(&out, matrix, &matPivotTranslate);
    
    if ( node->meshIdx != -1 )
    {
        rdMesh* mesh = &model->geosets[0].meshes[node->meshIdx];
        for (int i = 0; i < mesh->numVertices; i++)
        {
            rdVector3* vtx = &mesh->vertices[i];
            rdMatrix_TransformPoint34(&vertex_out, vtx, &out);
            float dist = rdVector_Len3(&vertex_out);
            if ( dist > rdModel3_fRadius )
                rdModel3_fRadius = dist;
        }
    }
    
    if (node->numChildren)
    {
        rdHierarchyNode* childIter = node->child;
        for (int i = 0; i < node->numChildren; i++)
        {
            rdModel3_BuildExpandedRadius(model, childIter, &out);
            childIter = childIter->nextSibling;
        }
    }
}

// from editors?
void rdModel3_CalcFaceNormals(rdModel3 *model)
{
    for (int geosetIdx = 0; geosetIdx < model->numGeosets; geosetIdx++)
    {
        rdGeoset* geoset = &model->geosets[geosetIdx];

        for (int meshIdx = 0; meshIdx < geoset->numMeshes; meshIdx++)
        {
            rdMesh* mesh = &geoset->meshes[meshIdx];
            for (int faceIdx = 0; faceIdx < mesh->numFaces; faceIdx++)
            {
                int idx1, idx2, idx3;
                rdFace* face = &mesh->faces[faceIdx];
                for (idx1 = 0; idx1 < face->numVertices; idx1++)
                {
                    idx2 = idx1 - 1;
                    if ( idx1 - 1 < 0 )
                        idx2 = face->numVertices - 1;
                    idx3 = ((idx1 + 1) % face->numVertices);
                    if ( !rdMath_PointsCollinear(
                              &mesh->vertices[face->vertexPosIdx[idx1]],
                              &mesh->vertices[face->vertexPosIdx[idx3]],
                              &mesh->vertices[face->vertexPosIdx[idx2]]))
                        break;
                }
                if ( idx1 < face->numVertices )
                    rdMath_CalcSurfaceNormal(
                        &face->normal,
                        &mesh->vertices[face->vertexPosIdx[idx1]],
                        &mesh->vertices[face->vertexPosIdx[idx3]],
                        &mesh->vertices[face->vertexPosIdx[idx2]]);
            }
        }
    } 
}

void rdModel3_CalcVertexNormals(rdModel3 *model)
{
    double v10; // st7
    double v11; // st6
    double v12; // st5
    double v13; // st4
    unsigned int v15; // eax
    rdVector3 *v19; // ecx
    int v22; // edx

    for (int geosetNum = 0; geosetNum < model->numGeosets; geosetNum++)
    {
        rdGeoset* geoset = &model->geosets[geosetNum];
        for (int meshNum = 0; meshNum < geoset->numMeshes; meshNum++)
        {
            rdMesh* mesh = &geoset->meshes[meshNum];

            for (int vtxNum = 0; vtxNum < mesh->numVertices; vtxNum++)
            {
                rdFace* faceRoot = mesh->faces;
                v10 = 0.0;
                v11 = 0.0;
                v12 = 0.0;
                v13 = 0.0;
                for (int faceNum = 0; faceNum < mesh->numFaces; faceNum++)
                {
                    rdFace* face = &mesh->faces[faceNum];
                    v15 = 0;
                    for (int i = 0; i < face->numVertices; i++)
                    {
                        if ( face->vertexPosIdx[v15] != vtxNum )
                        {
                            ++v15;
                            if ( v15 >= face->numVertices )
                                break;
                            continue;
                        }
                        v10 = v10 + face->normal.x;
                        v11 = v11 + face->normal.y;
                        v12 = v12 + face->normal.z;
                        v13 = v13 - -1.0;
                    }
                }
                if ( v13 == 0.0 )
                {
                    mesh->vertexNormals[vtxNum].x = 1.0;
                    mesh->vertexNormals[vtxNum].y = 0.0;
                    mesh->vertexNormals[vtxNum].z = 0.0;
                }
                else
                {
                    if ( v13 == 1.0 )
                    {
                        v19 = &mesh->vertices[faceRoot->vertexPosIdx[faceRoot->numVertices - 1]];
                        v22 = faceRoot->vertexPosIdx[1 % faceRoot->numVertices];
                        mesh->vertexNormals[vtxNum].y = (mesh->vertices->y - mesh->vertices[v22].y) + (mesh->vertices->y - v19->y);
                        mesh->vertexNormals[vtxNum].z = (mesh->vertices->z - mesh->vertices[v22].z) + (mesh->vertices->z - v19->z);
                        mesh->vertexNormals[vtxNum].x = (mesh->vertices->x - mesh->vertices[v22].x) + (mesh->vertices->x - v19->x);
                    }
                    else
                    {
                        mesh->vertexNormals[vtxNum].x = v10 / v13;
                        mesh->vertexNormals[vtxNum].y = v11 / v13;
                        mesh->vertexNormals[vtxNum].z = v12 / v13;
                    }
                    rdVector_Normalize3Acc(&mesh->vertexNormals[vtxNum]);
                }
            }
        }
    }
}

//vertexnormals, technically unused, from editors?

rdHierarchyNode* rdModel3_FindNamedNode(char *name, rdModel3 *model)
{
    uint32_t i = 0;
    rdHierarchyNode* nodeIter = model->hierarchyNodes;

    if ( !model->numHierarchyNodes )
        return 0;

    while (_strcmp(nodeIter->name, name))
    {
        ++nodeIter;
        if ( ++i >= model->numHierarchyNodes )
            return 0;
    }

    return nodeIter;
}

int rdModel3_GetMeshMatrix(rdThing *thing, rdMatrix34 *matrix, uint32_t nodeIdx, rdMatrix34 *out)
{
    if ( nodeIdx >= thing->model3->numHierarchyNodes )
        return 0;

    if ( thing->frameTrue != rdroid_frameTrue )
        rdPuppet_BuildJointMatrices(thing, matrix);

    _memcpy(out, &thing->hierarchyNodeMatrices[nodeIdx], sizeof(rdMatrix34));
    return 1;
}

int rdModel3_ReplaceMesh(rdModel3 *model, int geosetIdx, int meshIdx, rdMesh *in)
{
    _memcpy(&model->geosets[geosetIdx].meshes[meshIdx], in, sizeof(model->geosets[geosetIdx].meshes[meshIdx]));
    return 1;
}

int rdModel3_Draw(rdThing *thing, rdMatrix34 *matrix_4_3)
{
    int frustumCull;
    int geosetNum;
    rdGeoset *geoset;
    rdLight **pGeoLight;
    rdLight **lightIter;
    rdHierarchyNode *rootNode;
    int meshIdx;
    rdHierarchyNode *node;
    rdVector3 vertex_out;

    pCurThing = thing;
    pCurModel3 = thing->model3;
    rdMatrix_TransformPoint34(&vertex_out, &matrix_4_3->scale, &rdCamera_pCurCamera->view_matrix);
    if ( rdroid_curCullFlags & 2 )
        frustumCull = rdClip_SphereInFrustrum(rdCamera_pCurCamera->cameraClipFrustum, &vertex_out, pCurModel3->radius);
    else
        frustumCull = thing->clippingIdk;
    thingFrustrumCull = frustumCull;
    if ( frustumCull == 2 )
        return 0;
    thingFrustrumCull = 1;
    if ( thing->geosetSelect == -1 )
    {
        geosetNum = pCurModel3->geosetSelect;
    }
    else
    {
        geosetNum = pCurThing->geosetSelect;
    }
    geoset = &pCurModel3->geosets[geosetNum];
    rdModel3_pCurGeoset = geoset;
    if ( pCurThing->frameTrue != rdroid_frameTrue )
    {
        rdPuppet_BuildJointMatrices(pCurThing, matrix_4_3);
    }

    curGeometryMode = pCurThing->geometryMode;
    if ( curGeometryMode >= rdroid_curGeometryMode )
        curGeometryMode = rdroid_curGeometryMode;

    if ( rdroid_curRenderOptions & 2 && rdCamera_pCurCamera->ambientLight >= 1.0 )
    {
        curLightingMode = 0;
    }
    else
    {
        curLightingMode = pCurThing->lightingMode;
        if ( curLightingMode >= rdroid_curLightingMode )
            curLightingMode = rdroid_curLightingMode;
    }

    curTextureMode = pCurThing->textureMode;
    if ( curTextureMode >= rdroid_curTextureMode )
        curTextureMode = rdroid_curTextureMode;

    if ( curLightingMode > 1 )
    {
        rdModel3_numGeoLights = 0;
        pGeoLight = apGeoLights;
        for (int lNum = 0; lNum < rdCamera_pCurCamera->numLights; lNum++)
        {
            rdVector3* lightPos = &rdCamera_pCurCamera->lightPositions[lNum];
            rdLight* lightIter = rdCamera_pCurCamera->lights[lNum];

            if ( lightIter->falloffMin + pCurModel3->radius > rdVector_Dist3(lightPos, &matrix_4_3->scale))
            {
                *pGeoLight = lightIter;
                ++pGeoLight;
                ++rdModel3_numGeoLights;
            }
        }
    }
    
    rootNode = &pCurModel3->hierarchyNodes[0];
    meshIdx = rootNode->meshIdx;
    if ( meshIdx != -1 )
    {
        rdModel3_DrawMesh(&rdModel3_pCurGeoset->meshes[meshIdx], &pCurThing->hierarchyNodeMatrices[rootNode->idx]);
    }
    node = rootNode->child;
    for (int i = 0; i < rootNode->numChildren; i++ )
    {
        if ( !pCurThing->amputatedJoints[node->idx] )
        {
            rdModel3_DrawHNode(node);
        }
        node = node->nextSibling;
    }
#if 0
    rdDebug_DrawBoundingBox(matrix_4_3, pCurModel3->radius, 0xFF0000FF);
#endif
    ++rdModel3_numDrawnModels;
    return 1;
}

void rdModel3_DrawHNode(rdHierarchyNode *node)
{
    rdHierarchyNode *iter;

    if ( node->meshIdx != -1 )
        rdModel3_DrawMesh(&rdModel3_pCurGeoset->meshes[node->meshIdx], &pCurThing->hierarchyNodeMatrices[node->idx]);

    if (!node->numChildren)
        return;

    iter = node->child;
    for (int i = 0; i < node->numChildren; i++)
    {
        if ( !pCurThing->amputatedJoints[iter->idx] )
            rdModel3_DrawHNode(iter);
        iter = iter->nextSibling;
    }
}

void rdModel3_DrawMesh(rdMesh *meshIn, rdMatrix34 *mat)
{
    rdLight **pGeoLight;
    rdVector3 vertex;
    rdVector3 vertex_out;
    rdMatrix34 matInv;
    rdMatrix34 out;

    pCurMesh = meshIn;
    if ( !meshIn->geometryMode )
        return;

    rdMatrix_TransformPoint34(&vertex_out, &mat->scale, &rdCamera_pCurCamera->view_matrix);
    if ( thingFrustrumCull )
        meshFrustrumCull = rdroid_curCullFlags & 1 ? rdClip_SphereInFrustrum(rdCamera_pCurCamera->cameraClipFrustum, &vertex_out, pCurMesh->radius) : 1;
    else
        meshFrustrumCull = 0;

    if ( meshFrustrumCull == 2 )
        return;

    rdMatrix_Multiply34(&out, &rdCamera_pCurCamera->view_matrix, mat);
    rdMatrix_TransformPointLst34(&out, pCurMesh->vertices, aView, pCurMesh->numVertices);
    rdMatrix_InvertOrtho34(&matInv, mat);
    
    rdModel3_geometryMode = pCurMesh->geometryMode;
    if ( rdModel3_geometryMode >= curGeometryMode )
        rdModel3_geometryMode = curGeometryMode;

    rdModel3_lightingMode = pCurMesh->lightingMode;
    if ( rdModel3_lightingMode >= curLightingMode )
        rdModel3_lightingMode = curLightingMode;

    rdModel3_textureMode = pCurMesh->textureMode;
    if ( rdModel3_textureMode >= curTextureMode )
        rdModel3_textureMode = curTextureMode;

    vertexSrc.paDynamicLight = pCurMesh->vertices_unk;
    vertexSrc.verticesProjected = aView;
    vertexSrc.vertexUVs = pCurMesh->vertexUVs;
    vertexSrc.intensities = 0;
    vertexDst.verticesProjected = aFaceVerts;

    if (rdModel3_lightingMode == 0)
    {
    }
    else if (rdModel3_lightingMode == 1)
    {
    }
    else if (rdModel3_lightingMode == 2)
    {
        rdModel3_numMeshLights = 0;
        pGeoLight = apGeoLights;
        for (int i = 0; i < rdModel3_numGeoLights; i++)
        {
            int lightIdx = (*pGeoLight)->id;
            if ( (*pGeoLight)->falloffMin + pCurMesh->radius > rdVector_Dist3(&rdCamera_pCurCamera->lightPositions[lightIdx], &mat->scale) )
            {
                apMeshLights[rdModel3_numMeshLights] = *pGeoLight;
                rdMatrix_TransformPoint34(&aLocalLightPos[rdModel3_numMeshLights], &rdCamera_pCurCamera->lightPositions[lightIdx], &matInv);
                ++rdModel3_numMeshLights;
            }
            ++pGeoLight;
        }
    }
    else if (rdModel3_lightingMode == 3)
    {
        rdModel3_numMeshLights = 0;
        if (rdModel3_numGeoLights > 0)
        {
            pGeoLight = apGeoLights;
            for (int i = 0; i < rdModel3_numGeoLights; i++)
            {
                int lightIdx = (*pGeoLight)->id;
                if ( (*pGeoLight)->falloffMin + pCurMesh->radius > rdVector_Dist3(&rdCamera_pCurCamera->lightPositions[lightIdx], &mat->scale) )
                {
                    apMeshLights[rdModel3_numMeshLights] = *pGeoLight;
                    rdMatrix_TransformPoint34(&aLocalLightPos[rdModel3_numMeshLights], &rdCamera_pCurCamera->lightPositions[lightIdx], &matInv);
                    ++rdModel3_numMeshLights;
                }
                ++pGeoLight;
            }
        }
        rdLight_CalcVertexIntensities(
            apMeshLights,
            aLocalLightPos,
            rdModel3_numMeshLights,
            pCurMesh->vertexNormals,
            pCurMesh->vertices,
            pCurMesh->vertices_i,
            pCurMesh->vertices_unk,
            pCurMesh->numVertices,
            rdCamera_pCurCamera->attenuationMin);
    }

    rdMatrix_TransformPoint34(&localCamera, &rdCamera_camMatrix.scale, &matInv);
    rdFace* face = &meshIn->faces[0];
    for (int i = 0; i < meshIn->numFaces; i++)
    {
        int flags = 0;
        if ( (localCamera.y - pCurMesh->vertices[*face->vertexPosIdx].y) * face->normal.y
           + (localCamera.x - pCurMesh->vertices[*face->vertexPosIdx].x) * face->normal.x
           + (localCamera.z - pCurMesh->vertices[*face->vertexPosIdx].z) * face->normal.z <= 0.0 )
        {
            flags = 1;
            if ( !(face->type & 1) && rdroid_curRenderOptions & 1 )
            {
                ++face;
                continue;
            }
        }

        rdModel3_DrawFace(face, flags);
        ++face;
    }
}

int rdModel3_DrawFace(rdFace *face, int lightFlags)
{
    rdProcEntry *procEntry;
    int geometryMode;
    int lightingMode;
    int textureMode;
    rdVector3 faceNormal;
    int flags;

    procEntry = rdCache_GetProcEntry();
    if ( !procEntry )
        return 0;

    geometryMode = rdModel3_geometryMode;
    if ( rdModel3_geometryMode >= face->geometryMode )
        geometryMode = face->geometryMode;

    lightingMode = rdModel3_lightingMode;
    if ( rdModel3_lightingMode >= face->lightingMode )
        lightingMode = face->lightingMode;

    textureMode = rdModel3_textureMode;
    if ( rdModel3_textureMode >= face->textureMode )
        textureMode = face->textureMode;

    procEntry->geometryMode = geometryMode;
    procEntry->lightingMode = lightingMode;
    procEntry->textureMode = textureMode;
    vertexDst.verticesOrig = procEntry->vertices;
    vertexDst.vertexUVs = procEntry->vertexUVs;
    vertexDst.paDynamicLight = procEntry->vertexIntensities;
    vertexSrc.numVertices = face->numVertices;
    vertexSrc.vertexPosIdx = face->vertexPosIdx;
    vertexSrc.vertexUVIdx = face->vertexUVIdx;

    if ( meshFrustrumCull )
        rdPrimit3_ClipFace(rdCamera_pCurCamera->cameraClipFrustum, geometryMode, lightingMode, textureMode, (rdVertexIdxInfo *)&vertexSrc, &vertexDst, &face->clipIdk);
    else
        rdPrimit3_NoClipFace(geometryMode, lightingMode, textureMode, &vertexSrc, &vertexDst, &face->clipIdk);

    if ( vertexDst.numVertices < 3u )
        return 0;

    if ( procEntry->lightingMode == 2 )
    {
        if ( lightFlags )
        {
            rdVector_Neg3(&faceNormal, &face->normal);
            procEntry->light_level_static = rdLight_CalcFaceIntensity(
                      apMeshLights,
                      aLocalLightPos,
                      rdModel3_numMeshLights,
                      face,
                      &faceNormal,
                      pCurMesh->vertices,
                      rdCamera_pCurCamera->attenuationMin);
        }
        else
        {
            procEntry->light_level_static = rdLight_CalcFaceIntensity(
                      apMeshLights,
                      aLocalLightPos,
                      rdModel3_numMeshLights,
                      face,
                      &face->normal,
                      pCurMesh->vertices,
                      rdCamera_pCurCamera->attenuationMin);
        }
    }
    rdCamera_pCurCamera->projectLst(vertexDst.verticesOrig, vertexDst.verticesProjected, vertexDst.numVertices);
    if ( rdroid_curRenderOptions & 2 )
        procEntry->ambientLight = rdCamera_pCurCamera->ambientLight;
    else
        procEntry->ambientLight = 0.0;

    int isIdentityMap = (rdColormap_pCurMap == rdColormap_pIdentityMap);
    procEntry->wallCel = face->wallCel;
    if ( procEntry->ambientLight < 1.0 )
    {
        if ( procEntry->lightingMode == 2 )
        {
            if ( procEntry->light_level_static >= 1.0 && isIdentityMap )
            {
                procEntry->lightingMode = 0;
            }
            else if ( procEntry->light_level_static <= 0.0 )
            {
                procEntry->lightingMode = 1;
            }
            goto LABEL_44;
        }
        if ( procEntry->lightingMode != 3 )
            goto LABEL_44;

        for (int i = 1; i < vertexDst.numVertices; i++ )
        {
                float level = procEntry->vertexIntensities[i] - procEntry->vertexIntensities[0];
                if ( level < 0.0 )
                    level = -level;

                if ( level > 0.015625 )
                    goto LABEL_44;
        }
        
        if ( procEntry->vertexIntensities[0] != 1.0 )
        {
            if ( procEntry->vertexIntensities[0] == 0.0 )
            {
                procEntry->lightingMode = 1;
                procEntry->light_level_static = 0.0;
            }
            else
            {
                procEntry->lightingMode = 2;
                procEntry->light_level_static = procEntry->vertexIntensities[0];
            }
            goto LABEL_44;
        }
        if ( isIdentityMap )
        {
            procEntry->lightingMode = 0;
            goto LABEL_44;
        }

        procEntry->lightingMode = 2;
        procEntry->light_level_static = 1.0;
        goto LABEL_44;
    }
    if ( !isIdentityMap )
    {
        procEntry->lightingMode = 2;
        procEntry->light_level_static = 1.0;
        goto LABEL_44;
    }
    procEntry->lightingMode = 0;

LABEL_44:
    flags = 1;
    if ( procEntry->geometryMode >= 4 )
        flags = 3;
    if ( procEntry->lightingMode >= 3 )
        flags |= 4u;

    procEntry->light_flags = lightFlags;
    procEntry->type = face->type;
    procEntry->extralight = face->extraLight;
    procEntry->material = face->material;
    rdCache_AddProcFace(0, vertexDst.numVertices, flags);
    return 1;
}
