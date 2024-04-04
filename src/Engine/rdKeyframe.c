#include "rdKeyframe.h"

#include "Engine/rdroid.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Win95/std.h"
#include "jk.h"

keyframeLoader_t rdKeyframe_RegisterLoader(keyframeLoader_t loader)
{
    keyframeLoader_t result = pKeyframeLoader;
    pKeyframeLoader = loader;
    return result;
}

keyframeUnloader_t rdKeyframe_RegisterUnloader(keyframeUnloader_t loader)
{
    keyframeUnloader_t result = pKeyframeUnloader;
    pKeyframeUnloader = loader;
    return result;
}

void rdKeyframe_NewEntry(rdKeyframe *keyframe)
{
    _memset(keyframe, 0, sizeof(rdKeyframe));
    _strncpy(keyframe->name, "UNKNOWN", 0x1Fu);
    keyframe->name[31] = 0;
}

rdKeyframe* rdKeyframe_Load(char *fname)
{
    rdKeyframe *keyframe;

    if (pKeyframeLoader)
        return (rdKeyframe*)pKeyframeLoader(fname);

    keyframe = (rdKeyframe*)rdroid_pHS->alloc(sizeof(rdKeyframe));
    if (!keyframe)
        return NULL;

    if (rdKeyframe_LoadEntry(fname, keyframe))
      return keyframe;

    // This was inlined
    rdKeyframe_FreeEntry(keyframe);
    
    return NULL;
}

int rdKeyframe_LoadEntry(char *key_fpath, rdKeyframe *keyframe)
{
    char *key_fname_only;
    rdJoint *paJoints;
    rdKeyframe *num_joints;
    unsigned int num_markers_read;
    rdMarkers *markers;
    rdJoint *joint;
    rdAnimEntry *anim_entry;
    int anim_entry_read;
    unsigned int num_markers;
    int node_idx;
    int anim_entry_cnt;
    unsigned int num_nodes;
    rdVector3 pos;
    rdVector3 orientation;
    rdVector3 vel;
    rdVector3 angVel;
    int entry_num;
    char mesh_name[32];
    unsigned int nodes_read;

    _memset(keyframe, 0, sizeof(rdKeyframe));
    _strncpy(keyframe->name, "UNKNOWN", 0x1Fu);
    keyframe->name[31] = 0;
    key_fname_only = stdFileFromPath(key_fpath);
    _strncpy(keyframe->name, key_fname_only, 0x1Fu);
    keyframe->name[31] = 0;
    if (!stdConffile_OpenRead(key_fpath)) {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\rdKeyframe.c", 0, "OpenJKDF2: Failed to open keyframe file `%s`\n", key_fpath);
        goto open_fail;
    }

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " flags %d", &keyframe->flags) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " type %x", &keyframe->type) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " frames %d", &keyframe->numFrames) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " fps %f", &keyframe->fps) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_aLine, " joints %d", &keyframe->numJoints) != 1)
      goto read_fail;

    paJoints = (rdJoint *)rdroid_pHS->alloc(sizeof(rdJoint) * (keyframe->numJoints+1)); // Added: try and contain rdPuppet crashes...
    keyframe->paJoints = paJoints;
    if (!paJoints)
      goto read_fail;

    _memset(paJoints, 0, sizeof(rdJoint) * (keyframe->numJoints+1));
    keyframe->numJoints2 = keyframe->numJoints;

    if (!stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1)
      goto read_fail;

    if (!_memcmp(std_genBuffer, "markers", 8u))
    {
      if (!stdConffile_ReadLine())
        goto read_fail;

      if (_sscanf(stdConffile_aLine, " markers %d", &num_markers) != 1)
        goto read_fail;

      if (num_markers > 8)
        goto read_fail;

      keyframe->numMarkers = num_markers;
      for (num_markers_read = 0; num_markers_read < num_markers; num_markers_read++)
      {
        markers = &keyframe->markers;
        if (!stdConffile_ReadLine())
            break;
        
        if (_sscanf(stdConffile_aLine, "%f %d", &markers->marker_float[num_markers_read], &markers->marker_int[num_markers_read]) != 2)
            break;
      }
      
      if (num_markers_read < num_markers)
            goto read_fail;

      if (!stdConffile_ReadLine())
        goto read_fail;

      if (_sscanf(stdConffile_aLine, " section: %s", std_genBuffer) != 1)
        goto read_fail;
    }
    
    
    if (!stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " nodes %d", &num_nodes) != 1)
    {
      goto read_fail;
    }

    for (nodes_read = 0; nodes_read < num_nodes; nodes_read++)
    {
        if (!stdConffile_ReadLine())
            goto read_fail;
        if (_sscanf(stdConffile_aLine, " node %d", &node_idx) != 1)
            goto read_fail;
        if (!stdConffile_ReadLine())
            goto read_fail;
        if (_sscanf(stdConffile_aLine, " mesh name %s", mesh_name) != 1)
            goto read_fail;
        joint = &keyframe->paJoints[node_idx];
        
        _strncpy(joint->mesh_name, mesh_name, 0x1Fu);
        joint->mesh_name[31] = 0;
        
        if (!stdConffile_ReadLine())
            goto read_fail;

        if (_sscanf(stdConffile_aLine, " entries %d", &anim_entry_cnt) != 1)
            goto read_fail;

        joint->nodeIdx = node_idx;
        joint->numAnimEntries = anim_entry_cnt;
        joint->paAnimEntries = (rdAnimEntry*)rdroid_pHS->alloc(sizeof(rdAnimEntry) * anim_entry_cnt + 2); // Added: prevent some oob accesses in rdPuppet
        if (!joint->paAnimEntries)
          goto read_fail;

        anim_entry = joint->paAnimEntries;
        for (anim_entry_read = 0; anim_entry_read < joint->numAnimEntries; anim_entry_read++)
        {
            if (!stdConffile_ReadLine()) {
                goto read_fail;
            }
            
            if (_sscanf(
                   stdConffile_aLine,
                   " %d: %f %x %f %f %f %f %f %f",
                   &entry_num,
                   &anim_entry->frameNum,
                   &anim_entry->flags,
                   &pos.x,
                   &pos.y,
                   &pos.z,
                   &orientation.x,
                   &orientation.y,
                   &orientation.z) != 9) {
              goto read_fail;
            }
            
            anim_entry->pos = pos;
            anim_entry->orientation = orientation;
            
            if (!stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " %f %f %f %f %f %f", &vel.x, &vel.y, &vel.z, &angVel.x, &angVel.y, &angVel.z) != 6)
            {
              goto read_fail;
            }

            anim_entry->vel = vel;
            anim_entry->angVel = angVel;
            anim_entry++;
        }
    }
    
    stdConffile_Close();
    return 1;
  
read_fail:
    stdConffile_Close();
open_fail:
    return 0;
}

int rdKeyframe_Write(char *out_fpath, rdKeyframe *keyframe, char *creation_method)
{
    int fd;
    int totalAnimEntries;
    rdJoint *joint_iter;
    rdAnimEntry *animEntry_iter;
    unsigned int i;
    unsigned int j;

    fd = rdroid_pHS->fileOpen(out_fpath, "wt+");
    if (!fd)
        return 0;

    rdroid_pHS->filePrintf(fd, "# KEYFRAME '%s' created from '%s'\n\n", keyframe, creation_method);
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: HEADER\n\n");
    rdroid_pHS->filePrintf(fd, "FLAGS  0x%04x\n", keyframe->flags);
    rdroid_pHS->filePrintf(fd, "TYPE   0x%X\n", keyframe->type);
    rdroid_pHS->filePrintf(fd, "FRAMES %d\n", keyframe->numFrames);
    rdroid_pHS->filePrintf(fd, "FPS    %.3f\n", keyframe->fps);
    rdroid_pHS->filePrintf(fd, "JOINTS %d\n", keyframe->numJoints);
    if (keyframe->numMarkers)
    {
        rdroid_pHS->filePrintf(fd, "\n\n");
        rdroid_pHS->filePrintf(fd, "###############\n");
        rdroid_pHS->filePrintf(fd, "SECTION: MARKERS\n\n");
        rdroid_pHS->filePrintf(fd, "MARKERS %d\n\n", keyframe->numMarkers);
        for (i = 0; i < keyframe->numMarkers; i++)
        {
            rdroid_pHS->filePrintf(fd, "%f %d\n", keyframe->markers.marker_float[i], keyframe->markers.marker_int[i]);
        }
    }
    
    rdroid_pHS->filePrintf(fd, "\n\n");
    rdroid_pHS->filePrintf(fd, "###############\n");
    rdroid_pHS->filePrintf(fd, "SECTION: KEYFRAME NODES\n\n");
    totalAnimEntries = 0;
    for (i = 0; i < keyframe->numJoints2; i++)
    {
        if (keyframe->paJoints[i].numAnimEntries)
            ++totalAnimEntries;
    }
    rdroid_pHS->filePrintf(fd, "NODES %d\n\n", totalAnimEntries);
    joint_iter = keyframe->paJoints;
    for (i = 0; i < keyframe->numJoints2; i++, joint_iter++)
    {
        if (!joint_iter->numAnimEntries)
            continue;

        rdroid_pHS->filePrintf(fd, "NODE    %d\n", i);
        rdroid_pHS->filePrintf(fd, "MESH NAME %s\n", joint_iter);
        rdroid_pHS->filePrintf(fd, "ENTRIES %d\n", joint_iter->numAnimEntries);
        rdroid_pHS->filePrintf(fd, "\n");
        rdroid_pHS->filePrintf(
        fd,
        "# num:   frame:   flags:           x:           y:           z:           p:           y:           r:\n");
        rdroid_pHS->filePrintf(
        fd,
        "#                                 dx:          dy:          dz:          dp:          dy:          dr:\n");
        animEntry_iter = joint_iter->paAnimEntries;
        for (j = 0; j < joint_iter->numAnimEntries; j++ )
        {
            rdroid_pHS->filePrintf(
                fd,
                " %3d:  %7d   0x%04x %12.8f %12.8f %12.8f %12.8f %12.8f %12.8f\n",
                j,
                animEntry_iter->frameNum,
                animEntry_iter->flags,
                animEntry_iter->pos.x,
                animEntry_iter->pos.y,
                animEntry_iter->pos.z,
                animEntry_iter->orientation.x,
                animEntry_iter->orientation.y,
                animEntry_iter->orientation.z);

            rdroid_pHS->filePrintf(
                fd,
                " %35.8f %12.8f %12.8f %12.8f %12.8f %12.8f\n",
                animEntry_iter->vel.x,
                animEntry_iter->vel.y,
                animEntry_iter->vel.z,
                animEntry_iter->angVel.x,
                animEntry_iter->angVel.y,
                animEntry_iter->angVel.z);
            ++animEntry_iter;
        }
        rdroid_pHS->filePrintf(fd, "\n");
    }
    rdroid_pHS->fileClose(fd);
    
    return 1;
}

void rdKeyframe_FreeEntry(rdKeyframe *keyframe)
{
    if (!keyframe)
        return;

    if (pKeyframeUnloader)
    {
        pKeyframeUnloader(keyframe);
        return;
    }
    
    // This was inlined
    rdKeyframe_FreeJoints(keyframe);
    
    rdroid_pHS->free(keyframe);
}

void rdKeyframe_FreeJoints(rdKeyframe *keyframe)
{
    unsigned int i;
    rdJoint* joint_iter;
    
    if (!keyframe->paJoints)
        return;

    joint_iter = keyframe->paJoints;
    for (i = 0; i < keyframe->numJoints2; i++)
    {
        if (joint_iter->paAnimEntries)
        {
            rdroid_pHS->free(joint_iter->paAnimEntries);
            joint_iter->paAnimEntries = NULL;
        }
        joint_iter++;
    }
    rdroid_pHS->free(keyframe->paJoints);
    keyframe->paJoints = NULL;
}
