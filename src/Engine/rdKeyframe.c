#include "rdKeyframe.h"

#include "Engine/rdroid.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "General/crc32.h"
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
    stdPlatform_Memzero32(keyframe, sizeof(rdKeyframe)); // Added: word-safe (array may be in extram)
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(keyframe->name, "UNKNOWN", 32);
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    keyframe->namecrc = stdCrc32("UNKNOWN", strlen("UNKNOWN"));
#endif
}

rdKeyframe* rdKeyframe_Load(char *fname)
{
    rdKeyframe *keyframe;

    if (pKeyframeLoader)
        return (rdKeyframe*)pKeyframeLoader(fname);

    keyframe = (rdKeyframe*)RDROID_ALLOC(sizeof(rdKeyframe));
    if (!keyframe)
        return NULL;

    if (rdKeyframe_LoadEntry(fname, keyframe))
      return keyframe;

    // This was inlined
    rdKeyframe_Free(keyframe);
    
    return NULL;
}

int rdKeyframe_LoadEntry(char *key_fpath, rdKeyframe *keyframe)
{
    char *key_fname_only;
    rdJoint *aNodes;
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
    flex32_t posx, posy, posz;
    flex32_t orientationx, orientationy, orientationz;
    flex32_t velx, vely, velz;
    flex32_t angVelx, angVely, angVelz;
    int entry_num;
    char aMeshName[32];
    unsigned int nodes_read;
    flex32_t ftmp;

    rdKeyframe_NewEntry(keyframe);
    key_fname_only = stdFileFromPath(key_fpath);
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(keyframe->name, key_fname_only, 32);
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    keyframe->namecrc = stdCrc32(key_fname_only, strlen(key_fname_only));
#endif
    if (!stdConffile_Open(key_fpath)) {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\rdKeyframe.c", 0, "OpenJKDF2: Failed to open keyframe file `%s`\n", key_fpath);
        goto open_fail;
    }

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " section: %s", std_g_genBuffer) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " flags %d", &keyframe->flags) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " type %x", &keyframe->type) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " frames %d", &keyframe->numFrames) != 1)
      goto read_fail;

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " fps %f", &ftmp) != 1)
      goto read_fail;
    keyframe->fps = ftmp; // FLEXTODO

    if (!stdConffile_ReadLine())
      goto read_fail;

    if (_sscanf(stdConffile_g_aLine, " joints %d", &keyframe->numJoints) != 1)
      goto read_fail;

    { TWL_EXTRAM_SUGGEST(rdroid_g_pHS); // Added: joints are word-width on RETRO
    aNodes = (rdJoint *)RDROID_ALLOC(sizeof(rdJoint) * (keyframe->numJoints+1)); // Added: try and contain rdPuppet crashes...
    TWL_EXTRAM_RESTORE(rdroid_g_pHS); }
    keyframe->aNodes = aNodes;
    if (!aNodes)
      goto read_fail;

    stdPlatform_Memzero32(aNodes, sizeof(rdJoint) * (keyframe->numJoints+1)); // Added: word-safe
    keyframe->numJoints2 = keyframe->numJoints;

    if (!stdConffile_ReadLine() || _sscanf(stdConffile_g_aLine, " section: %s", std_g_genBuffer) != 1)
      goto read_fail;

    if (!_memcmp(std_g_genBuffer, "markers", 8u))
    {
      if (!stdConffile_ReadLine())
        goto read_fail;

      if (_sscanf(stdConffile_g_aLine, " markers %d", &num_markers) != 1)
        goto read_fail;

      if (num_markers > 8)
        goto read_fail;

      keyframe->numMarkers = num_markers;
      for (num_markers_read = 0; num_markers_read < num_markers; num_markers_read++)
      {
        markers = &keyframe->markers;
        if (!stdConffile_ReadLine())
            break;
        
        if (_sscanf(stdConffile_g_aLine, "%f %d", &ftmp, &markers->marker_int[num_markers_read]) != 2)
            break;
        markers->marker_float[num_markers_read] = ftmp;
      }
      
      if (num_markers_read < num_markers)
            goto read_fail;

      if (!stdConffile_ReadLine())
        goto read_fail;

      if (_sscanf(stdConffile_g_aLine, " section: %s", std_g_genBuffer) != 1)
        goto read_fail;
    }
    
    
    if (!stdConffile_ReadLine() || _sscanf(stdConffile_g_aLine, " aCurKfNodeEntryNums %d", &num_nodes) != 1)
    {
      goto read_fail;
    }

    for (nodes_read = 0; nodes_read < num_nodes; nodes_read++)
    {
        if (!stdConffile_ReadLine())
            goto read_fail;
        if (_sscanf(stdConffile_g_aLine, " node %d", &node_idx) != 1)
            goto read_fail;
        if (!stdConffile_ReadLine())
            goto read_fail;
        if (_sscanf(stdConffile_g_aLine, " mesh name %s", aMeshName) != 1)
            goto read_fail;
        joint = &keyframe->aNodes[node_idx];
        
#ifdef SITH_DEBUG_STRUCT_NAMES
        stdString_SafeStrCopy(joint->aMeshName, aMeshName, 32);
#endif
        
        if (!stdConffile_ReadLine())
            goto read_fail;

        if (_sscanf(stdConffile_g_aLine, " entries %d", &anim_entry_cnt) != 1)
            goto read_fail;

        joint->nodeNum = node_idx;
        joint->numEntries = anim_entry_cnt;
#ifdef TARGET_RETRO_HOMEBREW
        // Added: anim entries are written word-safely (parse-time float/u32 stores
        // only) and read-only afterward, so they can live in word-addressable-only
        // memory (DC VRAM arena). Biggest per-level chunk of animation data.
        int prevSuggest = rdroid_g_pHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
        joint->aEntries = (rdAnimEntry*)RDROID_ALLOC(sizeof(rdAnimEntry) * anim_entry_cnt + 2); // Added: prevent some oob accesses in rdPuppet
#ifdef TARGET_RETRO_HOMEBREW
        rdroid_g_pHS->suggestHeap(prevSuggest);
#endif
        if (!joint->aEntries)
          goto read_fail;

        anim_entry = joint->aEntries;
        for (anim_entry_read = 0; anim_entry_read < joint->numEntries; anim_entry_read++)
        {
            if (!stdConffile_ReadLine()) {
                goto read_fail;
            }
            
            if (_sscanf(
                   stdConffile_g_aLine,
                   " %d: %f %x %f %f %f %f %f %f",
                   &entry_num,
                   &ftmp,
                   &anim_entry->flags,
                   &posx,
                   &posy,
                   &posz,
                   &orientationx,
                   &orientationy,
                   &orientationz) != 9) {
              goto read_fail;
            }
            
            anim_entry->frameNum = ftmp; // FLEXTODO
            anim_entry->pos.x = posx; // FLEXTODO
            anim_entry->pos.y = posy; // FLEXTODO
            anim_entry->pos.z = posz; // FLEXTODO
            anim_entry->orientation.x = orientationx; // FLEXTODO
            anim_entry->orientation.y = orientationy; // FLEXTODO
            anim_entry->orientation.z = orientationz; // FLEXTODO
            
            if (!stdConffile_ReadLine()
              || _sscanf(stdConffile_g_aLine, " %f %f %f %f %f %f", &velx, &vely, &velz, &angVelx, &angVely, &angVelz) != 6)
            {
              goto read_fail;
            }

            anim_entry->vel.x = velx; // FLEXTODO
            anim_entry->vel.y = vely; // FLEXTODO
            anim_entry->vel.z = velz; // FLEXTODO
            anim_entry->angularVelocity.x = angVelx; // FLEXTODO
            anim_entry->angularVelocity.y = angVely; // FLEXTODO
            anim_entry->angularVelocity.z = angVelz; // FLEXTODO
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

    fd = rdroid_g_pHS->fileOpen(out_fpath, "wt+");
    if (!fd)
        return 0;

    rdroid_g_pHS->filePrintf(fd, "# KEYFRAME '%s' created from '%s'\n\n", keyframe, creation_method);
    rdroid_g_pHS->filePrintf(fd, "###############\n");
    rdroid_g_pHS->filePrintf(fd, "SECTION: HEADER\n\n");
    rdroid_g_pHS->filePrintf(fd, "FLAGS  0x%04x\n", keyframe->flags);
    rdroid_g_pHS->filePrintf(fd, "TYPE   0x%X\n", keyframe->type);
    rdroid_g_pHS->filePrintf(fd, "FRAMES %d\n", keyframe->numFrames);
    rdroid_g_pHS->filePrintf(fd, "FPS    %.3f\n", keyframe->fps);
    rdroid_g_pHS->filePrintf(fd, "JOINTS %d\n", keyframe->numJoints);
    if (keyframe->numMarkers)
    {
        rdroid_g_pHS->filePrintf(fd, "\n\n");
        rdroid_g_pHS->filePrintf(fd, "###############\n");
        rdroid_g_pHS->filePrintf(fd, "SECTION: MARKERS\n\n");
        rdroid_g_pHS->filePrintf(fd, "MARKERS %d\n\n", keyframe->numMarkers);
        for (i = 0; i < keyframe->numMarkers; i++)
        {
            rdroid_g_pHS->filePrintf(fd, "%f %d\n", keyframe->markers.marker_float[i], keyframe->markers.marker_int[i]);
        }
    }
    
    rdroid_g_pHS->filePrintf(fd, "\n\n");
    rdroid_g_pHS->filePrintf(fd, "###############\n");
    rdroid_g_pHS->filePrintf(fd, "SECTION: KEYFRAME NODES\n\n");
    totalAnimEntries = 0;
    for (i = 0; i < keyframe->numJoints2; i++)
    {
        if (keyframe->aNodes[i].numEntries)
            ++totalAnimEntries;
    }
    rdroid_g_pHS->filePrintf(fd, "NODES %d\n\n", totalAnimEntries);
    joint_iter = keyframe->aNodes;
    for (i = 0; i < keyframe->numJoints2; i++, joint_iter++)
    {
        if (!joint_iter->numEntries)
            continue;

        rdroid_g_pHS->filePrintf(fd, "NODE    %d\n", i);
#ifdef SITH_DEBUG_STRUCT_NAMES
        rdroid_g_pHS->filePrintf(fd, "MESH NAME %s\n", joint_iter->aMeshName);
#else
        rdroid_g_pHS->filePrintf(fd, "MESH NAME %s\n", "UNKNOWN");
#endif
        rdroid_g_pHS->filePrintf(fd, "ENTRIES %d\n", joint_iter->numEntries);
        rdroid_g_pHS->filePrintf(fd, "\n");
        rdroid_g_pHS->filePrintf(
        fd,
        "# num:   frame:   flags:           x:           y:           z:           p:           y:           r:\n");
        rdroid_g_pHS->filePrintf(
        fd,
        "#                                 dx:          dy:          dz:          dp:          dy:          dr:\n");
        animEntry_iter = joint_iter->aEntries;
        for (j = 0; j < joint_iter->numEntries; j++ )
        {
            rdroid_g_pHS->filePrintf(
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

            rdroid_g_pHS->filePrintf(
                fd,
                " %35.8f %12.8f %12.8f %12.8f %12.8f %12.8f\n",
                animEntry_iter->vel.x,
                animEntry_iter->vel.y,
                animEntry_iter->vel.z,
                animEntry_iter->angularVelocity.x,
                animEntry_iter->angularVelocity.y,
                animEntry_iter->angularVelocity.z);
            ++animEntry_iter;
        }
        rdroid_g_pHS->filePrintf(fd, "\n");
    }
    rdroid_g_pHS->fileClose(fd);
    
    return 1;
}

void rdKeyframe_Free(rdKeyframe *keyframe)
{
    if (!keyframe)
        return;

    if (pKeyframeUnloader)
    {
        pKeyframeUnloader(keyframe);
        return;
    }
    
    // This was inlined
    rdKeyframe_FreeEntry(keyframe);
    
    RDROID_FREE(keyframe);
}

void rdKeyframe_FreeEntry(rdKeyframe *keyframe)
{
    unsigned int i;
    rdJoint* joint_iter;
    
    if (!keyframe->aNodes)
        return;

    joint_iter = keyframe->aNodes;
    for (i = 0; i < keyframe->numJoints2; i++)
    {
        if (joint_iter->aEntries)
        {
            RDROID_FREE(joint_iter->aEntries);
            joint_iter->aEntries = NULL;
        }
        joint_iter++;
    }
    RDROID_FREE(keyframe->aNodes);
    keyframe->aNodes = NULL;
}
