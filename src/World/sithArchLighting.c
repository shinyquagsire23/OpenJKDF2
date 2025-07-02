#include "sithArchLighting.h"

#include "jk.h"
#include "globals.h"
#include "General/stdConffile.h"

#ifdef JKM_LIGHTING

void sithArchLighting_Free(sithWorld* pWorld)
{
    if (pWorld->aArchlights)
    {
        for (int i = 0; i < pWorld->numArchLights; i++) 
        {
            sithArchLight* psVar3 = &pWorld->aArchlights[i];
            for (int j = 0; j < psVar3->numMeshes; j++) 
            {
                pSithHS->free(psVar3->aMeshes[j].aMono);
                pSithHS->free(psVar3->aMeshes[j].aRed);
                pSithHS->free(psVar3->aMeshes[j].aGreen);
                pSithHS->free(psVar3->aMeshes[j].aBlue);
                //pSithHS->free(psVar3->aMeshes[j]); // MOTS bug
            }
            pSithHS->free(psVar3->aMeshes); // Added: free correctly
        }
        pSithHS->free(pWorld->aArchlights);
        pWorld->aArchlights = NULL;
        pWorld->numArchLights = 0;
    }
}

int sithArchLighting_ParseSection(sithWorld *pWorld, int unk)
{
    uint32_t uVar2;
    sithArchLight *psVar3;
    sithArchLightMesh *psVar4;
    uint32_t uVar5;
    flex_t *pfVar6;
    int iVar7;
    uint32_t uVar8;
    sithArchLightMesh *ppvVar11;
    int iVar9;
    void **ppvVar10;
    char *pcVar11;
    char *pcVar12;
    int bVar13;
    flex_t fVar15;
    flex_t fVar14;
    int iStack12;
    
    if (unk) 
    {
        unk = 0;
        sithArchLighting_Free(pWorld);
    }

    stdConffile_ReadArgs();

    if (strncmp(stdConffile_entry.args[0].value, "num", strlen("num"))) return 0;
    if (strncmp(stdConffile_entry.args[1].value, "archobjects", strlen("archobjects"))) return 0;

    uVar2 = _atoi(stdConffile_entry.args[2].value);
    uVar8 = uVar2 * sizeof(sithArchLight);
    if (uVar8 == 0) {
        uVar8 = sizeof(sithArchLight); // Added: 1 -> sizeof(sithArchLight)
    }
    psVar3 = (sithArchLight *)pSithHS->alloc(uVar8);
    pWorld->aArchlights = psVar3;
    if (!psVar3) return 0;

    pWorld->numArchLights = uVar2;
    unk = 0;
    if (uVar2 != 0) {
        do {
            psVar3 = pWorld->aArchlights + unk;
            stdConffile_ReadArgs();
            _atoi(stdConffile_entry.args[1].value);
            stdConffile_ReadArgs();
            if (!strncmp(stdConffile_entry.args[0].value, "nummeshes:", strlen("nummeshes:"))) {
                iStack12 = _atoi(stdConffile_entry.args[1].value);
                psVar3->numMeshes = iStack12;
                psVar4 = (sithArchLightMesh *)pSithHS->alloc(iStack12 * sizeof(sithArchLightMesh));
                psVar3->aMeshes = psVar4;
                if (iStack12 != 0) {
                    iVar9 = 0;
                    do {
                        stdConffile_ReadArgs();
                        _atoi(stdConffile_entry.args[1].value);
                        ppvVar11 = &psVar3->aMeshes[iVar9];
                        stdConffile_ReadArgs();
                        
                        if (!strncmp(stdConffile_entry.args[0].value, "numvertices:", strlen("numvertices:"))) {
                            uVar5 = _atoi(stdConffile_entry.args[1].value);
                            ppvVar11->numVertices = uVar5;
                            uVar8 = uVar5 * sizeof(flex_t);
                            pfVar6 = (flex_t *)pSithHS->alloc(uVar8);
                            ppvVar11->aMono = pfVar6;
                            pfVar6 = (flex_t *)pSithHS->alloc(uVar8);
                            ppvVar11->aRed = pfVar6;
                            pfVar6 = (flex_t *)pSithHS->alloc(uVar8);
                            ppvVar11->aGreen = pfVar6;
                            pfVar6 = (flex_t *)pSithHS->alloc(uVar8);
                            uVar8 = 0;
                            ppvVar11->aBlue = pfVar6;
                            if (uVar5 != 0) {
                                do {
                                    stdConffile_ReadArgs();
                                    fVar14 = _atof(stdConffile_entry.args[1].value);
                                    pcVar11 = stdConffile_entry.args[2].value;
                                    ppvVar11->aMono[uVar8] = fVar14;
                                    fVar15 = _atof(pcVar11);
                                    pcVar11 = stdConffile_entry.args[3].value;
                                    ppvVar11->aRed[uVar8] = fVar15;
                                    fVar15 = _atof(pcVar11);
                                    pcVar11 = stdConffile_entry.args[4].value;
                                    ppvVar11->aGreen[uVar8] = fVar15;
                                    fVar15 = _atof(pcVar11);
                                    ppvVar11->aBlue[uVar8] = fVar15;
                                    uVar8 = uVar8 + 1;
                                } while (uVar8 < uVar5);
                            }
                        }
                        iVar9++;
                        iStack12 = iStack12 + -1;
                    } while (iStack12 != 0);
                }
            }
            unk = unk + 1;
        } while (unk < uVar2);
    }
    return 1;
}

#endif // JKM_LIGHTING