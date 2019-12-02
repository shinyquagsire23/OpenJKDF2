#include "exe.h"

#include "main.h"
#include "vm.h"

std::map<int, std::map<int, ResourceData*> > resource_id_map;
std::map<int, std::map<std::string, ResourceData*> > resource_str_map;

std::string from_wstring(void* wstring, bool tolower)
{
    uint16_t len = *(uint16_t*)wstring;
    wstring += sizeof(uint16_t);
    
    std::string out = "";
    for (int i = 0; i < len; i++)
    {
        char val = *(char*)wstring;
        if (tolower)
            val = std::tolower(val);
        out += val;
        wstring += sizeof(uint16_t);
    }
    return out;
}

void parse_rsrc_table(void* resource_dir, void* resource_iter, int level = 0, int type = 0, int parent_id = 0, std::string parent_name = "")
{
    ResourceDirTable* table = (ResourceDirTable*)resource_iter;
    resource_iter += sizeof(ResourceDirTable);
    
    /*for (int j = 0; j < level; j++)
    {
        printf("  ");
    }
    
    printf("tbl head %x %x %u.%u names %u, ids %u\n", table->characteristics, table->timestamp, table->major, table->minor, table->cnt_names, table->cnt_ids);*/
    for (int i = 0; i < table->cnt_names; i++)
    {
        ResourceDirEntry* entry = (ResourceDirEntry*)resource_iter;
        bool dir = (entry->offset & 0x80000000);
        uint32_t entry_offset = entry->offset & 0x7FFFFFFF;
        ResourceData* entry_data = (ResourceData*)(resource_dir + entry_offset);

        if (entry_data->ptr < image_mem_addr)
            entry_data->ptr += image_mem_addr;
        
        for (int j = 0; j < level; j++)
        {
            printf("  ");
        }
        std::string name_str = from_wstring(resource_dir + (entry->name_offset & 0x7FFFFFFF), true);
        printf("name %s, %s offset %x\n", name_str.c_str(), dir ? "subdir" : "data", entry->offset & 0x7FFFFFFF);
        
        if (dir)
            parse_rsrc_table(resource_dir, resource_dir + (entry->offset & 0x7FFFFFFF), level + 1, type, parent_id, name_str);
        else
            resource_str_map[type][parent_name] = entry_data;
        
        resource_iter += sizeof(ResourceDirEntry);
    }
    
    for (int i = 0; i < table->cnt_ids; i++)
    {
        ResourceDirEntry* entry = (ResourceDirEntry*)resource_iter;
        bool dir = (entry->offset & 0x80000000);
        uint32_t entry_offset = entry->offset & 0x7FFFFFFF;
        ResourceData* entry_data = (ResourceData*)(resource_dir + entry_offset);
        
        if (entry_data->ptr < image_mem_addr)
            entry_data->ptr += image_mem_addr;
        
        for (int j = 0; j < level; j++)
        {
            printf("  ");
        }
        printf("id %u, %s offset %x\n", entry->id, dir ? "subdir" : "data", entry_offset);

        if (level == 0)
            type = entry->id;

        if (dir)
            parse_rsrc_table(resource_dir, resource_dir + (entry->offset & 0x7FFFFFFF), level + 1, type, entry->id, "");
        else
        {
            printf("%u, %u, %p\n", type, parent_id, entry_data);
            resource_id_map[type][parent_id] = entry_data;
        }
        
        resource_iter += sizeof(ResourceDirEntry);
    }
}

uint32_t load_executable(char* path, uint32_t *image_addr, void **image_mem, uint32_t *image_size, uint32_t *stack_addr, uint32_t *stack_size)
{
    struct DosHeader dosHeader;
    struct COFFHeader coffHeader;
    struct PEOptHeader peHeader;
    
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        printf("Failed to open %s, exiting\n", path);
        return -1;
    }
    
    fread(&dosHeader, sizeof(struct DosHeader), 1, f);
    fseek(f, dosHeader.e_lfanew + sizeof(uint32_t), SEEK_SET);
    fread(&coffHeader, sizeof(struct COFFHeader), 1, f);
    
    printf("PE header at 0x%08x\n", dosHeader.e_lfanew);
    printf("COFF:\nMachine %x\nNum Sections %x\nTimeDateStamp %x\nSymbol Table Ptr %x\nNum Symbols %x\nOpt Hdr Size %x\nCharacteristics %x\n", coffHeader.machine, coffHeader.numberOfSections, coffHeader.timeDateStamp, coffHeader.pointerToSymbolTable, coffHeader.numberOfSymbols, coffHeader.sizeOfOptionalHeader, coffHeader.characteristics);
    
    if (coffHeader.machine != COFF_I386)
    {
        printf("Bad COFF machine type %x, expected %x, exiting\n", coffHeader.machine, COFF_I386);
        return -1;
    }
    
    fread(&peHeader, sizeof(struct PEOptHeader), 1, f);
    
    printf("Code size %x section starts at %x, execution starts at %x, %x\n", peHeader.sizeOfCode, peHeader.baseOfCode + peHeader.imageBase, peHeader.addressOfEntryPoint, peHeader.sizeOfImage);
    
    //TODO: should this be here
    printf("Stack size %x, %x heap %x %x\n", peHeader.sizeOfStackReserve, peHeader.sizeOfStackCommit, peHeader.sizeOfHeapReserve, peHeader.sizeOfHeapCommit);
    
    *stack_addr = peHeader.imageBase + peHeader.sizeOfImage;
    *stack_size = peHeader.sizeOfStackReserve;
    
    *image_addr = peHeader.imageBase;
    
    uint64_t totalSize = peHeader.sizeOfImage + peHeader.sizeOfStackReserve;
    totalSize = (totalSize + 0xFFF) & ~0xFFF;
    
    //*image_mem = malloc(peHeader.sizeOfImage + peHeader.sizeOfStackReserve);
    *image_mem = vm_alloc(totalSize);
    *image_size = peHeader.sizeOfImage;
    
    void* resource_sect = nullptr;
    void* resource_dir = nullptr;
    for (int i = 0; i < coffHeader.numberOfSections; i++)
    {
        uint64_t temp;
        struct PESection peSection;
        fread(&peSection, sizeof(struct PESection), 1, f);
        temp = ftell(f);
        
        printf("Section %.8s size 0x%x, vsize 0x%x, vaddr 0x%0x at file 0x%x. %x relocs, %x lines\n", peSection.name, peSection.sizeOfRawData, peSection.addr.virtualSize, peSection.virtualAddress, peSection.pointerToRawData, peSection.numberOfRelocations, peSection.numberOfLinenumbers);
        
        fseek(f, peSection.pointerToRawData, SEEK_SET);
        fread(*image_mem + peSection.virtualAddress, peSection.sizeOfRawData, 1, f);
        
        fseek(f, temp, SEEK_SET);
        
        if (!strcmp(peSection.name, ".rsrc"))
        {
            resource_sect = *image_mem + peSection.virtualAddress;
        }
    }
    
    // Iterate directories and link
    for (int i = 0; i < 16; i++)
    {
        printf("directory %i, %x size %x\n", i, peHeader.dataDirectory[i].virtualAddress, peHeader.dataDirectory[i].size);
        
        if (i == IMAGE_DIRECTORY_ENTRY_RESOURCE)
            resource_dir = *image_mem + peHeader.dataDirectory[i].virtualAddress;
        
        struct ImportDesc tmp;
        if (i != IMAGE_DIRECTORY_ENTRY_IMPORT) continue;

        for (int j = 0; j < peHeader.dataDirectory[i].size / sizeof(struct ImportDesc); j++)
        {
            memcpy(&tmp, *image_mem + peHeader.dataDirectory[i].virtualAddress + j*sizeof(struct ImportDesc), sizeof(struct ImportDesc));

            std::string name = std::string((char*)(*image_mem + tmp.name));
            printf("%s:\n", name.c_str());
            
            printf("%x %x\n", peHeader.imageBase + tmp.name_desc_ptr, peHeader.imageBase + tmp.import_ptr_list);
            
            for (int i = 0; true; i++)
            {
                uint32_t importEntryRelAddr = *(uint32_t*)(*image_mem + tmp.name_desc_ptr + i*sizeof(uint32_t));
                
                if (!importEntryRelAddr) break;
                if (importEntryRelAddr & 0x80000000)
                {
                    uint32_t index = importEntryRelAddr & ~0x80000000;
                    std::string to_register = "";
                    if (!strcmp(name.c_str(), "COMCTL32.dll") && index == 17)
                    {
                        to_register = "InitCommonControls";
                    }
                    else if (!strcmp(name.c_str(), "DPLAYX.dll") && index == 4)
                    {
                        to_register = "DirectPlayLobbyCreateA";
                    }
                    else if (!strcmp(name.c_str(), "smackw32.DLL"))
                    {
                        bool skip = false;
                        switch (index)
                        {
                            case 38:
                                to_register = "SmackSoundUseDirectSound";
                                break;
                            case 21:
                                to_register = "SmackNextFrame";
                                break;
                            case 18:
                                to_register = "SmackClose";
                                break;
                            case 14:
                                to_register = "SmackOpen";
                                break;
                            case 26:
                                to_register = "SmackGetTrackData";
                                break;
                            case 19:
                                to_register = "SmackDoFrame";
                                break;
                            case 23:
                                to_register = "SmackToBuffer";
                                break;
                            case 32:
                                to_register = "SmackWait";
                                break;
                            case 17:
                                to_register = "SmackSoundOnOff";
                                break;
                            default:
                                printf("Unknown index %i for %s\n", index, name.c_str());
                                skip = true;
                                break;
                        }
                        
                        if (skip) continue;
                    }
                    else
                    {
                        printf("Unknown index %i for %s\n", index, name.c_str());
                        continue;
                    }
                    
                    register_import(name, to_register, peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
                    printf("%s:%s at 0x%x\n", name.c_str(), to_register.c_str(), peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
                    continue;
                }
                
                uint16_t hint = *(uint16_t*)(*image_mem + importEntryRelAddr);

                std::string funcName = std::string((char*)(*image_mem + importEntryRelAddr + sizeof(uint16_t)));
                register_import(name, funcName, peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));

                printf("%s:%s at 0x%x\n", name.c_str(), funcName.c_str(), peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
            }
            printf("\n");
        }
    }
    
    if (resource_sect != nullptr)
    {
        void* resource_iter = resource_sect;

        parse_rsrc_table(resource_dir, resource_iter);
        
        //while (1);
    }
    
    fclose(f);

    return peHeader.imageBase + peHeader.addressOfEntryPoint;
}
