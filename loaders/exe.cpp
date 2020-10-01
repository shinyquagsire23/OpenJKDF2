#include "exe.h"

#include "main.h"
#include "vm.h"

#include <algorithm>

std::map<int, std::map<int, ResourceData*> > resource_id_map;
std::map<int, std::map<std::string, ResourceData*> > resource_str_map;

std::map<std::string, uint32_t> dll_exports;

std::string from_wstring(void* wstring, bool tolower)
{
    uint16_t len = *(uint16_t*)wstring;
    wstring = (void*)((intptr_t)wstring + sizeof(uint16_t));
    
    std::string out = "";
    for (int i = 0; i < len; i++)
    {
        char val = *(char*)wstring;
        if (tolower)
            val = std::tolower(val);
        out += val;
        wstring = (void*)((intptr_t)wstring + sizeof(uint16_t));
    }
    return out;
}

void parse_rsrc_table(void* resource_dir, void* resource_iter, int level = 0, int type = 0, int parent_id = 0, std::string parent_name = "")
{
    ResourceDirTable* table = (ResourceDirTable*)resource_iter;
    resource_iter = (void*)(table + 1);
    
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
        ResourceData* entry_data = (ResourceData*)((intptr_t)resource_dir + entry_offset);

        if (entry_data->ptr < image_mem_addr[0]) // TODO this kinda sucks
            entry_data->ptr += image_mem_addr[0]; // TODO this kinda sucks
        
        for (int j = 0; j < level; j++)
        {
            printf("  ");
        }
        std::string name_str = from_wstring((void*)((intptr_t)resource_dir + (entry->name_offset & 0x7FFFFFFF)), true);
        printf("name %s, %s offset %x\n", name_str.c_str(), dir ? "subdir" : "data", entry->offset & 0x7FFFFFFF);
        
        if (dir)
            parse_rsrc_table(resource_dir, (void*)((intptr_t)resource_dir + (entry->offset & 0x7FFFFFFF)), level + 1, type, parent_id, name_str);
        else
            resource_str_map[type][parent_name] = entry_data;
        
        resource_iter = (void*)(entry + 1);
    }
    
    for (int i = 0; i < table->cnt_ids; i++)
    {
        ResourceDirEntry* entry = (ResourceDirEntry*)resource_iter;
        bool dir = (entry->offset & 0x80000000);
        uint32_t entry_offset = entry->offset & 0x7FFFFFFF;
        ResourceData* entry_data = (ResourceData*)((intptr_t)resource_dir + entry_offset);
        
        if (entry_data->ptr < image_mem_addr[0]) // TODO this kinda sucks
            entry_data->ptr += image_mem_addr[0]; // TODO this kinda sucks
        
        for (int j = 0; j < level; j++)
        {
            printf("  ");
        }
        printf("id %u, %s offset %x\n", entry->id, dir ? "subdir" : "data", entry_offset);

        if (level == 0)
            type = entry->id;

        if (dir)
            parse_rsrc_table(resource_dir, (void*)((intptr_t)resource_dir + (entry->offset & 0x7FFFFFFF)), level + 1, type, entry->id, "");
        else
        {
            printf("%u, %u, %p\n", type, parent_id, entry_data);
            resource_id_map[type][parent_id] = entry_data;
        }
        
        resource_iter = (void*)(entry + 1);
    }
}

void PortableExecutable::load_imports()
{
    struct ImportDesc tmp;
    
    struct data_directory* directory = &dataDirectory[import_diridx];

    for (uint32_t j = 0; true; j++)
    {
        memcpy(&tmp, (void*)((intptr_t)pe_mem + directory->virtualAddress + j*sizeof(struct ImportDesc)), sizeof(struct ImportDesc));
        if (!tmp.name_desc_ptr) break;

        std::string name = std::string((char*)((intptr_t)pe_mem + tmp.name));
        printf("%s:\n", name.c_str());
        
        printf("%x %x\n", va_base + tmp.name_desc_ptr, va_base + tmp.import_ptr_list);
        
        for (int i = 0; true; i++)
        {
            uint32_t importEntryRelAddr = *(uint32_t*)((intptr_t)pe_mem + tmp.name_desc_ptr + i*sizeof(uint32_t));
            uint32_t import_rel = tmp.import_ptr_list + i*sizeof(uint32_t);
            if (!strcmp(name.c_str(), "KERNEL32.DLL"))
                name = "KERNEL32.dll"; // TODO handle different casing
            
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
                    
                    std::string export_name = "smackw32.dll::" + std::to_string(index - 1);
                    uint32_t export_addr = dll_exports[export_name];
                    
                    if (export_addr)
                    {
                        printf("Using native func for %s, funcptr %08x/%08x oldval %08x %08x (import ptr @ %08x)\n", export_name.c_str(), export_addr, export_addr - 0x9f6000 + 0x401000, *(uint32_t*)((intptr_t)pe_mem + import_rel), *(uint32_t*)vm_ptr_to_real_ptr(va_base+import_rel), va_base+import_rel);
                        *(uint32_t*)((intptr_t)pe_mem + import_rel) = export_addr;
                        //*(uint8_t*)vm_ptr_to_real_ptr(0x42688E) = 0x0f;
                        //*(uint8_t*)vm_ptr_to_real_ptr(0x42688E + 1) = 0x0b;
                        
                        //printf("%08x\n", *(uint32_t*)vm_ptr_to_real_ptr(0x0040F9DC - 0x401000 + 0x9f6000));
                        skip = true;
                        continue;
                    }
                    
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
                
                vm_import_register(name, to_register, va_base + tmp.import_ptr_list + i*sizeof(uint32_t));
                printf("%s::%s at 0x%" PRIx32 "\n", name.c_str(), to_register.c_str(), (uint32_t)(va_base + tmp.import_ptr_list + i*sizeof(uint32_t)));
                //printf("idk %08x\n", *(uint32_t*)((intptr_t)pe_mem + import_rel));
                continue;
            }
            
            //uint16_t hint = *(uint16_t*)((intptr_t)pe_mem + importEntryRelAddr);

            std::string funcName = std::string((char*)((intptr_t)pe_mem + importEntryRelAddr + sizeof(uint16_t)));
            vm_import_register(name, funcName, va_base + tmp.import_ptr_list + i*sizeof(uint32_t));

            printf("%s::%s at 0x%" PRIx32 "\n", name.c_str(), funcName.c_str(), (uint32_t)(va_base + tmp.import_ptr_list + i*sizeof(uint32_t)));
           //printf("idk %08x\n", *(uint32_t*)((intptr_t)pe_mem + import_rel));
        }
        printf("\n");
    }
}

void PortableExecutable::load_exports(void* image_mem, struct data_directory* dataDirectory)
{
    struct ExportDesc tmp;
    
    memcpy(&tmp, (void*)((intptr_t)image_mem + dataDirectory->virtualAddress), sizeof(struct ExportDesc));
    
    printf("%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n", tmp.characteristics, tmp.timeDateStamp, tmp.majorVersion, tmp.minorVersion, tmp.name, tmp.base, tmp.numberOfFunctions, tmp.numberOfNames, tmp.addressOfFunctions, tmp.addressOfNames, tmp.addressOfNameOrdinals);
    
    char* name = image_mem + tmp.name;
    uint32_t* functions_data = (uint32_t*)(image_mem + tmp.addressOfFunctions);
    uint32_t* names_data = (uint32_t*)(image_mem + tmp.addressOfNames);
    uint16_t* name_ord_data = (uint16_t*)(image_mem + tmp.addressOfNameOrdinals);
    printf("%x (%s) %x %x\n", va_base + tmp.name, name, va_base + tmp.addressOfFunctions, va_base + tmp.addressOfNames);
    
    std::string path_lower = path;
    std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);
    
    for (int i = 0; i < tmp.numberOfFunctions; i++)
    {
        uint32_t addr = va_base + functions_data[name_ord_data[i]];
        std::string export_register = path_lower + "::" + std::to_string(name_ord_data[i]);
        printf("export %08x idx %02x (%s -> %s)\n", addr, name_ord_data[i], (char*)(image_mem + names_data[i]), export_register.c_str());
        
        dll_exports[export_register] = addr;
    }
}

void PortableExecutable::load_relocations(void* image_mem, struct data_directory* dataDirectory)
{
    struct RelocDesc tmp;
    size_t block_pos = 0;
    
    while (block_pos < dataDirectory->size)
    {
        memcpy(&tmp, (void*)((intptr_t)image_mem + dataDirectory->virtualAddress + block_pos), sizeof(struct RelocDesc));
        
        uint32_t num_relocs = (tmp.block_size - sizeof(RelocDesc))/sizeof(uint16_t);
        uint16_t* relocs = (uint16_t*)((intptr_t)image_mem + dataDirectory->virtualAddress + block_pos + sizeof(RelocDesc));
        printf("block vaddr %08x size %08x\n", tmp.vaddr, tmp.block_size);
        for (int i = 0; i < num_relocs; i++)
        {
            uint8_t type = relocs[i] >> 12;
            uint16_t addr = relocs[i] & 0xFFF;
            
            if (tmp.vaddr == 0x7000)
                printf("%08x [%08x] %01x %04x\n", tmp.vaddr, *(uint32_t*)((intptr_t)image_mem + tmp.vaddr + addr), type, addr);
            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                *(uint32_t*)((intptr_t)image_mem + tmp.vaddr + addr) += (va_base - peHeader.imageBase);
                //*(uint32_t*)((intptr_t)image_mem + tmp.vaddr + addr) -= (peHeader.imageBase);
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {} // no-op           
            else
            {
                printf("    %01x %04x\n", type, addr);
            }
            if (tmp.vaddr == 0x7000 && addr == 0x19f)
                *(uint32_t*)((intptr_t)image_mem + tmp.vaddr + addr) = 0x80000000;
        }
        block_pos += tmp.block_size;
    }
}

uint32_t PortableExecutable::load_executable(uint32_t *image_addr, void **image_mem, uint32_t *image_size, uint32_t *stack_addr, uint32_t *stack_size)
{
    
    FILE *f = fopen(path.c_str(), "rb");
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
    
    if (!va_base)
        va_base = peHeader.imageBase;

    printf("Code size %x section starts at %x, execution starts at %x, %x\n", peHeader.sizeOfCode, peHeader.baseOfCode + va_base, peHeader.addressOfEntryPoint, peHeader.sizeOfImage);
    
    //TODO: should this be here
    printf("Stack size %x, %x heap %x %x\n", peHeader.sizeOfStackReserve, peHeader.sizeOfStackCommit, peHeader.sizeOfHeapReserve, peHeader.sizeOfHeapCommit);
    
    *stack_addr = va_base + peHeader.sizeOfImage;
    *stack_size = peHeader.sizeOfStackReserve;
    
    *image_addr = va_base;
    
    uint64_t totalSize = peHeader.sizeOfImage + peHeader.sizeOfStackReserve;
    totalSize = (totalSize + 0xFFF) & ~0xFFF;
    
    //*image_mem = malloc(peHeader.sizeOfImage + peHeader.sizeOfStackReserve);
    pe_mem = vm_alloc(totalSize);
    *image_mem = pe_mem;
    *image_size = peHeader.sizeOfImage;
    
    size_t dataDirectory_size = peHeader.numberOfRvaAndSizes * sizeof(struct data_directory);
    dataDirectory = (struct data_directory*)malloc(dataDirectory_size);
    fread(dataDirectory, dataDirectory_size, 1, f);
    
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
        fread((void*)((intptr_t)*image_mem + peSection.virtualAddress), peSection.sizeOfRawData, 1, f);
        
        fseek(f, temp, SEEK_SET);
        
        if (!strcmp(peSection.name, ".rsrc"))
        {
            resource_sect = (void*)((intptr_t)*image_mem + peSection.virtualAddress);
        }
    }
    
    // Iterate directories and link
    for (int i = 0; i < peHeader.numberOfRvaAndSizes; i++)
    {
        printf("directory %i, %x size %x\n", i, dataDirectory[i].virtualAddress, dataDirectory[i].size);
        
        if (i == IMAGE_DIRECTORY_ENTRY_RESOURCE)
            resource_dir = (void*)((intptr_t)*image_mem + dataDirectory[i].virtualAddress);
        
        
        if (i == IMAGE_DIRECTORY_ENTRY_IMPORT)
            import_diridx = i;
        else if (i == IMAGE_DIRECTORY_ENTRY_EXPORT)
            load_exports(*image_mem, &dataDirectory[i]);
        else if (i == IMAGE_DIRECTORY_ENTRY_BASERELOC)
            load_relocations(*image_mem, &dataDirectory[i]);
        
    }
    
    if (resource_sect != nullptr)
    {
        void* resource_iter = resource_sect;

        parse_rsrc_table(resource_dir, resource_iter);
        
        //while (1);
    }
    
    fclose(f);

    return va_base + peHeader.addressOfEntryPoint;
}
