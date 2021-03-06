#ifndef WINUTILS_H
#define WINUTILS_H

#include <stdint.h>
#include <string>

std::string guid_to_string(uint8_t* lpGUID);

uint32_t CreateInterfaceInstance(std::string name, int num_funcs);

uint32_t GlobalQueryInterface(std::string iid_str, uint32_t* lpInterface);
void GlobalRelease(void* this_ptr);

#endif
