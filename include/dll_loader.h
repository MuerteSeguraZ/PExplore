#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace inspector {

class DllLoader {
public:
    // Try to locate and load a DLL by name (searches system dirs)
    // Returns true if found and mapped
    static bool load_dll(const std::string& dll_name, 
                        std::vector<uint8_t>& out_bytes,
                        std::string& out_path);

private:
    // Search paths in order: current dir, System32, SysWOW64
    static std::vector<std::string> get_search_paths();
};

} // namespace inspector