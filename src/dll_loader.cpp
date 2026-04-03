#include "dll_loader.h"
#include <shlwapi.h>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

namespace inspector {

std::vector<std::string> DllLoader::get_search_paths() {
    std::vector<std::string> paths;
    char buf[MAX_PATH];

    // Current directory
    if (GetCurrentDirectoryA(MAX_PATH, buf))
        paths.push_back(buf);

    // System32
    if (GetSystemDirectoryA(buf, MAX_PATH))
        paths.push_back(buf);

    // SysWOW64 (32-bit system DLLs on 64-bit OS)
    if (GetWindowsDirectoryA(buf, MAX_PATH)) {
        std::string wow64 = buf;
        wow64 += "\\SysWOW64";
        paths.push_back(wow64);
    }

    return paths;
}

bool DllLoader::load_dll(const std::string& dll_name,
                         std::vector<uint8_t>& out_bytes,
                         std::string& out_path) {
    out_bytes.clear();
    out_path.clear();

    auto paths = get_search_paths();

    for (auto& dir : paths) {
        std::string full_path = dir + "\\" + dll_name;

        // Try with .dll extension if not present
        if (dll_name.find(".dll") == std::string::npos &&
            dll_name.find(".DLL") == std::string::npos) {
            full_path += ".dll";
        }

        // Check if file exists
        if (GetFileAttributesA(full_path.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;

        // Try to open and read the file
        HANDLE hFile = CreateFileA(full_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            continue;

        LARGE_INTEGER sz_li;
        if (!GetFileSizeEx(hFile, &sz_li)) {
            CloseHandle(hFile);
            continue;
        }

        size_t sz = static_cast<size_t>(sz_li.QuadPart);
        if (sz == 0 || sz > 256 * 1024 * 1024) {  // Sanity check: max 256MB
            CloseHandle(hFile);
            continue;
        }

        out_bytes.resize(sz);
        DWORD bytes_read = 0;
        if (!ReadFile(hFile, out_bytes.data(), static_cast<DWORD>(sz),
                      &bytes_read, nullptr) ||
            bytes_read != sz) {
            CloseHandle(hFile);
            out_bytes.clear();
            continue;
        }

        CloseHandle(hFile);
        out_path = full_path;
        return true;
    }

    return false;
}

} // namespace inspector