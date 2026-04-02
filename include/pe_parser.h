#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace inspector {

struct ExportEntry {
    std::string  name;
    uint32_t     rva       = 0;
    uint16_t     ordinal   = 0;
    bool         forwarder = false;
    std::string  forwarder_name;
};

struct ImportEntry {
    std::string  name;
    uint16_t     hint       = 0;
    bool         by_ordinal = false;
    uint16_t     ordinal    = 0;
    uint32_t     iat_rva    = 0;
};

struct ImportModule {
    std::string              module_name;
    std::vector<ImportEntry> functions;
};

struct Section {
    std::string  name;
    uint32_t     virtual_address  = 0;
    uint32_t     virtual_size     = 0;
    uint32_t     raw_offset       = 0;
    uint32_t     raw_size         = 0;
    uint32_t     characteristics  = 0;
};

struct PeInfo {
    bool         is_64bit     = false;
    bool         is_dll       = false;
    uint32_t     image_base32 = 0;
    uint64_t     image_base64 = 0;
    uint32_t     entry_point  = 0;
    std::string  machine_str;

    std::vector<Section>       sections;
    std::vector<ExportEntry>   exports;
    std::vector<ImportModule>  imports;
};

// ---------------------------------------------------------------------------

class PeParser {
public:
    explicit PeParser(const std::wstring& path);
    ~PeParser();

    bool parse();

    const PeInfo&    info() const { return info_; }
    const std::wstring& path() const { return path_; }

    bool rva_to_offset(uint32_t rva, uint32_t& out_offset) const;

    const uint8_t* bytes_at_rva(uint32_t rva) const;

    size_t max_bytes_at_rva(uint32_t rva) const;

private:
    void parse_section_table(uint16_t count, const IMAGE_SECTION_HEADER* secs);
    void parse_exports_dir(IMAGE_DATA_DIRECTORY dir);
    void parse_imports_dir(IMAGE_DATA_DIRECTORY dir, bool x64);

    std::wstring    path_;
    HANDLE          file_    = INVALID_HANDLE_VALUE;
    HANDLE          mapping_ = nullptr;
    const uint8_t*  base_    = nullptr;
    size_t          size_    = 0;
    PeInfo          info_;
};

} // namespace inspector