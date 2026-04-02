#include "pe_parser.h"
#include <algorithm>
#include <cstring>

namespace inspector {

PeParser::PeParser(const std::wstring& path) : path_(path) {}

PeParser::~PeParser() {
    if (base_)                         UnmapViewOfFile(base_);
    if (mapping_)                      CloseHandle(mapping_);
    if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
}

bool PeParser::parse() {
    // Open & map the file read-only.
    file_ = CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz_li;
    if (!GetFileSizeEx(file_, &sz_li)) return false;
    size_ = static_cast<size_t>(sz_li.QuadPart);

    mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_) return false;

    base_ = static_cast<const uint8_t*>(MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0));
    if (!base_) return false;

    if (size_ < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
    if (pe_off + sizeof(IMAGE_NT_HEADERS32) > size_) return false;

    auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base_ + pe_off);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return false;

    switch (nt32->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:  info_.machine_str = "x86 (i386)";  info_.is_64bit = false; break;
        case IMAGE_FILE_MACHINE_AMD64: info_.machine_str = "x64 (AMD64)"; info_.is_64bit = true;  break;
        case IMAGE_FILE_MACHINE_ARM:   info_.machine_str = "ARM (Thumb2)"; info_.is_64bit = false; break;
        case IMAGE_FILE_MACHINE_ARM64: info_.machine_str = "ARM64";        info_.is_64bit = true;  break;
        default:                       info_.machine_str = "Unknown";       info_.is_64bit = false; break;
    }
    info_.is_dll = (nt32->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    if (info_.is_64bit) {
        if (pe_off + sizeof(IMAGE_NT_HEADERS64) > size_) return false;
        auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ + pe_off);
        auto& opt  = nt64->OptionalHeader;

        info_.image_base64 = opt.ImageBase;
        info_.entry_point  = opt.AddressOfEntryPoint;

        auto* secs = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(&opt) + nt64->FileHeader.SizeOfOptionalHeader);
        parse_section_table(nt64->FileHeader.NumberOfSections, secs);
        parse_exports_dir(opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        parse_imports_dir(opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], true);
    } else {
        auto& opt = nt32->OptionalHeader;

        info_.image_base32 = opt.ImageBase;
        info_.entry_point  = opt.AddressOfEntryPoint;

        auto* secs = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(&opt) + nt32->FileHeader.SizeOfOptionalHeader);
        parse_section_table(nt32->FileHeader.NumberOfSections, secs);
        parse_exports_dir(opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        parse_imports_dir(opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], false);
    }

    return true;
}

void PeParser::parse_section_table(uint16_t count, const IMAGE_SECTION_HEADER* secs) {
    info_.sections.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        Section s;
        char buf[9] = {};
        memcpy(buf, secs[i].Name, 8);
        s.name            = buf;
        s.virtual_address = secs[i].VirtualAddress;
        s.virtual_size    = secs[i].Misc.VirtualSize;
        s.raw_offset      = secs[i].PointerToRawData;
        s.raw_size        = secs[i].SizeOfRawData;
        s.characteristics = secs[i].Characteristics;
        info_.sections.push_back(s);
    }
}

bool PeParser::rva_to_offset(uint32_t rva, uint32_t& out_offset) const {
    for (auto& s : info_.sections) {
        if (rva >= s.virtual_address &&
            rva <  s.virtual_address + s.virtual_size) {
            uint32_t delta = rva - s.virtual_address;
            if (delta < s.raw_size) {
                out_offset = s.raw_offset + delta;
                return true;
            }
        }
    }
    return false;
}

const uint8_t* PeParser::bytes_at_rva(uint32_t rva) const {
    uint32_t off;
    if (!rva_to_offset(rva, off)) return nullptr;
    if (off >= size_)             return nullptr;
    return base_ + off;
}

size_t PeParser::max_bytes_at_rva(uint32_t rva) const {
    for (auto& s : info_.sections) {
        if (rva >= s.virtual_address &&
            rva <  s.virtual_address + s.virtual_size) {
            uint32_t delta      = rva - s.virtual_address;
            if (delta >= s.raw_size) return 0;
            uint32_t off        = s.raw_offset + delta;
            uint32_t sec_remain = s.raw_size - delta;
            size_t   file_remain= (off < size_) ? (size_ - off) : 0;
            return std::min(static_cast<size_t>(sec_remain), file_remain);
        }
    }
    return 0;
}

void PeParser::parse_exports_dir(IMAGE_DATA_DIRECTORY dir) {
    if (!dir.VirtualAddress || !dir.Size) return;
    auto* p = bytes_at_rva(dir.VirtualAddress);
    if (!p) return;

    auto* ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(p);
    uint32_t n_funcs   = ed->NumberOfFunctions;
    uint32_t n_names   = ed->NumberOfNames;
    uint32_t base_ord  = ed->Base;

    auto* fn_rvas   = reinterpret_cast<const uint32_t*>(bytes_at_rva(ed->AddressOfFunctions));
    auto* name_rvas = reinterpret_cast<const uint32_t*>(bytes_at_rva(ed->AddressOfNames));
    auto* name_ords = reinterpret_cast<const uint16_t*>(bytes_at_rva(ed->AddressOfNameOrdinals));
    if (!fn_rvas) return;

    uint32_t exp_start = dir.VirtualAddress;
    uint32_t exp_end   = exp_start + dir.Size;

    std::vector<std::string> names_by_idx(n_funcs);
    for (uint32_t i = 0; i < n_names && name_rvas && name_ords; ++i) {
        uint16_t idx = name_ords[i];
        if (idx < n_funcs) {
            auto* np = bytes_at_rva(name_rvas[i]);
            if (np) names_by_idx[idx] = reinterpret_cast<const char*>(np);
        }
    }

    info_.exports.reserve(n_funcs);
    for (uint32_t i = 0; i < n_funcs; ++i) {
        if (!fn_rvas[i]) continue;
        ExportEntry e;
        e.rva     = fn_rvas[i];
        e.ordinal = static_cast<uint16_t>(base_ord + i);
        e.name    = names_by_idx[i].empty()
                        ? ("Ordinal_" + std::to_string(e.ordinal))
                        : names_by_idx[i];
        e.forwarder = (e.rva >= exp_start && e.rva < exp_end);
        if (e.forwarder) {
            auto* fp = bytes_at_rva(e.rva);
            if (fp) e.forwarder_name = reinterpret_cast<const char*>(fp);
        }
        info_.exports.push_back(std::move(e));
    }

    std::sort(info_.exports.begin(), info_.exports.end(),
              [](const ExportEntry& a, const ExportEntry& b) {
                  return a.name < b.name;
              });
}

void PeParser::parse_imports_dir(IMAGE_DATA_DIRECTORY dir, bool x64) {
    if (!dir.VirtualAddress) return;
    auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                     bytes_at_rva(dir.VirtualAddress));
    if (!desc) return;

    while (desc->Name) {
        ImportModule mod;
        auto* np = bytes_at_rva(desc->Name);
        mod.module_name = np ? reinterpret_cast<const char*>(np) : "?";

        uint32_t thunk_rva = desc->OriginalFirstThunk
                                 ? desc->OriginalFirstThunk
                                 : desc->FirstThunk;
        uint32_t iat_rva   = desc->FirstThunk;

        if (x64) {
            auto* thunks = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                               bytes_at_rva(thunk_rva));
            while (thunks && thunks->u1.AddressOfData) {
                ImportEntry ie;
                ie.iat_rva = iat_rva;
                if (thunks->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    ie.by_ordinal = true;
                    ie.ordinal    = IMAGE_ORDINAL64(thunks->u1.Ordinal);
                    ie.name       = "#" + std::to_string(ie.ordinal);
                } else {
                    auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        bytes_at_rva(static_cast<uint32_t>(thunks->u1.AddressOfData)));
                    if (ibn) { ie.hint = ibn->Hint; ie.name = ibn->Name; }
                }
                mod.functions.push_back(ie);
                ++thunks;
                iat_rva += 8;
            }
        } else {
            auto* thunks = reinterpret_cast<const IMAGE_THUNK_DATA32*>(
                               bytes_at_rva(thunk_rva));
            while (thunks && thunks->u1.AddressOfData) {
                ImportEntry ie;
                ie.iat_rva = iat_rva;
                if (thunks->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    ie.by_ordinal = true;
                    ie.ordinal    = IMAGE_ORDINAL32(thunks->u1.Ordinal);
                    ie.name       = "#" + std::to_string(ie.ordinal);
                } else {
                    auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        bytes_at_rva(thunks->u1.AddressOfData));
                    if (ibn) { ie.hint = ibn->Hint; ie.name = ibn->Name; }
                }
                mod.functions.push_back(ie);
                ++thunks;
                iat_rva += 4;
            }
        }
        info_.imports.push_back(std::move(mod));
        ++desc;
    }
}

} // namespace inspector