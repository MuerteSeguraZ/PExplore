#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace inspector {

struct Instruction {
    uint64_t    address      = 0;
    uint8_t     size         = 0;
    std::string mnemonic;
    std::string op_str;
    std::string bytes_hex;   // "48 89 5c 24 08 ..."
    bool        is_ret       = false;
    bool        is_call      = false;
    bool        is_jmp       = false;   // unconditional
    bool        is_jcc       = false;   // conditional
    bool        is_nop       = false;
};

struct DisasmResult {
    std::vector<Instruction> instructions;
    std::string              error;   // non-empty on failure
};

// ------------------------------------------------------------------------------

class Disassembler {
public:
    explicit Disassembler(bool x64);
    ~Disassembler();

    DisasmResult disassemble(const uint8_t* buf,
                             size_t         buf_size,
                             uint64_t       virtual_addr,
                             size_t         max_insns = 512) const;

private:
    void*  handle_ = nullptr;   // csh — opaque to callers
    bool   x64_;
};

} // namespace inspector