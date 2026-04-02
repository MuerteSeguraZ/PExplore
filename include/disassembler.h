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

    // Resolved call/jmp target VA (0 = indirect / unresolved)
    uint64_t    call_target  = 0;
};

struct DisasmResult {
    std::vector<Instruction> instructions;
    std::string              error;   // non-empty on failure
};

// ------------------------------------------------------------------
// XREFs  –  who calls into a given function VA
// ------------------------------------------------------------------
struct XRefEntry {
    std::string caller_name;   // export name of the caller
    uint64_t    caller_va;     // VA of the call instruction itself
    uint64_t    callee_va;     // VA of the callee (= the function being inspected)
};

// ------------------------------------------------------------------
// Call-graph node  –  what a function calls out to
// ------------------------------------------------------------------
struct CallGraphNode {
    std::string callee_name;   // resolved name, or hex VA if unknown
    uint64_t    callee_va;     // 0 = indirect / unresolved
    uint64_t    call_site_va;  // VA of the call instruction inside caller
    bool        is_import;     // target resolved to an IAT entry
    bool        is_indirect;   // call reg / call [mem]
};

// ------------------------------------------------------------------

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