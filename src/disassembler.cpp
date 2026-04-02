#include "disassembler.h"
#include <capstone/capstone.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace inspector {

Disassembler::Disassembler(bool x64) : x64_(x64) {
    csh h = 0;
    cs_mode mode = x64 ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &h) == CS_ERR_OK) {
        cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        handle_ = reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
}

Disassembler::~Disassembler() {
    if (handle_) {
        csh h = static_cast<csh>(reinterpret_cast<uintptr_t>(handle_));
        cs_close(&h);
    }
}

static bool insn_is_ret(const cs_insn* i) {
    for (uint8_t g = 0; g < i->detail->groups_count; ++g)
        if (i->detail->groups[g] == CS_GRP_RET ||
            i->detail->groups[g] == CS_GRP_IRET)
            return true;
    return (i->id == X86_INS_RET  ||
            i->id == X86_INS_RETF ||
            i->id == X86_INS_RETFQ);
}

static bool insn_is_call(const cs_insn* i) {
    for (uint8_t g = 0; g < i->detail->groups_count; ++g)
        if (i->detail->groups[g] == CS_GRP_CALL)
            return true;
    return false;
}

static bool insn_is_jmp(const cs_insn* i) {
    return (i->id == X86_INS_JMP || i->id == X86_INS_LJMP);
}

static bool insn_is_jcc(const cs_insn* i) {
    if (insn_is_jmp(i)) return false;
    for (uint8_t g = 0; g < i->detail->groups_count; ++g)
        if (i->detail->groups[g] == CS_GRP_JUMP)
            return true;
    return false;
}

static bool insn_is_nop(const cs_insn* i) {
    return (i->id == X86_INS_NOP ||
            i->id == X86_INS_FNOP);
}

DisasmResult Disassembler::disassemble(const uint8_t* buf,
                                        size_t         buf_size,
                                        uint64_t       virtual_addr,
                                        size_t         max_insns) const {
    DisasmResult result;
    if (!handle_) {
        result.error = "Capstone engine failed to initialise";
        return result;
    }
    if (!buf || buf_size == 0) {
        result.error = "Empty buffer";
        return result;
    }

    csh h = static_cast<csh>(reinterpret_cast<uintptr_t>(handle_));

    cs_insn* insns  = nullptr;
    size_t   count  = cs_disasm(h, buf, buf_size, virtual_addr, max_insns, &insns);

    if (count == 0) {
        result.error = std::string("cs_disasm: ") + cs_strerror(cs_errno(h));
        return result;
    }

    result.instructions.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const cs_insn& ci = insns[i];
        Instruction    inst;

        inst.address  = ci.address;
        inst.size     = ci.size;
        inst.mnemonic = ci.mnemonic;
        inst.op_str   = ci.op_str;

        // Build "48 89 5c 24 08" style hex string
        {
            std::ostringstream hex;
            for (int b = 0; b < ci.size; ++b) {
                if (b) hex << ' ';
                hex << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned>(ci.bytes[b]);
            }
            inst.bytes_hex = hex.str();
        }

        inst.is_ret  = insn_is_ret(&ci);
        inst.is_call = insn_is_call(&ci);
        inst.is_jmp  = insn_is_jmp(&ci);
        inst.is_jcc  = insn_is_jcc(&ci);
        inst.is_nop  = insn_is_nop(&ci);

        result.instructions.push_back(std::move(inst));

        if (inst.is_ret || inst.is_jmp)
            break;
    }

    cs_free(insns, count);
    return result;
}

} // namespace inspector