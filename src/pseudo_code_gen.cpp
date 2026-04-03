#include "pseudo_code_gen.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

namespace inspector {

std::vector<PseudoCodeLine> PseudoCodeGenerator::generate(const DisasmResult& disasm) const {
    std::vector<PseudoCodeLine> result;

    if (!disasm.error.empty()) {
        PseudoCodeLine line;
        line.code = "// ERROR: " + disasm.error;
        line.orig_addr = 0;
        line.is_label = false;
        result.push_back(line);
        return result;
    }

    // Track addresses that are jump targets (for labels)
    std::unordered_map<uint64_t, int> jump_targets;
    for (size_t i = 0; i < disasm.instructions.size(); ++i) {
        auto& inst = disasm.instructions[i];
        if ((inst.is_jmp || inst.is_jcc) && inst.call_target != 0) {
            jump_targets[inst.call_target]++;
        }
    }

    // Track register state for better pseudo-code
    RegState reg_state;

    // Generate pseudo-code
    for (size_t i = 0; i < disasm.instructions.size(); ++i) {
        auto& inst = disasm.instructions[i];

        // Check if this address is a jump target (add label)
        if (jump_targets.count(inst.address)) {
            std::ostringstream label;
            label << ".L" << std::hex << inst.address << ":";
            PseudoCodeLine l{label.str(), inst.address, true, {}};
            l.tokens = PseudoCodeGenerator::tokenize(l.code, true);
            result.push_back(std::move(l));
        }

        // Skip prologue/epilogue instructions
        if (is_prologue_instruction(inst) || is_epilogue_instruction(inst)) {
            std::ostringstream comment;
            comment << "// [function prologue/epilogue]";
            PseudoCodeLine l{comment.str(), inst.address, false, {}};
            l.tokens = PseudoCodeGenerator::tokenize(l.code, false);
            result.push_back(std::move(l));
            continue;
        }

        // Convert instruction
        std::string code = convert_instruction(inst, disasm, i, reg_state);
        if (!code.empty()) {
            PseudoCodeLine l{code, inst.address, false, {}};
            l.tokens = PseudoCodeGenerator::tokenize(l.code, false);
            result.push_back(std::move(l));
        }
    }

    return result;
}

std::string PseudoCodeGenerator::simplify_operand(const std::string& op) const {
    std::string result = op;
    
    // Handle memory operands specially
    if (result.find('[') != std::string::npos && result.find(']') != std::string::npos) {
        size_t start = result.find('[');
        size_t end = result.rfind(']');
        if (start != std::string::npos && end != std::string::npos && start < end) {
            std::string prefix = result.substr(0, start);
            std::string content = result.substr(start + 1, end - start - 1);
            std::string suffix = result.substr(end + 1);
            
            // Clean size specifiers from content
            content = std::regex_replace(content, std::regex("\\s*ptr\\s+"), "");
            
            // Simplify registers inside brackets
            content = simplify_registers_in_string(content);
            
            result = prefix + "[" + content + "]" + suffix;
        }
    } else {
        // Not a memory operand, simplify normally
        result = simplify_registers_in_string(result);
    }
    
    return result;
}

std::string PseudoCodeGenerator::simplify_registers_in_string(const std::string& str) const {
    std::string result = str;
    
    // Remove size specifiers
    result = std::regex_replace(result, std::regex("\\bqword\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bdword\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bword\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bbyte\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bxmmword\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bymmword\\s+ptr\\s+"), "");
    result = std::regex_replace(result, std::regex("\\bzmmword\\s+ptr\\s+"), "");
    
    // Simplify common x86-64 registers
    std::vector<std::pair<std::regex, std::string>> replacements = {
        // 64-bit general purpose
        {std::regex("\\brax\\b"), "a"},
        {std::regex("\\brbx\\b"), "b"},
        {std::regex("\\brcx\\b"), "c"},
        {std::regex("\\brdx\\b"), "d"},
        {std::regex("\\brsi\\b"), "src"},
        {std::regex("\\brdi\\b"), "dst"},
        {std::regex("\\brbp\\b"), "bp"},
        {std::regex("\\brsp\\b"), "sp"},
        {std::regex("\\br8\\b"), "r8"},
        {std::regex("\\br9\\b"), "r9"},
        {std::regex("\\br10\\b"), "r10"},
        {std::regex("\\br11\\b"), "r11"},
        {std::regex("\\br12\\b"), "r12"},
        {std::regex("\\br13\\b"), "r13"},
        {std::regex("\\br14\\b"), "r14"},
        {std::regex("\\br15\\b"), "r15"},
        
        // 32-bit
        {std::regex("\\beax\\b"), "a"},
        {std::regex("\\bebx\\b"), "b"},
        {std::regex("\\becx\\b"), "c"},
        {std::regex("\\bedx\\b"), "d"},
        {std::regex("\\besi\\b"), "src"},
        {std::regex("\\bedi\\b"), "dst"},
        {std::regex("\\bebp\\b"), "bp"},
        {std::regex("\\besp\\b"), "sp"},
        {std::regex("\\br8d\\b"), "r8"},
        {std::regex("\\br9d\\b"), "r9"},
        {std::regex("\\br10d\\b"), "r10"},
        {std::regex("\\br11d\\b"), "r11"},
        {std::regex("\\br12d\\b"), "r12"},
        {std::regex("\\br13d\\b"), "r13"},
        {std::regex("\\br14d\\b"), "r14"},
        {std::regex("\\br15d\\b"), "r15"},
        
        // 16-bit
        {std::regex("\\bax\\b"), "a"},
        {std::regex("\\bbx\\b"), "b"},
        {std::regex("\\bcx\\b"), "c"},
        {std::regex("\\bdx\\b"), "d"},
        {std::regex("\\bsi\\b"), "src"},
        {std::regex("\\bdi\\b"), "dst"},
        {std::regex("\\bbp\\b"), "bp"},
        {std::regex("\\bsp\\b"), "sp"},
        {std::regex("\\br8w\\b"), "r8"},
        {std::regex("\\br9w\\b"), "r9"},
        {std::regex("\\br10w\\b"), "r10"},
        {std::regex("\\br11w\\b"), "r11"},
        {std::regex("\\br12w\\b"), "r12"},
        {std::regex("\\br13w\\b"), "r13"},
        {std::regex("\\br14w\\b"), "r14"},
        {std::regex("\\br15w\\b"), "r15"},
        
        // 8-bit
        {std::regex("\\bal\\b"), "a"},
        {std::regex("\\bbl\\b"), "b"},
        {std::regex("\\bcl\\b"), "c"},
        {std::regex("\\bdl\\b"), "d"},
        {std::regex("\\bsil\\b"), "src"},
        {std::regex("\\bdil\\b"), "dst"},
        {std::regex("\\bbpl\\b"), "bp"},
        {std::regex("\\bspl\\b"), "sp"},
        {std::regex("\\br8b\\b"), "r8"},
        {std::regex("\\br9b\\b"), "r9"},
        {std::regex("\\br10b\\b"), "r10"},
        {std::regex("\\br11b\\b"), "r11"},
        {std::regex("\\br12b\\b"), "r12"},
        {std::regex("\\br13b\\b"), "r13"},
        {std::regex("\\br14b\\b"), "r14"},
        {std::regex("\\br15b\\b"), "r15"},
        
        // High bytes
        {std::regex("\\bah\\b"), "a_hi"},
        {std::regex("\\bbh\\b"), "b_hi"},
        {std::regex("\\bch\\b"), "c_hi"},
        {std::regex("\\bdh\\b"), "d_hi"},
    };
    
    for (auto& pair : replacements) {
        result = std::regex_replace(result, pair.first, pair.second);
    }
    
    return result;
}

std::string PseudoCodeGenerator::convert_instruction(const Instruction& inst,
                                                     const DisasmResult& context,
                                                     size_t inst_idx,
                                                     RegState& reg_state) const {
    std::ostringstream out;
    const std::string& mn = inst.mnemonic;
    const std::string& op = inst.op_str;

    // Parse operands
    std::vector<std::string> operands = parse_operands(op);

    // ============================================================
    // SIMD: SSE Moves (Various Alignments)
    // ============================================================
    if (mn == "movups") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movups (unaligned)";
            } else {
                out << dst << " = " << src << ";  // movups (unaligned)";
            }
            return out.str();
        }
    }

    if (mn == "movaps") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movaps (aligned)";
            } else {
                out << dst << " = " << src << ";  // movaps (aligned)";
            }
            return out.str();
        }
    }

    if (mn == "movdqu") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movdqu (unaligned)";
            } else {
                out << dst << " = " << src << ";  // movdqu (unaligned)";
            }
            return out.str();
        }
    }

    if (mn == "movdqa") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movdqa (aligned)";
            } else {
                out << dst << " = " << src << ";  // movdqa (aligned)";
            }
            return out.str();
        }
    }

    if (mn == "movsd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movsd (double)";
            } else {
                out << dst << " = " << src << ";  // movsd (double)";
            }
            return out.str();
        }
    }

    if (mn == "movss") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // movss (float)";
            } else {
                out << dst << " = " << src << ";  // movss (float)";
            }
            return out.str();
        }
    }

    if (mn == "vmovups" || mn == "vmovaps" || mn == "vmovdqu" || mn == "vmovdqa") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            std::string type = (mn.find("dq") != std::string::npos) ? "int" : "float";
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // " << mn << " (avx " << type << ")";
            } else {
                out << dst << " = " << src << ";  // " << mn << " (avx " << type << ")";
            }
            return out.str();
        }
    }

    if (mn == "vmovsd" || mn == "vmovss") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";  // " << mn;
            } else {
                out << dst << " = " << src << ";  // " << mn;
            }
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Arithmetic Operations
    // ============================================================
    if (mn == "addps" || mn == "addpd" || mn == "paddd" || mn == "paddq" || 
        mn == "paddb" || mn == "paddw" || mn == "vaddps" || mn == "vaddpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") += " << src << ";  // simd add";
            } else {
                out << dst << " += " << src << ";  // simd add";
            }
            return out.str();
        }
    }

    if (mn == "subps" || mn == "subpd" || mn == "psubd" || mn == "psubq" ||
        mn == "psubb" || mn == "psubw" || mn == "vsubps" || mn == "vsubpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") -= " << src << ";  // simd sub";
            } else {
                out << dst << " -= " << src << ";  // simd sub";
            }
            return out.str();
        }
    }

    if (mn == "mulps" || mn == "mulpd" || mn == "pmulld" || mn == "pmullq" ||
        mn == "vmulps" || mn == "vmulpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") *= " << src << ";  // simd mul";
            } else {
                out << dst << " *= " << src << ";  // simd mul";
            }
            return out.str();
        }
    }

    if (mn == "divps" || mn == "divpd" || mn == "vdivps" || mn == "vdivpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") /= " << src << ";  // simd div";
            } else {
                out << dst << " /= " << src << ";  // simd div";
            }
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Logical Operations
    // ============================================================
    if (mn == "xorps" || mn == "xorpd" || mn == "pxor" || mn == "vxorps" || mn == "vxorpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst == src) {
                out << dst << " = 0;  // simd zero";
            } else {
                if (dst.find('[') != std::string::npos) {
                    out << "*(" << dst << ") ^= " << src << ";  // simd xor";
                } else {
                    out << dst << " ^= " << src << ";  // simd xor";
                }
            }
            return out.str();
        }
    }

    if (mn == "andps" || mn == "andpd" || mn == "pand" || mn == "vandps" || mn == "vandpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") &= " << src << ";  // simd and";
            } else {
                out << dst << " &= " << src << ";  // simd and";
            }
            return out.str();
        }
    }

    if (mn == "orps" || mn == "orpd" || mn == "por" || mn == "vorps" || mn == "vorpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") |= " << src << ";  // simd or";
            } else {
                out << dst << " |= " << src << ";  // simd or";
            }
            return out.str();
        }
    }

    if (mn == "andnps" || mn == "andnpd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = ~(" << dst << ") & " << src << ";  // simd and-not";
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Comparison
    // ============================================================
    if (mn == "cmpps" || mn == "cmppd" || mn == "pcmpd" || mn == "pcmpq") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_cmp(" << dst << ", " << src << ");  // simd cmp";
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Shift Operations
    // ============================================================
    if (mn == "psllq" || mn == "pslld" || mn == "psllw") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            out << dst << " <<= " << cnt << ";  // simd shl";
            return out.str();
        }
    }

    if (mn == "psrlq" || mn == "psrld" || mn == "psrlw") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            out << dst << " >>= " << cnt << ";  // simd shr (logical)";
            return out.str();
        }
    }

    if (mn == "psraq" || mn == "psrad") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            out << dst << " >>= " << cnt << ";  // simd shr (arithmetic)";
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Shuffle/Permute
    // ============================================================
    if (mn == "shufps" || mn == "shufpd") {
        if (operands.size() >= 3) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            std::string imm = simplify_operand(operands[2]);
            out << dst << " = simd_shuffle(" << dst << ", " << src << ", " << imm << ");  // shuffle";
            return out.str();
        }
    }

    if (mn == "pshufd" || mn == "pshufb" || mn == "pshuflw" || mn == "pshufhw") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_shuffle(" << dst << ", " << src << ");  // " << mn;
            return out.str();
        }
    }

    if (mn.find("vpermq") != std::string::npos || mn.find("vpermd") != std::string::npos) {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_permute(" << dst << ", " << src << ");  // avx permute";
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Extract/Insert
    // ============================================================
    if (mn == "pextrd" || mn == "pextrq" || mn == "pextrb" || mn == "pextrw") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_extract(" << src << ");  // " << mn;
            return out.str();
        }
    }

    if (mn == "pinsrd" || mn == "pinsrq" || mn == "pinsrb" || mn == "pinsrw") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_insert(" << dst << ", " << src << ");  // " << mn;
            return out.str();
        }
    }

    // ============================================================
    // SIMD: Type Conversion
    // ============================================================
    if (mn == "cvtdq2ps" || mn == "cvtps2dq" || mn == "cvttps2dq") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = simd_cvt(" << src << ");  // " << mn;
            return out.str();
        }
    }

    if (mn == "cvtsi2ss" || mn == "cvtsi2sd" || mn == "cvtss2si" || mn == "cvtsd2si") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = cvt(" << src << ");  // scalar convert";
            return out.str();
        }
    }

    // ============================================================
    // AES-NI Instructions
    // ============================================================
    if (mn == "aesenc") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_encrypt_round(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "aesenclast") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_encrypt_final(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "aesdec") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_decrypt_round(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "aesdeclast") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_decrypt_final(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "aesimc") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_inv_mixcol(" << src << ");";
            return out.str();
        }
    }

    if (mn == "aeskeygenassist") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = aes_keygen(" << src << ");";
            return out.str();
        }
    }

    // ============================================================
    // Cryptography: CLMUL
    // ============================================================
    if (mn == "pclmulqdq") {
        if (operands.size() >= 3) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            std::string imm = simplify_operand(operands[2]);
            out << dst << " = clmul(" << dst << ", " << src << ", " << imm << ");";
            return out.str();
        }
    }

    // ============================================================
    // Cryptography: SHA
    // ============================================================
    if (mn == "sha1rnds4") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = sha1_round(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "sha1nexte" || mn == "sha1msg1" || mn == "sha1msg2") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = sha1_" << mn.substr(5) << "(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    if (mn == "sha256rnds2" || mn == "sha256msg1" || mn == "sha256msg2") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = sha256_" << mn.substr(7) << "(" << dst << ", " << src << ");";
            return out.str();
        }
    }

    // ============================================================
    // Movement Instructions
    // ============================================================
    if (mn == "mov") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") = " << src << ";";
            } else {
                out << dst << " = " << src << ";";
            }
            return out.str();
        }
    }

    if (mn == "movzx") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = zext(" << src << ");";
            return out.str();
        }
    }

    if (mn == "movsx" || mn == "movsxd") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = sext(" << src << ");";
            return out.str();
        }
    }

    if (mn == "lea") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string addr = simplify_operand(operands[1]);
            out << dst << " = &(" << addr << ");";
            return out.str();
        }
    }

    if (mn == "xchg") {
        if (operands.size() >= 2) {
            std::string op1 = simplify_operand(operands[0]);
            std::string op2 = simplify_operand(operands[1]);
            out << "swap(" << op1 << ", " << op2 << ");";
            return out.str();
        }
    }

    if (mn == "cmpxchg") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << "if (a == " << dst << ") { " << dst << " = " << src << "; ZF=1; } else { a=" << dst << "; ZF=0; }";
            return out.str();
        }
    }

    if (mn == "cmpxchg8b" || mn == "cmpxchg16b") {
        out << "atomic_compare_and_swap();  // " << mn;
        return out.str();
    }

    // ============================================================
    // Arithmetic: Basic
    // ============================================================
    if (mn == "add") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") += " << src << ";";
            } else {
                out << dst << " += " << src << ";";
            }
            return out.str();
        }
    }

    if (mn == "sub") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") -= " << src << ";";
            } else {
                out << dst << " -= " << src << ";";
            }
            return out.str();
        }
    }

    if (mn == "imul") {
        if (operands.size() == 3) {
            std::string dst = simplify_operand(operands[0]);
            std::string op1 = simplify_operand(operands[1]);
            std::string op2 = simplify_operand(operands[2]);
            out << dst << " = " << op1 << " * " << op2 << ";";
            return out.str();
        } else if (operands.size() == 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") *= " << src << ";";
            } else {
                out << dst << " *= " << src << ";";
            }
            return out.str();
        } else if (operands.size() == 1) {
            std::string src = simplify_operand(operands[0]);
            out << "a:d = a * " << src << ";  // rax:rdx";
            return out.str();
        }
    }

    if (mn == "mul") {
        if (operands.size() >= 1) {
            std::string src = simplify_operand(operands[0]);
            out << "a:d = a * " << src << ";  // unsigned, rax:rdx";
            return out.str();
        }
    }

    if (mn == "div") {
        if (operands.size() >= 1) {
            std::string src = simplify_operand(operands[0]);
            out << "a = a:d / " << src << "; d = a:d % " << src << ";  // unsigned";
            return out.str();
        }
    }

    if (mn == "idiv") {
        if (operands.size() >= 1) {
            std::string src = simplify_operand(operands[0]);
            out << "a = a:d / " << src << "; d = a:d % " << src << ";  // signed";
            return out.str();
        }
    }

    if (mn == "inc") {
        if (operands.size() >= 1) {
            std::string op = simplify_operand(operands[0]);
            if (op.find('[') != std::string::npos) {
                out << "++(*(" << op << "));";
            } else {
                out << "++" << op << ";";
            }
            return out.str();
        }
    }

    if (mn == "dec") {
        if (operands.size() >= 1) {
            std::string op = simplify_operand(operands[0]);
            if (op.find('[') != std::string::npos) {
                out << "--(*(" << op << "));";
            } else {
                out << "--" << op << ";";
            }
            return out.str();
        }
    }

    if (mn == "neg") {
        if (operands.size() >= 1) {
            std::string op = simplify_operand(operands[0]);
            if (op.find('[') != std::string::npos) {
                out << "*(" << op << ") = -(*(" << op << "));";
            } else {
                out << op << " = -" << op << ";";
            }
            return out.str();
        }
    }

    if (mn == "not") {
        if (operands.size() >= 1) {
            std::string op = simplify_operand(operands[0]);
            if (op.find('[') != std::string::npos) {
                out << "*(" << op << ") = ~(*(" << op << "));";
            } else {
                out << op << " = ~" << op << ";";
            }
            return out.str();
        }
    }

    if (mn == "adc") {  // add with carry
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " += " << src << " + CF;";
            return out.str();
        }
    }

    if (mn == "sbb") {  // subtract with borrow
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " -= " << src << " + CF;";
            return out.str();
        }
    }

    // ============================================================
    // Logical Operations
    // ============================================================
    if (mn == "xor") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst == src) {
                out << dst << " = 0;";
            } else {
                if (dst.find('[') != std::string::npos) {
                    out << "*(" << dst << ") ^= " << src << ";";
                } else {
                    out << dst << " ^= " << src << ";";
                }
            }
            return out.str();
        }
    }

    if (mn == "and") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") &= " << src << ";";
            } else {
                out << dst << " &= " << src << ";";
            }
            return out.str();
        }
    }

    if (mn == "or") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") |= " << src << ";";
            } else {
                out << dst << " |= " << src << ";";
            }
            return out.str();
        }
    }

    // ============================================================
    // Bit Operations
    // ============================================================
    if (mn == "shl" || mn == "sal") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") <<= " << cnt << ";";
            } else {
                out << dst << " <<= " << cnt << ";";
            }
            return out.str();
        }
    }

    if (mn == "shr") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") >>= " << cnt << ";  // logical";
            } else {
                out << dst << " >>= " << cnt << ";  // logical";
            }
            return out.str();
        }
    }

    if (mn == "sar") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            if (dst.find('[') != std::string::npos) {
                out << "*(" << dst << ") >>= " << cnt << ";  // arithmetic";
            } else {
                out << dst << " >>= " << cnt << ";  // arithmetic";
            }
            return out.str();
        }
    }

    if (mn == "rol") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            out << dst << " = rotate_left(" << dst << ", " << cnt << ");";
            return out.str();
        }
    }

    if (mn == "ror") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string cnt = simplify_operand(operands[1]);
            out << dst << " = rotate_right(" << dst << ", " << cnt << ");";
            return out.str();
        }
    }

    // ============================================================
    // Bit Scan Operations
    // ============================================================
    if (mn == "bsf") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = bsf(" << src << ");  // bit scan forward";
            return out.str();
        }
    }

    if (mn == "bsr") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = bsr(" << src << ");  // bit scan reverse";
            return out.str();
        }
    }

    if (mn == "lzcnt") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = lzcnt(" << src << ");  // leading zeros";
            return out.str();
        }
    }

    if (mn == "popcnt") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = popcount(" << src << ");  // population count";
            return out.str();
        }
    }

    if (mn == "tzcnt") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = tzcnt(" << src << ");  // trailing zeros";
            return out.str();
        }
    }

    // ============================================================
    // Byte Swap & Bit Operations
    // ============================================================
    if (mn == "bswap") {
        if (operands.size() >= 1) {
            std::string op = simplify_operand(operands[0]);
            out << op << " = bswap(" << op << ");  // byte swap";
            return out.str();
        }
    }

    if (mn == "bt") {  // bit test
        if (operands.size() >= 2) {
            std::string base = simplify_operand(operands[0]);
            std::string idx = simplify_operand(operands[1]);
            out << "CF = getbit(" << base << ", " << idx << ");  // bit test";
            return out.str();
        }
    }

    if (mn == "bts") {  // bit test and set
        if (operands.size() >= 2) {
            std::string base = simplify_operand(operands[0]);
            std::string idx = simplify_operand(operands[1]);
            out << "CF = getbit(" << base << ", " << idx << "); setbit(" << base << ", " << idx << ");";
            return out.str();
        }
    }

    if (mn == "btr") {  // bit test and reset
        if (operands.size() >= 2) {
            std::string base = simplify_operand(operands[0]);
            std::string idx = simplify_operand(operands[1]);
            out << "CF = getbit(" << base << ", " << idx << "); clearbit(" << base << ", " << idx << ");";
            return out.str();
        }
    }

    if (mn == "btc") {  // bit test and complement
        if (operands.size() >= 2) {
            std::string base = simplify_operand(operands[0]);
            std::string idx = simplify_operand(operands[1]);
            out << "CF = getbit(" << base << ", " << idx << "); togglebit(" << base << ", " << idx << ");";
            return out.str();
        }
    }

    // ============================================================
    // Comparisons & Tests
    // ============================================================
    if (mn == "cmp") {
        if (operands.size() >= 2) {
            std::string op1 = simplify_operand(operands[0]);
            std::string op2 = simplify_operand(operands[1]);
            out << "// cmp " << op1 << ", " << op2 << " (sets flags)";
            return out.str();
        }
    }

    if (mn == "test") {
        if (operands.size() >= 2) {
            std::string op1 = simplify_operand(operands[0]);
            std::string op2 = simplify_operand(operands[1]);
            out << "// test " << op1 << ", " << op2 << " (sets flags)";
            return out.str();
        }
    }

    // ============================================================
    // Conditional & Unconditional Jumps
    // ============================================================
    if (inst.is_jcc) {
        std::ostringstream target;
        if (inst.call_target != 0) {
            target << ".L" << std::hex << inst.call_target;
            out << "if (" << condition_name(mn) << ") goto " << target.str() << ";";
        } else {
            out << "if (" << condition_name(mn) << ") goto " << inst.op_str << ";";
        }
        return out.str();
    }

    if (inst.is_jmp) {
        if (inst.call_target != 0) {
            std::ostringstream target;
            target << ".L" << std::hex << inst.call_target;
            out << "goto " << target.str() << ";";
        } else {
            out << "goto " << inst.op_str << ";";
        }
        return out.str();
    }

    // ============================================================
    // Loop Instructions
    // ============================================================
    if (mn == "loop") {
        if (inst.call_target != 0) {
            std::ostringstream target;
            target << ".L" << std::hex << inst.call_target;
            out << "c--; if (c != 0) goto " << target.str() << ";  // loop";
        } else {
            out << "c--; if (c != 0) goto <target>;  // loop";
        }
        return out.str();
    }

    if (mn == "loope" || mn == "loopz") {
        if (inst.call_target != 0) {
            std::ostringstream target;
            target << ".L" << std::hex << inst.call_target;
            out << "c--; if (c != 0 && ZF) goto " << target.str() << ";  // loop if equal";
        } else {
            out << "c--; if (c != 0 && ZF) goto <target>;";
        }
        return out.str();
    }

    if (mn == "loopne" || mn == "loopnz") {
        if (inst.call_target != 0) {
            std::ostringstream target;
            target << ".L" << std::hex << inst.call_target;
            out << "c--; if (c != 0 && !ZF) goto " << target.str() << ";  // loop if not equal";
        } else {
            out << "c--; if (c != 0 && !ZF) goto <target>;";
        }
        return out.str();
    }

    // ============================================================
    // Function Calls
    // ============================================================
    if (inst.is_call) {
        if (inst.call_target != 0) {
            out << "call_function(0x" << std::hex << inst.call_target << ");";
        } else {
            std::string target = operands.size() > 0 ? simplify_operand(operands[0]) : "?";
            out << "call_function(" << target << ");  // indirect";
        }
        return out.str();
    }

    // ============================================================
    // Returns
    // ============================================================
    if (inst.is_ret) {
        out << "return;";
        return out.str();
    }

    // ============================================================
    // Syscall/Sysenter/CPUID
    // ============================================================
    if (mn == "syscall") {
        out << "syscall();  // system call";
        return out.str();
    }

    if (mn == "sysenter") {
        out << "sysenter();  // fast system call";
        return out.str();
    }

    if (mn == "sysexit") {
        out << "sysexit();  // fast system exit";
        return out.str();
    }

    if (mn == "sysret") {
        out << "sysret();  // return from syscall";
        return out.str();
    }

    if (mn == "cpuid") {
        out << "cpuid(a);  // CPUID instruction";
        return out.str();
    }

    // ============================================================
    // Prefetch
    // ============================================================
    if (mn == "prefetcht0" || mn == "prefetcht1" || mn == "prefetcht2" ||
        mn == "prefetchnta" || mn == "prefetch") {
        if (operands.size() >= 1) {
            std::string addr = simplify_operand(operands[0]);
            out << "prefetch(" << addr << ");  // " << mn;
            return out.str();
        }
    }

    // ============================================================
    // Memory Fence / Barrier
    // ============================================================
    if (mn == "lfence") {
        out << "lfence();  // load fence";
        return out.str();
    }

    if (mn == "sfence") {
        out << "sfence();  // store fence";
        return out.str();
    }

    if (mn == "mfence") {
        out << "mfence();  // memory fence";
        return out.str();
    }

    // ============================================================
    // NOP / Hints
    // ============================================================
    if (inst.is_nop || mn == "nop") {
        out << "// nop";
        return out.str();
    }

    if (mn == "pause") {
        out << "pause();  // pause (spin-loop hint)";
        return out.str();
    }

    // ============================================================
    // Stack Operations
    // ============================================================
    if (mn == "push") {
        if (operands.size() > 0) {
            std::string val = simplify_operand(operands[0]);
            out << "push(" << val << ");";
            return out.str();
        }
    }

    if (mn == "pop") {
        if (operands.size() > 0) {
            std::string val = simplify_operand(operands[0]);
            if (val.find('[') != std::string::npos) {
                out << "*(" << val << ") = pop();";
            } else {
                out << val << " = pop();";
            }
            return out.str();
        }
    }

    if (mn == "pushad" || mn == "pushall") {
        out << "push_all_regs();";
        return out.str();
    }

    if (mn == "popad" || mn == "popall") {
        out << "pop_all_regs();";
        return out.str();
    }

    if (mn == "pushfd" || mn == "pushfq") {
        out << "push_flags();";
        return out.str();
    }

    if (mn == "popfd" || mn == "popfq") {
        out << "pop_flags();";
        return out.str();
    }

    // ============================================================
    // Conditional Moves
    // ============================================================
    if (mn.substr(0, 2) == "cm" && mn.length() > 2) {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            std::string cond = condition_name(mn.substr(1));
            out << "if (" << cond << ") " << dst << " = " << src << ";";
            return out.str();
        }
    }

    // ============================================================
    // Flag Operations
    // ============================================================
    if (mn == "setcc" || mn.substr(0, 3) == "set") {
        if (operands.size() >= 1) {
            std::string dst = simplify_operand(operands[0]);
            std::string flag = condition_name(mn.substr(3));
            out << dst << " = (" << flag << ") ? 1 : 0;  // " << mn;
            return out.str();
        }
    }

    if (mn == "clc") {
        out << "CF = 0;  // clear carry";
        return out.str();
    }

    if (mn == "stc") {
        out << "CF = 1;  // set carry";
        return out.str();
    }

    if (mn == "cmc") {
        out << "CF = !CF;  // complement carry";
        return out.str();
    }

    if (mn == "cld") {
        out << "DF = 0;  // clear direction";
        return out.str();
    }

    if (mn == "std") {
        out << "DF = 1;  // set direction";
        return out.str();
    }

    if (mn == "cli") {
        out << "IF = 0;  // clear interrupt";
        return out.str();
    }

    if (mn == "sti") {
        out << "IF = 1;  // set interrupt";
        return out.str();
    }

    // ============================================================
    // String Operations
    // ============================================================
    if (mn == "movs" || mn == "movsb" || mn == "movsw" || mn == "movsd" || mn == "movsq") {
        out << "mem[dst++] = mem[src++];  // " << mn << " (string move)";
        return out.str();
    }

    if (mn == "stos" || mn == "stosb" || mn == "stosw" || mn == "stosd" || mn == "stosq") {
        out << "mem[dst++] = a;  // " << mn << " (store)";
        return out.str();
    }

    if (mn == "lods" || mn == "lodsb" || mn == "lodsw" || mn == "lodsd" || mn == "lodsq") {
        out << "a = mem[src++];  // " << mn << " (load)";
        return out.str();
    }

    if (mn == "scas" || mn == "scasb" || mn == "scasw" || mn == "scasd" || mn == "scasq") {
        out << "// cmp a, mem[dst++]  // " << mn << " (scan)";
        return out.str();
    }

    if (mn == "cmps" || mn == "cmpsb" || mn == "cmpsw" || mn == "cmpsd" || mn == "cmpsq") {
        out << "// cmp mem[src++], mem[dst++]  // " << mn << " (compare)";
        return out.str();
    }

    // ============================================================
    // Floating Point (x87)
    // ============================================================
    if (mn == "fld" || mn == "flds" || mn == "fldd" || mn == "fldl") {
        if (operands.size() >= 1) {
            std::string val = simplify_operand(operands[0]);
            out << "fpu_push(" << val << ");  // FPU load";
            return out.str();
        }
    }

    if (mn == "fst" || mn == "fsts" || mn == "fstd") {
        if (operands.size() >= 1) {
            std::string dst = simplify_operand(operands[0]);
            out << "*(" << dst << ") = fpu_pop();  // FPU store";
            return out.str();
        }
    }

    if (mn == "fstp") {
        if (operands.size() >= 1) {
            std::string dst = simplify_operand(operands[0]);
            out << "*(" << dst << ") = fpu_pop();  // FPU store and pop";
            return out.str();
        }
    }

    if (mn == "fadd" || mn == "fadds" || mn == "faddl") {
        out << "fpu_add();  // FPU add";
        return out.str();
    }

    if (mn == "fsub" || mn == "fsubs" || mn == "fsubl") {
        out << "fpu_sub();  // FPU subtract";
        return out.str();
    }

    if (mn == "fmul" || mn == "fmuls" || mn == "fmull") {
        out << "fpu_mul();  // FPU multiply";
        return out.str();
    }

    if (mn == "fdiv" || mn == "fdivs" || mn == "fdivl") {
        out << "fpu_div();  // FPU divide";
        return out.str();
    }

    if (mn == "fldz") {
        out << "fpu_push(0.0);  // FPU load zero";
        return out.str();
    }

    if (mn == "fld1") {
        out << "fpu_push(1.0);  // FPU load one";
        return out.str();
    }

    // ============================================================
    // Transactional Memory (TSX)
    // ============================================================
    if (mn == "xbegin") {
        out << "if (rtm_begin()) goto <abort>;  // transaction begin";
        return out.str();
    }

    if (mn == "xend") {
        out << "rtm_end();  // transaction end";
        return out.str();
    }

    if (mn == "xabort") {
        out << "rtm_abort();  // abort transaction";
        return out.str();
    }

    if (mn == "xtest") {
        out << "// test if in transaction";
        return out.str();
    }

    // ============================================================
    // BMI/ABM Instructions
    // ============================================================
    if (mn == "andn") {
        if (operands.size() >= 3) {
            std::string dst = simplify_operand(operands[0]);
            std::string op1 = simplify_operand(operands[1]);
            std::string op2 = simplify_operand(operands[2]);
            out << dst << " = ~" << op1 << " & " << op2 << ";  // andn";
            return out.str();
        }
    }

    if (mn == "blsi" || mn == "blsr" || mn == "blsmsk") {
        if (operands.size() >= 2) {
            std::string dst = simplify_operand(operands[0]);
            std::string src = simplify_operand(operands[1]);
            out << dst << " = bmi_" << mn << "(" << src << ");";
            return out.str();
        }
    }

    if (mn == "pdep" || mn == "pext") {
        if (operands.size() >= 3) {
            std::string dst = simplify_operand(operands[0]);
            std::string op1 = simplify_operand(operands[1]);
            std::string op2 = simplify_operand(operands[2]);
            out << dst << " = bmi2_" << mn << "(" << op1 << ", " << op2 << ");";
            return out.str();
        }
    }

    // ============================================================
    // Default: Unknown instruction
    // ============================================================
    out << "// [" << mn << "] " << op;
    return out.str();
}

std::vector<std::string> PseudoCodeGenerator::parse_operands(const std::string& op_str) const {
    std::vector<std::string> operands;
    std::string current;
    int bracket_depth = 0;

    for (size_t i = 0; i < op_str.length(); ++i) {
        char c = op_str[i];
        if (c == '[') {
            bracket_depth++;
            current += c;
        } else if (c == ']') {
            bracket_depth--;
            current += c;
        } else if (c == ',' && bracket_depth == 0) {
            if (!current.empty()) {
                size_t start = current.find_first_not_of(" \t");
                size_t end = current.find_last_not_of(" \t");
                if (start != std::string::npos) {
                    operands.push_back(current.substr(start, end - start + 1));
                }
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        size_t start = current.find_first_not_of(" \t");
        size_t end = current.find_last_not_of(" \t");
        if (start != std::string::npos) {
            operands.push_back(current.substr(start, end - start + 1));
        }
    }

    return operands;
}

std::string PseudoCodeGenerator::condition_name(const std::string& mnemonic) const {
    // Conditional jump mnemonics
    if (mnemonic == "je" || mnemonic == "jz")   return "ZF";
    if (mnemonic == "jne" || mnemonic == "jnz") return "!ZF";
    if (mnemonic == "jg")                       return "ZF==0 && SF==OF";
    if (mnemonic == "jge")                      return "SF==OF";
    if (mnemonic == "jl")                       return "SF!=OF";
    if (mnemonic == "jle")                      return "ZF || (SF!=OF)";
    if (mnemonic == "ja" || mnemonic == "jnbe") return "!CF && !ZF";
    if (mnemonic == "jae" || mnemonic == "jnb") return "!CF";
    if (mnemonic == "jb" || mnemonic == "jnae") return "CF";
    if (mnemonic == "jbe" || mnemonic == "jna") return "CF || ZF";
    if (mnemonic == "jo")                       return "OF";
    if (mnemonic == "jno")                      return "!OF";
    if (mnemonic == "js")                       return "SF";
    if (mnemonic == "jns")                      return "!SF";
    if (mnemonic == "jp" || mnemonic == "jpe")  return "PF";
    if (mnemonic == "jnp" || mnemonic == "jpo") return "!PF";
    
    // Set byte mnemonics
    if (mnemonic == "e" || mnemonic == "z")   return "ZF";
    if (mnemonic == "ne" || mnemonic == "nz") return "!ZF";
    if (mnemonic == "g")                       return "ZF==0 && SF==OF";
    if (mnemonic == "ge")                      return "SF==OF";
    if (mnemonic == "l")                       return "SF!=OF";
    if (mnemonic == "le")                      return "ZF || (SF!=OF)";
    if (mnemonic == "a" || mnemonic == "nbe")  return "!CF && !ZF";
    if (mnemonic == "ae" || mnemonic == "nb")  return "!CF";
    if (mnemonic == "b" || mnemonic == "nae")  return "CF";
    if (mnemonic == "be" || mnemonic == "na")  return "CF || ZF";
    if (mnemonic == "o")                       return "OF";
    if (mnemonic == "no")                      return "!OF";
    if (mnemonic == "s")                       return "SF";
    if (mnemonic == "ns")                      return "!SF";
    if (mnemonic == "p" || mnemonic == "pe")   return "PF";
    if (mnemonic == "np" || mnemonic == "po")  return "!PF";
    
    return "?";
}

bool PseudoCodeGenerator::is_prologue_instruction(const Instruction& inst) const {
    const std::string& mn = inst.mnemonic;
    const std::string& op = inst.op_str;
    
    return (mn == "push" && (op.find("rbp") != std::string::npos || op.find("ebp") != std::string::npos)) ||
           (mn == "mov" && op.find("rsp") != std::string::npos && 
            (op.find("rbp") != std::string::npos || op.find("ebp") != std::string::npos)) ||
           (mn == "sub" && (op.find("rsp") != std::string::npos || op.find("esp") != std::string::npos));
}

bool PseudoCodeGenerator::is_epilogue_instruction(const Instruction& inst) const {
    const std::string& mn = inst.mnemonic;
    const std::string& op = inst.op_str;
    
    return (mn == "leave") ||
           (mn == "pop" && (op.find("rbp") != std::string::npos || op.find("ebp") != std::string::npos)) ||
           (mn == "mov" && (op.find("rbp") != std::string::npos || op.find("ebp") != std::string::npos) &&
            (op.find("rsp") != std::string::npos || op.find("esp") != std::string::npos)) ||
           (mn == "add" && (op.find("rsp") != std::string::npos || op.find("esp") != std::string::npos));
}

// ---------------------------------------------------------------------------
// Syntax highlighting tokeniser
// ---------------------------------------------------------------------------

/*static*/ std::vector<PseudoCodeToken>
PseudoCodeGenerator::tokenize(const std::string& line, bool is_label) {
    std::vector<PseudoCodeToken> tokens;

    // Whole line is a label
    if (is_label) {
        tokens.push_back({line, PseudoTokenType::Label});
        return tokens;
    }

    // Whole line is a comment
    if (line.size() >= 2 && line[0] == '/' && line[1] == '/') {
        tokens.push_back({line, PseudoTokenType::Comment});
        return tokens;
    }

    static const std::vector<std::string> keywords = {
        "if", "else", "goto", "return", "while", "for", "do",
        "break", "continue", "switch", "case", "default", "nullptr",
        "true", "false", "void", "int", "uint", "long", "char",
    };

    static const std::vector<std::string> type_keywords = {
        "qword", "dword", "word", "byte", "xmmword", "ymmword", "zmmword",
        "ptr", "bp", "sp", "rip", "eip",
        "float", "double", "bool", "size_t", "uint8", "uint16", "uint32", "uint64",
    };

    auto is_keyword = [&](const std::string& w) -> bool {
        for (auto& k : keywords) if (w == k) return true;
        return false;
    };
    auto is_type_keyword = [&](const std::string& w) -> bool {
        for (auto& k : type_keywords) if (w == k) return true;
        return false;
    };

    // Simple character-by-character scan
    size_t i = 0;
    const size_t n = line.size();

    while (i < n) {
        char c = line[i];

        // --- Whitespace ---
        if (c == ' ' || c == '\t') {
            size_t start = i;
            while (i < n && (line[i] == ' ' || line[i] == '\t')) ++i;
            tokens.push_back({line.substr(start, i - start), PseudoTokenType::Plain});
            continue;
        }

        // --- Inline comment  // ... ---
        if (c == '/' && i + 1 < n && line[i+1] == '/') {
            tokens.push_back({line.substr(i), PseudoTokenType::Comment});
            break;
        }

        // --- Number literal: 0x..., decimal, float ---
        if (c == '-' && i + 1 < n && std::isdigit((unsigned char)line[i+1])) {
            // Negative number — treat '-' as operator then fall into number on next iteration
            tokens.push_back({"-", PseudoTokenType::Operator});
            ++i;
            continue;
        }
        if (std::isdigit((unsigned char)c) ||
            (c == '0' && i + 1 < n && (line[i+1] == 'x' || line[i+1] == 'X'))) {
            size_t start = i;
            if (c == '0' && i + 1 < n && (line[i+1] == 'x' || line[i+1] == 'X')) {
                i += 2;
                while (i < n && std::isxdigit((unsigned char)line[i])) ++i;
            } else {
                while (i < n && (std::isdigit((unsigned char)line[i]) || line[i] == '.')) ++i;
            }
            tokens.push_back({line.substr(start, i - start), PseudoTokenType::Number});
            continue;
        }

        // --- Identifier or keyword ---
        if (std::isalpha((unsigned char)c) || c == '_' || c == '.') {
            size_t start = i;
            while (i < n && (std::isalnum((unsigned char)line[i]) ||
                             line[i] == '_' || line[i] == '.')) ++i;
            std::string word = line.substr(start, i - start);

            // Peek: function call?
            size_t j = i;
            while (j < n && line[j] == ' ') ++j;
            if (j < n && line[j] == '(') {
                tokens.push_back({word, PseudoTokenType::FuncCall});
            } else if (is_keyword(word)) {
                tokens.push_back({word, PseudoTokenType::Keyword});
            } else if (is_type_keyword(word)) {
                tokens.push_back({word, PseudoTokenType::TypeKeyword});
            } else {
                tokens.push_back({word, PseudoTokenType::Identifier});
            }
            continue;
        }

        // --- Operator / punctuation ---
        {
            // Multi-char operators
            if (i + 1 < n) {
                std::string two = line.substr(i, 2);
                if (two == "==" || two == "!=" || two == "<=" || two == ">=" ||
                    two == "+=" || two == "-=" || two == "&=" || two == "|=" ||
                    two == "^=" || two == "*=" || two == "/=" || two == "%=" ||
                    two == "<<" || two == ">>" || two == "->") {
                    tokens.push_back({two, PseudoTokenType::Operator});
                    i += 2;
                    continue;
                }
            }
            static const std::string op_chars = "=+-*&|^~!<>()[]{};,:%";
            if (op_chars.find(c) != std::string::npos) {
                tokens.push_back({std::string(1, c), PseudoTokenType::Operator});
            } else {
                tokens.push_back({std::string(1, c), PseudoTokenType::Plain});
            }
            ++i;
        }
    }

    // --- Post-pass: mark LHS of assignment as Variable ---
    {
        size_t eq_idx = std::string::npos;
        for (size_t t = 0; t < tokens.size(); ++t) {
            auto& tok = tokens[t];
            // Already-combined compound ops like "+=" are a single token
            if (tok.type == PseudoTokenType::Operator && tok.text.size() == 2 &&
                tok.text[1] == '=') {
                eq_idx = t; break;
            }
            // Standalone '=' — make sure it's not part of ==
            if (tok.type == PseudoTokenType::Operator && tok.text == "=") {
                bool prev_compound = (t > 0 &&
                    tokens[t-1].type == PseudoTokenType::Operator &&
                    (tokens[t-1].text == "!" || tokens[t-1].text == "<" ||
                     tokens[t-1].text == ">" || tokens[t-1].text == "="));
                if (!prev_compound) { eq_idx = t; break; }
            }
        }
        if (eq_idx != std::string::npos) {
            for (size_t t = 0; t < eq_idx; ++t) {
                if (tokens[t].type == PseudoTokenType::Identifier)
                    tokens[t].type = PseudoTokenType::Variable;
            }
        }
    }

    return tokens;
}

} // namespace inspector