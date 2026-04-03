#pragma once
#include "disassembler.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace inspector {

// ------------------------------------------------------------------
// Syntax highlighting token types for pseudo-code
// ------------------------------------------------------------------
enum class PseudoTokenType {
    Keyword,     // if, goto, return, while, else, ...
    TypeKeyword, // qword, dword, xmmword, ptr, bp, sp, ...
    Comment,     // // ...
    Number,      // 0x1234, 42, 0.0
    Identifier,  // variable / register names
    Variable,    // LHS of an assignment
    Operator,    // = += & | ~ ! < > * ( ) [ ] , ;
    Label,       // .Laddr:
    FuncCall,    // name( — the function name part
    String,      // any quoted string (rare in pseudo-code but possible)
    Plain,       // everything else (whitespace, punctuation)
};

struct PseudoCodeToken {
    std::string    text;
    PseudoTokenType type = PseudoTokenType::Plain;
};

struct PseudoCodeLine {
    std::string              code;       // The full pseudo-code line (kept for plain rendering)
    uint64_t                 orig_addr;  // Original instruction address (for correlation)
    bool                     is_label;   // Is this a label?
    std::vector<PseudoCodeToken> tokens; // Pre-tokenised for syntax highlighting
};

// Track register state for better pseudo-code generation
struct RegState {
    std::unordered_map<std::string, uint64_t> register_values;
    // Can be extended with flow analysis info
};

class PseudoCodeGenerator {
public:
    // Convert a disasm result to pseudo-code
    std::vector<PseudoCodeLine> generate(const DisasmResult& disasm) const;

    // Tokenise a single pseudo-code line for syntax highlighting
    static std::vector<PseudoCodeToken> tokenize(const std::string& line, bool is_label);

private:
    // Instruction pattern recognition and conversion
    std::string convert_instruction(const Instruction& inst,
                                   const DisasmResult& context,
                                   size_t inst_idx,
                                   RegState& reg_state) const;

    // Helpers
    std::string simplify_operand(const std::string& op) const;
    std::string simplify_registers_in_string(const std::string& str) const;
    std::vector<std::string> parse_operands(const std::string& op_str) const;
    std::string condition_name(const std::string& mnemonic) const;
    bool is_prologue_instruction(const Instruction& inst) const;
    bool is_epilogue_instruction(const Instruction& inst) const;
};

} // namespace inspector