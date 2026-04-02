#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include "pe_parser.h"
#include "disassembler.h"

namespace inspector {

// ------------------------------------------------------------------
// XRef / call-graph caches
// ------------------------------------------------------------------

// keyed by callee VA  →  list of incoming call sites
using XRefMap = std::unordered_map<uint64_t, std::vector<XRefEntry>>;

// keyed by caller export name  →  outgoing calls (call graph nodes)
using CallGraphMap = std::unordered_map<std::string, std::vector<CallGraphNode>>;

// ------------------------------------------------------------------

class App {
public:
    App();
    ~App();

    bool init(HWND hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx);

    void render();
    void load_file(const std::wstring& path);
    void drop_file(const wchar_t* path);

private:
    // ── Render sub-panels ──────────────────────────────────────────────────
    void render_menu_bar();
    void render_symbol_tree();
    void render_disasm_view();
    void render_graph_panel();      // NEW: third panel (call graph + xrefs)
    void render_status_bar();

    // ── Actions ───────────────────────────────────────────────────────────
    void disassemble_export(const ExportEntry& exp);
    void open_file_dialog();

    // ── Graph / XREF helpers ──────────────────────────────────────────────
    // Build a VA→export-name lookup (computed once per file load)
    void build_va_maps();

    // Disassemble one export and return its call graph nodes (no side-effects)
    std::vector<CallGraphNode> compute_callgraph(const ExportEntry& exp) const;

    // Lazily compute XREFs for the currently selected function
    void ensure_xrefs_for_current();

    // Precompute XREFs for ALL exports (triggered by checkbox)
    void precompute_all_xrefs();

    // ── State ─────────────────────────────────────────────────────────────
    HWND         hwnd_           = nullptr;
    std::string  file_path_;

    std::unique_ptr<PeParser>     parser_;
    std::unique_ptr<Disassembler> disasm_;
    DisasmResult                  current_disasm_;
    std::string                   current_symbol_;
    uint64_t                      current_va_     = 0;   // VA of selected export
    std::string                   status_;

    char filter_buf_[256] = {};

    // ── VA lookup maps (built on file load) ───────────────────────────────
    // export VA  →  export name
    std::unordered_map<uint64_t, std::string> va_to_export_;
    // IAT entry VA  →  "Module.Function" string
    std::unordered_map<uint64_t, std::string> va_to_import_;

    // ── Graph panel state ─────────────────────────────────────────────────
    bool   graph_panel_open_    = true;
    float  graph_panel_width_   = 280.0f;

    // Call graph for currently selected function
    std::vector<CallGraphNode>   current_callgraph_;

    // XRef cache (lazy)
    XRefMap      xref_map_;                    // callee_va → xrefs
    CallGraphMap callgraph_map_;               // caller_name → callgraph
    bool         xrefs_computed_for_current_ = false;

    // UI options
    bool   precompute_xrefs_   = false;        // checkbox
    bool   precompute_running_ = false;        // guard against re-entry
};

} // namespace inspector