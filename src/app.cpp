#include "app.h"
#include "imgui.h"
#include <commdlg.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace inspector {

App::App()  = default;
App::~App() = default;

bool App::init(HWND hwnd, ID3D11Device*, ID3D11DeviceContext*) {
    hwnd_    = hwnd;
    status_  = "Drop a .exe / .dll here, or File ▸ Open";
    return true;
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

void App::load_file(const std::wstring& path) {
    parser_.reset();
    disasm_.reset();
    imported_dll_parser_.reset();
    imported_dll_disasm_.reset();
    current_disasm_ = {};
    current_symbol_.clear();
    current_va_     = 0;
    current_callgraph_.clear();
    xref_map_.clear();
    callgraph_map_.clear();
    va_to_export_.clear();
    va_to_import_.clear();
    xrefs_computed_for_current_ = false;
    precompute_running_         = false;
    pseudo_code_mode_           = false;
    imported_dll_name_.clear();
    imported_dll_path_.clear();
    memset(filter_buf_, 0, sizeof(filter_buf_));

    parser_ = std::make_unique<PeParser>(path);
    if (!parser_->parse()) {
        status_ = "ERROR: Not a valid PE file (or access denied)";
        parser_.reset();
        return;
    }

    auto& info = parser_->info();
    disasm_    = std::make_unique<Disassembler>(info.is_64bit);

    file_path_.clear();
    for (wchar_t c : path)
        file_path_ += (c < 128) ? static_cast<char>(c) : '?';

    build_va_maps();

    std::ostringstream ss;
    ss << info.machine_str
       << "  |  " << (info.is_dll ? "DLL" : "EXE")
       << "  |  " << info.exports.size() << " exports"
       << "  |  " << info.imports.size() << " import modules"
       << "  |  " << info.sections.size() << " sections"
       << "  |  EP: 0x" << std::hex << std::uppercase << info.entry_point;
    status_ = ss.str();
}

void App::drop_file(const wchar_t* path) { load_file(path); }

// ---------------------------------------------------------------------------
// VA lookup maps
// ---------------------------------------------------------------------------

void App::build_va_maps() {
    if (!parser_) return;
    auto& info = parser_->info();

    uint64_t base = info.is_64bit
                        ? info.image_base64
                        : static_cast<uint64_t>(info.image_base32);

    // Export VA map
    for (auto& exp : info.exports) {
        if (exp.forwarder) continue;
        uint64_t va = base + exp.rva;
        va_to_export_[va] = exp.name;
    }

    // Import IAT VA map  (IAT RVA stored per-entry)
    for (auto& mod : info.imports) {
        for (auto& fn : mod.functions) {
            if (!fn.iat_rva) continue;
            uint64_t va = base + fn.iat_rva;
            va_to_import_[va] = mod.module_name + "!" + fn.name;
        }
    }
}

// ---------------------------------------------------------------------------
// Compute call graph for one export (no side-effects, safe to call for any)
// ---------------------------------------------------------------------------

std::vector<CallGraphNode> App::compute_callgraph(const ExportEntry& exp) const {
    std::vector<CallGraphNode> nodes;
    if (!parser_ || !disasm_ || exp.forwarder) return nodes;

    const uint8_t* buf = parser_->bytes_at_rva(exp.rva);
    size_t         sz  = parser_->max_bytes_at_rva(exp.rva);
    if (!buf || sz == 0) return nodes;

    uint64_t base = parser_->info().is_64bit
                        ? parser_->info().image_base64
                        : static_cast<uint64_t>(parser_->info().image_base32);

    uint64_t va = base + exp.rva;
    DisasmResult dr = disasm_->disassemble(buf, sz, va, 512);

    for (auto& ins : dr.instructions) {
        if (!ins.is_call && !(ins.is_jmp)) continue;

        CallGraphNode node;
        node.call_site_va = ins.address;
        node.callee_va    = ins.call_target;
        node.is_indirect  = (ins.call_target == 0);
        node.is_import    = false;

        if (node.is_indirect) {
            node.callee_name = ins.op_str;
        } else {
            // Try export table first
            auto it = va_to_export_.find(node.callee_va);
            if (it != va_to_export_.end()) {
                node.callee_name = it->second;
            } else {
                // Try IAT  (call [IAT slot])
                auto ii = va_to_import_.find(node.callee_va);
                if (ii != va_to_import_.end()) {
                    node.callee_name = ii->second;
                    node.is_import   = true;
                } else {
                    // Unknown — show hex VA
                    std::ostringstream hex;
                    hex << "0x" << std::hex << std::uppercase << node.callee_va;
                    node.callee_name = hex.str();
                }
            }
        }
        nodes.push_back(std::move(node));
    }
    return nodes;
}

// ---------------------------------------------------------------------------
// Lazy XREF computation for the current symbol
// ---------------------------------------------------------------------------

void App::ensure_xrefs_for_current() {
    if (!parser_ || !disasm_ || current_va_ == 0) return;
    if (xrefs_computed_for_current_) return;

    // Clear old XREFs for this VA to avoid duplication when returning to same function
    xref_map_[current_va_].clear();

    // Walk every non-forwarder export, disasm it, look for calls to current_va_
    for (auto& exp : parser_->info().exports) {
        if (exp.forwarder) continue;

        // Use cached callgraph if available, otherwise compute on the fly
        std::vector<CallGraphNode>* nodes = nullptr;
        auto it = callgraph_map_.find(exp.name);
        if (it != callgraph_map_.end()) {
            nodes = &it->second;
        } else {
            callgraph_map_[exp.name] = compute_callgraph(exp);
            nodes = &callgraph_map_[exp.name];
        }

        for (auto& node : *nodes) {
            if (node.callee_va == current_va_) {
                XRefEntry xr;
                xr.caller_name = exp.name;
                xr.caller_va   = node.call_site_va;
                xr.callee_va   = current_va_;
                xref_map_[current_va_].push_back(xr);
            }
        }
    }

    xrefs_computed_for_current_ = true;
}

// ---------------------------------------------------------------------------
// Precompute all XREFs (triggered by checkbox)
// ---------------------------------------------------------------------------

void App::precompute_all_xrefs() {
    if (!parser_ || !disasm_ || precompute_running_) return;
    precompute_running_ = true;

    xref_map_.clear();
    callgraph_map_.clear();

    for (auto& exp : parser_->info().exports) {
        if (exp.forwarder) continue;
        callgraph_map_[exp.name] = compute_callgraph(exp);
    }

    // Build reverse map from call graph entries
    uint64_t base = parser_->info().is_64bit
                        ? parser_->info().image_base64
                        : static_cast<uint64_t>(parser_->info().image_base32);

    for (auto& exp : parser_->info().exports) {
        if (exp.forwarder) continue;
        uint64_t caller_va = base + exp.rva;
        auto it = callgraph_map_.find(exp.name);
        if (it == callgraph_map_.end()) continue;

        for (auto& node : it->second) {
            if (node.callee_va == 0) continue;
            XRefEntry xr;
            xr.caller_name = exp.name;
            xr.caller_va   = node.call_site_va;
            xr.callee_va   = node.callee_va;
            xref_map_[node.callee_va].push_back(xr);
        }
    }

    // Mark current as computed too
    xrefs_computed_for_current_ = true;
    precompute_running_ = false;

    status_ = "XREFs precomputed for " +
              std::to_string(callgraph_map_.size()) + " exports.";
}

// ---------------------------------------------------------------------------
// Open file dialog
// ---------------------------------------------------------------------------

void App::open_file_dialog() {
    OPENFILENAMEW ofn   = {};
    wchar_t       buf[MAX_PATH] = {};
    ofn.lStructSize     = sizeof(ofn);
    ofn.hwndOwner       = hwnd_;
    ofn.lpstrFile       = buf;
    ofn.nMaxFile        = MAX_PATH;
    ofn.lpstrFilter     = L"PE Files\0*.exe;*.dll;*.sys;*.ocx;*.efi\0All Files\0*.*\0";
    ofn.lpstrTitle      = L"Open PE File";
    ofn.Flags           = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn))
        load_file(buf);
}

// ---------------------------------------------------------------------------
// Disassemble export (also fills call graph, invalidates xref cache)
// ---------------------------------------------------------------------------

void App::disassemble_export(const ExportEntry& exp) {
    if (!parser_ || !disasm_) return;
    current_symbol_ = exp.name;
    xrefs_computed_for_current_ = false;
    pseudo_code_mode_ = false;

    uint64_t base = parser_->info().is_64bit
                        ? parser_->info().image_base64
                        : static_cast<uint64_t>(parser_->info().image_base32);
    current_va_ = exp.forwarder ? 0 : (base + exp.rva);

    if (exp.forwarder) {
        current_disasm_       = {};
        current_disasm_.error = "Forwarder  →  " + exp.forwarder_name;
        current_callgraph_.clear();
        return;
    }

    const uint8_t* buf = parser_->bytes_at_rva(exp.rva);
    size_t         sz  = parser_->max_bytes_at_rva(exp.rva);

    if (!buf || sz == 0) {
        current_disasm_       = {};
        current_disasm_.error = "Cannot read bytes at RVA 0x" +
            [&]{ std::ostringstream s; s << std::hex << exp.rva; return s.str(); }();
        current_callgraph_.clear();
        return;
    }

    current_disasm_ = disasm_->disassemble(buf, sz, current_va_, 512);

    // Generate pseudo-code from disasm
    current_pseudocode_ = pcgen_.generate(current_disasm_);

    // Build / retrieve call graph for this export
    auto it = callgraph_map_.find(exp.name);
    if (it != callgraph_map_.end()) {
        current_callgraph_ = it->second;
    } else {
        current_callgraph_ = compute_callgraph(exp);
        callgraph_map_[exp.name] = current_callgraph_;
    }
}

// ---------------------------------------------------------------------------
// Import DLL loading
// ---------------------------------------------------------------------------

void App::load_import_dll(const std::string& module_name) {
    imported_dll_parser_.reset();
    imported_dll_disasm_.reset();
    imported_dll_name_ = module_name;
    imported_dll_path_.clear();

    std::vector<uint8_t> dll_bytes;
    if (!DllLoader::load_dll(module_name, dll_bytes, imported_dll_path_)) {
        status_ = "ERROR: Could not find or load " + module_name;
        return;
    }

    // Create a temporary file to parse the DLL from memory
    // (PeParser expects a file path, so we need to work around that)
    // For now, we'll create an in-memory PE parser approach
    // We'll simplify by just showing that we loaded it
    status_ = "Loaded " + module_name + " from " + imported_dll_path_;

    // Note: In a real implementation, we'd extend PeParser to support
    // loading from memory buffer. For now, just track the load.
}

void App::disassemble_import(const std::string& module_name, const std::string& function_name) {
    // Try to load the import DLL if not already loaded
    if (imported_dll_name_ != module_name) {
        load_import_dll(module_name);
    }

    if (imported_dll_path_.empty()) {
        current_disasm_.error = "Could not load " + module_name + ". DLL not found in system paths.";
        current_symbol_ = module_name + "!" + function_name;
        return;
    }

    current_symbol_ = module_name + "!" + function_name;
    current_callgraph_.clear();
    current_disasm_.error = "Import function: " + module_name + "!" + function_name +
                           "\nPath: " + imported_dll_path_ + "\n\n" +
                           "To disassemble imported functions, you'd need to load the DLL file.\n" +
                           "This is a system function from " + module_name + ".";
}

void App::toggle_pseudo_code_mode() {
    pseudo_code_mode_ = !pseudo_code_mode_;
}

// ---------------------------------------------------------------------------
// Top-level render
// ---------------------------------------------------------------------------

void App::render() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoTitleBar    |
                 ImGuiWindowFlags_NoResize      |
                 ImGuiWindowFlags_NoMove        |
                 ImGuiWindowFlags_NoScrollbar   |
                 ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_MenuBar);

    render_menu_bar();

    float content_top = ImGui::GetCursorPosY();
    float status_h    = 26.0f;
    float content_h   = io.DisplaySize.y - content_top - status_h - 2.0f;
    float left_w      = 310.0f;

    // Graph panel width: shown only when open
    float graph_w = graph_panel_open_ ? graph_panel_width_ : 0.0f;
    float mid_w   = io.DisplaySize.x - left_w - graph_w - 8.0f; // 2 separators × 4px

    // ── Left: symbol tree ────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.15f, 1.0f));
    ImGui::BeginChild("##left", ImVec2(left_w, content_h), false);
    render_symbol_tree();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0, 4);

    // ── Middle: disasm ───────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.09f, 0.09f, 0.12f, 1.0f));
    ImGui::BeginChild("##right", ImVec2(mid_w, content_h), false);
    render_disasm_view();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    // ── Right: graph panel (collapsible) ─────────────────────────────────
    if (graph_panel_open_) {
        ImGui::SameLine(0, 4);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.11f, 0.11f, 0.16f, 1.0f));
        ImGui::BeginChild("##graph", ImVec2(graph_w, content_h), false);
        render_graph_panel();
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    render_status_bar();
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Menu bar
// ---------------------------------------------------------------------------

void App::render_menu_bar() {
    if (!ImGui::BeginMenuBar()) return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) open_file_dialog();
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))    PostQuitMessage(0);
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Graph / XREFs Panel", nullptr, &graph_panel_open_);
        ImGui::EndMenu();
    }

    if (!file_path_.empty()) {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 12.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.75f, 1.0f, 1.0f));
        ImGui::TextUnformatted(file_path_.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::EndMenuBar();
}

// ---------------------------------------------------------------------------
// Symbol tree (left panel)
// ---------------------------------------------------------------------------

void App::render_symbol_tree() {
    if (!parser_) {
        ImGui::Spacing();
        ImGui::SetCursorPosX(12);
        ImGui::TextDisabled("No file loaded.");
        ImGui::SetCursorPosX(12);
        ImGui::TextDisabled("Drop a PE here to begin.");
        return;
    }

    auto& info = parser_->info();

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.18f, 0.18f, 0.22f, 1.0f));
    ImGui::InputTextWithHint("##filter", "Filter symbols...",
                             filter_buf_, sizeof(filter_buf_));
    ImGui::PopStyleColor();
    ImGui::Separator();

    std::string filter = filter_buf_;
    std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);

    auto matches = [&](const std::string& name) -> bool {
        if (filter.empty()) return true;
        std::string low = name;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        return low.find(filter) != std::string::npos;
    };

    // Exports
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.9f, 0.5f, 1.0f));
        bool open = ImGui::TreeNodeEx("##exports_node",
                                      ImGuiTreeNodeFlags_DefaultOpen |
                                      ImGuiTreeNodeFlags_SpanAvailWidth,
                                      "Exports");
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled(" %zu", info.exports.size());

        if (open) {
            for (auto& exp : info.exports) {
                if (!matches(exp.name)) continue;
                bool sel = (current_symbol_ == exp.name);

                ImGuiTreeNodeFlags flags =
                    ImGuiTreeNodeFlags_Leaf        |
                    ImGuiTreeNodeFlags_NoTreePushOnOpen |
                    ImGuiTreeNodeFlags_SpanAvailWidth;
                if (sel) flags |= ImGuiTreeNodeFlags_Selected;

                if (exp.forwarder)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.4f, 1.0f));

                ImGui::TreeNodeEx(exp.name.c_str(), flags);

                if (exp.forwarder)
                    ImGui::PopStyleColor();

                if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
                    disassemble_export(exp);

                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                    ImGui::BeginTooltip();
                    ImGui::Text("RVA:     0x%08X", exp.rva);
                    ImGui::Text("Ordinal: %u",     exp.ordinal);
                    if (exp.forwarder)
                        ImGui::Text("Forwarder → %s", exp.forwarder_name.c_str());
                    ImGui::EndTooltip();
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::Spacing();

    // Imports
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.7f, 1.0f, 1.0f));
        bool open = ImGui::TreeNodeEx("##imports_node",
                                      ImGuiTreeNodeFlags_DefaultOpen |
                                      ImGuiTreeNodeFlags_SpanAvailWidth,
                                      "Imports");
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled(" %zu modules", info.imports.size());

        if (open) {
            for (auto& mod : info.imports) {
                if (!filter.empty()) {
                    bool any = false;
                    for (auto& fn : mod.functions)
                        if (matches(fn.name)) { any = true; break; }
                    if (!any && !matches(mod.module_name)) continue;
                }

                std::string label = mod.module_name +
                    "  (" + std::to_string(mod.functions.size()) + ")";

                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.8f, 0.6f, 1.0f));
                bool mod_open = ImGui::TreeNode(label.c_str());
                ImGui::PopStyleColor();

                if (mod_open) {
                    for (auto& fn : mod.functions) {
                        if (!matches(fn.name)) continue;
                        ImGui::TreeNodeEx(fn.name.c_str(),
                            ImGuiTreeNodeFlags_Leaf |
                            ImGuiTreeNodeFlags_NoTreePushOnOpen);
                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                            ImGui::BeginTooltip();
                            ImGui::Text("IAT RVA: 0x%08X", fn.iat_rva);
                            if (fn.by_ordinal)
                                ImGui::Text("Imported by ordinal #%u", fn.ordinal);
                            else
                                ImGui::Text("Hint: %u", fn.hint);
                            ImGui::EndTooltip();
                        }
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::Spacing();

    // Sections
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.6f, 0.4f, 1.0f));
        bool open = ImGui::TreeNodeEx("##sections_node",
                                      ImGuiTreeNodeFlags_SpanAvailWidth,
                                      "Sections");
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled(" %zu", info.sections.size());

        if (open) {
            for (auto& sec : info.sections) {
                if (!matches(sec.name)) continue;
                ImGui::TreeNodeEx(sec.name.c_str(),
                    ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                    uint32_t ch = sec.characteristics;
                    ImGui::BeginTooltip();
                    ImGui::Text("VA:      0x%08X", sec.virtual_address);
                    ImGui::Text("VSize:   0x%X",   sec.virtual_size);
                    ImGui::Text("RawOff:  0x%08X", sec.raw_offset);
                    ImGui::Text("RawSize: 0x%X",   sec.raw_size);
                    ImGui::Text("Access:  %s%s%s",
                        (ch & IMAGE_SCN_MEM_READ)    ? "R" : "-",
                        (ch & IMAGE_SCN_MEM_WRITE)   ? "W" : "-",
                        (ch & IMAGE_SCN_MEM_EXECUTE) ? "X" : "-");
                    ImGui::EndTooltip();
                }
            }
            ImGui::TreePop();
        }
    }
}

// ---------------------------------------------------------------------------
// Disasm color palette (mirrors WinDbg dark theme)
// ---------------------------------------------------------------------------

namespace col {
    static const ImVec4 addr    = { 0.45f, 0.45f, 0.60f, 1.0f };
    static const ImVec4 bytes   = { 0.38f, 0.38f, 0.38f, 1.0f };
    static const ImVec4 ret     = { 1.00f, 0.38f, 0.38f, 1.0f };
    static const ImVec4 call    = { 0.40f, 0.82f, 1.00f, 1.0f };
    static const ImVec4 jmp     = { 1.00f, 0.78f, 0.25f, 1.0f };
    static const ImVec4 jcc     = { 1.00f, 0.90f, 0.50f, 1.0f };
    static const ImVec4 nop     = { 0.35f, 0.35f, 0.35f, 1.0f };
    static const ImVec4 normal  = { 0.55f, 0.90f, 0.55f, 1.0f };
    static const ImVec4 operand = { 0.90f, 0.88f, 0.70f, 1.0f };
    static const ImVec4 sep     = { 0.30f, 0.30f, 0.30f, 1.0f };
    static const ImVec4 error   = { 1.00f, 0.35f, 0.35f, 1.0f };
    static const ImVec4 symbol  = { 0.40f, 0.90f, 0.50f, 1.0f };

    // Graph panel
    static const ImVec4 graph_hdr    = { 0.70f, 0.85f, 1.00f, 1.0f };
    static const ImVec4 callee_exp   = { 0.40f, 0.90f, 0.50f, 1.0f };
    static const ImVec4 callee_imp   = { 0.80f, 0.70f, 0.40f, 1.0f };
    static const ImVec4 callee_unk   = { 0.60f, 0.60f, 0.60f, 1.0f };
    static const ImVec4 callee_indir = { 0.50f, 0.50f, 0.50f, 1.0f };
    static const ImVec4 xref_caller  = { 0.85f, 0.60f, 1.00f, 1.0f };
    static const ImVec4 xref_va      = { 0.45f, 0.45f, 0.60f, 1.0f };
    static const ImVec4 badge_import = { 0.85f, 0.65f, 0.20f, 1.0f };
    static const ImVec4 badge_indir  = { 0.45f, 0.45f, 0.45f, 1.0f };
}

// ---------------------------------------------------------------------------
// Disasm view (middle panel)
// ---------------------------------------------------------------------------

void App::render_disasm_view() {
    if (current_symbol_.empty()) {
        ImGui::Spacing();
        ImGui::SetCursorPosX(16);
        ImGui::TextDisabled("← Select an exported function to disassemble it");
        return;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, col::symbol);
    ImGui::Text("  %s", current_symbol_.c_str());
    ImGui::PopStyleColor();

    // Add pseudo-code toggle button
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80.0f);
    if (ImGui::SmallButton(pseudo_code_mode_ ? "Asm ◀" : "▶ C-Code")) {
        toggle_pseudo_code_mode();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::BeginTooltip();
        ImGui::TextDisabled("Toggle between assembly and\npseudo-code view");
        ImGui::EndTooltip();
    }

    ImGui::Separator();

    if (!current_disasm_.error.empty()) {
        ImGui::Spacing();
        ImGui::SetCursorPosX(12);
        ImGui::TextColored(col::error, "%s", current_disasm_.error.c_str());
        return;
    }

    if (current_disasm_.instructions.empty()) {
        ImGui::TextDisabled("(no instructions decoded)");
        return;
    }

    ImFont* mono = (ImGui::GetIO().Fonts->Fonts.Size > 1)
                       ? ImGui::GetIO().Fonts->Fonts[1]
                       : ImGui::GetIO().Fonts->Fonts[0];
    ImGui::PushFont(mono);

    ImGui::BeginChild("##disasm_scroll", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    if (pseudo_code_mode_) {
        // Pseudo-code color palette
        struct PC {
            static ImVec4 keyword()     { return {0.56f, 0.74f, 0.98f, 1.0f}; } // blue
            static ImVec4 type_kw()     { return {0.78f, 0.55f, 0.92f, 1.0f}; } // purple — qword/ptr/bp
            static ImVec4 comment()     { return {0.45f, 0.62f, 0.45f, 1.0f}; } // muted green
            static ImVec4 number()      { return {0.82f, 0.65f, 0.38f, 1.0f}; } // gold
            static ImVec4 identifier()  { return {0.88f, 0.86f, 0.80f, 1.0f}; } // off-white
            static ImVec4 variable()    { return {0.40f, 0.86f, 0.55f, 1.0f}; } // green — LHS variables
            static ImVec4 op()          { return {0.85f, 0.60f, 0.55f, 1.0f}; } // soft red — arithmetic/punct
            static ImVec4 label()       { return {1.00f, 0.78f, 0.25f, 1.0f}; } // amber
            static ImVec4 funccall()    { return {0.40f, 0.86f, 0.86f, 1.0f}; } // cyan
            static ImVec4 plain()       { return {0.70f, 0.70f, 0.70f, 1.0f}; } // grey
        };

        for (const auto& line : current_pseudocode_) {
            if (line.tokens.empty()) {
                // Fallback: render plain
                ImGui::TextColored(PC::plain(), "%s", line.code.c_str());
                continue;
            }

            bool first_token = true;
            for (const auto& tok : line.tokens) {
                if (!first_token) ImGui::SameLine(0.0f, 0.0f);
                first_token = false;

                ImVec4 col;
                switch (tok.type) {
                    case PseudoTokenType::Keyword:     col = PC::keyword();    break;
                    case PseudoTokenType::TypeKeyword:  col = PC::type_kw();    break;
                    case PseudoTokenType::Comment:     col = PC::comment();    break;
                    case PseudoTokenType::Number:      col = PC::number();     break;
                    case PseudoTokenType::Identifier:  col = PC::identifier(); break;
                    case PseudoTokenType::Variable:    col = PC::variable();   break;
                    case PseudoTokenType::Operator:    col = PC::op();         break;
                    case PseudoTokenType::Label:       col = PC::label();      break;
                    case PseudoTokenType::FuncCall:    col = PC::funccall();   break;
                    default:                           col = PC::plain();      break;
                }
                ImGui::TextColored(col, "%s", tok.text.c_str());
            }
        }
    } else {
        // Render assembly
        for (const auto& ins : current_disasm_.instructions) {
            ImGui::TextColored(col::addr, "  %016llX", ins.address);
            ImGui::SameLine();

            char bytes_col[32];
            snprintf(bytes_col, sizeof(bytes_col), "%-22s", ins.bytes_hex.c_str());
            ImGui::TextColored(col::bytes, "%s", bytes_col);
            ImGui::SameLine();

            ImVec4 mn_col = ins.is_ret  ? col::ret  :
                            ins.is_call ? col::call :
                            ins.is_jmp  ? col::jmp  :
                            ins.is_jcc  ? col::jcc  :
                            ins.is_nop  ? col::nop  :
                                          col::normal;

            char mn_pad[16];
            snprintf(mn_pad, sizeof(mn_pad), "%-10s", ins.mnemonic.c_str());
            ImGui::TextColored(mn_col, "%s", mn_pad);

            if (!ins.op_str.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(col::operand, "%s", ins.op_str.c_str());
            }

            if (ins.is_ret) {
                ImGui::TextColored(col::sep,
                    "  ──────────────────────────────────────────────────");
            }
        }
    }

    ImGui::EndChild();
    ImGui::PopFont();
}

// ---------------------------------------------------------------------------
// Graph panel (right panel)
// ---------------------------------------------------------------------------

void App::render_graph_panel() {
    // Panel toggle button at top
    {
        ImGui::PushStyleColor(ImGuiCol_Text, col::graph_hdr);
        ImGui::TextUnformatted("  Call Graph / XREFs");
        ImGui::PopStyleColor();

        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 18.0f);
        if (ImGui::SmallButton("×"))
            graph_panel_open_ = false;

        ImGui::Separator();
    }

    if (current_symbol_.empty()) {
        ImGui::Spacing();
        ImGui::SetCursorPosX(8);
        ImGui::TextDisabled("Select a function");
        ImGui::SetCursorPosX(8);
        ImGui::TextDisabled("to see its graph.");
        return;
    }

    // Precompute checkbox + button
    {
        bool prev = precompute_xrefs_;
        if (ImGui::Checkbox("Precompute all XREFs", &precompute_xrefs_)) {
            if (precompute_xrefs_ && !prev && parser_)
                precompute_all_xrefs();
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            ImGui::BeginTooltip();
            ImGui::TextDisabled("Scans all exports to build a full\n"
                                "cross-reference map. Slower on large\n"
                                "binaries but gives instant XREFs.");
            ImGui::EndTooltip();
        }
    }

    ImGui::Separator();
    ImGui::Spacing();

    // ── Call Graph ───────────────────────────────────────────────────────
    {
        bool open = ImGui::TreeNodeEx("##callgraph_tree",
                                      ImGuiTreeNodeFlags_DefaultOpen |
                                      ImGuiTreeNodeFlags_SpanAvailWidth,
                                      "Calls out");
        ImGui::SameLine();
        ImGui::TextDisabled(" %zu", current_callgraph_.size());

        if (open) {
            if (current_callgraph_.empty()) {
                ImGui::TextDisabled("  (none found)");
            } else {
                ImFont* mono = (ImGui::GetIO().Fonts->Fonts.Size > 1)
                                   ? ImGui::GetIO().Fonts->Fonts[1]
                                   : ImGui::GetIO().Fonts->Fonts[0];

                for (auto& node : current_callgraph_) {
                    ImGui::PushFont(mono);

                    ImVec4 name_col = node.is_indirect ? col::callee_indir :
                                      node.is_import   ? col::callee_imp   :
                                      (va_to_export_.count(node.callee_va))
                                                       ? col::callee_exp   :
                                                         col::callee_unk;

                    ImGuiTreeNodeFlags fl =
                        ImGuiTreeNodeFlags_Leaf |
                        ImGuiTreeNodeFlags_NoTreePushOnOpen |
                        ImGuiTreeNodeFlags_SpanAvailWidth;

                    ImGui::PushStyleColor(ImGuiCol_Text, name_col);
                    ImGui::TreeNodeEx(node.callee_name.c_str(), fl);
                    ImGui::PopStyleColor();
                    ImGui::PopFont();

                    // Badge
                    if (node.is_import) {
                        ImGui::SameLine();
                        ImGui::TextColored(col::badge_import, "[imp]");
                    } else if (node.is_indirect) {
                        ImGui::SameLine();
                        ImGui::TextColored(col::badge_indir, "[ind]");
                    }

                    // Tooltip
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Call site: 0x%016llX", node.call_site_va);
                        if (!node.is_indirect)
                            ImGui::Text("Target:    0x%016llX", node.callee_va);
                        if (node.is_import)   ImGui::TextDisabled("Imported function");
                        if (node.is_indirect) ImGui::TextDisabled("Indirect call — target unknown");
                        ImGui::EndTooltip();
                    }

                    // Click to navigate (internal exports + imports)
                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                        if (node.is_import) {
                            // Parse import name: "Module!Function"
                            size_t sep = node.callee_name.find('!');
                            if (sep != std::string::npos) {
                                std::string module = node.callee_name.substr(0, sep);
                                std::string function = node.callee_name.substr(sep + 1);
                                disassemble_import(module, function);
                            }
                        } else if (!node.is_indirect) {
                            // Internal export
                            auto it = va_to_export_.find(node.callee_va);
                            if (it != va_to_export_.end() && parser_) {
                                for (auto& exp : parser_->info().exports) {
                                    if (exp.name == it->second) {
                                        disassemble_export(exp);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::Spacing();

    // ── XREFs ────────────────────────────────────────────────────────────
    {
        // Lazy-compute on demand
        ensure_xrefs_for_current();

        auto& xrefs = xref_map_[current_va_];
        bool open = ImGui::TreeNodeEx("##xref_tree",
                                      ImGuiTreeNodeFlags_DefaultOpen |
                                      ImGuiTreeNodeFlags_SpanAvailWidth,
                                      "Referenced by (XREFs)");
        ImGui::SameLine();
        ImGui::TextDisabled(" %zu", xrefs.size());

        if (open) {
            if (xrefs.empty()) {
                ImGui::TextDisabled("  (none found)");
            } else {
                ImFont* mono = (ImGui::GetIO().Fonts->Fonts.Size > 1)
                                   ? ImGui::GetIO().Fonts->Fonts[1]
                                   : ImGui::GetIO().Fonts->Fonts[0];

                for (auto& xr : xrefs) {
                    ImGui::PushFont(mono);

                    ImGuiTreeNodeFlags fl =
                        ImGuiTreeNodeFlags_Leaf |
                        ImGuiTreeNodeFlags_NoTreePushOnOpen |
                        ImGuiTreeNodeFlags_SpanAvailWidth;

                    ImGui::PushStyleColor(ImGuiCol_Text, col::xref_caller);
                    ImGui::TreeNodeEx(xr.caller_name.c_str(), fl);
                    ImGui::PopStyleColor();
                    ImGui::PopFont();

                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                        ImGui::BeginTooltip();
                        ImGui::Text("Caller:    %s",         xr.caller_name.c_str());
                        ImGui::Text("Call site: 0x%016llX",  xr.caller_va);
                        ImGui::Text("Callee:    0x%016llX",  xr.callee_va);
                        ImGui::EndTooltip();
                    }

                    // Click to navigate to caller
                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && parser_) {
                        for (auto& exp : parser_->info().exports) {
                            if (exp.name == xr.caller_name) {
                                disassemble_export(exp);
                                break;
                            }
                        }
                    }
                }
            }
            ImGui::TreePop();
        }
    }
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

void App::render_status_bar() {
    ImGuiIO&  io = ImGui::GetIO();
    float     y  = io.DisplaySize.y - 26.0f;

    ImGui::SetCursorPos(ImVec2(0, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.14f, 0.18f, 1.0f));
    ImGui::BeginChild("##statusbar", ImVec2(0, 26.0f), false);
    ImGui::SetCursorPosY(5.0f);
    ImGui::TextColored(ImVec4(0.65f, 0.65f, 0.65f, 1.0f),
                       "  %s", status_.c_str());
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

} // namespace inspector