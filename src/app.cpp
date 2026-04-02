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

void App::load_file(const std::wstring& path) {
    parser_.reset();
    disasm_.reset();
    current_disasm_ = {};
    current_symbol_.clear();
    memset(filter_buf_, 0, sizeof(filter_buf_));

    parser_ = std::make_unique<PeParser>(path);
    if (!parser_->parse()) {
        status_ = "ERROR: Not a valid PE file (or access denied)";
        parser_.reset();
        return;
    }

    auto& info = parser_->info();
    disasm_    = std::make_unique<Disassembler>(info.is_64bit);

    // Narrow path for the menu bar display
    file_path_.clear();
    for (wchar_t c : path)
        file_path_ += (c < 128) ? static_cast<char>(c) : '?';

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

void App::disassemble_export(const ExportEntry& exp) {
    if (!parser_ || !disasm_) return;
    current_symbol_ = exp.name;

    if (exp.forwarder) {
        current_disasm_       = {};
        current_disasm_.error = "Forwarder  →  " + exp.forwarder_name;
        return;
    }

    const uint8_t* buf = parser_->bytes_at_rva(exp.rva);
    size_t         sz  = parser_->max_bytes_at_rva(exp.rva);

    if (!buf || sz == 0) {
        current_disasm_       = {};
        current_disasm_.error = "Cannot read bytes at RVA 0x" +
            [&]{ std::ostringstream s; s << std::hex << exp.rva; return s.str(); }();
        return;
    }

    uint64_t va = exp.rva;
    if (parser_->info().is_64bit)
        va += parser_->info().image_base64;
    else
        va += parser_->info().image_base32;

    current_disasm_ = disasm_->disassemble(buf, sz, va, 512);
}

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

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.15f, 1.0f));
    ImGui::BeginChild("##left", ImVec2(left_w, content_h), false);
    render_symbol_tree();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0, 4);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.09f, 0.09f, 0.12f, 1.0f));
    ImGui::BeginChild("##right", ImVec2(0, content_h), false);
    render_disasm_view();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    render_status_bar();
    ImGui::End();
}

void App::render_menu_bar() {
    if (!ImGui::BeginMenuBar()) return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) open_file_dialog();
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))    PostQuitMessage(0);
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

    // Filter bar
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

// try to mirror WinDbg dark theme
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
}

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

    ImGui::EndChild();
    ImGui::PopFont();
}

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