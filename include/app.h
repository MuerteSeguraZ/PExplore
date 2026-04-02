#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <memory>
#include "pe_parser.h"
#include "disassembler.h"

namespace inspector {

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
    void render_status_bar();

    // ── Actions ───────────────────────────────────────────────────────────
    void disassemble_export(const ExportEntry& exp);
    void open_file_dialog();

    // ── State ─────────────────────────────────────────────────────────────
    HWND         hwnd_           = nullptr;
    std::string  file_path_;        // narrow display copy

    std::unique_ptr<PeParser>     parser_;
    std::unique_ptr<Disassembler> disasm_;
    DisasmResult                  current_disasm_;
    std::string                   current_symbol_;
    std::string                   status_;

    char filter_buf_[256] = {};
};

} // namespace inspector