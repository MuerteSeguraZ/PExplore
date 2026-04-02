// test_pe_parser.cpp
// Minimal test runner — no external framework needed.
// Build: CMake test target or cl /EHsc /I../include test_pe_parser.cpp pe_parser.cpp
//
// On Windows the tests expect to find notepad.exe and ntdll.dll.
// They can also accept an arbitrary PE path via argv[1].

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <string>
#include "pe_parser.h"

using namespace inspector;

static int g_pass = 0, g_fail = 0;

#define CHECK(expr) \
    do { if (expr) { ++g_pass; } \
         else { ++g_fail; printf("FAIL  %s:%d  %s\n", __FILE__, __LINE__, #expr); } } while(0)

#define CHECK_MSG(expr, msg) \
    do { if (expr) { ++g_pass; } \
         else { ++g_fail; printf("FAIL  %s:%d  %s — %s\n", __FILE__, __LINE__, #expr, msg); } } while(0)

static void test_notepad() {
    printf("\n=== notepad.exe ===\n");
    PeParser p(L"C:\\Windows\\System32\\notepad.exe");
    bool ok = p.parse();
    CHECK_MSG(ok, "notepad.exe must be parseable");
    if (!ok) return;

    auto& info = p.info();
    CHECK(!info.is_dll);
    CHECK(info.sections.size() > 0);
    CHECK(info.entry_point != 0);
    printf("  machine:  %s\n", info.machine_str.c_str());
    printf("  sections: %zu\n", info.sections.size());
    printf("  exports:  %zu\n", info.exports.size());
    printf("  imports:  %zu modules\n", info.imports.size());
    printf("  entry:    0x%08X\n", info.entry_point);
}

static void test_ntdll() {
    printf("\n=== ntdll.dll ===\n");
    PeParser p(L"C:\\Windows\\System32\\ntdll.dll");
    bool ok = p.parse();
    CHECK_MSG(ok, "ntdll.dll must be parseable");
    if (!ok) return;

    auto& info = p.info();
    CHECK(info.is_dll);
    CHECK(info.exports.size() > 100);      // ntdll exports many functions
    CHECK(info.imports.size() > 0);
    printf("  machine:  %s\n", info.machine_str.c_str());
    printf("  exports:  %zu\n", info.exports.size());
    printf("  imports:  %zu modules\n", info.imports.size());

    // Every named export shouldn't be empty
    for (auto& e : info.exports) {
        CHECK(!e.name.empty());
        if (!e.forwarder) CHECK(e.rva != 0);
    }

    bool found = false;
    for (auto& e : info.exports)
        if (e.name == "NtQuerySystemInformation") { found = true; break; }
    CHECK_MSG(found, "NtQuerySystemInformation must be exported by ntdll");
}

static void test_rva_mapping() {
    printf("\n=== RVA mapping (ntdll.dll) ===\n");
    PeParser p(L"C:\\Windows\\System32\\ntdll.dll");
    if (!p.parse()) { printf("  SKIP (parse failed)\n"); return; }

    int bad = 0;
    for (auto& e : p.info().exports) {
        if (e.forwarder) continue;
        const uint8_t* b = p.bytes_at_rva(e.rva);
        size_t         sz = p.max_bytes_at_rva(e.rva);
        if (!b || sz == 0) ++bad;
    }
    CHECK(bad == 0);
    printf("  all %zu non-forwarder exports mapped successfully\n",
           p.info().exports.size());
}

static void test_invalid_file() {
    printf("\n=== invalid / missing file ===\n");
    PeParser p(L"C:\\does_not_exist_xyz.exe");
    CHECK(!p.parse());

    wchar_t tmp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_path);
    wcscat_s(tmp_path, L"insp_test_garbage.bin");
    {
        HANDLE h = CreateFileW(tmp_path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD written;
            const char junk[] = "This is not a PE file at all!";
            WriteFile(h, junk, sizeof(junk)-1, &written, nullptr);
            CloseHandle(h);
        }
    }
    PeParser p2(tmp_path);
    CHECK(!p2.parse());
    DeleteFileW(tmp_path);
    printf("  invalid-file rejection OK\n");
}

static void test_arbitrary(const wchar_t* path) {
    printf("\n=== arbitrary file: ");
    for (const wchar_t* c = path; *c; ++c) putchar(*c < 128 ? (char)*c : '?');
    printf(" ===\n");

    PeParser p(path);
    bool ok = p.parse();
    CHECK(ok);
    if (!ok) return;

    auto& info = p.info();
    printf("  machine:  %s\n", info.machine_str.c_str());
    printf("  type:     %s\n", info.is_dll ? "DLL" : "EXE");
    printf("  sections: %zu\n", info.sections.size());
    printf("  exports:  %zu\n", info.exports.size());
    printf("  imports:  %zu modules\n", info.imports.size());
}

int main(int argc, char** argv) {
    printf("Win32 Inspector — PE parser tests\n");
    printf("==================================\n");

    test_notepad();
    test_ntdll();
    test_rva_mapping();
    test_invalid_file();

    if (argc > 1) {
        int needed = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nullptr, 0);
        std::wstring wpath(needed, L'\0');
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath.data(), needed);
        test_arbitrary(wpath.c_str());
    }

    printf("\n──────────────────────────────────\n");
    printf("Results:  %d passed,  %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}