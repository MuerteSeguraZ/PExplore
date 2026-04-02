#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <d3d11.h>
#include <dxgi.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "app.h"

static ID3D11Device*           g_device  = nullptr;
static ID3D11DeviceContext*    g_ctx     = nullptr;
static IDXGISwapChain*         g_swap    = nullptr;
static ID3D11RenderTargetView* g_rtv     = nullptr;

static inspector::App* g_app = nullptr;  // for WM_DROPFILES

static void create_rtv() {
    ID3D11Texture2D* back = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
    g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
}

static void destroy_rtv() {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

static bool create_device(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd         = {};
    sd.BufferCount                  = 2;
    sd.BufferDesc.Format            = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage                  = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                 = hwnd;
    sd.SampleDesc.Count             = 1;
    sd.Windowed                     = TRUE;
    sd.SwapEffect                   = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL levels[]  = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL achieved  = {};
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, levels, 2, D3D11_SDK_VERSION,
        &sd, &g_swap, &g_device, &achieved, &g_ctx);
    if (FAILED(hr)) return false;
    create_rtv();
    return true;
}

static void destroy_device() {
    destroy_rtv();
    if (g_swap)   { g_swap->Release();   g_swap   = nullptr; }
    if (g_ctx)    { g_ctx->Release();    g_ctx    = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

extern IMGUI_IMPL_API LRESULT
ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
        return TRUE;

    switch (msg) {
    case WM_SIZE:
        if (g_device && wp != SIZE_MINIMIZED) {
            destroy_rtv();
            g_swap->ResizeBuffers(0, LOWORD(lp), HIWORD(lp),
                                  DXGI_FORMAT_UNKNOWN, 0);
            create_rtv();
        }
        return 0;

    case WM_DROPFILES: {
        HDROP  drop = reinterpret_cast<HDROP>(wp);
        wchar_t buf[MAX_PATH];
        if (DragQueryFileW(drop, 0, buf, MAX_PATH) && g_app)
            g_app->drop_file(buf);
        DragFinish(drop);
        return 0;
    }

    // no beep for you
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_KEYMENU) return 0;
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    WNDCLASSEXW wc = {};
    wc.cbSize       = sizeof(wc);
    wc.style        = CS_CLASSDC;
    wc.lpfnWndProc  = WndProc;
    wc.hInstance    = hInst;
    wc.hIcon        = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor      = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName= L"Win32InspectorClass";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES,                     // enable drag-and-drop
        wc.lpszClassName,
        L"PExplore",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1400, 860,
        nullptr, nullptr, hInst, nullptr);

    if (!create_device(hwnd)) {
        destroy_device();
        UnregisterClassW(wc.lpszClassName, hInst);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);
    
    // setup
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename  = "pexplore.ini";

    // Dark theme with some tweaks
    ImGui::StyleColorsDark();
    ImGuiStyle& style       = ImGui::GetStyle();
    style.WindowRounding    = 0.0f;
    style.FrameRounding     = 3.0f;
    style.ScrollbarRounding = 3.0f;
    style.TabRounding       = 3.0f;
    style.WindowBorderSize  = 0.0f;
    style.Colors[ImGuiCol_WindowBg]    = ImVec4(0.10f, 0.10f, 0.13f, 1.0f);
    style.Colors[ImGuiCol_MenuBarBg]   = ImVec4(0.13f, 0.13f, 0.17f, 1.0f);
    style.Colors[ImGuiCol_Header]      = ImVec4(0.20f, 0.20f, 0.30f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.28f, 0.28f, 0.42f, 1.0f);
    style.Colors[ImGuiCol_HeaderActive]  = ImVec4(0.35f, 0.35f, 0.55f, 1.0f);

    io.Fonts->AddFontDefault();

    ImFontConfig mono_cfg;
    mono_cfg.SizePixels = 14.0f;
    const char* consolas = "C:\\Windows\\Fonts\\consola.ttf";
    if (GetFileAttributesA(consolas) != INVALID_FILE_ATTRIBUTES)
        io.Fonts->AddFontFromFileTTF(consolas, 14.0f, &mono_cfg);
    else
        io.Fonts->AddFontDefault();   // fallback if Consolas not present

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_ctx);

    // -- App ----------------------------------------------------------------
    inspector::App app;
    app.init(hwnd, g_device, g_ctx);
    g_app = &app;

    {
        int     argc;
        wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv && argc > 1)
            app.load_file(argv[1]);
        LocalFree(argv);
    }

    const float CLEAR[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) goto done;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, CLEAR);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);      // vsync
    }

done:
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    destroy_device();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}