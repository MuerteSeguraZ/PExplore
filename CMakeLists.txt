cmake_minimum_required(VERSION 3.20)
project(PExplore VERSION 1.0.0 LANGUAGES CXX)

# ── Language standard ─────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Fetch dependencies ────────────────────────────────────────────────────────
include(FetchContent)

# Capstone — the disassembly engine
FetchContent_Declare(capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
    GIT_SHALLOW    TRUE
)
set(CAPSTONE_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL  OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT   ON  CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(capstone)

# Dear ImGui — immediate-mode GUI
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.91.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)

# ── Main executable ───────────────────────────────────────────────────────────
add_executable(PExplore WIN32
    src/main.cpp
    src/pe_parser.cpp
    src/disassembler.cpp
    src/app.cpp
    ${IMGUI_SOURCES}
)

target_include_directories(PExplore PRIVATE
    include/
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(PExplore PRIVATE
    capstone
    d3d11
    dxgi
    d3dcompiler
    dwmapi
    comdlg32   # GetOpenFileName
)

# Enable high-DPI awareness manifest
if (MSVC)
    target_sources(PExplore PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/dpi.manifest
    )
    # Silence MSVC's "secure CRT" warnings; the code is already bounds-checked.
    target_compile_definitions(PExplore PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()

add_executable(TestPeParser
    test/test_pe_parser.cpp
    src/pe_parser.cpp
)
target_include_directories(TestPeParser PRIVATE include/)
target_compile_definitions(TestPeParser PRIVATE
    _CRT_SECURE_NO_WARNINGS NOMINMAX
)

add_test(NAME PeParserTests COMMAND TestPeParser)