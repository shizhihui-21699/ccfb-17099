cmake_minimum_required(VERSION 3.20)

project(DllGuard
    VERSION 0.1.0
    DESCRIPTION "Windows DLL search-order hijacking scanner and safe loader"
    LANGUAGES CXX)

option(DLLGUARD_BUILD_SCANNER "Build the portable PE/source scanner" ON)
option(DLLGUARD_BUILD_RUNTIME "Build the Windows safe-loader runtime" ${WIN32})
option(DLLGUARD_BUILD_EXAMPLES "Build examples" ON)
option(DLLGUARD_BUILD_TESTS "Build tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(DLLGUARD_BUILD_SCANNER)
    add_library(dllscan_core STATIC
        src/scanner/PeParser.cpp
        src/scanner/SourceScanner.cpp
        src/scanner/Engine.cpp
        src/scanner/Report.cpp
    )
    target_include_directories(dllscan_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_features(dllscan_core PUBLIC cxx_std_17)
    if(MSVC)
        target_compile_options(dllscan_core PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(dllscan_core PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_executable(dllscan src/scanner/main.cpp)
    target_link_libraries(dllscan PRIVATE dllscan_core)

    if(DLLGUARD_BUILD_TESTS)
        enable_testing()
        add_executable(dllscan_tests tests/test_scanner.cpp)
        target_link_libraries(dllscan_tests PRIVATE dllscan_core)
        add_test(NAME dllscan_tests COMMAND dllscan_tests)
    endif()
endif()

if(DLLGUARD_BUILD_RUNTIME AND WIN32)
    add_library(dllguard STATIC
        src/runtime/SafeLoad.cpp
        src/runtime/ModuleAudit.cpp
    )
    add_library(DllGuard::dllguard ALIAS dllguard)
    target_include_directories(dllguard PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_features(dllguard PUBLIC cxx_std_17)
    target_compile_definitions(dllguard PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000000
    )
    target_link_libraries(dllguard PUBLIC wintrust crypt32 psapi advapi32)
    if(MSVC)
        target_compile_options(dllguard PRIVATE /W4 /permissive- /utf-8)
        # Applies safe dependent-load flags to images linked against this target.
        # 0x800 == LOAD_LIBRARY_SEARCH_SYSTEM32.
        target_link_options(dllguard PUBLIC "/DEPENDENTLOADFLAG:0x800")
    elseif(MINGW)
        target_compile_options(dllguard PRIVATE -Wall -Wextra)
        target_compile_options(dllguard PUBLIC -municode)
        target_link_options(dllguard PUBLIC -municode)
    endif()

    if(DLLGUARD_BUILD_EXAMPLES)
        add_executable(vulnerable_app examples/vulnerable_app.cpp)
        target_compile_definitions(vulnerable_app PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
        if(MINGW)
            target_compile_options(vulnerable_app PRIVATE -municode)
            target_link_options(vulnerable_app PRIVATE -municode)
        endif()

        add_executable(hardened_app examples/hardened_app.cpp)
        target_link_libraries(hardened_app PRIVATE dllguard)
    endif()
endif()
