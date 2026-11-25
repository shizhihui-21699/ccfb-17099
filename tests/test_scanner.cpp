#include "scanner/Engine.h"
#include "scanner/PeParser.h"
#include "scanner/SourceScanner.h"

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

using namespace dllscan;

namespace {

void testSeverityOrdering() {
    assert(severityRank(Severity::Critical) > severityRank(Severity::High));
    assert(parseSeverity("HIGH") == Severity::High);
    assert(!parseSeverity("bogus").has_value());
}

void testMinimalPeImportParser() {
    std::vector<std::uint8_t> pe(1024, 0);
    auto u16 = [&](std::size_t offset, std::uint16_t value) {
        pe[offset] = static_cast<std::uint8_t>(value);
        pe[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    };
    auto u32 = [&](std::size_t offset, std::uint32_t value) {
        for (int i = 0; i < 4; ++i) pe[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    };
    auto u64 = [&](std::size_t offset, std::uint64_t value) {
        for (int i = 0; i < 8; ++i) pe[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    };
    auto bytes = [&](std::size_t offset, const char* value) {
        for (std::size_t i = 0; value[i] != '\0'; ++i) pe[offset + i] = static_cast<std::uint8_t>(value[i]);
    };

    pe[0] = 'M';
    pe[1] = 'Z';
    u32(0x3c, 0x80);
    bytes(0x80, "PE");

    const std::size_t coff = 0x84;
    u16(coff, 0x8664);             // AMD64
    u16(coff + 2, 1);              // one section
    u16(coff + 16, 0xF0);          // PE32+ optional header size
    u16(coff + 18, 0x0022);        // executable image

    const std::size_t opt = coff + 20;  // 0x98
    u16(opt, 0x20b);
    u64(opt + 24, 0x140000000);
    u32(opt + 32, 0x1000);         // section alignment
    u32(opt + 36, 0x200);          // file alignment
    u32(opt + 56, 0x2000);         // image size
    u32(opt + 60, 0x200);          // headers size
    u16(opt + 68, 3);              // console subsystem
    u32(opt + 108, 16);            // numberOfRvaAndSizes
    u32(opt + 120, 0x1020);        // import directory RVA
    u32(opt + 124, 40);

    const std::size_t section = opt + 0xF0;  // 0x188
    bytes(section, ".rdata");
    u32(section + 8, 0x200);       // virtual size
    u32(section + 12, 0x1000);     // virtual address
    u32(section + 16, 0x200);      // raw size
    u32(section + 20, 0x200);      // raw pointer

    const std::size_t data = 0x200;
    u64(data, 0x1050);              // ILT -> hint/name
    u64(data + 16, 0x1050);         // IAT
    u32(data + 32, 0x1000);         // descriptor original first thunk
    u32(data + 44, 0x1080);         // descriptor DLL name RVA
    u32(data + 48, 0x1010);         // first thunk
    bytes(data + 82, "LoadLibraryW");
    bytes(data + 128, "kernel32.dll");

    const auto path = std::filesystem::temp_directory_path() / "dllguard_minimal_pe.exe";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(pe.data()),
                  static_cast<std::streamsize>(pe.size()));
    }

    BinaryInfo info = parsePeFile(path, false);
    assert(info.parsed);
    assert(info.is64Bit);
    assert(info.imports.size() == 1);
    assert(info.imports[0].name == "kernel32.dll");
    assert(info.imports[0].functions.size() == 1);
    assert(info.imports[0].functions[0].name == "LoadLibraryW");

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void testInvalidPe() {
    const auto path = std::filesystem::temp_directory_path() / "dllguard_not_pe.bin";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << "not a pe file";
    }
    BinaryInfo info = parsePeFile(path, false);
    assert(!info.parsed);
    assert(!info.error.empty());
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void testSourceScannerFindsCalls() {
    const auto path = std::filesystem::temp_directory_path() / "dllguard_sample.cpp";
    {
        std::ofstream out(path, std::ios::trunc);
        out << R"CPP(
#include <windows.h>
void f() {
    HMODULE a = LoadLibraryW(L"version.dll");
    HMODULE b = LoadLibraryExW(name.c_str(), nullptr, 0);
    HMODULE c = LoadLibraryExW(L"C:\\Program Files\\App\\plug.dll", nullptr,
                               LOAD_LIBRARY_SEARCH_SYSTEM32);
    HMODULE d = LoadLibraryW((prefix + "_plugin.dll").c_str());
    const char* logText = "LoadLibraryW(this is text, not a call)";
    SetDllDirectoryW(L"");
}
)CPP";
    }

    auto calls = scanSourceFile(path, {});
    assert(calls.size() == 5);

    const SourceCall& bare = calls[0];
    assert(bare.api == "LoadLibraryW");
    assert(bare.firstStringLiteral == "version.dll");
    assert(bare.literalIsComplete);
    assert(bare.line == 4);

    const SourceCall& composed = calls[1];
    assert(composed.api == "LoadLibraryExW");
    assert(!composed.literalIsComplete);
    assert(!composed.hasSafeFlag);

    const SourceCall& absoluteSafe = calls[2];
    assert(absoluteSafe.literalIsComplete);
    assert(absoluteSafe.hasSafeFlag);

    const SourceCall& removeCwd = calls[4];
    assert(removeCwd.isSearchPathConfiguration);
    assert(removeCwd.literalIsComplete);
    assert(removeCwd.firstStringLiteral.empty());

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void testEndToEndSourceFindings() {
    ScanOptions options;
    options.sourcePaths.push_back(std::filesystem::temp_directory_path());
    options.recursive = false;
    // Avoid scanning every unrelated temp file: directly test Engine through a
    // dedicated directory containing only one source file.
    auto dir = std::filesystem::temp_directory_path() / "dllguard_scan_dir";
    std::filesystem::create_directories(dir);
    auto file = dir / "load.cpp";
    {
        std::ofstream out(file, std::ios::trunc);
        out << "HMODULE h = LoadLibraryA(\"dbghelp.dll\");\n";
    }

    ScanOptions local;
    local.sourcePaths.push_back(dir);
    local.binaryPaths.push_back(dir / "definitely_missing.exe");
    ScanReport report = runScan(local);

    bool foundBare = false;
    for (const auto& finding : report.findings) {
        if (finding.ruleId == "SRC-LOAD-BARE-NAME") foundBare = true;
    }
    assert(foundBare);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

}  // namespace

int main() {
    testSeverityOrdering();
    testMinimalPeImportParser();
    testInvalidPe();
    testSourceScannerFindsCalls();
    testEndToEndSourceFindings();
    std::cout << "all scanner tests passed\n";
    return 0;
}
