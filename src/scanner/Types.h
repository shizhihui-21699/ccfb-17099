#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dllscan {

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

const char* severityName(Severity severity);
std::optional<Severity> parseSeverity(const std::string& text);
int severityRank(Severity severity);

struct ImportedFunction {
    std::string name;
    std::uint16_t ordinal = 0;
    bool byOrdinal = false;
};

struct ImportedModule {
    std::string name;
    bool delayLoaded = false;
    std::vector<ImportedFunction> functions;
};

struct BinaryInfo {
    std::filesystem::path path;
    bool parsed = false;
    std::string error;

    bool is64Bit = false;
    std::uint16_t machine = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dllCharacteristics = 0;
    bool isDynamicLinkLibrary = false;

    std::optional<std::uint16_t> dependentLoadFlags;
    std::vector<ImportedModule> imports;
    std::vector<std::string> asciiDllStrings;
    std::vector<std::string> utf16DllStrings;
};

struct SourceCall {
    std::string api;
    std::string argumentExpression;
    std::string firstStringLiteral;
    bool literalIsComplete = false;
    std::filesystem::path file;
    int line = 0;
    int column = 0;
    bool hasSearchFlags = false;
    bool hasSafeFlag = false;
    bool callsSafeWrapper = false;
    bool isSearchPathConfiguration = false;
    bool suppressed = false;
};

struct Finding {
    std::string ruleId;
    Severity severity = Severity::Info;
    std::string title;
    std::string detail;
    std::string recommendation;
    std::string file;
    std::string location;
    std::map<std::string, std::string> metadata;
};

struct ScanOptions {
    std::vector<std::filesystem::path> binaryPaths;
    std::vector<std::filesystem::path> sourcePaths;
    std::vector<std::filesystem::path> knownDllLists;
    std::vector<std::filesystem::path> systemDllDirectories;
    std::vector<std::string> extraLoadApis;
    bool recursive = true;
    bool scanStrings = true;
};

struct ScanReport {
    int schemaVersion = 1;
    std::string toolVersion = "0.1.0";
    std::vector<BinaryInfo> binaries;
    std::vector<SourceCall> sourceCalls;
    std::vector<Finding> findings;
    std::map<std::string, int> countsBySeverity;
};

}  // namespace dllscan
