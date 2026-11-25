#include "scanner/Engine.h"
#include "scanner/Report.h"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

void printHelp(const char* program) {
    std::cout <<
        "DllGuard PE/source scanner\n\n"
        "Usage:\n"
        "  " << program << " [scan] <binary-path>... [options]\n\n"
        "Arguments:\n"
        "  <binary-path>              EXE/DLL file or directory to scan\n\n"
        "Options:\n"
        "  --source <path>            C/C++ file or directory to scan (repeatable)\n"
        "  --format <text|json|sarif> Output format (default: text)\n"
        "  --out <file>               Write report to file instead of stdout\n"
        "  --known-dlls <file>        Text list of exact KnownDLL names (repeatable)\n"
        "  --system-dll-dir <dir>     Directory such as C:\\Windows\\System32 (repeatable)\n"
        "  --load-api <name>          Additional runtime load API/wrapper to detect\n"
        "  --fail-on <level|none>     info, low, medium, high, critical (default: high)\n"
        "  --no-recursive             Do not recurse into directories\n"
        "  --no-strings               Skip binary DLL-like string extraction\n"
        "  -h, --help                 Show this help\n"
        "  -v, --version              Show version\n\n"
        "Example:\n"
        "  " << program << " dist --source src --system-dll-dir C:\\Windows\\System32 \\\n"
        "          --format sarif --out dllscan.sarif --fail-on medium\n";
}

bool consumeValue(int& index, int argc, char** argv, const std::string& option,
                  std::string& value) {
    if (index + 1 >= argc) {
        std::cerr << "error: " << option << " requires a value\n";
        return false;
    }
    value = argv[++index];
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    dllscan::ScanOptions options;
    std::string format = "text";
    std::string outputPath;
    std::string failOn = "high";
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "scan" && i == 1) {
            continue;
        } else if (arg == "-h" || arg == "--help") {
            printHelp(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "dllscan 0.1.0\n";
            return 0;
        } else if (arg == "--format") {
            if (!consumeValue(i, argc, argv, arg, format)) return 1;
        } else if (arg == "--out") {
            if (!consumeValue(i, argc, argv, arg, outputPath)) return 1;
        } else if (arg == "--fail-on") {
            if (!consumeValue(i, argc, argv, arg, failOn)) return 1;
        } else if (arg == "--source") {
            std::string value;
            if (!consumeValue(i, argc, argv, arg, value)) return 1;
            options.sourcePaths.emplace_back(value);
        } else if (arg == "--known-dlls") {
            std::string value;
            if (!consumeValue(i, argc, argv, arg, value)) return 1;
            options.knownDllLists.emplace_back(value);
        } else if (arg == "--system-dll-dir") {
            std::string value;
            if (!consumeValue(i, argc, argv, arg, value)) return 1;
            options.systemDllDirectories.emplace_back(value);
        } else if (arg == "--load-api") {
            std::string value;
            if (!consumeValue(i, argc, argv, arg, value)) return 1;
            options.extraLoadApis.push_back(value);
        } else if (arg == "--no-recursive") {
            options.recursive = false;
        } else if (arg == "--no-strings") {
            options.scanStrings = false;
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "error: unknown option: " << arg << "\n";
            printHelp(argv[0]);
            return 1;
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.empty()) {
        printHelp(argv[0]);
        std::cerr << "\nerror: at least one binary file or directory is required\n";
        return 1;
    }

    for (const auto& path : positional) options.binaryPaths.emplace_back(path);

    if (format != "text" && format != "json" && format != "sarif") {
        std::cerr << "error: unsupported format: " << format << "\n";
        return 1;
    }

    dllscan::ScanReport report = dllscan::runScan(options);
    std::string rendered;
    if (format == "json") rendered = dllscan::renderJsonReport(report);
    else if (format == "sarif") rendered = dllscan::renderSarifReport(report);
    else rendered = dllscan::renderTextReport(report);

    if (!outputPath.empty()) {
        std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "error: cannot write output: " << outputPath << "\n";
            return 1;
        }
        out << rendered;
    } else {
        std::cout << rendered;
    }

    if (failOn == "none") return 0;
    auto threshold = dllscan::parseSeverity(failOn);
    if (!threshold) {
        std::cerr << "error: invalid --fail-on level: " << failOn << "\n";
        return 1;
    }

    for (const auto& finding : report.findings) {
        if (dllscan::severityRank(finding.severity) >= dllscan::severityRank(*threshold)) {
            return 2;
        }
    }
    return 0;
}
