#include "scanner/Engine.h"

#include "scanner/PeParser.h"
#include "scanner/SourceScanner.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <string_view>

namespace dllscan {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool isApiSet(const std::string& name) {
    std::string n = lower(name);
    return n.rfind("api-ms-", 0) == 0 || n.rfind("ext-ms-", 0) == 0;
}

bool isBareFileName(const std::string& value) {
    return value.find_first_of("/\\") == std::string::npos;
}

bool isAbsolutePath(const std::string& value) {
    if (value.size() >= 3 && std::isalpha(static_cast<unsigned char>(value[0])) &&
        value[1] == ':' && (value[2] == '\\' || value[2] == '/')) {
        return true;
    }
    return value.rfind("\\\\", 0) == 0 || value.rfind("//", 0) == 0 ||
           value.rfind("\\??\\", 0) == 0 || value.rfind("/", 0) == 0;
}

std::set<std::string> builtInKnownDlls() {
    // Conservative subset of the default KnownDLLs object directory. Supply
    // --known-dlls from the target machine's registry for an exact list.
    return {
        "advapi32.dll", "clbcatq.dll", "combase.dll", "comctl32.dll",
        "comdlg32.dll", "gdi32.dll", "gdi32full.dll", "imm32.dll",
        "kernel32.dll", "kernelbase.dll", "msctf.dll", "msvcrt.dll",
        "normaliz.dll", "ole32.dll", "oleaut32.dll", "propsys.dll",
        "rpcrt4.dll", "sechost.dll", "setupapi.dll", "shell32.dll",
        "shcore.dll", "shlwapi.dll", "user32.dll", "win32u.dll",
        "windows.storage.dll", "winrnr.dll", "ws2_32.dll",
    };
}

std::set<std::string> builtInSystemNames() {
    // Common OS binaries that are frequent planting targets. This is not a
    // complete Windows manifest; --system-dll-dir adds exact target files.
    return {
        "bcrypt.dll", "bcryptprimitives.dll", "cabinet.dll", "crypt32.dll",
        "cryptbase.dll", "dbghelp.dll", "dhcpcsvc.dll", "dnsapi.dll",
        "dwmapi.dll", "dxgi.dll", "edputil.dll", "iphlpapi.dll",
        "msasn1.dll", "ncrypt.dll", "netapi32.dll", "powrprof.dll",
        "profapi.dll", "psapi.dll", "secur32.dll", "sspicli.dll",
        "userenv.dll", "uxtheme.dll", "version.dll", "wer.dll",
        "winhttp.dll", "wininet.dll", "winmm.dll", "wintrust.dll",
        "wsock32.dll", "wtsapi32.dll",
    };
}

std::set<std::string> readNameList(const std::filesystem::path& path) {
    std::set<std::string> result;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        if (auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
        line = lower(line);
        line.erase(std::remove_if(line.begin(), line.end(),
                                  [](unsigned char c) { return std::isspace(c); }),
                   line.end());
        if (!line.empty()) result.insert(line);
    }
    return result;
}

std::set<std::string> collectSystemNames(const ScanOptions& options) {
    std::set<std::string> names = builtInSystemNames();
    for (const auto& listPath : options.knownDllLists) {
        auto values = readNameList(listPath);
        names.insert(values.begin(), values.end());
    }
    for (const auto& directory : options.systemDllDirectories) {
        std::error_code ec;
        if (!std::filesystem::is_directory(directory, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
            if (entry.is_regular_file(ec)) names.insert(lower(entry.path().filename().string()));
        }
    }
    return names;
}

bool hasExtension(const std::filesystem::path& path, std::initializer_list<const char*> extensions) {
    std::string ext = lower(path.extension().string());
    for (const char* expected : extensions) {
        if (ext == expected) return true;
    }
    return false;
}

void collectByExtension(const std::vector<std::filesystem::path>& inputs,
                        std::initializer_list<const char*> extensions,
                        bool recursive,
                        std::vector<std::filesystem::path>& output) {
    std::error_code ec;
    for (const auto& input : inputs) {
        if (std::filesystem::is_regular_file(input, ec)) {
            if (hasExtension(input, extensions)) output.push_back(input);
            continue;
        }
        if (!std::filesystem::is_directory(input, ec)) continue;

        if (recursive) {
            for (auto it = std::filesystem::recursive_directory_iterator(
                     input, std::filesystem::directory_options::skip_permission_denied, ec);
                 it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_regular_file(ec) && hasExtension(it->path(), extensions)) {
                    output.push_back(it->path());
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(
                     input, std::filesystem::directory_options::skip_permission_denied, ec)) {
                if (entry.is_regular_file(ec) && hasExtension(entry.path(), extensions)) {
                    output.push_back(entry.path());
                }
            }
        }
    }

    std::sort(output.begin(), output.end());
    output.erase(std::unique(output.begin(), output.end()), output.end());
}

std::set<std::string> siblingFileNames(const std::filesystem::path& binary) {
    std::set<std::string> names;
    std::error_code ec;
    auto parent = binary.parent_path();
    if (!std::filesystem::is_directory(parent, ec)) return names;
    for (const auto& entry : std::filesystem::directory_iterator(parent, ec)) {
        if (entry.is_regular_file(ec)) names.insert(lower(entry.path().filename().string()));
    }
    return names;
}

bool isDynamicLoadApi(const std::string& name) {
    std::string n = lower(name);
    return n.find("loadlibrary") != std::string::npos ||
           n == "ldrloaddll" || n == "loadpackagedlibrary";
}

void addFinding(ScanReport& report, Finding finding) {
    report.findings.push_back(std::move(finding));
}

std::string displayPath(const std::filesystem::path& path) {
    return path.string();
}

void analyzeBinary(const BinaryInfo& binary,
                   const std::set<std::string>& knownDlls,
                   const std::set<std::string>& systemNames,
                   ScanReport& report) {
    const std::string file = displayPath(binary.path);

    if (!binary.parsed) {
        addFinding(report, {
            "PE-UNREADABLE", Severity::Info,
            "PE file could not be parsed",
            binary.error,
            "Verify that the file is a valid Windows PE image and that the scanner has read access.",
            file, {}, {},
        });
        return;
    }

    const bool dependentLoadFlagSafe =
        binary.dependentLoadFlags.has_value() &&
        (*binary.dependentLoadFlags & 0x0800) != 0;

    if (!binary.isDynamicLinkLibrary && !dependentLoadFlagSafe) {
        addFinding(report, {
            "PE-DEPENDENTLOADFLAG-MISSING", Severity::Medium,
            "Executable does not pin static imports to System32",
            binary.dependentLoadFlags
                ? "DependentLoadFlags=0x" + [&] {
                      std::ostringstream out;
                      out << std::hex << *binary.dependentLoadFlags;
                      return out.str();
                  }() + " does not include LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800)."
                : "No load-configuration DependentLoadFlags value was found.",
            "Link with /DEPENDENTLOADFLAG:0x800 and call SetDefaultDllDirectories early. "
            "Static imports are resolved before WinMain, so runtime calls alone are too late.",
            file, "load_config",
            {{"is64bit", binary.is64Bit ? "true" : "false"}},
        });
    }

    const std::set<std::string> siblings = siblingFileNames(binary.path);

    for (const ImportedModule& module : binary.imports) {
        const std::string name = lower(module.name);
        if (name.empty()) continue;

        bool hasDynamicApi = false;
        std::vector<std::string> apiNames;
        for (const auto& function : module.functions) {
            if (isDynamicLoadApi(function.name)) {
                hasDynamicApi = true;
                apiNames.push_back(function.name);
            }
        }

        if (hasDynamicApi) {
            addFinding(report, {
                "PE-RUNTIME-LOAD-API", Severity::Medium,
                "Binary imports a runtime dynamic-library loading API",
                module.name + (module.delayLoaded ? " (delay-load import)" : "") +
                    ": " + [&] {
                        std::string all;
                        for (std::size_t i = 0; i < apiNames.size(); ++i) {
                            if (i) all += ", ";
                            all += apiNames[i];
                        }
                        return all;
                    }(),
                "Audit every call site. Replace own-code calls with dllguard safe loaders; "
                "for closed-source callers, enforce process search policy and verify observed loads.",
                file, "import:" + module.name,
                {{"api", [&] {
                    std::string all;
                    for (std::size_t i = 0; i < apiNames.size(); ++i) {
                        if (i) all += ",";
                        all += apiNames[i];
                    }
                    return all;
                }()},
                 {"delay_loaded", module.delayLoaded ? "true" : "false"}},
            });
        }

        if (isApiSet(name) || knownDlls.count(name)) continue;

        const bool bundledBesideBinary = siblings.count(name) != 0;
        const bool likelySystem = systemNames.count(name) != 0;
        Severity severity = Severity::Medium;
        std::string rule = "PE-IMPORT-UNKNOWN";
        std::string title = "Imported module is resolved through the normal search order";
        std::string detail = module.name + (module.delayLoaded ? " (delay-loaded)." : ".");
        std::string recommendation =
            "Use /DEPENDENTLOADFLAG:0x800, deploy in a read-only Program Files directory, "
            "and verify Authenticode signatures or use an application-local manifest/allowlist.";

        if (likelySystem) {
            rule = "PE-IMPORT-SYSTEM-NAME";
            title = "Imported operating-system DLL name is not a pinned KnownDLL/API set";
            severity = Severity::High;
            detail += " Its bare name can be planted in a writable application directory, "
                      "current directory, or another active search path.";
            recommendation =
                "Preload it from %SystemRoot%\\System32 at startup, link with "
                "/DEPENDENTLOADFLAG:0x800, and call SetDefaultDllDirectories("
                "LOAD_LIBRARY_SEARCH_SYSTEM32).";
        }

        if (bundledBesideBinary) {
            rule = "PE-IMPORT-BUNDLED-DLL";
            title = "Imported DLL is bundled next to the binary";
            severity = Severity::Medium;
            detail += " A same-name file exists in the binary directory. If that directory "
                      "is user-writable (for example Downloads or a per-user extraction folder), "
                      "the bundled DLL can be replaced or planted.";
            recommendation =
                "Install under Program Files with an admin-only ACL and verify signatures; "
                "for plugins, canonicalize the path, constrain it to a trusted root, and verify signer.";
        }

        if (dependentLoadFlagSafe && !bundledBesideBinary) {
            severity = Severity::Low;
            detail += " The image sets DependentLoadFlags=0x800, which substantially mitigates "
                      "static dependency search-order abuse.";
        }

        addFinding(report, {
            rule, severity, title, detail, recommendation,
            file, "import:" + module.name,
            {{"module", module.name},
             {"delay_loaded", module.delayLoaded ? "true" : "false"},
             {"bundled", bundledBesideBinary ? "true" : "false"},
             {"likely_system_name", likelySystem ? "true" : "false"}},
        });
    }

    if (!report.binaries.back().asciiDllStrings.empty() ||
        !report.binaries.back().utf16DllStrings.empty()) {
        const bool hasRuntimeLoadApi = std::any_of(
            binary.imports.begin(), binary.imports.end(), [](const ImportedModule& m) {
                return std::any_of(m.functions.begin(), m.functions.end(),
                                   [](const ImportedFunction& f) { return isDynamicLoadApi(f.name); });
            });

        std::set<std::string> importedNames;
        for (const auto& module : binary.imports) importedNames.insert(lower(module.name));

        auto considerString = [&](const std::string& value, const char* encoding) {
            std::string n = lower(value);
            bool composed = n.find('%') != std::string::npos;
            bool bare = isBareFileName(value);

            if (composed) {
                addFinding(report, {
                    "PE-STRING-COMPOSED-DLL-NAME", Severity::High,
                    "Binary contains a formatted/composed DLL name",
                    std::string(encoding) + " string: " + value,
                    "Static analysis cannot determine the final name. Trace the format arguments, "
                    "replace with dllguard::LoadTrustedDll/LoadSystemDll, and add a QA Process Monitor "
                    "capture for NAME NOT FOUND loads from writable directories.",
                    file, std::string("string:") + encoding,
                    {{"value", value}, {"encoding", encoding}},
                });
            } else if (bare && !importedNames.count(n)) {
                addFinding(report, {
                    "PE-STRING-DLL-NAME",
                    hasRuntimeLoadApi ? Severity::Medium : Severity::Low,
                    "Binary contains a bare DLL filename string",
                    std::string(encoding) + " string: " + value +
                        (hasRuntimeLoadApi ? " The binary also imports a dynamic loader API."
                                          : " Correlate with loader behavior; it may be text or an indirect load."),
                    "Confirm whether it reaches LoadLibrary/LdrLoadDll. If it does, load only through "
                    "an absolute canonical path constrained to System32 or a signed trusted root.",
                    file, std::string("string:") + encoding,
                    {{"value", value}, {"encoding", encoding},
                     {"runtime_load_api", hasRuntimeLoadApi ? "true" : "false"}},
                });
            }
        };

        for (const auto& value : binary.asciiDllStrings) considerString(value, "ascii");
        for (const auto& value : binary.utf16DllStrings) considerString(value, "utf16");
    }
}

void analyzeSourceCall(const SourceCall& call, ScanReport& report) {
    const std::string file = displayPath(call.file);
    const std::string location = file + ":" + std::to_string(call.line) + ":" +
                                 std::to_string(call.column);

    if (call.isSearchPathConfiguration) {
        if (call.literalIsComplete && call.firstStringLiteral.empty()) {
            addFinding(report, {
                "SRC-SEARCH-PATH-CWD-REMOVED", Severity::Info,
                "Call removes the current directory from the DLL search path",
                call.api + "(L\"\")",
                "Prefer SetDefaultDllDirectories plus the DllGuard initializer so the policy is explicit and version-tolerant.",
                file, location, {{"api", call.api}},
            });
        } else {
            const bool absolute = call.literalIsComplete &&
                                  isAbsolutePath(call.firstStringLiteral);
            addFinding(report, {
                "SRC-UNSAFE-DLL-DIRECTORY",
                call.literalIsComplete && absolute ? Severity::Medium : Severity::High,
                "Call adds or changes the DLL search directory",
                call.api + "(" + call.argumentExpression + ")",
                "Do not add relative, user-writable, or user-controlled directories. Call "
                "SetDllDirectory(L\"\")/SetDefaultDllDirectories early and use AddDllDirectory "
                "only for canonical, ACL-protected plugin roots.",
                file, location,
                {{"api", call.api}, {"literal", call.firstStringLiteral}},
            });
        }
        return;
    }

    if (call.api.find("Safe") != std::string::npos || call.callsSafeWrapper) {
        addFinding(report, {
            "SRC-SAFE-WRAPPER-CALL", Severity::Info,
            "Call appears to use a safe wrapper",
            call.api + "(" + call.argumentExpression + ")",
            "Ensure the wrapper policy enforces canonical roots and signature checks.",
            file, location, {{"api", call.api}},
        });
        return;
    }

    Severity severity = Severity::High;
    std::string rule;
    std::string title;
    std::string detail = call.api + "(" + call.argumentExpression + ")";
    std::string recommendation =
        "Replace with dllguard::LoadSystemDll for OS libraries or dllguard::LoadPlugin/"
        "LoadTrustedDll for application components. Do not call LoadLibrary with a mutable or "
        "relative name.";

    const std::string& literal = call.firstStringLiteral;
    const bool expressionIsLiteral = call.literalIsComplete && !literal.empty();

    if (!literal.empty() && expressionIsLiteral) {
        if (isAbsolutePath(literal)) {
            rule = "SRC-LOAD-ABSOLUTE";
            title = "Dynamic load uses an absolute literal path";
            severity = call.hasSafeFlag ? Severity::Low : Severity::Medium;
            detail += " The target path is absolute, but adjacent dependencies may still be searched unsafely.";
            recommendation = "Canonicalize the final path, verify its signature/root, and call LoadLibraryEx "
                             "with LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 | "
                             "LOAD_LIBRARY_SEARCH_USER_DIRS as appropriate.";
        } else if (isBareFileName(literal)) {
            rule = "SRC-LOAD-BARE-NAME";
            title = "Dynamic load uses a bare DLL name";
            severity = call.hasSafeFlag ? Severity::Medium : Severity::High;
            detail += " Windows resolves the name through search order and already-loaded-module reuse.";
        } else {
            rule = "SRC-LOAD-RELATIVE-PATH";
            title = "Dynamic load uses a relative path";
            severity = call.hasSafeFlag ? Severity::Medium : Severity::High;
            detail += " The path is relative to the process current directory or another search location.";
        }
    } else {
        rule = "SRC-LOAD-COMPOSED-NAME";
        title = "Dynamic DLL name is variable or composed";
        severity = Severity::High;
        detail += " Static scanning cannot prove which filename is loaded.";
        recommendation = "Remove filename construction from untrusted input. Map logical plugin IDs to an "
                         "allowlist, build a path inside a fixed trusted root, canonicalize it, enforce the "
                         "root prefix, and verify the signature before loading.";
    }

    if (call.api.rfind("LoadLibraryEx", 0) == 0 && !call.hasSearchFlags) {
        severity = std::max(severity, Severity::Medium);
        detail += " No LOAD_LIBRARY_SEARCH_* flag was detected.";
    }

    if (call.hasSafeFlag && severity > Severity::Low) {
        // Explicit safe flags are meaningful but do not resolve a composed/untrusted path.
        if (rule == "SRC-LOAD-BARE-NAME" || rule == "SRC-LOAD-RELATIVE-PATH") {
            severity = Severity::Medium;
        }
    }

    addFinding(report, {
        rule, severity, title, detail, recommendation,
        file, location,
        {{"api", call.api}, {"line", std::to_string(call.line)},
         {"literal", literal}, {"has_search_flags", call.hasSearchFlags ? "true" : "false"}},
    });
}

}  // namespace

const char* severityName(Severity severity) {
    switch (severity) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

std::optional<Severity> parseSeverity(const std::string& text) {
    std::string value = lower(text);
    if (value == "info" || value == "note") return Severity::Info;
    if (value == "low") return Severity::Low;
    if (value == "medium" || value == "moderate" || value == "warning") return Severity::Medium;
    if (value == "high" || value == "error") return Severity::High;
    if (value == "critical") return Severity::Critical;
    return std::nullopt;
}

int severityRank(Severity severity) {
    return static_cast<int>(severity);
}

ScanReport runScan(const ScanOptions& options) {
    ScanReport report;

    std::vector<std::filesystem::path> binaryFiles;
    collectByExtension(options.binaryPaths,
                       {".exe", ".dll", ".ocx", ".cpl", ".sys", ".drv", ".scr"},
                       options.recursive, binaryFiles);

    std::vector<std::filesystem::path> sourceFiles;
    collectByExtension(options.sourcePaths,
                       {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx", ".inl"},
                       options.recursive, sourceFiles);

    std::set<std::string> knownDlls = builtInKnownDlls();
    for (const auto& listPath : options.knownDllLists) {
        auto values = readNameList(listPath);
        knownDlls.insert(values.begin(), values.end());
    }
    const std::set<std::string> systemNames = collectSystemNames(options);

    for (const auto& binaryPath : binaryFiles) {
        BinaryInfo binary = parsePeFile(binaryPath, options.scanStrings);
        report.binaries.push_back(std::move(binary));
        analyzeBinary(report.binaries.back(), knownDlls, systemNames, report);
    }

    for (const auto& sourcePath : sourceFiles) {
        auto calls = scanSourceFile(sourcePath, options.extraLoadApis);
        for (auto& call : calls) {
            report.sourceCalls.push_back(call);
            if (!call.suppressed) analyzeSourceCall(call, report);
        }
    }

    for (Severity severity : {Severity::Info, Severity::Low, Severity::Medium,
                              Severity::High, Severity::Critical}) {
        report.countsBySeverity[severityName(severity)] = 0;
    }
    for (const Finding& finding : report.findings) {
        ++report.countsBySeverity[severityName(finding.severity)];
    }

    return report;
}

}  // namespace dllscan
