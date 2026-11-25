#include <dllguard/ModuleAudit.h>

#include <psapi.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace dllguard {
namespace {

std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

bool pathContainsInsensitive(const std::wstring& path, const wchar_t* component) {
    std::wstring normalized = L"\\" + lower(path) + L"\\";
    std::wstring needle = L"\\" + lower(component) + L"\\";
    return normalized.find(needle) != std::wstring::npos;
}

ModuleAuditFinding makeFinding(ModuleAuditFinding::Severity severity,
                               std::wstring rule,
                               const LoadedModuleInfo& module,
                               std::wstring detail) {
    ModuleAuditFinding finding;
    finding.severity = severity;
    finding.ruleId = std::move(rule);
    finding.moduleName = module.moduleName;
    finding.path = module.path;
    finding.detail = std::move(detail);
    return finding;
}

}  // namespace

const wchar_t* auditSeverityName(ModuleAuditFinding::Severity severity) {
    switch (severity) {
        case ModuleAuditFinding::Severity::Info: return L"info";
        case ModuleAuditFinding::Severity::Low: return L"low";
        case ModuleAuditFinding::Severity::Medium: return L"medium";
        case ModuleAuditFinding::Severity::High: return L"high";
    }
    return L"unknown";
}

std::vector<LoadedModuleInfo> EnumerateLoadedModules() {
    std::vector<LoadedModuleInfo> result;
    HANDLE process = GetCurrentProcess();

    DWORD requiredBytes = 0;
    if (!EnumProcessModulesEx(process, nullptr, 0, &requiredBytes, LIST_MODULES_ALL) ||
        requiredBytes == 0) {
        return result;
    }

    std::vector<HMODULE> handles(requiredBytes / sizeof(HMODULE));
    DWORD actualBytes = 0;
    if (!EnumProcessModulesEx(process, handles.data(),
                              static_cast<DWORD>(handles.size() * sizeof(HMODULE)),
                              &actualBytes, LIST_MODULES_ALL)) {
        return result;
    }

    const std::size_t count = actualBytes / sizeof(HMODULE);
    result.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        std::vector<wchar_t> pathBuffer(32768);
        DWORD length = GetModuleFileNameExW(
            process, handles[i], pathBuffer.data(),
            static_cast<DWORD>(pathBuffer.size()));
        if (length == 0) continue;

        LoadedModuleInfo info;
        info.path.assign(pathBuffer.data(), length);
        info.moduleName = BaseName(info.path);
        result.push_back(std::move(info));
    }

    return result;
}

std::vector<ModuleAuditFinding> AuditLoadedModules(bool verifySignatures) {
    std::vector<ModuleAuditFinding> findings;
    std::vector<LoadedModuleInfo> modules = EnumerateLoadedModules();

    wchar_t systemBuffer[MAX_PATH]{};
    GetSystemDirectoryW(systemBuffer, MAX_PATH);
    std::wstring systemDirectory = systemBuffer;
    std::wstring systemFinal;
    ResolveFinalPath(systemDirectory, systemFinal);

    wchar_t exeBuffer[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeBuffer, MAX_PATH);
    std::wstring exePath = exeBuffer;
    std::wstring exeDirectory = ParentPath(exePath);
    std::wstring exeDirectoryFinal;
    ResolveFinalPath(exeDirectory, exeDirectoryFinal);

    wchar_t currentBuffer[MAX_PATH]{};
    GetCurrentDirectoryW(MAX_PATH, currentBuffer);
    std::wstring currentDirectory = currentBuffer;
    std::wstring currentFinal;
    ResolveFinalPath(currentDirectory, currentFinal);

    wchar_t tempBuffer[MAX_PATH]{};
    DWORD tempLength = GetTempPathW(MAX_PATH, tempBuffer);
    std::wstring tempDirectory = tempLength ? std::wstring(tempBuffer, tempLength) : L"";
    std::wstring tempFinal;
    if (!tempDirectory.empty()) ResolveFinalPath(tempDirectory, tempFinal);

    for (const LoadedModuleInfo& module : modules) {
        std::wstring finalPath;
        if (!ResolveFinalPath(module.path, finalPath)) finalPath = module.path;

        const bool inSystem = !systemFinal.empty() && IsUnderPath(finalPath, systemFinal);
        const bool inExeDirectory = !exeDirectoryFinal.empty() &&
                                    IsUnderPath(finalPath, exeDirectoryFinal);
        const bool inCurrentDirectory = !currentFinal.empty() &&
                                        IsUnderPath(finalPath, currentFinal);
        const bool inTemp = !tempFinal.empty() && IsUnderPath(finalPath, tempFinal);
        const bool inDownloads = pathContainsInsensitive(finalPath, L"Downloads");

        if (inSystem) continue;

        if (inTemp) {
            findings.push_back(makeFinding(
                ModuleAuditFinding::Severity::High, L"MODULE-FROM-TEMP-DIRECTORY", module,
                L"A DLL is mapped from the temporary directory."));
        }

        if (inDownloads) {
            findings.push_back(makeFinding(
                ModuleAuditFinding::Severity::High, L"MODULE-FROM-DOWNLOADS-DIRECTORY", module,
                L"A DLL is mapped from a user Downloads directory, a classic planting location."));
        }

        if (inCurrentDirectory && !inExeDirectory && !inSystem) {
            findings.push_back(makeFinding(
                ModuleAuditFinding::Severity::High, L"MODULE-FROM-CURRENT-DIRECTORY", module,
                L"A DLL is mapped from the process current directory outside the application directory."));
        }

        std::wstring parent = ParentPath(finalPath);
        Result acl = CheckDirectoryAcl(parent);
        if (!acl && acl.win32Error == ERROR_ACCESS_DENIED) {
            findings.push_back(makeFinding(
                ModuleAuditFinding::Severity::High, L"MODULE-DIRECTORY-WRITABLE-BY-USERS", module,
                L"The loaded DLL's directory is writable by Everyone/Users/Authenticated Users: " +
                    acl.message));
        }

        if (!inExeDirectory && !inCurrentDirectory && !inTemp && !inDownloads) {
            findings.push_back(makeFinding(
                ModuleAuditFinding::Severity::Medium, L"MODULE-OUTSIDE-EXPECTED-ROOTS", module,
                L"The module is outside System32 and the executable directory. Confirm that this is an allowed plugin/component path."));
        }

        if (verifySignatures) {
            SignaturePolicy policy;
            if (Result signature = VerifyAuthenticode(finalPath, policy); !signature) {
                findings.push_back(makeFinding(
                    ModuleAuditFinding::Severity::High, L"MODULE-INVALID-SIGNATURE", module,
                    L"The loaded module does not have a valid Authenticode/catalog signature: " +
                        signature.message));
            }
        }
    }

    return findings;
}

}  // namespace dllguard
