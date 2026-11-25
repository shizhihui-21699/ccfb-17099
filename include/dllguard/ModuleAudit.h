#pragma once

#include <dllguard/SafeLoad.h>

#include <string>
#include <vector>

namespace dllguard {

struct LoadedModuleInfo {
    std::wstring moduleName;
    std::wstring path;
};

struct ModuleAuditFinding {
    enum class Severity { Info, Low, Medium, High };

    Severity severity = Severity::Info;
    std::wstring ruleId;
    std::wstring moduleName;
    std::wstring path;
    std::wstring detail;
};

// Enumerates modules mapped into the current process.
std::vector<LoadedModuleInfo> EnumerateLoadedModules();

// Looks for modules mapped from writable or obvious planting locations.
// This is a runtime verification complement to static scanning, especially
// useful for closed-source components and composed DLL names.
std::vector<ModuleAuditFinding> AuditLoadedModules(bool verifySignatures = false);

const wchar_t* auditSeverityName(ModuleAuditFinding::Severity severity);

}  // namespace dllguard
