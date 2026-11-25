// Hardened replacement for vulnerable_app.cpp.

#include <dllguard/ModuleAudit.h>
#include <dllguard/SafeLoad.h>

#include <iostream>

int wmain() {
    // First line of application code. For this image's own static imports, also
    // link with /DEPENDENTLOADFLAG:0x800 (propagated by the dllguard CMake target).
    dllguard::InitConfig config;
    config.strictSystem32Default = false;  // app dir + System32 + AddDllDirectory roots
    config.trustedDllDirectories = {L"C:\\Program Files\\Contoso\\App\\plugins"};

    if (auto initialized = dllguard::Initialize(config); !initialized) {
        std::wcerr << L"DllGuard initialization failed: " << initialized.message << L'\n';
        return ERROR_DLL_INIT_FAILED;
    }

    // OS library: always resolved from the real System32 and signature checked.
    auto version = dllguard::LoadSystemDll(L"version.dll");
    if (!version) {
        std::wcerr << L"version.dll load failed: " << version.message << L'\n';
        return version.win32Error;
    }

    // Plugin: logical file name mapped into a fixed root. No user-controlled
    // path concatenation. In Program Files the ACL check is appropriate; for a
    // per-user plugin directory set policy.checkRootAcl=false but require a
    // publisher/thumbprint policy.
    dllguard::LoadPolicy pluginPolicy;
    pluginPolicy.allowedRoots = {L"C:\\Program Files\\Contoso\\App\\plugins"};
    pluginPolicy.checkRootAcl = true;
    pluginPolicy.signature.requireValidSignature = true;
    pluginPolicy.signature.publisherContains = L"Contoso";
    pluginPolicy.signature.allowedThumbprints = {
        // "aa:bb:..." or plain hex SHA-1 thumbprint(s)
    };

    auto plugin = dllguard::LoadTrustedDll(
        L"C:\\Program Files\\Contoso\\App\\plugins\\report_plugin.dll", pluginPolicy);
    if (!plugin) {
        std::wcerr << L"plugin blocked: " << plugin.message << L'\n';
        // In production, raise a security event and fail closed.
    }

#if defined(DLLGUARD_RUN_RUNTIME_AUDIT)
    for (const auto& issue : dllguard::AuditLoadedModules(true)) {
        std::wcerr << L"[" << dllguard::auditSeverityName(issue.severity) << L"] "
                   << issue.ruleId << L": " << issue.path << L" - " << issue.detail << L'\n';
    }
#endif

    return 0;
}
