#pragma once

// DllGuard safe dynamic-loader policy for Windows.
//
// The most important static-import mitigation is /DEPENDENTLOADFLAG:0x800.
// Static imports are resolved before DllMain/WinMain, so Initialize() alone
// cannot retroactively protect the calling image's own import table.

#include <windows.h>

#include <string>
#include <vector>

namespace dllguard {

struct SignaturePolicy {
    // Verify a full Authenticode/catalog chain using WinVerifyTrust.
    bool requireValidSignature = true;

    // Require the signer display name to contain "Microsoft".
    bool requireMicrosoft = false;

    // Optional case-insensitive substring required in the signer name.
    std::wstring publisherContains;

    // Optional SHA-1 certificate thumbprints, hexadecimal with or without
    // colons/spaces. When non-empty, the signer certificate must match one.
    std::vector<std::string> allowedThumbprints;
};

struct LoadPolicy {
    // Directories from which a DLL may be loaded. Canonical final paths are
    // checked, so ".." and symlink escapes are rejected.
    std::vector<std::wstring> allowedRoots;

    SignaturePolicy signature;

    // Reject roots/directories that grant write access to broad low-privilege
    // SIDs such as Everyone, Users, or Authenticated Users. Signed per-user
    // plugin directories may set this to false and rely on signature policy.
    bool checkRootAcl = true;

    // Search flags for dependencies of the DLL being loaded.
    bool allowPluginDirectoryDependencies = true;   // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
    bool allowSystem32Dependencies = true;          // LOAD_LIBRARY_SEARCH_SYSTEM32
    bool allowUserDirectoryDependencies = true;      // LOAD_LIBRARY_SEARCH_USER_DIRS
    bool allowApplicationDirectoryDependencies = false;

    // If a same-named module is already mapped, require its file to match the
    // canonical target. Otherwise return an error instead of reusing a squatted
    // module. The wrong DllMain may already have run, so callers should treat
    // this as fatal integrity failure.
    bool rejectIfAlreadyLoadedFromWrongPath = true;
};

struct InitConfig {
    // true  -> SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)
    // false -> APPLICATION_DIR | SYSTEM32 | USER_DIRS (current directory removed)
    bool strictSystem32Default = false;

    bool removeCurrentDirectory = true;
    bool enablePermanentSafeSearchMode = true;

    std::vector<std::wstring> trustedDllDirectories;

    // Preload frequently planted OS DLL names from System32 so later bare-name
    // requests reuse the trusted mapped image.
    bool preloadHijackProneSystemDlls = true;
};

struct Result {
    bool ok = false;
    DWORD win32Error = ERROR_SUCCESS;
    HMODULE module = nullptr;
    std::wstring canonicalPath;
    std::wstring message;

    explicit operator bool() const noexcept { return ok; }

    static Result Success(HMODULE loadedModule, std::wstring path = {}) {
        Result result;
        result.ok = true;
        result.module = loadedModule;
        result.canonicalPath = std::move(path);
        result.message = L"ok";
        return result;
    }

    static Result Failure(DWORD error, std::wstring errorMessage, std::wstring path = {}) {
        Result result;
        result.ok = false;
        result.win32Error = error;
        result.canonicalPath = std::move(path);
        result.message = std::move(errorMessage);
        return result;
    }
};

// Applies process-wide search-order hardening and optional preloading.
Result Initialize(const InitConfig& config = {});

// Removes CWD, enables permanent safe SearchPath mode, and sets default load
// directories. Safe to call as the first statement in WinMain/wmain.
Result HardenSearchPath(bool strictSystem32Default = false);

// Wrapper around AddDllDirectory, resolved dynamically for older Windows.
Result AddTrustedDllDirectory(const std::wstring& directory, PVOID* cookie = nullptr);

// Best-effort preload. Names should be bare OS filenames such as L"version.dll".
Result PreloadSystemDlls(const std::vector<std::wstring>& names);

// Loads an OS DLL only from the real System32 directory (or an API-set name).
Result LoadSystemDll(const wchar_t* name, bool verifySignature = true);

// Canonicalizes, root-checks, ACL-checks, signature-verifies, and safely loads.
Result LoadTrustedDll(const std::wstring& path, const LoadPolicy& policy);

// Convenience wrapper for application/plugin DLLs.
Result LoadPlugin(const std::wstring& path,
                  std::vector<std::wstring> allowedRoots,
                  const SignaturePolicy& signature = {});

// Path and trust helpers exposed for tests and custom policies.
std::wstring ExpandAndNormalizePath(const std::wstring& path);
Result ResolveFinalPath(const std::wstring& path, std::wstring& finalPath);
bool IsUnderPath(const std::wstring& path, const std::wstring& root);
std::wstring ParentPath(const std::wstring& path);
std::wstring BaseName(const std::wstring& path);

// Returns success only when the DACL does not grant obvious write permission to
// broad low-privilege SIDs. This is a conservative deployment check, not a
// replacement for a complete authorization/ACL review.
Result CheckDirectoryAcl(const std::wstring& directory);

Result VerifyAuthenticode(const std::wstring& path, const SignaturePolicy& policy);

}  // namespace dllguard
