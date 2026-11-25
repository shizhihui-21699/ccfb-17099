#include "dllguard/SafeLoad.h"

#include <aclapi.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <iterator>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif
#ifndef LOAD_LIBRARY_SEARCH_APPLICATION_DIR
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR 0x00000200
#endif
#ifndef LOAD_LIBRARY_SEARCH_USER_DIRS
#define LOAD_LIBRARY_SEARCH_USER_DIRS 0x00000400
#endif
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif
#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x00001000
#endif
#ifndef BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE
#define BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE 0x00000001
#endif
#ifndef BASE_SEARCH_PATH_PERMANENT
#define BASE_SEARCH_PATH_PERMANENT 0x00008000
#endif

namespace dllguard {
namespace {

using SetDefaultDllDirectoriesFn = BOOL(WINAPI*)(DWORD);
using AddDllDirectoryFn = PVOID(WINAPI*)(PCWSTR);
using RemoveDllDirectoryFn = BOOL(WINAPI*)(PVOID);
using SetSearchPathModeFn = BOOL(WINAPI*)(DWORD);

std::wstring toLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::string toLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::wstring win32Message(DWORD error) {
    LPWSTR buffer = nullptr;
    DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message = length ? std::wstring(buffer, length) : L"Win32 error";
    if (buffer) LocalFree(buffer);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

Result lastFailure(const wchar_t* operation, std::wstring path = {}) {
    DWORD error = GetLastError();
    std::wstring message = operation;
    message += L": ";
    message += win32Message(error);
    return Result::Failure(error, std::move(message), std::move(path));
}

template <typename Function>
Function resolveKernel32(const char* name) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return nullptr;
    FARPROC procedure = GetProcAddress(kernel32, name);
    if (!procedure) return nullptr;
    return reinterpret_cast<Function>(reinterpret_cast<void*>(procedure));
}

std::wstring stripExtendedLengthPrefix(std::wstring path) {
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        return L"\\\\" + path.substr(8);
    }
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        return path.substr(4);
    }
    return path;
}

std::wstring bytesToHex(const BYTE* bytes, DWORD length) {
    static const wchar_t digits[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(static_cast<std::size_t>(length) * 2);
    for (DWORD i = 0; i < length; ++i) {
        result.push_back(digits[bytes[i] >> 4]);
        result.push_back(digits[bytes[i] & 0x0f]);
    }
    return result;
}

std::string normalizeThumbprint(std::string value) {
    value = toLowerAscii(std::move(value));
    value.erase(std::remove_if(value.begin(), value.end(),
                               [](unsigned char c) {
                                   return !((c >= '0' && c <= '9') ||
                                            (c >= 'a' && c <= 'f'));
                               }),
                value.end());
    return value;
}

bool isBroadUntrustedSid(PSID sid) {
    SID_IDENTIFIER_AUTHORITY worldAuthority = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY creatorAuthority = SECURITY_CREATOR_SID_AUTHORITY;

    PSID everyone = nullptr;
    PSID authenticatedUsers = nullptr;
    PSID builtinUsers = nullptr;
    PSID creatorOwner = nullptr;

    AllocateAndInitializeSid(&worldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0,
                             &everyone);
    AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0,
                             0, 0, 0, &authenticatedUsers);
    AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                             DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &builtinUsers);
    AllocateAndInitializeSid(&creatorAuthority, 1, SECURITY_CREATOR_OWNER_RID, 0, 0, 0, 0,
                             0, 0, 0, &creatorOwner);

    bool matches = false;
    PSID candidates[] = {everyone, authenticatedUsers, builtinUsers, creatorOwner};
    for (PSID candidate : candidates) {
        if (candidate && EqualSid(sid, candidate)) {
            matches = true;
            break;
        }
    }

    if (everyone) FreeSid(everyone);
    if (authenticatedUsers) FreeSid(authenticatedUsers);
    if (builtinUsers) FreeSid(builtinUsers);
    if (creatorOwner) FreeSid(creatorOwner);
    return matches;
}

Result modulePathMatches(HMODULE module, const std::wstring& expectedFinalPath) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetModuleFileNameW(module, buffer.data(),
                                     static_cast<DWORD>(buffer.size()));
    if (length == 0) return lastFailure(L"GetModuleFileNameW");
    if (length >= buffer.size()) return Result::Failure(ERROR_INSUFFICIENT_BUFFER,
                                                        L"module path is too long");

    std::wstring actual(buffer.data(), length);
    std::wstring actualFinal;
    if (Result resolved = ResolveFinalPath(actual, actualFinal); !resolved) {
        return resolved;
    }

    if (toLower(actualFinal) != toLower(expectedFinalPath)) {
        return Result::Failure(
            ERROR_INVALID_IMAGE_HASH,
            L"already-loaded module path does not match trusted target: " + actualFinal,
            actualFinal);
    }
    return Result::Success(module, actualFinal);
}

Result checkAlreadyLoadedModule(const std::wstring& targetFinalPath,
                                const LoadPolicy& policy) {
    if (!policy.rejectIfAlreadyLoadedFromWrongPath) return Result::Success(nullptr);

    std::wstring base = BaseName(targetFinalPath);
    HMODULE existing = GetModuleHandleW(base.c_str());
    if (!existing) return Result::Success(nullptr);

    Result match = modulePathMatches(existing, targetFinalPath);
    if (!match) return match;
    return Result::Success(existing, targetFinalPath);
}

}  // namespace

std::wstring ExpandAndNormalizePath(const std::wstring& path) {
    DWORD expandedLength = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
    std::wstring expanded;
    if (expandedLength > 0) {
        expanded.resize(expandedLength);
        DWORD written = ExpandEnvironmentStringsW(
            path.c_str(), expanded.data(), expandedLength);
        if (written > 0) expanded.resize(written - 1);
        else expanded = path;
    } else {
        expanded = path;
    }

    DWORD fullLength = GetFullPathNameW(expanded.c_str(), 0, nullptr, nullptr);
    if (fullLength == 0) return expanded;

    std::vector<wchar_t> buffer(fullLength);
    LPWSTR filePart = nullptr;
    DWORD written = GetFullPathNameW(expanded.c_str(), fullLength, buffer.data(), &filePart);
    if (written == 0) return expanded;
    return std::wstring(buffer.data(), written);
}

Result ResolveFinalPath(const std::wstring& path, std::wstring& finalPath) {
    std::wstring normalized = ExpandAndNormalizePath(path);
    HANDLE handle = CreateFileW(
        normalized.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
        return lastFailure(L"CreateFileW while resolving path", normalized);
    }

    std::vector<wchar_t> buffer(32768);
    DWORD length = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    DWORD error = GetLastError();
    CloseHandle(handle);

    if (length == 0) {
        return Result::Failure(error, L"GetFinalPathNameByHandleW failed", normalized);
    }
    if (length >= buffer.size()) {
        return Result::Failure(ERROR_INSUFFICIENT_BUFFER, L"final path is too long",
                               normalized);
    }

    finalPath.assign(buffer.data(), length);
    return Result::Success(nullptr, finalPath);
}

bool IsUnderPath(const std::wstring& path, const std::wstring& root) {
    std::wstring normalizedPath = stripExtendedLengthPrefix(ExpandAndNormalizePath(path));
    std::wstring normalizedRoot = stripExtendedLengthPrefix(ExpandAndNormalizePath(root));

    std::wstring rootWithSlash = normalizedRoot;
    if (!rootWithSlash.empty() && rootWithSlash.back() != L'\\' &&
        rootWithSlash.back() != L'/') {
        rootWithSlash.push_back(L'\\');
    }

    if (normalizedPath.size() == normalizedRoot.size() &&
        CompareStringOrdinal(normalizedPath.c_str(),
                             static_cast<int>(normalizedPath.size()),
                             normalizedRoot.c_str(),
                             static_cast<int>(normalizedRoot.size()), TRUE) == CSTR_EQUAL) {
        return true;
    }

    if (normalizedPath.size() < rootWithSlash.size()) return false;
    return CompareStringOrdinal(
               normalizedPath.c_str(), static_cast<int>(rootWithSlash.size()),
               rootWithSlash.c_str(), static_cast<int>(rootWithSlash.size()),
               TRUE) == CSTR_EQUAL;
}

std::wstring ParentPath(const std::wstring& path) {
    std::wstring normalized = ExpandAndNormalizePath(path);
    std::size_t pos = normalized.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".";
    if (pos == 0) return normalized.substr(0, 1);
    return normalized.substr(0, pos);
}

std::wstring BaseName(const std::wstring& path) {
    std::size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

Result CheckDirectoryAcl(const std::wstring& directory) {
    std::wstring normalized = ExpandAndNormalizePath(directory);
    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;

    DWORD error = GetNamedSecurityInfoW(
        normalized.c_str(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr,
        nullptr, nullptr, &securityDescriptor);

    if (error != ERROR_SUCCESS) {
        return Result::Failure(error, L"GetNamedSecurityInfoW failed", normalized);
    }

    auto cleanup = [&]() {
        if (securityDescriptor) LocalFree(securityDescriptor);
    };

    if (!GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl,
                                   &daclDefaulted)) {
        error = GetLastError();
        cleanup();
        return Result::Failure(error, L"GetSecurityDescriptorDacl failed", normalized);
    }

    if (!daclPresent || !dacl) {
        cleanup();
        return Result::Failure(ERROR_INVALID_SECURITY_DESCR,
                               L"directory has no discretionary ACL", normalized);
    }

    GENERIC_MAPPING mapping{};
    mapping.GenericRead = FILE_GENERIC_READ;
    mapping.GenericWrite = FILE_GENERIC_WRITE;
    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    mapping.GenericAll = FILE_ALL_ACCESS;

    const ACCESS_MASK dangerousWriteBits =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_DELETE_CHILD;

    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        PVOID acePointer = nullptr;
        if (!GetAce(dacl, i, &acePointer) || !acePointer) continue;

        ACE_HEADER* header = static_cast<ACE_HEADER*>(acePointer);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

        ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(acePointer);
        ACCESS_MASK mask = ace->Mask;
        MapGenericMask(&mask, &mapping);

        if ((mask & dangerousWriteBits) == 0) continue;

        PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
        if (!isBroadUntrustedSid(sid)) continue;

        LPWSTR sidString = nullptr;
        ConvertSidToStringSidW(sid, &sidString);
        std::wstring sidText = sidString ? sidString : L"SID";
        if (sidString) LocalFree(sidString);

        cleanup();
        return Result::Failure(
            ERROR_ACCESS_DENIED,
            L"directory grants write access to broad low-privilege SID " + sidText,
            normalized);
    }

    cleanup();
    return Result::Success(nullptr, normalized);
}

Result VerifyAuthenticode(const std::wstring& path, const SignaturePolicy& policy) {
    if (!policy.requireValidSignature) return Result::Success(nullptr, path);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = nullptr;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG trustStatus = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    if (trustStatus != ERROR_SUCCESS) {
        DWORD error = static_cast<DWORD>(trustStatus);
        return Result::Failure(error, L"Authenticode verification failed", path);
    }

    const bool needSignerDetails = policy.requireMicrosoft ||
                                   !policy.publisherContains.empty() ||
                                   !policy.allowedThumbprints.empty();
    if (!needSignerDetails) return Result::Success(nullptr, path);

    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encodingType = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encodingType, &contentType,
            &formatType, &store, &message, nullptr)) {
        DWORD error = GetLastError();
        if (store) CertCloseStore(store, 0);
        if (message) CryptMsgClose(message);
        return Result::Failure(error, L"CryptQueryObject failed", path);
    }

    DWORD signerSize = 0;
    bool ok = CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) &&
              signerSize > 0;
    std::vector<BYTE> signerBuffer(signerSize);
    PCMSG_SIGNER_INFO signerInfo = nullptr;
    if (ok) {
        ok = CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
                              signerBuffer.data(), &signerSize) != FALSE;
        signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerBuffer.data());
    }

    PCCERT_CONTEXT signerCert = nullptr;
    if (ok && signerInfo) {
        CERT_INFO certInfo{};
        certInfo.Issuer = signerInfo->Issuer;
        certInfo.SerialNumber = signerInfo->SerialNumber;
        signerCert = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);
        ok = signerCert != nullptr;
    }

    if (!ok) {
        DWORD error = GetLastError();
        if (signerCert) CertFreeCertificateContext(signerCert);
        if (store) CertCloseStore(store, 0);
        if (message) CryptMsgClose(message);
        return Result::Failure(error, L"could not read Authenticode signer", path);
    }

    if (!policy.allowedThumbprints.empty()) {
        DWORD hashSize = 0;
        CertGetCertificateContextProperty(signerCert, CERT_SHA1_HASH_PROP_ID,
                                          nullptr, &hashSize);
        std::vector<BYTE> hash(hashSize);
        if (hashSize == 0 ||
            !CertGetCertificateContextProperty(signerCert, CERT_SHA1_HASH_PROP_ID,
                                               hash.data(), &hashSize)) {
            DWORD error = GetLastError();
            CertFreeCertificateContext(signerCert);
            CertCloseStore(store, 0);
            CryptMsgClose(message);
            return Result::Failure(error, L"could not read signer thumbprint", path);
        }

        std::string thumbprint;
        std::wstring wideThumb = bytesToHex(hash.data(), hashSize);
        thumbprint.reserve(wideThumb.size());
        for (wchar_t c : wideThumb) thumbprint.push_back(static_cast<char>(c));

        bool thumbprintAllowed = false;
        for (const std::string& allowed : policy.allowedThumbprints) {
            if (normalizeThumbprint(allowed) == thumbprint) {
                thumbprintAllowed = true;
                break;
            }
        }
        if (!thumbprintAllowed) {
            CertFreeCertificateContext(signerCert);
            CertCloseStore(store, 0);
            CryptMsgClose(message);
            return Result::Failure(ERROR_INVALID_IMAGE_HASH,
                                   L"signer thumbprint is not allow-listed", path);
        }
    }

    if (policy.requireMicrosoft || !policy.publisherContains.empty()) {
        std::vector<wchar_t> nameBuffer(2048);
        DWORD nameLength = CertGetNameStringW(
            signerCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
            nameBuffer.data(), static_cast<DWORD>(nameBuffer.size()));
        std::wstring publisher = nameLength ? std::wstring(nameBuffer.data()) : L"";
        std::wstring loweredPublisher = toLower(publisher);

        if (policy.requireMicrosoft &&
            loweredPublisher.find(L"microsoft") == std::wstring::npos) {
            CertFreeCertificateContext(signerCert);
            CertCloseStore(store, 0);
            CryptMsgClose(message);
            return Result::Failure(ERROR_INVALID_IMAGE_HASH,
                                   L"signer is not Microsoft: " + publisher, path);
        }

        if (!policy.publisherContains.empty()) {
            std::wstring wanted = toLower(policy.publisherContains);
            if (loweredPublisher.find(wanted) == std::wstring::npos) {
                CertFreeCertificateContext(signerCert);
                CertCloseStore(store, 0);
                CryptMsgClose(message);
                return Result::Failure(ERROR_INVALID_IMAGE_HASH,
                                       L"signer does not match publisher policy: " + publisher,
                                       path);
            }
        }
    }

    CertFreeCertificateContext(signerCert);
    CertCloseStore(store, 0);
    CryptMsgClose(message);
    return Result::Success(nullptr, path);
}

Result HardenSearchPath(bool strictSystem32Default) {
    std::wstring messages;
    bool anyPolicyApplied = false;

    auto setSearchPathMode = resolveKernel32<SetSearchPathModeFn>("SetSearchPathMode");
    if (setSearchPathMode) {
        if (setSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE |
                              BASE_SEARCH_PATH_PERMANENT)) {
            anyPolicyApplied = true;
        } else {
            DWORD error = GetLastError();
            messages += L"SetSearchPathMode failed: " + win32Message(error) + L"; ";
        }
    }

    // An empty string removes the current directory from the search order.
    if (SetDllDirectoryW(L"")) {
        anyPolicyApplied = true;
    } else {
        DWORD error = GetLastError();
        messages += L"SetDllDirectory(empty) failed: " + win32Message(error) + L"; ";
    }

    auto setDefaultDllDirectories =
        resolveKernel32<SetDefaultDllDirectoriesFn>("SetDefaultDllDirectories");
    if (setDefaultDllDirectories) {
        DWORD flags = strictSystem32Default
            ? LOAD_LIBRARY_SEARCH_SYSTEM32
            : (LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
               LOAD_LIBRARY_SEARCH_SYSTEM32 |
               LOAD_LIBRARY_SEARCH_USER_DIRS);
        if (setDefaultDllDirectories(flags)) {
            anyPolicyApplied = true;
        } else {
            DWORD error = GetLastError();
            messages += L"SetDefaultDllDirectories failed: " + win32Message(error) + L"; ";
        }
    }

    if (!anyPolicyApplied) {
        return Result::Failure(ERROR_NOT_SUPPORTED,
                               messages.empty() ? L"no search-policy API is available"
                                                : std::move(messages));
    }
    return Result::Success(nullptr, std::move(messages));
}

Result AddTrustedDllDirectory(const std::wstring& directory, PVOID* cookie) {
    std::wstring finalPath;
    if (Result resolved = ResolveFinalPath(directory, finalPath); !resolved) {
        return resolved;
    }

    auto addDllDirectory = resolveKernel32<AddDllDirectoryFn>("AddDllDirectory");
    if (!addDllDirectory) {
        return Result::Failure(ERROR_NOT_SUPPORTED,
                               L"AddDllDirectory is unavailable; install KB2533623 or newer Windows");
    }

    PVOID addedCookie = addDllDirectory(finalPath.c_str());
    if (!addedCookie) return lastFailure(L"AddDllDirectory", finalPath);
    if (cookie) *cookie = addedCookie;
    return Result::Success(nullptr, finalPath);
}

Result PreloadSystemDlls(const std::vector<std::wstring>& names) {
    std::wstring failed;
    DWORD firstError = ERROR_SUCCESS;
    int loaded = 0;

    for (const std::wstring& name : names) {
        Result result = LoadSystemDll(name.c_str(), false);
        if (result) {
            ++loaded;
        } else {
            if (firstError == ERROR_SUCCESS) firstError = result.win32Error;
            failed += name + L"(err=" + std::to_wstring(result.win32Error) + L"); ";
        }
    }

    if (!failed.empty()) {
        return Result::Failure(firstError ? firstError : ERROR_GEN_FAILURE,
                              L"preload failures: " + failed);
    }
    return Result::Success(reinterpret_cast<HMODULE>(static_cast<ULONG_PTR>(loaded)),
                           L"preloaded");
}

Result Initialize(const InitConfig& config) {
    Result hardened = HardenSearchPath(config.strictSystem32Default);
    if (!hardened) return hardened;

    for (const std::wstring& directory : config.trustedDllDirectories) {
        Result added = AddTrustedDllDirectory(directory);
        if (!added) return added;
    }

    if (config.preloadHijackProneSystemDlls) {
        static const std::wstring kCommonTargets[] = {
            L"bcrypt.dll",
            L"cryptbase.dll",
            L"dbghelp.dll",
            L"dnsapi.dll",
            L"dwmapi.dll",
            L"iphlpapi.dll",
            L"powrprof.dll",
            L"propsys.dll",
            L"shcore.dll",
            L"uxtheme.dll",
            L"version.dll",
            L"winmm.dll",
            L"wintrust.dll",
        };
        // Best effort: a missing optional component should not prevent startup.
        (void)PreloadSystemDlls(
            std::vector<std::wstring>(std::begin(kCommonTargets),
                                      std::end(kCommonTargets)));
    }

    return Result::Success(nullptr, hardened.message);
}

Result LoadSystemDll(const wchar_t* name, bool verifySignature) {
    if (!name || name[0] == L'\0') {
        return Result::Failure(ERROR_INVALID_PARAMETER, L"system DLL name is empty");
    }

    std::wstring requested(name);
    if (requested.find_first_of(L"\\/") != std::wstring::npos ||
        requested.find(L"..") != std::wstring::npos) {
        return Result::Failure(ERROR_INVALID_PARAMETER,
                               L"system DLL name must be a bare filename or API-set name",
                               requested);
    }

    bool apiSet = requested.rfind(L"api-ms-", 0) == 0 ||
                  requested.rfind(L"ext-ms-", 0) == 0;

    if (apiSet) {
        // dllscan-ignore: API-set name plus LOAD_LIBRARY_SEARCH_SYSTEM32.
        HMODULE module = LoadLibraryExW(
            requested.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) return lastFailure(L"LoadLibraryExW(api-set)", requested);
        return Result::Success(module, requested);
    }

    wchar_t systemDirectory[MAX_PATH]{};
    UINT length = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return lastFailure(L"GetSystemDirectoryW");
    }

    std::wstring fileName = requested;
    if (fileName.find(L'.') == std::wstring::npos) fileName += L".dll";
    std::wstring systemPath = std::wstring(systemDirectory) + L"\\" + fileName;

    std::wstring finalPath;
    if (Result resolved = ResolveFinalPath(systemPath, finalPath); !resolved) {
        return resolved;
    }

    std::wstring systemFinal;
    if (Result systemResolved = ResolveFinalPath(systemDirectory, systemFinal);
        !systemResolved) {
        return systemResolved;
    }
    if (!IsUnderPath(finalPath, systemFinal)) {
        return Result::Failure(ERROR_ACCESS_DENIED,
                               L"resolved system DLL is outside System32", finalPath);
    }

    SignaturePolicy signaturePolicy;
    signaturePolicy.requireValidSignature = verifySignature;
    if (verifySignature) {
        if (Result verified = VerifyAuthenticode(finalPath, signaturePolicy); !verified) {
            return verified;
        }
    }

    LoadPolicy preloadPolicy;
    preloadPolicy.allowedRoots = {systemFinal};
    preloadPolicy.checkRootAcl = false;
    if (Result existing = checkAlreadyLoadedModule(finalPath, preloadPolicy); !existing) {
        return existing;
    }

    // dllscan-ignore: final System32 path verified above and loaded with SEARCH_SYSTEM32.
    HMODULE module = LoadLibraryExW(stripExtendedLengthPrefix(finalPath).c_str(), nullptr,
                                    LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return lastFailure(L"LoadLibraryExW(system)", finalPath);

    if (Result matched = modulePathMatches(module, finalPath); !matched) {
        return matched;
    }
    return Result::Success(module, finalPath);
}

Result LoadTrustedDll(const std::wstring& path, const LoadPolicy& policy) {
    if (path.empty()) {
        return Result::Failure(ERROR_INVALID_PARAMETER, L"DLL path is empty");
    }

    std::wstring finalPath;
    if (Result resolved = ResolveFinalPath(path, finalPath); !resolved) {
        return resolved;
    }

    std::wstring matchedRootFinal;
    for (const std::wstring& root : policy.allowedRoots) {
        std::wstring rootFinal;
        if (!ResolveFinalPath(root, rootFinal)) {
            // Also try lexical containment for not-yet-created? DLL must exist,
            // so continue and report the canonical target below if none match.
            continue;
        }
        if (IsUnderPath(finalPath, rootFinal)) {
            matchedRootFinal = rootFinal;
            break;
        }
    }

    if (!policy.allowedRoots.empty() && matchedRootFinal.empty()) {
        return Result::Failure(
            ERROR_ACCESS_DENIED,
            L"DLL path is outside every allowed root",
            stripExtendedLengthPrefix(finalPath));
    }

    if (policy.checkRootAcl) {
        std::wstring aclPath = !matchedRootFinal.empty() ? matchedRootFinal
                                                         : ParentPath(finalPath);
        if (Result acl = CheckDirectoryAcl(aclPath); !acl) return acl;
    }

    if (policy.signature.requireValidSignature) {
        if (Result verified = VerifyAuthenticode(finalPath, policy.signature); !verified) {
            return verified;
        }
    }

    Result alreadyLoaded = checkAlreadyLoadedModule(finalPath, policy);
    if (!alreadyLoaded) return alreadyLoaded;
    if (alreadyLoaded.module) {
        return Result::Success(alreadyLoaded.module, finalPath);
    }

    DWORD flags = 0;
    if (policy.allowPluginDirectoryDependencies) {
        flags |= LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
    }
    if (policy.allowSystem32Dependencies) flags |= LOAD_LIBRARY_SEARCH_SYSTEM32;
    if (policy.allowUserDirectoryDependencies) flags |= LOAD_LIBRARY_SEARCH_USER_DIRS;
    if (policy.allowApplicationDirectoryDependencies) {
        flags |= LOAD_LIBRARY_SEARCH_APPLICATION_DIR;
    }
    if (flags == 0) flags = LOAD_LIBRARY_SEARCH_SYSTEM32;

    std::wstring loadPath = stripExtendedLengthPrefix(finalPath);
    // dllscan-ignore: path/root/ACL/signature policy completed above; flags are explicit.
    HMODULE module = LoadLibraryExW(loadPath.c_str(), nullptr, flags);
    if (!module) return lastFailure(L"LoadLibraryExW(trusted)", finalPath);

    if (Result matched = modulePathMatches(module, finalPath); !matched) {
        return matched;
    }
    return Result::Success(module, finalPath);
}

Result LoadPlugin(const std::wstring& path,
                  std::vector<std::wstring> allowedRoots,
                  const SignaturePolicy& signature) {
    LoadPolicy policy;
    policy.allowedRoots = std::move(allowedRoots);
    policy.signature = signature;
    return LoadTrustedDll(path, policy);
}

}  // namespace dllguard
