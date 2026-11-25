// Deliberately vulnerable examples for scanner validation.
// Do not ship this code.

#include <windows.h>
#include <iostream>
#include <string>

using LoadLibraryW_t = HMODULE(WINAPI*)(PCWSTR);

int wmain(int argc, wchar_t** argv) {
    // Bare system-DLL name: search order / preloaded-name abuse.
    HMODULE version = LoadLibraryW(L"version.dll");

    // No SEARCH_* flags.
    HMODULE dbg = LoadLibraryExW(L"dbghelp.dll", nullptr, 0);

    // Composed at runtime: source scanning can flag it but cannot know the name.
    std::wstring pluginName = argc > 1 ? argv[1] : L"report";
    std::wstring composed = L"vendor_" + pluginName + L".dll";
    HMODULE plugin = LoadLibraryW(composed.c_str());

    // Relative path is interpreted against unsafe process state.
    HMODULE relative = LoadLibraryW(L"plugins\\extension.dll");

    // Obsolete/unsafe search directory configuration.
    SetDllDirectoryW(L"plugins");

    std::wcout << L"loaded: " << version << L' ' << dbg << L' ' << plugin << L' '
               << relative << L'\n';

    if (version) FreeLibrary(version);
    if (dbg) FreeLibrary(dbg);
    if (plugin) FreeLibrary(plugin);
    if (relative) FreeLibrary(relative);
    return 0;
}
