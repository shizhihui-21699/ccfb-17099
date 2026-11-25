# DllGuard — Windows DLL 劫持检测与安全加载加固

DllGuard 面向 Windows 客户端研发/安全团队，解决三类问题：

1. **开发阶段扫描所有 PE 文件**：解析 EXE/DLL/OCX/CPL/SYS 的普通导入表、延迟导入表、`DependentLoadFlags` 和 DLL 相关字符串。
2. **扫描 C/C++ 调用点**：识别 `LoadLibrary*`、`LdrLoadDll`、拼接/变量型库名、裸库名和缺少 `LOAD_LIBRARY_SEARCH_*` 的调用。
3. **提供统一安全加载封装**：尽早移除当前目录搜索、固定 System32、规范化路径、限制插件根目录、检查目录 ACL、验证 Authenticode，并提供运行时已加载模块审计。

> 适用场景包括：安装包/文档与恶意同名库位于 Downloads 等用户可写目录、绿色版/自解压目录权限过宽、第三方闭源组件内部调用 `LoadLibrary`、库名由前缀/插件 ID 拼接，以及插件系统必须从程序目录加载 DLL。

---

## 1. 先厘清搜索顺序与真正风险

开启 `SafeDllSearchMode` 后，常见桌面程序的裸 DLL 搜索顺序大体是：

1. 内存中**已经按同名加载**的 DLL；
2. KnownDLLs / API Set；
3. 应用程序目录（通常是 EXE 所在目录）；
4. System32；
5. 16 位 System 目录；
6. Windows 目录；
7. 当前工作目录；
8. `PATH` 中的目录。

这并不意味着只有“当前目录”危险。报告中描述的“下载目录 + 安装包/文档 + 恶意 DLL”场景里，用户运行的 EXE 很可能就在 Downloads/解压目录中，因此 **EXE 目录本身就是用户可写目录，并且排在 System32 前面**。旧程序、`SetDllDirectory`、`LOAD_WITH_ALTERED_SEARCH_PATH`、不安全的 `PATH` 或关闭 SafeSearch 还会进一步改变顺序。

因此核心原则是：

- 静态导入：用 `/DEPENDENTLOADFLAG:0x800` 在加载器解析导入表前固定策略；
- 后续动态加载：进程启动第一时间调用 `SetDefaultDllDirectories` 和 `SetDllDirectory(L"")`；
- 自己的代码：只通过 DllGuard 封装加载；
- 闭源组件：进程级策略 + PE/字符串扫描 + ProcMon/运行时模块审计 + 签名/ACL 补偿控制；
- 插件：允许从程序目录加载，但必须满足“固定根目录 + 规范化前缀 + 管理员可写 ACL 或签名/发布者/指纹允许列表”。

---

## 2. 目录结构

```text
CMakeLists.txt
CMakePresets.json
include/dllguard/SafeLoad.h       # Windows 安全加载 API
include/dllguard/ModuleAudit.h    # 运行时已加载模块审计
src/scanner/                      # 可移植 PE + 源码扫描器 dllscan
src/runtime/SafeLoad.cpp          # Windows 安全加载实现
src/runtime/ModuleAudit.cpp       # 当前进程模块审计
examples/vulnerable_app.cpp       # 典型风险写法，供扫描器验证
examples/hardened_app.cpp         # DllGuard 替换示例
tools/Export-KnownDlls.ps1        # 导出目标机器精确 KnownDLL 列表
```

扫描器核心只使用 C++17 标准库，可以在 macOS/Linux/Windows 上构建；安全加载运行时使用 Win32 API，只能在 Windows 上编译和使用。

---

## 3. 构建扫描器

### 3.1 macOS/Linux 开发机

```bash
cmake -S . -B build-host -DDLLGUARD_BUILD_RUNTIME=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-host -j
ctest --test-dir build-host --output-on-failure

./build-host/dllscan ./dist \
  --source ./src \
  --system-dll-dir /path/to/windows-system32-baseline \
  --known-dlls ./known_dlls.txt \
  --format text
```

### 3.2 Windows

推荐使用 “x64 Native Tools Command Prompt for VS 2022” 或 CMakePresets：

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release

# 导出目标 Windows 版本的精确 KnownDLL 基线
powershell -ExecutionPolicy Bypass -File .\tools\Export-KnownDlls.ps1 `
  -OutFile .\known_dlls.txt

.\build-windows\Release\dllscan.exe C:\build\YourProduct `
  --source C:\src\YourProduct `
  --system-dll-dir C:\Windows\System32 `
  --known-dlls .\known_dlls.txt `
  --format sarif `
  --out .\dllscan.sarif `
  --fail-on medium
```

退出码：

- `0`：没有达到阈值的问题；
- `1`：参数/IO/报告错误；
- `2`：发现达到 `--fail-on` 阈值的问题，可直接让 CI 失败。

对于已经人工评审的封装内部调用，可在调用行或上一行添加 `// dllscan-ignore`（或 `// dllguard-ignore`）；扫描器仍会在 JSON 中记录该调用及其 `suppressed: true` 状态，但不再产生问题。

---

## 4. 扫描报告怎么用

### 4.1 常用规则

| 规则 | 含义 | 处置 |
|---|---|---|
| `PE-DEPENDENTLOADFLAG-MISSING` | EXE 未设置 `LOAD_LIBRARY_SEARCH_SYSTEM32` 依赖加载标志 | 添加 `/DEPENDENTLOADFLAG:0x800` |
| `PE-IMPORT-SYSTEM-NAME` | 导入了常见系统库同名 DLL，但不是 API Set/已知 KnownDLL | 从 System32 预加载并固定搜索策略 |
| `PE-IMPORT-BUNDLED-DLL` | 二进制同目录存在同名 DLL | 检查目录 ACL、签名和完整性 |
| `PE-IMPORT-UNKNOWN` | 未知普通导入/延迟导入 | 确认组件来源、部署路径和签名 |
| `PE-RUNTIME-LOAD-API` | 导入 `LoadLibrary*`/`LdrLoadDll` | 审计全部调用点 |
| `PE-STRING-DLL-NAME` | 二进制中存在裸 `.dll` 字符串 | 用 ProcMon/反汇编确认是否到达加载 API |
| `PE-STRING-COMPOSED-DLL-NAME` | 存在 `%s_*.dll` 等格式化库名 | 必须人工/动态分析，改允许列表和固定根 |
| `SRC-LOAD-BARE-NAME` | 源码用裸库名调用 `LoadLibrary*` | 替换为 `LoadSystemDll` 或受信插件加载 |
| `SRC-LOAD-RELATIVE-PATH` | 使用相对路径 | 基于固定受信根生成绝对路径并校验 |
| `SRC-LOAD-COMPOSED-NAME` | 库名由变量/拼接/格式化产生 | 逻辑 ID 映射到允许列表，禁止输入直接参与文件名 |
| `SRC-LOAD-ABSOLUTE` | 字面绝对路径，但缺少搜索标志 | 仍需校验根/签名和依赖 DLL 搜索位置 |
| `SRC-UNSAFE-DLL-DIRECTORY` | 调用非空 `SetDllDirectory` 增加/改变搜索目录 | 改用 `SetDefaultDllDirectories` + 受信 `AddDllDirectory` 根 |
| `SRC-SEARCH-PATH-CWD-REMOVED` | `SetDllDirectory(L"")` 已移除当前目录 | 可保留，建议统一到 DllGuard 初始化 |

JSON 报告保留每个 PE 的导入表、延迟导入、函数名、`DependentLoadFlags` 和字符串，可供资产系统或后续策略生成器消费；SARIF 可上传到 GitHub Code Scanning/Azure DevOps 等。

### 4.2 CI 示例

```bash
dllscan ./installer-root \
  --source ./src \
  --known-dlls ./ci/known_dlls-windows11-23h2.txt \
  --format sarif \
  --out dllscan.sarif \
  --fail-on high
```

建议把阈值设为：

- PR 阶段：`--fail-on critical`，评论中展示新增 High；
- 发布分支：`--fail-on high`；
- 加固成熟期：`--fail-on medium`，并为已接受风险维护例外清单。

---

## 5. 替换原有调用

### 5.1 链接和初始化

将本仓库作为子目录/第三方源码引入后，链接 `DllGuard::dllguard` 会传播 `/DEPENDENTLOADFLAG:0x800`：

```cmake
add_subdirectory(third_party/DllGuard)
target_link_libraries(your_app PRIVATE DllGuard::dllguard)
```

在 `wWinMain`/`wmain` 第一行业务代码处初始化：

```cpp
#include <dllguard/SafeLoad.h>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    dllguard::InitConfig config;
    config.strictSystem32Default = false;
    config.trustedDllDirectories = {
        L"C:\\Program Files\\Contoso\\App\\plugins"
    };

    if (auto rc = dllguard::Initialize(config); !rc) {
        // 记录安全事件并 fail closed。
        return rc.win32Error;
    }

    // ...
}
```

`Initialize` 会：

- 调用 `SetDllDirectoryW(L"")` 移除当前目录；
- 启用永久 SafeSearch 模式；
- 动态调用 `SetDefaultDllDirectories`，兼容没有 KB2533623 的旧系统；
- 通过 `AddDllDirectory` 注册受信依赖目录；
- 从真实 System32 预加载 `version.dll`、`winmm.dll`、`dbghelp.dll` 等常见劫持目标。

### 5.2 系统库

替换：

```cpp
LoadLibraryW(L"version.dll");
LoadLibraryExW(L"dbghelp.dll", nullptr, 0);
```

为：

```cpp
auto version = dllguard::LoadSystemDll(L"version.dll");
if (!version) {
    // 不要继续运行依赖该库的功能；上报安全事件。
}
```

`LoadSystemDll` 会拒绝路径分隔符和 `..`，解析 `%SystemRoot%\System32` 的最终路径，阻止符号链接逃逸，检查同名模块是否已从错误路径加载，并使用 `LOAD_LIBRARY_SEARCH_SYSTEM32` 加载。API Set 名称（`api-ms-*`、`ext-ms-*`）走专门分支。

### 5.3 插件和业务 DLL

不要这样做：

```cpp
std::wstring file = prefix + pluginId + L".dll";
LoadLibraryW(file.c_str());
```

应把 `pluginId` 当作不可信输入，先映射到内部允许列表，再基于固定根构造路径：

```cpp
dllguard::LoadPolicy policy;
policy.allowedRoots = {
    L"C:\\Program Files\\Contoso\\App\\plugins"
};
policy.checkRootAcl = true;                 // Program Files 场景
policy.signature.requireValidSignature = true;
policy.signature.publisherContains = L"Contoso";
policy.signature.allowedThumbprints = {
    "ab:cd:..."                            // 可选：固定签名证书
};

auto plugin = dllguard::LoadPlugin(
    L"C:\\Program Files\\Contoso\\App\\plugins\\report.dll",
    policy.allowedRoots,
    policy.signature);

if (!plugin) {
    // 拒绝加载并上报：plugin.win32Error / plugin.message
}
```

加载前会执行：

1. 环境变量展开和 `GetFullPathName`；
2. `CreateFile` + `GetFinalPathNameByHandle` 解析最终路径，防止 `..`/junction/symlink 逃逸；
3. 必须位于某个 `allowedRoots` 下；
4. 检查根目录 DACL 是否给 Everyone/Users/Authenticated Users/Creator Owner 授予写权限；
5. WinVerifyTrust 验证签名/目录签名，可选发布者和 SHA-1 指纹；
6. 检查同名模块是否已从错误路径映射；
7. 使用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS` 等显式标志加载。

如果插件必须安装在 `%LOCALAPPDATA%` 等用户可写目录，ACL 检查必然不适合作为唯一控制。此时设置 `checkRootAcl = false`，但必须强制签名验证，并建议固定证书指纹、启动时校验文件哈希、由每用户服务提升后安装，或迁移到 Program Files/系统服务目录。

---

## 6. 闭源第三方组件怎么办

闭源组件无法直接替换内部的 `LoadLibrary` 调用，建议按以下顺序处理。

### 6.1 先用扫描器建立事实

```powershell
dllscan.exe C:\Program Files\Contoso `
  --known-dlls .\known_dlls.txt `
  --system-dll-dir C:\Windows\System32 `
  --format json --out third-party.json
```

重点看：

- 导入了哪些非 KnownDLL 同名系统库；
- 是否导入 `LoadLibraryExW`/`LdrLoadDll`；
- 二进制中是否有 `%s.dll`、`*.dll`、插件名模板；
- 同目录是否附带 DLL；
- 组件 DLL 自己是否缺少 `/DEPENDENTLOADFLAG`。

### 6.2 进程级策略保护后续加载

即使不能重编译第三方 DLL，主程序尽早调用 `dllguard::Initialize()` 后，`SetDefaultDllDirectories` 会影响进程后续加载策略，并移除当前目录。对于主程序 `LoadLibrary(fullThirdPartyDll)` 触发的依赖解析，应使用带 `LOAD_LIBRARY_SEARCH_*` 标志的 DllGuard 封装加载该第三方 DLL，而不是裸 `LoadLibrary`。

主 EXE 的 `/DEPENDENTLOADFLAG:0x800` 只能直接保护该镜像的依赖加载策略；如果第三方 DLL 有自己的静态依赖且加载方式不安全，仍需通过显式安全标志加载它、应用程序清单、供应商修复或隔离进程解决。

### 6.3 动态验证实际加载路径

在 QA 机运行：

```cpp
#include <dllguard/ModuleAudit.h>

auto issues = dllguard::AuditLoadedModules(/*verifySignatures=*/true);
for (const auto& issue : issues) {
    // 写日志/上报
}
```

它会枚举当前进程模块，发现从 Temp、Downloads、当前目录、DACL 可写目录或预期根之外加载的模块，并可验证签名。

同时使用 Process Monitor：

1. 过滤 `Process Name = yourapp.exe`；
2. 过滤 `Operation is CreateFile` 且 `Path ends with .dll`，或使用 `Load Image` 事件；
3. 搜索 `NAME NOT FOUND`、路径包含 `Downloads`、`Temp`、`Users\\...\\AppData` 或异常当前目录的事件；
4. 覆盖首次启动、打开文档、登录、自动更新、插件扫描、导出报告等全部功能路径；
5. 对所有 `NAME NOT FOUND` 的系统同名库建立预加载/白名单。

### 6.4 部署和缓解措施

- 安装到 `C:\Program Files\...`，不要安装到 Downloads、桌面或可写的 `C:\Contoso`；
- MSI/安装器显式设置程序目录和 DLL ACL，禁止普通用户写/删除；
- 开启并检查 `/DEPENDENTLOADFLAG:0x800`、`/GUARD:CF`、ASLR、DEP；
- 对必须随程序发布的 DLL 做 Authenticode 签名或目录签名；
- 用应用程序清单启用合适的公共控件/并行程序集策略，避免不必要的 SxS 探测；
- 定期从干净 Windows 导出 KnownDLL 列表，因为不同 Windows 版本不同；
- 对高风险闭源插件考虑独立低权限进程，通过 IPC 通信，降低加载到主客户端后的影响。

---

## 7. 插件机制的安全设计

插件“必须从程序目录加载”和“防劫持”并不冲突，但不能允许任意文件名拼接：

1. **逻辑 ID 到文件名映射**：服务端/本地清单只发布 ID、版本、SHA-256、签名者；
2. **固定插件根**：例如 `%ProgramFiles%\Contoso\App\plugins`；
3. **禁止 `..` 和绝对路径输入**：最终路径必须通过前缀和 final path 检查；
4. **目录 ACL**：普通用户只读，仅 Administrators/SYSTEM/TrustedInstaller 可写；
5. **签名/哈希双因子**：加载前验证 Authenticode，发布者 CN 和证书指纹；同时比对更新清单中的 SHA-256；
6. **显式依赖目录**：插件自带依赖放在自己的版本化子目录，使用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`，或通过 `AddDllDirectory` 注册；
7. **加载后审计**：记录 `GetModuleFileName` 的最终路径和签名信息；
8. **失败关闭**：签名/根/ACL 不一致时不加载，并触发安全告警。

---

## 8. 当前限制

- PE 扫描器不执行反编译/数据流分析；“字符串是否最终到达 `LoadLibrary`”需要结合导入 API、源码和动态分析确认。
- 源码扫描是轻量词法分析，不是 Clang AST；复杂宏、模板和跨编译单元拼接可能漏报或需要配置 `--load-api`。
- 不能仅靠扫描器证明闭源组件在所有运行路径下安全；Process Monitor/ETW/运行时审计不可替代。
- `SetDefaultDllDirectories` 对调用前已经解析的静态导入无效，因此必须配合 `/DEPENDENTLOADFLAG:0x800`。
- ACL 检查覆盖常见宽泛 SID，不能替代完整 Windows 授权建模。
- 运行时库尚未在真实 MSVC 环境执行 CI 编译；接入 Windows 工程后应先运行示例和单元验证。

---

## 9. 后续建议路线

- 接入 Clang LibTooling，获得宏展开和跨函数数据流能力；
- 生成精确的 DLL 允许列表/YAML 例外基线；
- 增加 ETW `Microsoft-Windows-Kernel-Process` 消费器，做无注入的全进程加载审计；
- 为闭源组件生成 IAT/延迟加载加固垫片或启动器；
- 在安装包构建后自动扫描 MSI 展开目录和签名/ACL；
- 增加 CodeQL/SARIF 规则映射和 PR 评论。
