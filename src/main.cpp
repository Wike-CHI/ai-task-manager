// AI 任务管理器 —— Win32 + C++17，无第三方依赖
// 采集：ToolHelp32 + PSAPI + GlobalMemoryStatusEx + nvidia-smi
// 分析：本地推理引擎（规则 + 排序），输出结论、依据、可执行建议
// 历史：每 2 秒一个采样点，保留 3 分钟，画成内存/提交/显存三条曲线
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <objidl.h>      // WIN32_LEAN_AND_MEAN 把 IUnknown 剪掉了，GDI+ 需要它
#include <gdiplus.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")

static const wchar_t* APP_TITLE = L"AI 任务管理器";

#define ID_LIST        1001
#define ID_CHAT        1002
#define ID_INPUT       1003
#define ID_BTN_WHY     1004
#define ID_BTN_MEM     1005
#define ID_BTN_KILL    1006
#define ID_BTN_CLEAN   1007
#define ID_BTN_REFRESH 1008
#define ID_STATUS      1009
#define ID_BTN_COPY    1010
#define ID_BTN_ASK     1011
#define ID_BTN_THEME   1012

#define WM_APP_SNAPSHOT (WM_APP + 1)

#define IDM_TRAY_SHOW    2001
#define IDM_TRAY_REFRESH 2002
#define IDM_TRAY_EXIT    2003
#define IDM_TRAY_BALL    2101
#define IDM_TRAY_CLEAN   2102
#define IDM_TRAY_AUTO    2103
#define IDM_TRAY_THERM   2104
// 布局一律按 96dpi 的逻辑像素写，S() 换算到当前缩放，避免高 DPI 下被系统拉伸发糊
static int g_dpi = 96;
static bool g_dpiForced = false;        // 用 AITM_SCALE 强制缩放，方便验证高 DPI 布局
static inline int S(int v) { return MulDiv(v, g_dpi, 96); }

static bool InitDpiFromEnvironment() {
    wchar_t buf[16]{};
    if (GetEnvironmentVariableW(L"AITM_SCALE", buf, 16) > 0) {
        double f = _wtof(buf);
        if (f >= 0.75 && f <= 3.0) { g_dpi = (int)(96 * f + 0.5); return true; }
    }
    return false;
}

#define HEADER_H   S(324)
#define HIST_MAX   90
#define TIMER_ID   1

static COLORREF C_BG           = RGB(24, 25, 31);
static COLORREF C_PANEL        = RGB(38, 40, 50);
static COLORREF C_TEXT         = RGB(230, 230, 235);
static COLORREF C_MUTED        = RGB(139, 143, 154);
static COLORREF C_DIM          = RGB(85, 86, 95);
static COLORREF C_GRID         = RGB(48, 50, 62);
static COLORREF C_GREEN        = RGB(90, 218, 143);
static COLORREF C_AMBER        = RGB(224, 161, 58);
static COLORREF C_RED          = RGB(224, 85, 85);
static COLORREF C_BLUE         = RGB(77, 157, 224);

enum Risk { RISK_PROTECTED, RISK_MODEL, RISK_SAFE, RISK_CAREFUL, RISK_NORMAL };

struct ProcRow {
    std::wstring name;
    int    count = 0;
    double memMB = 0;
    double cpuPct = 0;
    int    ageMin = 0;
    Risk   risk = RISK_NORMAL;
    std::wstring why;
    std::vector<DWORD> pids;
};

struct Sample { double ram, com, vram, gpu, gpuT, cpuT, fan; };

struct Snapshot {
    double ramUsedGB = 0, ramTotalGB = 0, ramPct = 0;
    double comUsedGB = 0, comTotalGB = 0, comPct = 0;
    double cpuPct = 0;
    int    procCount = 0;
    bool   hasGpu = false;
    double gpuUtil = 0, vramUsed = 0, vramTotal = 0, gpuTemp = 0;
    double modelMemGB = 0;
    bool   modelRunning = false;
    std::vector<ProcRow> rows;
};

static Snapshot g_snap;
static CRITICAL_SECTION g_lock;
static std::atomic<bool> g_busy{false};
static HWND g_list, g_chat, g_input, g_status;
static int  g_hoverRow = -1;

static Sample g_hist[HIST_MAX];
static int g_histCount = 0;
static int g_histHead = 0;
static double g_weightsGB = 0;

static HWND g_ball = nullptr;
static bool g_ballOn = true;
static void BallKick();          // 定义在悬浮球那一段，快照回调要提前用

static void TrayAdd(HWND hwnd);
static void TrayUpdateTip(const std::wstring& tip);
static void TraySetIcon(HWND hwnd);
static void TrayRemove();
static void ShowFromTray(HWND hwnd);
static void HideToTray(HWND hwnd);

static const std::map<std::wstring, std::pair<Risk, const wchar_t*>> RISK_TABLE = {
    { L"system",              { RISK_PROTECTED, L"系统进程" } },
    { L"registry",            { RISK_PROTECTED, L"系统进程" } },
    { L"memory compression",  { RISK_PROTECTED, L"系统进程" } },
    { L"csrss.exe",           { RISK_PROTECTED, L"系统关键进程" } },
    { L"wininit.exe",         { RISK_PROTECTED, L"系统关键进程" } },
    { L"winlogon.exe",        { RISK_PROTECTED, L"系统关键进程" } },
    { L"services.exe",        { RISK_PROTECTED, L"系统关键进程" } },
    { L"lsass.exe",           { RISK_PROTECTED, L"系统关键进程" } },
    { L"smss.exe",            { RISK_PROTECTED, L"系统关键进程" } },
    { L"dwm.exe",             { RISK_PROTECTED, L"桌面合成器" } },
    { L"explorer.exe",        { RISK_PROTECTED, L"桌面外壳" } },
    { L"svchost.exe",         { RISK_PROTECTED, L"系统服务宿主" } },
    { L"msmpeng.exe",         { RISK_PROTECTED, L"Defender 引擎" } },
    { L"pythonw.exe",         { RISK_PROTECTED, L"本程序" } },
    { L"llama-server.exe",    { RISK_MODEL,     L"翻译模型，占显存不占内存" } },
    { L"chatgpt.exe",         { RISK_SAFE,      L"对话在云端，重开无损" } },
    { L"qoderwake-cn.exe",    { RISK_SAFE,      L"后台守护，用到时自恢复" } },
    { L"feishu.exe",          { RISK_SAFE,      L"消息会同步，重开不丢" } },
    { L"wxwork.exe",          { RISK_SAFE,      L"消息会同步，重开不丢" } },
    { L"wechatappex.exe",     { RISK_SAFE,      L"小程序容器，可重开" } },
    { L"msedgewebview2.exe",  { RISK_SAFE,      L"内嵌浏览器，随宿主退出" } },
    { L"codex.exe",           { RISK_SAFE,      L"命令行 agent 宿主" } },
    { L"code.exe",            { RISK_CAREFUL,   L"VS Code，可能有未保存文件" } },
    { L"qoderclicn-1.1.81.exe", { RISK_CAREFUL, L"Qoder IDE，可能有未保存文件" } },
    { L"cursor.exe",          { RISK_CAREFUL,   L"Cursor，可能有未保存文件" } },
    { L"workbuddy.exe",       { RISK_CAREFUL,   L"WorkBuddy，可能正在跑任务" } },
    { L"chrome.exe",          { RISK_CAREFUL,   L"浏览器标签会丢" } },
    { L"msedge.exe",          { RISK_CAREFUL,   L"浏览器标签会丢" } },
};

static std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static std::wstring Fmt(const wchar_t* f, ...) {
    wchar_t buf[1024]{};
    va_list ap;
    va_start(ap, f);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, f, ap);
    va_end(ap);
    return buf;
}

static void RunHidden(const std::wstring& cmd, std::wstring& out) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    // 每次调用独立文件：GPU 查询和温度脚本是两个线程，共用一个文件会互相删掉输出
    static std::atomic<unsigned> seq{ 0 };
    std::wstring path = std::wstring(tmp) + L"aitm_" +
                        std::to_wstring(GetCurrentProcessId()) + L"_" +
                        std::to_wstring(seq.fetch_add(1)) + L".txt";
    DeleteFileW(path.c_str());

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = h;
    si.hStdError = h;
    PROCESS_INFORMATION pi{};

    std::wstring c = cmd;
    if (CreateProcessW(nullptr, c.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 6000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    CloseHandle(h);

    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    f.close();
    DeleteFileW(path.c_str());

    std::string s = ss.str();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    out.resize(n);
    if (n) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
}

// ------------------------------------------------------------------ 温度采集
struct Temps {
    double gpu = 0, fan = 0;        // 显卡温度、风扇转速(%)
    double cpu = -1, disk = -1;     // ACPI 热区、磁盘温度；-1 表示读不到
    double gpu1minAgo = -1;
    DWORD  lastSlow = 0;
};

static Temps g_temps;

static void WriteTempScript() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"aitm_temp.ps1";

    // 必须 UTF-8 with BOM：脚本宿主按 ANSI 读无 BOM 的文件，中文/符号会全乱
    const std::wstring script =
        L"$z = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
        L"-ErrorAction SilentlyContinue | Sort-Object CurrentTemperature -Descending | Select-Object -First 1\r\n"
        L"$d = Get-PhysicalDisk | ForEach-Object { ($_ | Get-StorageReliabilityCounter "
        L"-ErrorAction SilentlyContinue).Temperature } | Where-Object { $_ -gt 0 } | "
        L"Select-Object -First 1\r\n"
        L"$cpu = if ($z) { [math]::Round($z.CurrentTemperature/10 - 273.15, 1) } else { -1 }\r\n"
        L"$disk = if ($d) { $d } else { -1 }\r\n"
        L"Write-Output (\"{0};{1}\" -f $cpu, $disk)\r\n";

    int n = WideCharToMultiByte(CP_UTF8, 0, script.c_str(), (int)script.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string utf8(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, script.c_str(), (int)script.size(),
                        utf8.data(), n, nullptr, nullptr);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
    WriteFile(h, bom, 3, &written, nullptr);
    WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
    CloseHandle(h);
}

static void SampleSlowTemps() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"aitm_temp.ps1";
    std::wstring cmd = L"powershell -NoProfile -ExecutionPolicy Bypass -File \"" + path + L"\"";
    std::wstring out;
    RunHidden(cmd, out);

    double cpu = -1, disk = -1;
    if (swscanf_s(out.c_str(), L"%lf;%lf", &cpu, &disk) >= 1) {
        if (cpu > 0 && cpu < 120) g_temps.cpu = cpu;
        if (disk > 0 && disk < 120) g_temps.disk = disk;
    }
    g_temps.lastSlow = GetTickCount();
}

static void ReadGpu(Snapshot& s) {
    std::wstring out;
    RunHidden(L"cmd /c \"\"C:\\Windows\\System32\\nvidia-smi.exe\" --query-gpu=utilization.gpu,"
              L"memory.used,memory.total,temperature.gpu,fan.speed --format=csv,noheader,nounits\"", out);
    if (out.empty()) { s.hasGpu = false; return; }
    double a = 0, b = 0, c = 0, d = 0, fan = 0;
    int n = swscanf_s(out.c_str(), L"%lf , %lf , %lf , %lf , %lf", &a, &b, &c, &d, &fan);
    if (n >= 3) {
        s.hasGpu = true;
        s.gpuUtil = a;
        s.vramUsed = b / 1024.0;
        s.vramTotal = c / 1024.0;
        s.gpuTemp = d;
        g_temps.gpu = d;
        if (n >= 5) g_temps.fan = fan;
    }
}

static double WeightsGB() {
    static double cached = -1;
    if (cached >= 0) return cached;
    cached = 0;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(L"D:\\AI\\hy-mt2-test\\models\\*.gguf", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            cached += ((double)fd.nFileSizeHigh * 4294967296.0 + fd.nFileSizeLow) / 1073741824.0;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return cached;
}

static ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

struct CpuSample { ULONGLONG kernel, user; };

static void Collect(Snapshot& s) {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    s.ramTotalGB = ms.ullTotalPhys / 1073741824.0;
    s.ramUsedGB = (ms.ullTotalPhys - ms.ullAvailPhys) / 1073741824.0;
    s.ramPct = (double)ms.dwMemoryLoad;
    s.comTotalGB = ms.ullTotalPageFile / 1073741824.0;
    s.comUsedGB = (ms.ullTotalPageFile - ms.ullAvailPageFile) / 1073741824.0;
    s.comPct = s.comTotalGB > 0 ? s.comUsedGB / s.comTotalGB * 100.0 : 0;

    static ULONGLONG prevIdle = 0, prevKernel = 0, prevUser = 0;
    FILETIME idle{}, kern{}, user{};
    if (GetSystemTimes(&idle, &kern, &user)) {
        ULONGLONG i = FileTimeToU64(idle), k = FileTimeToU64(kern), u = FileTimeToU64(user);
        if (prevKernel) {
            ULONGLONG di = i - prevIdle, dk = k - prevKernel, du = u - prevUser;
            ULONGLONG total = dk + du;
            if (total > 0) s.cpuPct = (1.0 - (double)di / total) * 100.0;
        }
        prevIdle = i; prevKernel = k; prevUser = u;
    }

    ReadGpu(s);

    static std::atomic<bool> slowBusy{false};
    if (!slowBusy && GetTickCount() - g_temps.lastSlow > 30000) {
        slowBusy = true;
        std::thread([]() { SampleSlowTemps(); slowBusy = false; }).detach();
    }

    s.modelRunning = false;
    s.modelMemGB = 0;

    static std::map<DWORD, CpuSample> prevCpu;
    std::map<DWORD, CpuSample> curCpu;
    std::map<std::wstring, ProcRow> groups;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        int count = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                count++;
                std::wstring name = pe.szExeFile;
                std::wstring key = Lower(name);
                DWORD pid = pe.th32ProcessID;

                auto& row = groups[key];
                row.name = name;
                row.count++;
                row.pids.push_back(pid);

                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (!h) continue;

                PROCESS_MEMORY_COUNTERS_EX pmc{};
                if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    double mb = pmc.WorkingSetSize / 1048576.0;
                    row.memMB += mb;
                    if (key == L"llama-server.exe") {
                        s.modelRunning = true;
                        s.modelMemGB += mb / 1024.0;
                    }
                }

                FILETIME ct{}, et{}, kt{}, ut{};
                if (GetProcessTimes(h, &ct, &et, &kt, &ut)) {
                    CpuSample now{ FileTimeToU64(kt), FileTimeToU64(ut) };
                    curCpu[pid] = now;
                    auto it = prevCpu.find(pid);
                    if (it != prevCpu.end()) {
                        double ds = (double)((now.kernel - it->second.kernel) +
                                             (now.user - it->second.user)) / 10000000.0;
                        if (ds > 0 && ds < 120) row.cpuPct += ds;
                    }
                }
                CloseHandle(h);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        s.procCount = count;
    }
    prevCpu.swap(curCpu);

    s.rows.clear();
    for (auto& kv : groups) {
        ProcRow r = kv.second;
        auto it = RISK_TABLE.find(kv.first);
        if (it != RISK_TABLE.end()) {
            r.risk = it->second.first;
            r.why = it->second.second;
        }
        s.rows.push_back(r);
    }
    std::sort(s.rows.begin(), s.rows.end(),
              [](const ProcRow& a, const ProcRow& b) { return a.memMB > b.memMB; });
}

static std::wstring RiskTag(Risk r) {
    switch (r) {
    case RISK_PROTECTED: return L"勿动";
    case RISK_MODEL:     return L"模型";
    case RISK_SAFE:      return L"可关";
    case RISK_CAREFUL:   return L"慎关";
    default:             return L"";
    }
}

static std::wstring TrendText() {
    if (g_histCount < 8) return L"（样本还不够，稍等半分钟）";
    auto at = [&](int back) {
        int idx = (g_histHead - 1 - back + HIST_MAX * 2) % HIST_MAX;
        return g_hist[idx];
    };
    double recent = 0, older = 0;
    for (int i = 0; i < 5; ++i) recent += at(i).com;
    for (int i = 5; i < 10; ++i) older += at(i).com;
    recent /= 5; older /= 5;
    double d = recent - older;
    if (d > 1.5) return Fmt(L"提交 30 秒内上升 %.0f%%，还在恶化", d);
    if (d < -1.5) return Fmt(L"提交 30 秒内下降 %.0f%%，在缓解", -d);
    return L"提交最近 30 秒基本持平";
}

static std::wstring TempTrendText() {
    if (g_histCount < 12 || g_temps.gpu <= 0) return L"";
    auto at = [&](int back) {
        int idx = (g_histHead - 1 - back + HIST_MAX * 2) % HIST_MAX;
        return g_hist[idx];
    };
    double now = g_temps.gpu, before = at(10).gpuT;   // 约 20 秒前
    if (before <= 0) return L"";
    double d = now - before;
    if (d >= 2) return Fmt(L"（GPU 20 秒内升 %.0f°C，%.0f→%.0f）", d, before, now);
    if (d <= -2) return Fmt(L"（GPU 20 秒内降 %.0f°C，%.0f→%.0f）", -d, before, now);
    return L"（GPU 温度平稳）";
}

static std::wstring AnalyzeWhy(const Snapshot& s) {
    std::wstring out;
    bool ramHigh = s.ramPct >= 88;
    bool comHigh = s.comPct >= 85;
    bool vramHigh = s.hasGpu && s.vramTotal > 0 && s.vramUsed / s.vramTotal > 0.92;

    if (comHigh || ramHigh) {
        out += L"结论：内存压力大，整机在被页面文件拖慢。\r\n\r\n";
        out += Fmt(L"· 物理内存 %.1f / %.1f GB（%.0f%%）\r\n", s.ramUsedGB, s.ramTotalGB, s.ramPct);
        out += Fmt(L"· 提交内存 %.1f / %.1f GB（%.0f%%）\r\n", s.comUsedGB, s.comTotalGB, s.comPct);
        out += L"· 提交逼近上限会疯狂换页，表现为打字卡、翻译从 1 秒变几十秒；";
        out += TrendText() + L"\r\n";
    } else if (vramHigh) {
        out += L"结论：显存接近打满，模型推理变慢，但打字不会卡。\r\n\r\n";
        out += Fmt(L"· 显存 %.1f / %.1f GB（%.0f%%）\r\n",
                   s.vramUsed, s.vramTotal, s.vramUsed / s.vramTotal * 100);
    } else {
        out += L"结论：资源正常，没看到明显瓶颈。\r\n\r\n";
        out += Fmt(L"· 内存 %.1f / %.1f GB（%.0f%%），提交 %.1f / %.1f GB（%.0f%%）\r\n",
                   s.ramUsedGB, s.ramTotalGB, s.ramPct, s.comUsedGB, s.comTotalGB, s.comPct);
    }

    if (s.hasGpu)
        out += Fmt(L"· GPU %.0f%%，显存 %.1f / %.1f GB，CPU %.0f%%\r\n",
                   s.gpuUtil, s.vramUsed, s.vramTotal, s.cpuPct);
    else
        out += Fmt(L"· CPU %.0f%%（没有检测到 N 卡）\r\n", s.cpuPct);

    if (g_temps.gpu > 0) {
        out += Fmt(L"· 温度：GPU %.0f°C（风扇 %.0f%%）", g_temps.gpu, g_temps.fan);
        if (g_temps.disk > 0) out += Fmt(L"，磁盘 %.0f°C", g_temps.disk);
        if (g_temps.cpu > 0) out += Fmt(L"，ACPI %.0f°C", g_temps.cpu);
        out += TempTrendText();
        out += L"\r\n";

        if (g_temps.gpu >= 83 && g_temps.fan >= 85)
            out += L"  ⚠ 显卡高温 + 高转速同时出现，散热可能受阻（积灰 / 风道 / 环境温度）\r\n";
        else if (g_temps.gpu >= 83)
            out += L"  ⚠ 显卡温度偏高而风扇未拉满，可检查风扇曲线\r\n";
        else if (g_temps.fan >= 90 && g_temps.gpu < 60)
            out += L"  散热余量充足（风扇高转速但温度低）\r\n";
    }

    out += L"\r\n内存前 5：\r\n";
    int n = 0;
    for (auto& r : s.rows) {
        if (n++ >= 5) break;
        std::wstring tag = RiskTag(r.risk);
        out += Fmt(L"· %s —— %.1f GB（%d 个进程）%s\r\n", r.name.c_str(), r.memMB / 1024.0, r.count,
                   tag.empty() ? L"" : (L"[" + tag + L"]").c_str());
    }

    out += L"\r\n建议（按释放量）：\r\n";
    int idx = 1;
    double gain = 0;
    for (auto& r : s.rows) {
        if (r.risk != RISK_SAFE || r.memMB < 80) continue;
        if (idx > 4) break;
        out += Fmt(L"%d. 关掉 %s —— 释放 %.1f GB（%s）\r\n",
                   idx++, r.name.c_str(), r.memMB / 1024.0, r.why.c_str());
        gain += r.memMB;
    }
    for (auto& r : s.rows) {
        if (r.risk != RISK_CAREFUL || r.memMB < 300) continue;
        out += Fmt(L"   谨慎：%s —— %.1f GB（%s）\r\n", r.name.c_str(), r.memMB / 1024.0, r.why.c_str());
        break;
    }
    if (gain > 200)
        out += Fmt(L"\r\n全关掉预计释放 %.1f GB，提交降到约 %.0f GB。\r\n",
                   gain / 1024.0, s.comUsedGB - gain / 1024.0);

    if (s.modelRunning)
        out += Fmt(L"\r\n模型在跑：显存 %.1f GB · 内存 %.2f GB · 权重 %.1f GB，别按内存大小误杀。\r\n",
                   s.vramUsed, s.modelMemGB, g_weightsGB);
    return out;
}

static std::wstring AnswerQuestion(const std::wstring& q, const Snapshot& s) {
    std::wstring low = Lower(q);
    auto has = [&](const wchar_t* k) { return low.find(k) != std::wstring::npos; };

    if (has(L"模型")) {
        if (!s.modelRunning) return L"翻译模型当前没在跑（找不到 llama-server 进程）。";
        return Fmt(L"模型占用：\r\n\r\n· 显存 %.1f / %.1f GB（含 KV 缓存）\r\n"
                   L"· 进程内存 %.2f GB\r\n· 权重文件 %.1f GB（磁盘）\r\n\r\n"
                   L"它吃的是显存，内存占比不高——按内存排序会排第一，别误杀。",
                   s.vramUsed, s.vramTotal, s.modelMemGB, g_weightsGB);
    }
    if (has(L"显存") || has(L"gpu") || has(L"显卡")) {
        if (!s.hasGpu) return L"没有检测到 NVIDIA 显卡（nvidia-smi 不可用）。";
        return Fmt(L"GPU 利用率 %.0f%%，显存 %.1f / %.1f GB（%.0f%%），温度 %.0f°C。\r\n\r\n"
                   L"显存大头是翻译模型。超过 92%% 时推理会变慢，但不会影响打字——打字卡是内存换页。",
                   s.gpuUtil, s.vramUsed, s.vramTotal,
                   s.vramTotal > 0 ? s.vramUsed / s.vramTotal * 100 : 0, s.gpuTemp);
    }
    if (has(L"关") || has(L"清理") || has(L"释放") || has(L"杀")) {
        std::wstring out = L"按「关掉基本无损」排序：\r\n\r\n";
        double gain = 0;
        int i = 1;
        for (auto& r : s.rows) {
            if (r.risk != RISK_SAFE) continue;
            out += Fmt(L"%d. %s —— %.1f GB，%d 个进程\r\n   %s\r\n",
                       i++, r.name.c_str(), r.memMB / 1024.0, r.count, r.why.c_str());
            gain += r.memMB;
        }
        if (i == 1) out += L"• 目前没有标记为「可关」的进程。\r\n";
        out += Fmt(L"\r\n合计可释放 %.1f GB。点「执行建议」可以直接关（会二次确认）。", gain / 1024.0);
        return out;
    }
    if (has(L"风扇") || has(L"散热") || has(L"温度")) {
        std::wstring out = L"当前温度：\r\n\r\n";
        if (g_temps.gpu > 0)
            out += Fmt(L"· GPU %.0f°C，风扇 %.0f%%\r\n", g_temps.gpu, g_temps.fan);
        if (g_temps.disk > 0) out += Fmt(L"· NVMe %.0f°C\r\n", g_temps.disk);
        if (g_temps.cpu > 0) out += Fmt(L"· ACPI 热区 %.0f°C（主板/机箱附近，不是核心温度）\r\n", g_temps.cpu);

        out += L"\r\n关于控制风扇：\r\n"
               L"· GPU：Windows 下 nvidia-smi 只能读不能写（本机确认无 --fan-speed），"
               L"要改转速得用 NVIDIA 控制面板或 MSI Afterburner。\r\n"
               L"· 主板/CPU 风扇：没有标准接口，得用厂商工具（华硕 AI Suite、微星 Center、"
               L"联想 Vantage）或进 BIOS 调风扇曲线。\r\n"
               L"· 通用做法要装内核驱动直接读写 Super I/O（如 WinRing0），"
               L"这类驱动会被杀软拦、也有蓝屏风险，本工具不做。\r\n";
        return out;
    }
    if (has(L"内存") || has(L"卡") || has(L"慢") || has(L"为什么")) return AnalyzeWhy(s);
    if (has(L"趋势") || has(L"曲线") || has(L"历史"))
        return Fmt(L"曲线保留最近 %d 个点（约 %d 秒）：绿色=内存，黄色=提交，蓝色=显存。\r\n当前趋势：%s",
                   g_histCount, g_histCount * 2, TrendText().c_str());
    if (has(L"磁盘") || has(L"io"))
        return L"磁盘 IO 没单独采样。判断是否换页看「提交」和曲线：提交逼近上限时系统会把内存页写回磁盘，整机变卡。";
    if (has(L"进程") || has(L"多少"))
        return Fmt(L"当前 %d 个进程，合并同名后 %d 项，内存总量 %.1f GB。",
                   s.procCount, (int)s.rows.size(), s.ramUsedGB);
    return AnalyzeWhy(s);
}

static bool KillPids(const std::vector<DWORD>& pids, std::wstring& err) {
    for (DWORD pid : pids) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) { err += Fmt(L"pid %u 打不开（权限/已退出）\r\n", pid); continue; }
        if (!TerminateProcess(h, 1)) err += Fmt(L"pid %u 结束失败（%u）\r\n", pid, GetLastError());
        CloseHandle(h);
    }
    return err.empty();
}

static void AppendChat(const std::wstring& text) {
    if (!g_chat) return;
    int len = GetWindowTextLengthW(g_chat);
    SendMessageW(g_chat, EM_SETSEL, len, len);
    std::wstring payload = (len ? L"\r\n" : L"") + text;
    SendMessageW(g_chat, EM_REPLACESEL, FALSE, (LPARAM)payload.c_str());
    SendMessageW(g_chat, EM_SCROLLCARET, 0, 0);
}

static void SetCell(HWND lv, int row, int col, const wchar_t* text) {
    LVITEMW it{};
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.iSubItem = col;
    it.pszText = (LPWSTR)text;
    SendMessageW(lv, LVM_SETITEMW, 0, (LPARAM)&it);
}

static void FillList() {
    int top = ListView_GetTopIndex(g_list);
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);

    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);
    wchar_t buf[64];
    for (int i = 0; i < (int)g_snap.rows.size(); ++i) {
        const auto& r = g_snap.rows[i];
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = i;
        it.lParam = i;
        it.pszText = (LPWSTR)r.name.c_str();
        ListView_InsertItem(g_list, &it);

        swprintf_s(buf, L"%d", r.count);      SetCell(g_list, i, 1, buf);
        swprintf_s(buf, L"%.0f", r.memMB);    SetCell(g_list, i, 2, buf);
        swprintf_s(buf, L"%.1f", r.cpuPct);   SetCell(g_list, i, 3, buf);
        SetCell(g_list, i, 4, RiskTag(r.risk).c_str());
    }
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);

    if (top > 0) ListView_EnsureVisible(g_list, top, FALSE);
    if (sel >= 0 && sel < (int)g_snap.rows.size())
        ListView_SetItemState(g_list, sel, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    InvalidateRect(g_list, nullptr, FALSE);
}

static void PushHistory(const Snapshot& s) {
    Sample x{ s.ramPct, s.comPct,
              s.vramTotal > 0 ? s.vramUsed / s.vramTotal * 100.0 : 0.0, s.gpuUtil,
              g_temps.gpu, g_temps.cpu, g_temps.fan };
    g_hist[g_histHead] = x;
    g_histHead = (g_histHead + 1) % HIST_MAX;
    if (g_histCount < HIST_MAX) g_histCount++;
}

// ------------------------------------------------------------------ 主题
struct Theme {
    bool glass = false;
    COLORREF bg1, bg2, panel, text, muted, dim, grid, borderTop, borderBottom;
    COLORREF listBg, listAlt, listSel, listHead, listLine, listHover;
};

static Theme g_theme;

static void ApplyTheme(bool glass) {
    g_theme.glass = glass;
    if (glass) {
        C_BG     = RGB(232, 244, 253);
        C_PANEL  = RGB(247, 251, 254);
        C_TEXT   = RGB(15, 23, 42);
        C_MUTED  = RGB(71, 85, 105);
        C_DIM    = RGB(120, 135, 150);
        C_GRID   = RGB(203, 227, 242);
        C_GREEN  = RGB(5, 150, 105);
        C_AMBER  = RGB(217, 119, 6);
        C_RED    = RGB(220, 38, 38);
        C_BLUE   = RGB(2, 132, 199);
        g_theme.bg1        = RGB(207, 229, 246);
        g_theme.bg2        = RGB(176, 210, 236);
        g_theme.panel      = RGB(255, 255, 255);
        g_theme.borderTop  = RGB(255, 255, 255);
        g_theme.borderBottom = RGB(158, 196, 226);
        g_theme.listBg  = RGB(252, 254, 255);
        g_theme.listAlt = RGB(240, 248, 253);
        g_theme.listSel = RGB(186, 219, 242);
        g_theme.listHead  = RGB(228, 241, 250);
        g_theme.listLine  = RGB(203, 227, 242);
        g_theme.listHover = RGB(228, 243, 252);
    } else {
        C_BG     = RGB(24, 25, 31);
        C_PANEL  = RGB(38, 40, 50);
        C_TEXT   = RGB(230, 230, 235);
        C_MUTED  = RGB(139, 143, 154);
        C_DIM    = RGB(85, 86, 95);
        C_GRID   = RGB(48, 50, 62);
        C_GREEN  = RGB(90, 218, 143);
        C_AMBER  = RGB(224, 161, 58);
        C_RED    = RGB(224, 85, 85);
        C_BLUE   = RGB(77, 157, 224);
        g_theme.bg1        = C_BG;
        g_theme.bg2        = C_BG;
        g_theme.borderTop  = RGB(60, 62, 74);
        g_theme.borderBottom = RGB(15, 16, 20);
        g_theme.listBg  = RGB(30, 31, 38);
        g_theme.listAlt = RGB(35, 37, 45);
        g_theme.listSel = RGB(45, 62, 84);
        g_theme.listHead  = RGB(40, 42, 52);
        g_theme.listLine  = RGB(54, 57, 70);
        g_theme.listHover = RGB(44, 47, 58);
    }
}

// 半透明填充：用 1x1 位图拉伸 + SourceConstantAlpha，GDI 里最省的做法
static void FillAlpha(HDC dc, int x, int y, int w, int h, COLORREF color, BYTE alpha) {
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, 1, 1);
    HGDIOBJ old = SelectObject(mem, bmp);
    HBRUSH br = CreateSolidBrush(color);
    RECT r{ 0, 0, 1, 1 };
    FillRect(mem, &r, br);
    DeleteObject(br);

    BLENDFUNCTION bf{ AC_SRC_OVER, 0, alpha, 0 };
    AlphaBlend(dc, x, y, w, h, mem, 0, 0, 1, 1, bf);

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
}

static void VGradient(HDC dc, int x, int y, int w, int h, COLORREF top, COLORREF bot,
                      BYTE aTop, BYTE aBot) {
    TRIVERTEX v[2];
    v[0].x = x;      v[0].y = y;
    v[0].Red   = (COLOR16)(GetRValue(top) << 8);
    v[0].Green = (COLOR16)(GetGValue(top) << 8);
    v[0].Blue  = (COLOR16)(GetBValue(top) << 8);
    v[0].Alpha = (COLOR16)(aTop << 8);

    v[1].x = x + w;  v[1].y = y + h;
    v[1].Red   = (COLOR16)(GetRValue(bot) << 8);
    v[1].Green = (COLOR16)(GetGValue(bot) << 8);
    v[1].Blue  = (COLOR16)(GetBValue(bot) << 8);
    v[1].Alpha = (COLOR16)(aBot << 8);

    GRADIENT_RECT g{ 0, 1 };
    GradientFill(dc, v, 2, &g, 1, GRADIENT_FILL_RECT_V);
}

// 玻璃面板：圆角 + 半透明本体 + 顶部高光 + 双色 1px 边
static void GlassPanel(HDC dc, int x, int y, int w, int h, int radius = 10) {
    // 投影：让卡片从背景里浮起来
    HRGN sh = CreateRoundRectRgn(x + 1, y + 4, x + w + 2, y + h + 5, radius, radius);
    SelectClipRgn(dc, sh);
    FillAlpha(dc, x, y + 4, w, h, RGB(40, 90, 140), 42);
    SelectClipRgn(dc, nullptr);
    DeleteObject(sh);

    HRGN rgn = CreateRoundRectRgn(x, y, x + w + 1, y + h + 1, radius, radius);
    SelectClipRgn(dc, rgn);

    FillAlpha(dc, x, y, w, h, g_theme.panel, 128);
    VGradient(dc, x, y, w, (int)(h * 0.45), RGB(255, 255, 255), RGB(255, 255, 255), 70, 0);

    SelectClipRgn(dc, nullptr);
    DeleteObject(rgn);

    // 外轮廓：中等蓝，保证浅色背景上也能看出卡片边
    HPEN pEdge = CreatePen(PS_SOLID, 1, RGB(146, 190, 222));
    HPEN pTop  = CreatePen(PS_SOLID, 1, g_theme.borderTop);
    HGDIOBJ oldPen = SelectObject(dc, pEdge);
    HGDIOBJ oldBr = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, x, y, x + w, y + h, radius, radius);

    // 顶部内亮线（1px 白，稍微缩进，模拟玻璃边缘反光）
    SelectObject(dc, pTop);
    MoveToEx(dc, x + radius / 2, y + 1, nullptr);
    LineTo(dc, x + w - radius / 2, y + 1);

    SelectObject(dc, oldBr);
    SelectObject(dc, oldPen);
    DeleteObject(pEdge);
    DeleteObject(pTop);
}

static void GlossBand(HDC dc, int w) {
    VGradient(dc, 0, 0, w, S(46), RGB(255, 255, 255), RGB(255, 255, 255), 138, 0);

    HRGN sheen = CreateEllipticRgn(w / 2 - S(300), -S(46), w / 2 + S(300), S(62));
    SelectClipRgn(dc, sheen);
    FillAlpha(dc, 0, 0, w, S(60), RGB(255, 255, 255), 85);
    SelectClipRgn(dc, nullptr);
    DeleteObject(sheen);

    HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
    HGDIOBJ old = SelectObject(dc, pen);
    MoveToEx(dc, 0, S(46), nullptr);
    LineTo(dc, w, S(46));
    SelectObject(dc, old);
    DeleteObject(pen);
}

static void DrawBar(HDC dc, int x, int y, int w, int h, double pct, COLORREF color) {
    if (g_theme.glass) {
        FillAlpha(dc, x, y, w, h, RGB(2, 132, 199), 28);
        pct = std::max(0.0, std::min(100.0, pct));
        int fillW = (int)(w * pct / 100.0);
        if (fillW > 0) {
            FillAlpha(dc, x, y + 1, fillW, h - 2, color, 235);
            FillAlpha(dc, x, y + 1, fillW, (h - 2) / 2, RGB(255, 255, 255), 70);
        }
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
        HGDIOBJ old = SelectObject(dc, pen);
        HGDIOBJ oldBr = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, x, y, x + w, y + h, h, h);
        SelectObject(dc, oldBr);
        SelectObject(dc, old);
        DeleteObject(pen);
        return;
    }

    HBRUSH back = CreateSolidBrush(C_PANEL);
    RECT r{ x, y, x + w, y + h };
    FillRect(dc, &r, back);
    DeleteObject(back);
    pct = std::max(0.0, std::min(100.0, pct));
    HBRUSH fill = CreateSolidBrush(color);
    RECT f{ x, y + 2, x + (int)(w * pct / 100.0), y + h - 2 };
    if (f.right > f.left) FillRect(dc, &f, fill);
    DeleteObject(fill);
}

static void TextAt(HDC dc, int x, int y, COLORREF color, const std::wstring& text) {
    SetTextColor(dc, color);
    TextOutW(dc, x, y, text.c_str(), (int)text.size());
}

static void PaintStat(HDC dc, int x, int y, const wchar_t* name, const std::wstring& value,
                      double pct, COLORREF color) {
    TextAt(dc, x, y, C_MUTED, name);
    TextAt(dc, x + S(62), y, C_TEXT, value);
    DrawBar(dc, x, y + S(18), S(220), S(10), pct, color);
}

static void PaintChart(HDC dc, int x, int y, int w, int h) {
    if (g_theme.glass) FillAlpha(dc, x, y, w, h, RGB(255, 255, 255), 110);

    SetBkMode(dc, TRANSPARENT);

    if (g_histCount < 2) {
        TextAt(dc, x + 70, y + h / 2 - 8, C_DIM, L"采样中…（每 2 秒一个点，保留 3 分钟）");
        return;
    }

    double vmin = 100, vmax = 0;
    for (int i = 0; i < g_histCount; ++i) {
        int idx = (g_histHead - g_histCount + i + HIST_MAX * 2) % HIST_MAX;
        const Sample& sm = g_hist[idx];
        double vals[3] = { sm.ram, sm.com, sm.vram };
        for (double v : vals) {
            vmin = std::min(vmin, v);
            vmax = std::max(vmax, v);
        }
    }
    double span = vmax - vmin;
    if (span < 12) {
        double mid = (vmax + vmin) / 2;
        vmin = mid - 6;
        vmax = mid + 6;
    }
    vmin = std::max(0.0, vmin - span * 0.15 - 1);
    vmax = std::min(100.0, vmax + span * 0.15 + 1);
    if (vmax - vmin < 1) vmax = vmin + 1;

    const int plotX = x + S(48), plotW = w - S(60), plotH = h - S(10);
    auto toY = [&](double v) {
        v = std::max(vmin, std::min(vmax, v));
        return y + h - S(4) - (int)((v - vmin) / (vmax - vmin) * (plotH - S(8)));
    };

    HPEN grid = CreatePen(PS_DOT, 1, C_GRID);
    HPEN oldPen = (HPEN)SelectObject(dc, grid);
    for (int i = 0; i <= 4; ++i) {
        int gy = y + S(4) + (plotH - S(8)) * i / 4;
        MoveToEx(dc, plotX, gy, nullptr);
        LineTo(dc, plotX + plotW, gy);
        double v = vmax - (vmax - vmin) * i / 4;
        TextAt(dc, x + S(4), gy - S(7), C_DIM, Fmt(L"%.0f%%", v));
    }
    SelectObject(dc, oldPen);
    DeleteObject(grid);

    double step = (double)plotW / (HIST_MAX - 1);

    auto drawLine = [&](COLORREF color, int which, double& lastV) {
        HPEN pen = CreatePen(PS_SOLID, g_theme.glass ? 2 : 2, color);
        HPEN op = (HPEN)SelectObject(dc, pen);
        bool first = true;
        for (int i = 0; i < g_histCount; ++i) {
            int idx = (g_histHead - g_histCount + i + HIST_MAX * 2) % HIST_MAX;
            const Sample& sm = g_hist[idx];
            double v = which == 0 ? sm.ram : (which == 1 ? sm.com : sm.vram);
            int px = plotX + plotW - (int)((g_histCount - 1 - i) * step);
            int py = toY(v);
            if (first) { MoveToEx(dc, px, py, nullptr); first = false; }
            else LineTo(dc, px, py);
            lastV = v;
        }
        SelectObject(dc, op);
        DeleteObject(pen);
    };

    double ramNow = 0, comNow = 0, gpuNow = 0;
    drawLine(C_BLUE, 2, gpuNow);
    drawLine(C_AMBER, 1, comNow);
    drawLine(C_GREEN, 0, ramNow);

    int lx = x + w - S(288);
    TextAt(dc, lx, y + S(2), C_GREEN, Fmt(L"● 内存 %.0f%%", ramNow));
    TextAt(dc, lx + S(94), y + S(2), C_AMBER, Fmt(L"● 提交 %.0f%%", comNow));
    TextAt(dc, lx + S(188), y + S(2), C_BLUE, Fmt(L"● 显存 %.0f%%", gpuNow));
}

// 风扇转速相对温度的滞后（秒）：在 0~30 秒里找相关系数最高的位移
// -1 样本不够；-2 两者无关（温度或转速基本不动）
static double FanLagSeconds() {
    if (g_histCount < 24 || g_temps.gpu <= 0) return -1;
    const int n = std::min(g_histCount, 60);
    auto fAt = [](int back) { return g_hist[(g_histHead - 1 - back + HIST_MAX * 2) % HIST_MAX].fan; };
    auto tAt = [](int back) { return g_hist[(g_histHead - 1 - back + HIST_MAX * 2) % HIST_MAX].gpuT; };

    auto corr = [&](int lag, double& r) {
        int m = n - lag;
        if (m < 15) return false;
        double sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0;
        for (int i = 0; i < m; ++i) {
            double a = tAt(i + lag), b = fAt(i);       // 更早的温度 对 更晚的转速
            sa += a; sb += b; saa += a * a; sbb += b * b; sab += a * b;
        }
        double va = saa - sa * sa / m, vb = sbb - sb * sb / m;
        if (va <= 1e-6 || vb <= 1e-6) return false;
        r = (sab - sa * sb / m) / std::sqrt(va * vb);
        return true;
    };

    double bestR = -2;
    int bestLag = 0;
    for (int lag = 0; lag <= 15; ++lag) {
        double r;
        if (corr(lag, r) && r > bestR) { bestR = r; bestLag = lag; }
    }
    if (bestR < 0.35) return -2;
    return bestLag * 2.0;
}

// 散热曲线：左轴=风扇转速(%)，右轴=GPU 温度(°C)，同一时间轴才看得出谁先动
static void PaintCoolChart(HDC dc, int x, int y, int w, int h) {
    if (g_theme.glass) FillAlpha(dc, x, y, w, h, RGB(255, 255, 255), 110);
    SetBkMode(dc, TRANSPARENT);

    const int leftW = S(42), rightW = S(40);
    const int plotX = x + leftW, plotW = w - leftW - rightW;
    const int plotY = y + S(18), plotH = h - S(18) - S(6);

    if (g_histCount < 2) {
        TextAt(dc, x + S(70), y + h / 2 - S(8), C_DIM, L"采样中…");
        return;
    }
    if (g_temps.gpu <= 0) {
        TextAt(dc, x + S(70), y + h / 2 - S(8), C_DIM, L"没有 GPU 温度，画不了散热曲线");
        return;
    }

    double fmin = 100, fmax = 0, tmin = 200, tmax = 0;
    for (int i = 0; i < g_histCount; ++i) {
        int idx = (g_histHead - g_histCount + i + HIST_MAX * 2) % HIST_MAX;
        const Sample& sm = g_hist[idx];
        if (sm.fan <= 0 && sm.gpuT <= 0) continue;
        fmin = std::min(fmin, sm.fan); fmax = std::max(fmax, sm.fan);
        tmin = std::min(tmin, sm.gpuT); tmax = std::max(tmax, sm.gpuT);
    }
    if (fmax <= 0 && tmax <= 0) {
        TextAt(dc, x + S(70), y + h / 2 - S(8), C_DIM, L"还没有读到转速/温度");
        return;
    }

    auto pad = [](double& lo, double& hi, double minSpan, double absLo, double absHi) {
        if (hi < lo) std::swap(hi, lo);
        if (hi - lo < minSpan) {
            double mid = (hi + lo) / 2;
            lo = mid - minSpan / 2; hi = mid + minSpan / 2;
        }
        double span = hi - lo;
        lo = std::max(absLo, lo - span * 0.15);
        hi = std::min(absHi, hi + span * 0.15);
        if (hi - lo < 1) hi = lo + 1;
    };
    pad(fmin, fmax, 10, 0, 100);
    pad(tmin, tmax, 6, 0, 120);

    auto yFan = [&](double v) {
        v = std::max(fmin, std::min(fmax, v));
        return plotY + plotH - S(2) - (int)((v - fmin) / (fmax - fmin) * (plotH - S(6)));
    };
    auto yTemp = [&](double v) {
        v = std::max(tmin, std::min(tmax, v));
        return plotY + plotH - S(2) - (int)((v - tmin) / (tmax - tmin) * (plotH - S(6)));
    };

    HPEN grid = CreatePen(PS_DOT, 1, C_GRID);
    HPEN oldPen = (HPEN)SelectObject(dc, grid);
    for (int i = 0; i <= 4; ++i) {
        int gy = plotY + (plotH - S(6)) * i / 4;
        MoveToEx(dc, plotX, gy, nullptr);
        LineTo(dc, plotX + plotW, gy);
        double fv = fmax - (fmax - fmin) * i / 4;
        double tv = tmax - (tmax - tmin) * i / 4;
        if (i > 0) {
            TextAt(dc, x + S(2), gy - S(7), C_DIM, Fmt(L"%.0f%%", fv));
            TextAt(dc, plotX + plotW + S(6), gy - S(7), C_DIM, Fmt(L"%.0f°C", tv));
        }
    }
    SelectObject(dc, oldPen);
    DeleteObject(grid);

    double step = (double)plotW / (HIST_MAX - 1);
    auto drawLine = [&](COLORREF color, bool isFan, double& lastV) {
        HPEN pen = CreatePen(PS_SOLID, 2, color);
        HPEN op = (HPEN)SelectObject(dc, pen);
        bool first = true;
        for (int i = 0; i < g_histCount; ++i) {
            int idx = (g_histHead - g_histCount + i + HIST_MAX * 2) % HIST_MAX;
            const Sample& sm = g_hist[idx];
            double v = isFan ? sm.fan : sm.gpuT;
            if (v <= 0) { first = true; continue; }          // 断点不连线
            int px = plotX + plotW - (int)((g_histCount - 1 - i) * step);
            int py = isFan ? yFan(v) : yTemp(v);
            if (first) { MoveToEx(dc, px, py, nullptr); first = false; }
            else LineTo(dc, px, py);
            lastV = v;
        }
        SelectObject(dc, op);
        DeleteObject(pen);
    };

    double fanNow = 0, tempNow = 0;
    drawLine(C_BLUE, true, fanNow);
    drawLine(C_RED, false, tempNow);

    TextAt(dc, x + S(6), y + S(1), C_BLUE, Fmt(L"● 转速 %.0f%%", fanNow));
    TextAt(dc, x + S(112), y + S(1), C_RED, Fmt(L"● 温度 %.0f°C", tempNow));

    double lag = FanLagSeconds();
    if (lag >= 0)
        TextAt(dc, x + w - S(96), y + S(1), lag < 2 ? C_MUTED : C_AMBER,
               lag < 2 ? L"两者同步" : Fmt(L"滞后 %.0f 秒", lag));
    else if (lag == -2)
        TextAt(dc, x + w - S(96), y + S(1), C_DIM, L"暂无可比");
}

static void PaintCooling(HDC dc, int x, int y, int w) {
    SetBkMode(dc, TRANSPARENT);
    if (g_temps.gpu <= 0) {
        TextAt(dc, x, y + S(2), C_DIM, L"散热：没读到 GPU 温度（nvidia-smi 不可用），风扇转速无从对比");
        return;
    }

    auto at = [&](int back) {
        int idx = (g_histHead - 1 - back + HIST_MAX * 2) % HIST_MAX;
        return g_hist[idx];
    };
    const bool hasOld = g_histCount >= 12;          // 约 20 秒前
    const double fanNow = g_temps.fan;
    const double fanOld = hasOld ? at(10).fan : -1;
    const double tNow = g_temps.gpu;
    const double tOld = hasOld ? at(10).gpuT : -1;

    TextAt(dc, x, y + S(11), C_MUTED, L"散热");

    const int lx = x + S(52), barX = lx + S(74), barW = S(170), barH = S(9), pitch = S(22);

    // 两条同宽的条：一眼看出「转速拉到多少 / 温度压到多少」
    COLORREF fanColor = fanNow >= 90 ? C_RED : (fanNow >= 70 ? C_AMBER : C_BLUE);
    COLORREF tColor = tNow >= 83 ? C_RED : (tNow >= 70 ? C_AMBER : C_GREEN);

    TextAt(dc, lx, y + S(4), C_MUTED, L"风扇");
    DrawBar(dc, barX, y + S(5), barW, barH, fanNow, fanColor);
    TextAt(dc, barX + barW + S(12), y + S(2), C_TEXT, Fmt(L"%.0f%%", fanNow));
    if (hasOld && fanOld >= 0) {
        double d = fanNow - fanOld;
        TextAt(dc, barX + barW + S(68), y + S(2), C_DIM,
               std::fabs(d) < 1 ? std::wstring(L"20 秒前持平")
                                : Fmt(L"20 秒前 %.0f%%（%s%.0f%%）", fanOld,
                                      d > 0 ? L"+" : L"-", std::fabs(d)));
    }

    TextAt(dc, lx, y + S(2) + pitch, C_MUTED, L"GPU 温度");
    double tPct = (tNow - 20) / 75 * 100;           // 20~95°C 映射到整条
    DrawBar(dc, barX, y + S(3) + pitch, barW, barH, tPct, tColor);
    TextAt(dc, barX + barW + S(12), y + pitch, C_TEXT, Fmt(L"%.0f°C", tNow));
    if (hasOld && tOld > 0) {
        double d = tNow - tOld;
        TextAt(dc, barX + barW + S(68), y + pitch, C_DIM,
               std::fabs(d) < 1 ? std::wstring(L"20 秒前持平")
                                : Fmt(L"20 秒前 %.0f°C（%s%.0f°C）", tOld,
                                      d > 0 ? L"+" : L"-", std::fabs(d)));
    }

    // 右侧结论：温度和转速放一起才看得出散热够不够
    const wchar_t* verdict = L"";
    COLORREF vColor = C_MUTED;
    if (tNow >= 83 && fanNow >= 85) { verdict = L"高温高转：散热受阻（积灰/风道）"; vColor = C_RED; }
    else if (tNow >= 83)            { verdict = L"温度偏高，风扇没拉满：查风扇曲线"; vColor = C_AMBER; }
    else if (fanNow >= 90 && tNow < 60) { verdict = L"转速高但温度低：散热余量充足"; vColor = C_BLUE; }
    else if (tNow < 60 && fanNow < 40)  { verdict = L"低转速低温度：散热轻松"; vColor = C_GREEN; }
    if (verdict[0]) TextAt(dc, x + w - S(300), y + S(13), vColor, verdict);
}

static void PaintHeader(HDC dc, int w, int h) {
    HFONT font = CreateFontW(S(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH, L"Microsoft YaHei UI");
    HGDIOBJ old = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);

    if (g_theme.glass) {
        GlossBand(dc, w);
        GlassPanel(dc, S(14), S(52), w - S(28), h - S(58), S(10));
    }
    else {
        HBRUSH bg = CreateSolidBrush(C_BG);
        RECT all{ 0, 0, w, h };
        FillRect(dc, &all, bg);
        DeleteObject(bg);
    }

    const Snapshot& s = g_snap;
    COLORREF ramColor = s.ramPct >= 88 ? C_RED : C_GREEN;
    COLORREF comColor = s.comPct >= 90 ? C_RED : (s.comPct >= 85 ? C_AMBER : C_GREEN);
    double vpct = s.vramTotal > 0 ? s.vramUsed / s.vramTotal * 100 : 0;
    COLORREF vColor = vpct >= 92 ? C_RED : C_AMBER;

    PaintStat(dc, S(30), S(64), L"内存", Fmt(L"%.1f / %.1f GB (%.0f%%)", s.ramUsedGB, s.ramTotalGB, s.ramPct),
              s.ramPct, ramColor);
    PaintStat(dc, S(30), S(104), L"提交", Fmt(L"%.1f / %.1f GB (%.0f%%)", s.comUsedGB, s.comTotalGB, s.comPct),
              s.comPct, comColor);
    PaintStat(dc, S(282), S(64), L"显存", s.hasGpu ? Fmt(L"%.1f / %.1f GB", s.vramUsed, s.vramTotal) : L"无 N 卡",
              vpct, vColor);
    PaintStat(dc, S(282), S(104), L"GPU", s.hasGpu ? Fmt(L"%.0f%%  %.0f°C", s.gpuUtil, s.gpuTemp) : L"—",
              s.gpuUtil, C_BLUE);

    TextAt(dc, S(532), S(66), C_MUTED, Fmt(L"CPU %.0f%%    %d 个进程", s.cpuPct, s.procCount));
    TextAt(dc, S(532), S(94), C_MUTED, L"模型占用");
    if (s.modelRunning)
        TextAt(dc, S(532), S(112), C_TEXT,
               Fmt(L"显存 %.1f GB · 内存 %.2f GB · 权重 %.1f GB", s.vramUsed, s.modelMemGB, g_weightsGB));
    else
        TextAt(dc, S(532), S(112), C_DIM, Fmt(L"未运行（权重 %.1f GB）", g_weightsGB));

    const int gap = S(14);
    const int halfW = (w - S(48) - gap) / 2;
    PaintChart(dc, S(24), S(136), halfW, S(90));
    PaintCoolChart(dc, S(24) + halfW + gap, S(136), halfW, S(90));

    TextAt(dc, S(28), S(232), C_DIM, Fmt(L"最近 %.0f 秒", g_histCount * 2.0));
    TextAt(dc, w - S(60), S(232), C_DIM, L"现在");
    TextAt(dc, S(24), S(248), C_MUTED, Fmt(L"趋势：%s", TrendText().c_str()));
    PaintCooling(dc, S(24), S(272), w - S(48));

    SelectObject(dc, old);
    DeleteObject(font);
}

static void RefreshAsync(HWND hwnd) {
    if (g_busy.exchange(true)) return;
    std::thread([hwnd]() {
        auto* snap = new Snapshot();
        Collect(*snap);
        PostMessageW(hwnd, WM_APP_SNAPSHOT, 0, (LPARAM)snap);
    }).detach();
}

static void OnSnapshot(HWND hwnd, Snapshot* snap) {
    EnterCriticalSection(&g_lock);
    g_snap = *snap;
    delete snap;
    PushHistory(g_snap);
    LeaveCriticalSection(&g_lock);

    FillList();

    RECT head{ 0, 0, 4000, HEADER_H };
    InvalidateRect(hwnd, &head, FALSE);

    SYSTEMTIME st;
    GetLocalTime(&st);
    {
        std::wstring t = Fmt(L"%02d:%02d:%02d   内存 %.1f/%.1f（%.0f%%）  提交 %.1f/%.1f（%.0f%%）  进程 %d  CPU %.0f%%",
                             st.wHour, st.wMinute, st.wSecond,
                             g_snap.ramUsedGB, g_snap.ramTotalGB, g_snap.ramPct,
                             g_snap.comUsedGB, g_snap.comTotalGB, g_snap.comPct,
                             g_snap.procCount, g_snap.cpuPct);
        if (g_temps.gpu > 0) t += Fmt(L"   GPU %.0f°C/风扇%.0f%%", g_temps.gpu, g_temps.fan);
        if (g_temps.disk > 0) t += Fmt(L"   磁盘 %.0f°C", g_temps.disk);
        if (g_temps.cpu > 0) t += Fmt(L"   ACPI %.0f°C", g_temps.cpu);
        SetWindowTextW(g_status, t.c_str());
    }
    if (g_ball && IsWindowVisible(g_ball)) BallKick();

    TrayUpdateTip(Fmt(L"内存 %.0f%% · 提交 %.0f%% · 显存 %.0f%%",
                      g_snap.ramPct, g_snap.comPct,
                      g_snap.vramTotal > 0 ? g_snap.vramUsed / g_snap.vramTotal * 100 : 0));
    g_busy = false;
}

static void EnableDwmGlass(HWND hwnd);
static void ApplyCaptionTheme(HWND hwnd);

// 0=深色 1=玻璃 2=跟随系统
static int  g_mode = 0;
static const wchar_t* MODE_KEY[3] = { L"dark", L"glass", L"auto" };

static bool SystemIsLight() {
    HKEY k = nullptr;
    bool light = true;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                      0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        DWORD v = 1, cb = sizeof(v), type = 0;
        if (RegQueryValueExW(k, L"AppsUseLightTheme", nullptr, &type, (LPBYTE)&v, &cb) == ERROR_SUCCESS)
            light = (v != 0);
        RegCloseKey(k);
    }
    return light;
}

static bool ModeToGlass(int mode) {
    if (mode == 1) return true;
    if (mode == 2) return SystemIsLight();
    return false;
}

static const wchar_t* ModeName(int mode) {
    return mode == 0 ? L"深色" : (mode == 1 ? L"玻璃" : L"跟随系统");
}

static void SaveThemePref(int mode) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        const wchar_t* v = MODE_KEY[mode < 0 || mode > 2 ? 0 : mode];
        RegSetValueExW(k, L"theme", 0, REG_SZ, (const BYTE*)v,
                       (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
    }
}

static int LoadThemePref() {           // -1 未设置, 0 深色, 1 玻璃
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, KEY_QUERY_VALUE, &k)
        != ERROR_SUCCESS) return -1;
    wchar_t buf[16]{};
    DWORD cb = sizeof(buf), type = 0;
    int r = -1;
    if (RegQueryValueExW(k, L"theme", nullptr, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS
        && type == REG_SZ)
        if (_wcsicmp(buf, L"glass") == 0) r = 1;
        else if (_wcsicmp(buf, L"auto") == 0) r = 2;
        else r = 0;
    RegCloseKey(k);
    return r;
}

static void ShowFromTray(HWND hwnd);
static void HideToTray(HWND hwnd);

// ------------------------------------------------------------------ 偏好项
static bool g_autostart = false;
static int  g_ballX = -1, g_ballY = -1;

static void RegSetStr(const wchar_t* name, const wchar_t* value) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value,
                       (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
    }
}

static bool RegGetStr(const wchar_t* name, wchar_t* buf, DWORD chars) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, KEY_QUERY_VALUE, &k)
        != ERROR_SUCCESS) return false;
    DWORD cb = chars * sizeof(wchar_t), type = 0;
    bool ok = RegQueryValueExW(k, name, nullptr, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS;
    RegCloseKey(k);
    return ok;
}

static void RegSetDword(const wchar_t* name, DWORD v) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
        RegCloseKey(k);
    }
}

static DWORD RegGetDword(const wchar_t* name, DWORD def) {
    HKEY k = nullptr;
    DWORD v = def, cb = sizeof(v), type = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\AITaskManager", 0, KEY_QUERY_VALUE, &k)
        == ERROR_SUCCESS) {
        RegQueryValueExW(k, name, nullptr, &type, (LPBYTE)&v, &cb);
        RegCloseKey(k);
    }
    return v;
}

// ------------------------------------------------------------------ 开机自启
static bool AutostartEnabled() {
    wchar_t buf[MAX_PATH * 2]{};
    if (!RegGetStr(L"autostart", buf, MAX_PATH * 2)) return false;
    return buf[0] == L'1';
}

static void SetAutostart(bool on) {
    RegSetStr(L"autostart", on ? L"1" : L"0");

    // 实际生效的是 HKCU\...\Run 这一项
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return;
    if (on) {
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring quoted = L"\"" + std::wstring(exe) + L"\"";
        RegSetValueExW(k, L"AITaskManager", 0, REG_SZ, (const BYTE*)quoted.c_str(),
                       (DWORD)((quoted.size() + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(k, L"AITaskManager");
    }
    RegCloseKey(k);
    g_autostart = on;
}

// ------------------------------------------------------------------ 清理内存
struct CleanResult { int count = 0; double freedMB = 0; };

static CleanResult CleanMemory() {
    CleanResult r;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return r;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                                   FALSE, pe.th32ProcessID);
            if (!h) continue;

            PROCESS_MEMORY_COUNTERS_EX before{}, after{};
            if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&before, sizeof(before))) {
                if (EmptyWorkingSet(h) &&
                    GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&after, sizeof(after))) {
                    double delta = (double)before.WorkingSetSize - (double)after.WorkingSetSize;
                    if (delta > 0) {
                        r.freedMB += delta / 1048576.0;
                        r.count++;
                    }
                }
            }
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return r;
}

// ------------------------------------------------------------------ 气泡提示
// 球只有 64px，塞不下"538 个进程 / 释放 8.0 GB"，用独立的分层窗口弹出来
#define TOAST_TMR      21
#define TOAST_IN_MS    150
#define TOAST_HOLD_MS  2600
#define TOAST_OUT_MS   220

static HWND    g_toast = nullptr;
static HDC     g_toastDC = nullptr;
static HBITMAP g_toastDib = nullptr;
static int     g_toastW = 0, g_toastH = 0;
static int     g_toastAlpha = 0;
static int     g_toastPhase = 0;        // 0=淡入 1=停留 2=淡出
static DWORD   g_toastT0 = 0;
static std::wstring g_toastL1, g_toastL2;

static void ToastPaint() {
    if (!g_toast || !g_toastDib) return;
    HGDIOBJ old = SelectObject(g_toastDC, g_toastDib);

    RECT wr{};
    GetWindowRect(g_toast, &wr);
    POINT dst{ wr.left, wr.top };
    SIZE sz{ g_toastW, g_toastH };
    POINT src{ 0, 0 };
    BLENDFUNCTION bf{ AC_SRC_OVER, 0, (BYTE)g_toastAlpha, AC_SRC_ALPHA };
    HDC screen = GetDC(nullptr);
    UpdateLayeredWindow(g_toast, screen, &dst, &sz, g_toastDC, &src, 0, &bf, ULW_ALPHA);
    ReleaseDC(nullptr, screen);

    SelectObject(g_toastDC, old);
}

static void ToastHide() {
    if (!g_toast) return;
    KillTimer(g_toast, TOAST_TMR);
    ShowWindow(g_toast, SW_HIDE);
    g_toastPhase = 0;
    g_toastAlpha = 0;
    if (g_toastDC) { DeleteDC(g_toastDC); g_toastDC = nullptr; }
    if (g_toastDib) { DeleteObject(g_toastDib); g_toastDib = nullptr; }
}

static LRESULT CALLBACK ToastProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_TIMER && w == TOAST_TMR) {
        DWORD dt = GetTickCount() - g_toastT0;
        if (g_toastPhase == 0) {
            g_toastAlpha = (int)std::min<DWORD>(255, 255 * dt / TOAST_IN_MS);
            if (dt >= TOAST_IN_MS) { g_toastPhase = 1; g_toastT0 = GetTickCount(); g_toastAlpha = 255; }
        } else if (g_toastPhase == 1) {
            if (dt >= TOAST_HOLD_MS) { g_toastPhase = 2; g_toastT0 = GetTickCount(); }
        } else {
            int k = (int)std::min<DWORD>(TOAST_OUT_MS, dt);
            g_toastAlpha = 255 - 255 * k / TOAST_OUT_MS;
            if (dt >= TOAST_OUT_MS) { ToastHide(); return 0; }
        }
        ToastPaint();
        return 0;
    }
    if (m == WM_ERASEBKGND) return 1;
    return DefWindowProcW(h, m, w, l);
}

static void ToastShow(int count, double freedMB) {
    if (!g_toast) {
        static bool reg = false;
        if (!reg) {
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = ToastProc;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = L"AITMToastWnd";
            RegisterClassExW(&wc);
            reg = true;
        }
        g_toast = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
                                  L"AITMToastWnd", L"", WS_POPUP,
                                  0, 0, 10, 10, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!g_toast) return;
    }

    ToastHide();

    g_toastL1 = Fmt(L"整理完成 · %d 个进程", count);
    g_toastL2 = freedMB >= 1024 ? Fmt(L"工作集释放 %.1f GB", freedMB / 1024.0)
                                : Fmt(L"工作集释放 %.0f MB", freedMB);

    Gdiplus::FontFamily fam(L"Microsoft YaHei UI");
    Gdiplus::Font f1(&fam, (Gdiplus::REAL)S(13), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
    Gdiplus::Font f2(&fam, (Gdiplus::REAL)S(12), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);

    Gdiplus::RectF b1{}, b2{};
    {
        Gdiplus::Bitmap probe(1, 1, 4, PixelFormat32bppPARGB, nullptr);
        Gdiplus::Graphics pg(&probe);
        Gdiplus::StringFormat sf;
        pg.MeasureString(g_toastL1.c_str(), -1, &f1, Gdiplus::PointF(0, 0), &sf, &b1);
        pg.MeasureString(g_toastL2.c_str(), -1, &f2, Gdiplus::PointF(0, 0), &sf, &b2);
    }

    const int padX = S(16), padY = S(12), iconW = S(24), gap = S(10);
    const int textW = (int)std::max(b1.Width, b2.Width) + S(2);
    g_toastW = padX * 2 + iconW + gap + textW;
    const int bodyH = padY * 2 + (int)b1.Height + (int)b2.Height + S(3);
    const int tailH = S(6), tailHalf = S(10);

    // 先定位置：上方放得下就放上面，否则放下面；尖角始终指向球心
    RECT br{}, work{};
    GetWindowRect(g_ball, &br);
    MONITORINFO mi{ sizeof(mi) };
    HMONITOR mon = MonitorFromWindow(g_ball, MONITOR_DEFAULTTONEAREST);
    if (mon && GetMonitorInfoW(mon, &mi)) work = mi.rcWork;
    else SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);

    g_toastH = bodyH + tailH;
    const bool tailUp = (br.top - (bodyH + tailH) - S(6)) < ((int)work.top + S(4));

    int bx = br.left + ((br.right - br.left) - g_toastW) / 2;
    int by = tailUp ? br.bottom + S(6) : br.top - g_toastH - S(6);
    bx = std::max((int)work.left + S(4), std::min(bx, (int)work.right - g_toastW - S(4)));

    const int bodyTop = tailUp ? tailH : 0;

    // 尖角在气泡里的横坐标：对着球心，再夹在圆角之间，不会顶到边
    int tipX = (br.left + br.right) / 2 - bx;
    const int tipMin = S(14) + tailHalf;
    const int tipMax = g_toastW - S(14) - tailHalf;
    tipX = std::max(tipMin, std::min(tipX, tipMax));

    HDC screen = GetDC(nullptr);
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = g_toastW;
    bi.bmiHeader.biHeight = -g_toastH;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    g_toastDib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    g_toastDC = CreateCompatibleDC(screen);
    ReleaseDC(nullptr, screen);
    if (!g_toastDib || !g_toastDC) { ToastHide(); return; }
    memset(bits, 0, (size_t)g_toastW * g_toastH * 4);

    {
        Gdiplus::Bitmap bmp(g_toastW, g_toastH, g_toastW * 4, PixelFormat32bppPARGB, (BYTE*)bits);
        Gdiplus::Graphics g(&bmp);
        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        g.SetTextRenderingHint(Gdiplus::TextRenderingHintAntiAliasGridFit);

        const Gdiplus::REAL rr = (Gdiplus::REAL)S(10);
        const Gdiplus::REAL wR = (Gdiplus::REAL)g_toastW;
        const Gdiplus::REAL top = (Gdiplus::REAL)bodyTop;
        const Gdiplus::REAL bot = top + (Gdiplus::REAL)bodyH;
        const Gdiplus::REAL tX = (Gdiplus::REAL)tipX;
        const Gdiplus::REAL tHalf = (Gdiplus::REAL)tailHalf;
        const Gdiplus::REAL tH = (Gdiplus::REAL)tailH;

        // 圆角矩形 + 尖角画成同一条路径：填充和描边都不会在接缝处出现一条线
        Gdiplus::GraphicsPath path;
        path.AddArc(0.5f, top + 0.5f, rr, rr, 180.0f, 90.0f);
        if (tailUp) {
            path.AddLine(rr, top, tX - tHalf, top);
            path.AddLine(tX - tHalf, top, tX, top - tH);
            path.AddLine(tX, top - tH, tX + tHalf, top);
            path.AddLine(tX + tHalf, top, wR - rr, top);
        } else {
            path.AddLine(rr, top, wR - rr, top);
        }
        path.AddArc(wR - rr - 0.5f, top + 0.5f, rr, rr, 270.0f, 90.0f);
        path.AddArc(wR - rr - 0.5f, bot - rr - 0.5f, rr, rr, 0.0f, 90.0f);
        if (!tailUp) {
            path.AddLine(wR - rr, bot, tX + tHalf, bot);
            path.AddLine(tX + tHalf, bot, tX, bot + tH);
            path.AddLine(tX, bot + tH, tX - tHalf, bot);
            path.AddLine(tX - tHalf, bot, rr, bot);
        } else {
            path.AddLine(wR - rr, bot, rr, bot);
        }
        path.AddArc(0.5f, bot - rr - 0.5f, rr, rr, 90.0f, 90.0f);
        path.CloseFigure();

        Gdiplus::SolidBrush bg(Gdiplus::Color(244, 26, 29, 38));
        g.FillPath(&bg, &path);
        Gdiplus::Pen edge(Gdiplus::Color(46, 255, 255, 255), 1.0f);
        g.DrawPath(&edge, &path);

        // 左侧勾：一个绿圆 + 两道白线，比 emoji 稳定
        float iconCx = padX + iconW / 2.0f;
        float iconCy = (Gdiplus::REAL)bodyTop + bodyH / 2.0f;
        Gdiplus::SolidBrush ok(Gdiplus::Color(255, 66, 208, 142));
        g.FillEllipse(&ok, iconCx - iconW / 2.0f, iconCy - iconW / 2.0f, (Gdiplus::REAL)iconW, (Gdiplus::REAL)iconW);
        Gdiplus::Pen tick(Gdiplus::Color(255, 22, 24, 30), (Gdiplus::REAL)S(2));
        tick.SetStartCap(Gdiplus::LineCapRound);
        tick.SetEndCap(Gdiplus::LineCapRound);
        float tx = iconCx - S(5), ty = iconCy;
        g.DrawLine(&tick, tx, ty, tx + S(3), ty + S(3));
        g.DrawLine(&tick, tx + S(3), ty + S(3), tx + S(8), ty - S(4));

        float textX = (float)(padX + iconW + gap);
        float textY = (Gdiplus::REAL)bodyTop + padY;
        Gdiplus::SolidBrush t1(Gdiplus::Color(255, 237, 241, 248));
        Gdiplus::SolidBrush t2(Gdiplus::Color(255, 110, 231, 183));
        Gdiplus::StringFormat sf;
        sf.SetAlignment(Gdiplus::StringAlignmentNear);
        g.DrawString(g_toastL1.c_str(), -1, &f1, Gdiplus::PointF(textX, textY), &sf, &t1);
        g.DrawString(g_toastL2.c_str(), -1, &f2,
                     Gdiplus::PointF(textX, textY + b1.Height + S(2)), &sf, &t2);
    }

    SetWindowPos(g_toast, HWND_TOPMOST, bx, by, g_toastW, g_toastH,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);

    g_toastPhase = 0;
    g_toastAlpha = 0;
    g_toastT0 = GetTickCount();
    SetTimer(g_toast, TOAST_TMR, 16, nullptr);
    ToastPaint();
}

// ------------------------------------------------------------------ 悬浮球
#define BALL_W        S(88)                 // 窗口（球 + 阴影留白）
#define BALL_D        S(64)                 // 球本体直径
#define BALL_TMR_FRAME 11
#define BALL_TMR_CLICK 12
#define BALL_MSG_CLEAN (WM_APP + 3)

static bool g_ballDrag = false;
static bool g_ballMoved = false;
static POINT g_dragOrigin{}, g_winOrigin{};

static bool   g_ballHovering = false;
static double g_ballPct = 0;                // 显示值，平滑逼近真实值
static double g_ballHover = 0, g_ballHoverT = 0;
static double g_ballPress = 0, g_ballPressT = 0;
static double g_ballSpin = 0;
static bool   g_ballCleaning = false;
static DWORD  g_ballLastClick = 0;

static inline Gdiplus::REAL SR(int v) { return (Gdiplus::REAL)S(v); }

static HWND    g_ballTip = nullptr;
static HBITMAP g_ballDib = nullptr;
static HDC     g_ballMemDC = nullptr;
static void*   g_ballBits = nullptr;

static Gdiplus::Color BallRingColor(double pct) {
    if (pct >= 90) return Gdiplus::Color(255, 240, 92, 92);
    if (pct >= 80) return Gdiplus::Color(255, 240, 168, 60);
    return Gdiplus::Color(255, 66, 208, 142);
}

static void BallKick() {
    if (g_ball) SetTimer(g_ball, BALL_TMR_FRAME, 33, nullptr);
}

static void RenderBall() {
    HWND h = g_ball;
    if (!h) return;

    const int size = BALL_W;
    if (!g_ballDib) {
        HDC screen = GetDC(nullptr);
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = size;
        bi.bmiHeader.biHeight = -size;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        g_ballDib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &g_ballBits, nullptr, 0);
        g_ballMemDC = CreateCompatibleDC(screen);
        ReleaseDC(nullptr, screen);
        if (!g_ballDib || !g_ballMemDC) return;
    }
    memset(g_ballBits, 0, (size_t)size * size * 4);

    const Gdiplus::REAL cx = size / 2.0f, cy = size / 2.0f;
    const Gdiplus::REAL scale = 1.0f + 0.06f * (Gdiplus::REAL)g_ballHover
                                      - 0.05f * (Gdiplus::REAL)g_ballPress;
    const Gdiplus::REAL R = (BALL_D / 2.0f - S(3)) * scale;
    const Gdiplus::REAL ringW = S(5) * (1.0f + 0.12f * (Gdiplus::REAL)g_ballHover);
    const Gdiplus::REAL ringR = R - ringW / 2 - S(1);

    {
        Gdiplus::Bitmap bmp(size, size, size * 4, PixelFormat32bppPARGB, (BYTE*)g_ballBits);
        Gdiplus::Graphics g(&bmp);
        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
        g.SetTextRenderingHint(Gdiplus::TextRenderingHintAntiAliasGridFit);

        // 柔和投影：中心浓、边缘透明，比一圈圈描边干净
        {
            Gdiplus::GraphicsPath path;
            path.AddEllipse(cx - R - S(5), cy - R - S(3), (R + S(5)) * 2, (R + S(5)) * 2);
            Gdiplus::PathGradientBrush sbr(&path);
            sbr.SetCenterColor(Gdiplus::Color(96, 0, 0, 0));
            Gdiplus::Color edge[1] = { Gdiplus::Color(0, 0, 0, 0) };
            int n = 1;
            sbr.SetSurroundColors(edge, &n);
            g.FillPath(&sbr, &path);
        }

        // 球体：上浅下深，像一颗压下去的玻璃珠
        {
            Gdiplus::LinearGradientBrush body(Gdiplus::PointF(cx, cy - R), Gdiplus::PointF(cx, cy + R),
                                              Gdiplus::Color(255, 46, 50, 66),
                                              Gdiplus::Color(255, 17, 19, 26));
            g.FillEllipse(&body, cx - R, cy - R, R * 2, R * 2);
        }

        // 轨道
        {
            Gdiplus::Pen track(Gdiplus::Color(255, 56, 60, 76), ringW);
            g.DrawEllipse(&track, cx - ringR, cy - ringR, ringR * 2, ringR * 2);
        }

        // 进度 / 清理中转圈
        Gdiplus::Color ringCol = BallRingColor(g_ballPct);
        if (g_ballCleaning) ringCol = Gdiplus::Color(255, 120, 205, 255);

        Gdiplus::Pen arc(ringCol, ringW);
        arc.SetStartCap(Gdiplus::LineCapRound);
        arc.SetEndCap(Gdiplus::LineCapRound);

        if (g_ballCleaning) {
            g.DrawArc(&arc, cx - ringR, cy - ringR, ringR * 2, ringR * 2,
                      (Gdiplus::REAL)(g_ballSpin - 90), 100.0f);
        } else {
            double sweep = std::max(1.0, std::min(360.0, g_ballPct * 3.6));
            g.DrawArc(&arc, cx - ringR, cy - ringR, ringR * 2, ringR * 2, -90.0f, (Gdiplus::REAL)sweep);
        }

        // 悬停时外面套一圈淡淡的光
        if (g_ballHover > 0.02) {
            Gdiplus::Pen glow(Gdiplus::Color((BYTE)(70 * g_ballHover), ringCol.GetR(),
                                             ringCol.GetG(), ringCol.GetB()), SR(1));
            Gdiplus::REAL gr = R + SR(2);
            g.DrawEllipse(&glow, cx - gr, cy - gr, gr * 2, gr * 2);
        }

        Gdiplus::StringFormat sf;
        sf.SetAlignment(Gdiplus::StringAlignmentCenter);
        sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);

        Gdiplus::FontFamily fam(L"Microsoft YaHei UI");

        // 百分比
        {
            Gdiplus::Font f(&fam, (Gdiplus::REAL)S(18), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
            Gdiplus::SolidBrush br(Gdiplus::Color(255, 237, 241, 248));
            Gdiplus::RectF tr(cx - R, cy - SR(19), R * 2, SR(24));
            std::wstring txt = Fmt(L"%.0f%%", g_ballPct);
            g.DrawString(txt.c_str(), -1, &f, tr, &sf, &br);
        }

        // 下方一行说明：这球是干嘛的、现在能干嘛
        {
            std::wstring label = L"内存";
            Gdiplus::Color lc(255, 136, 146, 170);
            if (g_ballCleaning)                      { label = L"清理中"; lc = Gdiplus::Color(255, 120, 205, 255); }
            else if (g_ballHover > 0.5)              { label = L"点击清理"; lc = Gdiplus::Color(255, 127, 212, 255); }

            Gdiplus::Font f(&fam, (Gdiplus::REAL)S(9), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            Gdiplus::SolidBrush br(lc);
            Gdiplus::RectF tr(cx - R, cy + SR(4), R * 2, SR(14));
            g.DrawString(label.c_str(), -1, &f, tr, &sf, &br);
        }
    }

    HGDIOBJ oldBmp = SelectObject(g_ballMemDC, g_ballDib);

    RECT wr{};
    GetWindowRect(h, &wr);
    POINT dst{ wr.left, wr.top };
    SIZE sz{ size, size };
    POINT src{ 0, 0 };
    BLENDFUNCTION bf{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    HDC screen = GetDC(nullptr);
    UpdateLayeredWindow(h, screen, &dst, &sz, g_ballMemDC, &src, 0, &bf, ULW_ALPHA);
    ReleaseDC(nullptr, screen);

    SelectObject(g_ballMemDC, oldBmp);
}

static void SaveBallPos() {
    RECT r{};
    if (GetWindowRect(g_ball, &r)) {
        RegSetDword(L"ballX", (DWORD)r.left);
        RegSetDword(L"ballY", (DWORD)r.top);
    }
}

static void BallStartClean(HWND h) {
    if (g_ballCleaning) return;
    ToastHide();               // 上一轮的气泡别和这次的转圈同时出现
    g_ballCleaning = true;
    g_ballSpin = 0;
    BallKick();
    std::thread([h]() {
        CleanResult r = CleanMemory();
        PostMessageW(h, BALL_MSG_CLEAN, 0, (LPARAM)new CleanResult(r));
    }).detach();
}

// 每帧推进动画；全部稳定了就停表，空转不占 CPU
static bool BallTick(HWND h) {
    bool changed = false;

    if (std::fabs(g_snap.ramPct - g_ballPct) > 0.15) {
        g_ballPct += (g_snap.ramPct - g_ballPct) * 0.16;
        changed = true;
    } else if (g_ballPct != g_snap.ramPct) {
        g_ballPct = g_snap.ramPct;
        changed = true;
    }

    auto ease = [&](double& v, double target, double k) {
        if (std::fabs(v - target) > 0.01) { v += (target - v) * k; return true; }
        if (v != target) { v = target; return true; }
        return false;
    };
    changed |= ease(g_ballHover, g_ballHoverT, 0.30);
    changed |= ease(g_ballPress, g_ballPressT, 0.35);

    if (g_ballCleaning) {
        g_ballSpin += 9.0;
        if (g_ballSpin >= 360) g_ballSpin -= 360;
        changed = true;
    }

    if (changed) RenderBall();
    return changed;
}

static LRESULT CALLBACK BallProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_TIMER:
        if (w == BALL_TMR_FRAME) {
            if (!BallTick(h)) KillTimer(h, BALL_TMR_FRAME);
        } else if (w == BALL_TMR_CLICK) {
            KillTimer(h, BALL_TMR_CLICK);
            BallStartClean(h);
        }
        return 0;

    case BALL_MSG_CLEAN: {
        auto* r = (CleanResult*)l;
        if (r) {
            g_ballCleaning = false;
            ToastShow(r->count, r->freedMB);
            HWND main = GetParent(h);
            if (main && IsWindow(main))
                PostMessageW(main, WM_APP_SNAPSHOT + 2, 0, (LPARAM)new CleanResult(*r));
            delete r;
        }
        BallKick();
        return 0;
    }

    case WM_LBUTTONDOWN:
        ToastHide();
        SetCapture(h);
        g_ballDrag = true;
        g_ballMoved = false;
        g_ballPressT = 1.0;
        GetCursorPos(&g_dragOrigin);
        {
            RECT r{};
            GetWindowRect(h, &r);
            g_winOrigin.x = r.left;
            g_winOrigin.y = r.top;
        }
        BallKick();
        return 0;

    case WM_MOUSEMOVE: {
        if (g_ballDrag) {
            POINT p;
            GetCursorPos(&p);
            int dx = p.x - g_dragOrigin.x, dy = p.y - g_dragOrigin.y;
            if (abs(dx) > 3 || abs(dy) > 3) g_ballMoved = true;
            MoveWindow(h, g_winOrigin.x + dx, g_winOrigin.y + dy, BALL_W, BALL_W, TRUE);
        } else if (!g_ballHovering) {
            g_ballHovering = true;
            g_ballHoverT = 1.0;
            TRACKMOUSEEVENT tme{ sizeof(tme) };
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = h;
            TrackMouseEvent(&tme);
            BallKick();
        }
        return 0;
    }

    case WM_MOUSELEAVE:
        if (!g_ballDrag) {
            g_ballHovering = false;
            g_ballHoverT = 0;
            BallKick();
        }
        return 0;

    case WM_LBUTTONUP: {
        ReleaseCapture();
        g_ballDrag = false;
        g_ballPressT = 0;
        BallKick();

        if (g_ballMoved) { SaveBallPos(); return 0; }

        // 单击清理，双击打开窗口：用 260ms 的延迟把两者分开
        DWORD now = GetTickCount();
        if (g_ballLastClick && now - g_ballLastClick <= (DWORD)GetDoubleClickTime()) {
            KillTimer(h, BALL_TMR_CLICK);
            g_ballLastClick = 0;
            HWND main = GetParent(h);
            if (main) ShowFromTray(main);
        } else {
            g_ballLastClick = now;
            SetTimer(h, BALL_TMR_CLICK, 260, nullptr);
        }
        return 0;
    }

    case WM_RBUTTONUP: {
        POINT pt;
        GetCursorPos(&pt);
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, IDM_TRAY_SHOW, L"打开主窗口");
        AppendMenuW(menu, MF_STRING, 2110, L"立即清理内存");
        AppendMenuW(menu, MF_STRING, 2101, L"隐藏悬浮球");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"退出");
        SetForegroundWindow(h);
        int cmd = (int)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                      pt.x, pt.y, 0, h, nullptr);
        DestroyMenu(menu);
        HWND main = GetParent(h);
        if (cmd == IDM_TRAY_SHOW && main) ShowFromTray(main);
        else if (cmd == 2110) BallStartClean(h);
        else if (cmd == 2101) ShowWindow(h, SW_HIDE), g_ballOn = false, RegSetStr(L"ball", L"0");
        else if (cmd == IDM_TRAY_EXIT && main) DestroyWindow(main);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;
    }
    return DefWindowProcW(h, m, w, l);
}

static void CreateBall(HWND owner) {
    if (g_ball) { ShowWindow(g_ball, SW_SHOW); RenderBall(); return; }

    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = BallProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_HAND);
        wc.lpszClassName = L"AITaskBallWnd";
        RegisterClassExW(&wc);
        registered = true;
    }

    int x = g_ballX >= 0 ? g_ballX : (GetSystemMetrics(SM_CXSCREEN) - BALL_W - S(40));
    int y = g_ballY >= 0 ? g_ballY : (GetSystemMetrics(SM_CYSCREEN) / 3);
    g_ball = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
                             L"AITaskBallWnd", L"", WS_POPUP,
                             x, y, BALL_W, BALL_W, owner, nullptr,
                             GetModuleHandleW(nullptr), nullptr);
    if (!g_ball) return;

    g_ballPct = g_snap.ramPct;

    // 只有球体本身响应鼠标，阴影留白点不到
    int m = (BALL_W - BALL_D) / 2 + S(2);
    HRGN rgn = CreateEllipticRgn(m, m, BALL_W - m, BALL_W - m);
    SetWindowRgn(g_ball, rgn, TRUE);

    ShowWindow(g_ball, SW_SHOW);
    RenderBall();

    // 光看球不知道能点，给个提示
    g_ballTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_ballTip) {
        TOOLINFOW ti{};
        ti.cbSize = sizeof(ti);
        ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        ti.hwnd = g_ball;
        ti.uId = (UINT_PTR)g_ball;
        static wchar_t tipText[] = L"单击：清理内存\n双击：打开主窗口\n右键：更多";
        ti.lpszText = tipText;
        SendMessageW(g_ballTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        SendMessageW(g_ballTip, TTM_SETDELAYTIME, TTDT_INITIAL, MAKELPARAM(600, 0));
    }
}

static void DestroyBall() {
    ToastHide();
    if (g_toast) { DestroyWindow(g_toast); g_toast = nullptr; }
    if (g_ballTip) { DestroyWindow(g_ballTip); g_ballTip = nullptr; }
    if (g_ball) { DestroyWindow(g_ball); g_ball = nullptr; }
    if (g_ballMemDC) { DeleteDC(g_ballMemDC); g_ballMemDC = nullptr; }
    if (g_ballDib) { DeleteObject(g_ballDib); g_ballDib = nullptr; }
}

// ------------------------------------------------------------------ 托盘
static NOTIFYICONDATAW g_nid{};
static bool g_trayAdded = false;
static bool g_hiddenToTray = false;

static HICON TrayIconForTheme(HINSTANCE inst) {
    int id = g_theme.glass ? 2 : 1;
    return (HICON)LoadImageW(inst, MAKEINTRESOURCEW(id), IMAGE_ICON, 16, 16, LR_SHARED);
}

static void TrayAdd(HWND hwnd) {
    if (g_trayAdded) return;
    HINSTANCE inst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_APP_SNAPSHOT + 1;
    g_nid.hIcon = TrayIconForTheme(inst);
    wcscpy_s(g_nid.szTip, L"AI 任务管理器");
    g_trayAdded = Shell_NotifyIconW(NIM_ADD, &g_nid) != FALSE;
}

static void TrayUpdateTip(const std::wstring& tip) {
    if (!g_trayAdded) return;
    wcsncpy_s(g_nid.szTip, tip.c_str(), _TRUNCATE);
    g_nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void TraySetIcon(HWND hwnd) {
    if (!g_trayAdded) return;
    HINSTANCE inst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
    g_nid.uFlags = NIF_ICON;
    g_nid.hIcon = TrayIconForTheme(inst);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void TrayRemove() {
    if (!g_trayAdded) return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_trayAdded = false;
}

static void ShowFromTray(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
    g_hiddenToTray = false;
}

static void HideToTray(HWND hwnd) {
    ShowWindow(hwnd, SW_HIDE);
    g_hiddenToTray = true;

    static bool hinted = false;
    if (!hinted && g_trayAdded) {
        g_nid.uFlags = NIF_INFO;
        wcscpy_s(g_nid.szInfoTitle, L"还在后台运行");
        wcscpy_s(g_nid.szInfo, L"双击托盘图标恢复窗口，右键有菜单。");
        g_nid.dwInfoFlags = NIIF_INFO;
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
        hinted = true;
    }
}

static void TrayMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IDM_TRAY_SHOW, g_hiddenToTray ? L"显示窗口" : L"隐藏窗口");
    AppendMenuW(menu, MF_STRING, IDM_TRAY_REFRESH, L"立即刷新");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (g_ballOn ? MF_CHECKED : 0), IDM_TRAY_BALL, L"内存悬浮球");
    AppendMenuW(menu, MF_STRING, IDM_TRAY_CLEAN, L"清理内存");
    AppendMenuW(menu, MF_STRING, IDM_TRAY_THERM, L"温度与风扇");
    AppendMenuW(menu, MF_STRING | (AutostartEnabled() ? MF_CHECKED : 0), IDM_TRAY_AUTO, L"开机自启");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"退出");

    SetForegroundWindow(hwnd);          // 不先设前台，菜单点外面不会消失
    int cmd = (int)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                  pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);

    switch (cmd) {
    case IDM_TRAY_SHOW:
        if (g_hiddenToTray) ShowFromTray(hwnd);
        else HideToTray(hwnd);
        break;
    case IDM_TRAY_REFRESH:
        RefreshAsync(hwnd);
        break;
    case IDM_TRAY_BALL:
    case IDM_TRAY_CLEAN:
    case IDM_TRAY_AUTO:
    case IDM_TRAY_THERM:
        PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
        break;
    case IDM_TRAY_EXIT:
        DestroyWindow(hwnd);
        break;
    default:
        break;
    }
}

static void ApplyMode(HWND hwnd, int mode) {
    ApplyTheme(ModeToGlass(mode));
    if (g_list) {
        ListView_SetBkColor(g_list, g_theme.listBg);
        ListView_SetTextBkColor(g_list, g_theme.listBg);
        ListView_SetTextColor(g_list, C_TEXT);
        InvalidateRect(ListView_GetHeader(g_list), nullptr, TRUE);
        InvalidateRect(g_list, nullptr, FALSE);
    }
    if (g_theme.glass) EnableDwmGlass(hwnd);
    ApplyCaptionTheme(hwnd);
    // 按钮写"下一档"
    HWND btn = GetDlgItem(hwnd, ID_BTN_THEME);
    if (btn) SetWindowTextW(btn, ModeName((mode + 1) % 3));

    // 图标也跟着换：深色标题栏用亮图标，浅色标题栏用暗图标
    HINSTANCE inst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
    int iconId = g_theme.glass ? 2 : 1;
    HICON icoBig = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(iconId), IMAGE_ICON, 0, 0,
                                     LR_DEFAULTSIZE | LR_SHARED);
    HICON icoSmall = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(iconId), IMAGE_ICON, 16, 16,
                                       LR_SHARED);
    TraySetIcon(hwnd);
    if (icoBig) SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)icoBig);
    if (icoSmall) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)icoSmall);
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
}

// 列宽也要跟着 DPI 走，否则换到高分屏后列会挤成一条
static void ApplyListColumns() {
    if (!g_list) return;
    const int w[5] = { S(230), S(50), S(85), S(70), S(62) };
    for (int i = 0; i < 5; ++i) ListView_SetColumnWidth(g_list, i, w[i]);
}

// ------------------------------------------------------------------ 自绘按钮
static std::map<HWND, bool> g_hoverBtns;

static COLORREF LerpColor(COLORREF a, COLORREF b, double t) {
    t = std::max(0.0, std::min(1.0, t));
    return RGB((int)(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * t),
               (int)(GetGValue(a) + (GetGValue(b) - GetGValue(a)) * t),
               (int)(GetBValue(a) + (GetBValue(b) - GetBValue(a)) * t));
}

static void FillSolid(HDC dc, const RECT& rc, COLORREF color) {
    HBRUSH b = CreateSolidBrush(color);
    FillRect(dc, &rc, b);
    DeleteObject(b);
}

// 圆角外那四个小角要露出父窗口的底色，按父窗口的渐变位置现算一个同色
static void PaintParentBg(HDC dc, HWND btn, const RECT& rc) {
    HWND parent = GetParent(btn);
    RECT pr{};
    GetClientRect(parent, &pr);
    RECT br{};
    GetWindowRect(btn, &br);
    MapWindowPoints(nullptr, parent, (POINT*)&br, 2);

    int H = pr.bottom > 0 ? (int)pr.bottom : 1;
    if (g_theme.glass) {
        COLORREF top = LerpColor(g_theme.bg1, g_theme.bg2, (double)br.top / H);
        COLORREF bot = LerpColor(g_theme.bg1, g_theme.bg2, (double)br.bottom / H);
        VGradient(dc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, top, bot, 255, 255);
    } else {
        FillSolid(dc, rc, C_BG);
    }
}

static void OnDrawItem(LPDRAWITEMSTRUCT di) {
    if (di->CtlType != ODT_BUTTON) return;

    HDC dc = di->hDC;
    RECT rc = di->rcItem;
    const bool pressed  = (di->itemState & ODS_SELECTED) != 0;
    const bool disabled = (di->itemState & ODS_DISABLED) != 0;
    const bool focus    = (di->itemState & ODS_FOCUS) != 0;
    auto it = g_hoverBtns.find(di->hwndItem);
    const bool hover = (it != g_hoverBtns.end()) && it->second;

    PaintParentBg(dc, di->hwndItem, rc);

    COLORREF top, bot, border;
    if (g_theme.glass) {
        if (pressed)      { top = RGB(207, 230, 246); bot = RGB(191, 220, 241); border = RGB(134, 187, 220); }
        else if (hover)   { top = RGB(255, 255, 255); bot = RGB(216, 237, 251); border = RGB(121, 190, 232); }
        else              { top = RGB(255, 255, 255); bot = RGB(233, 244, 252); border = RGB(169, 203, 229); }
    } else {
        if (pressed)      { top = RGB(30, 34, 44);  bot = RGB(35, 39, 51); border = RGB(59, 65, 80); }
        else if (hover)   { top = RGB(59, 65, 87);  bot = RGB(48, 54, 71); border = RGB(85, 96, 128); }
        else              { top = RGB(51, 55, 74);  bot = RGB(40, 44, 57); border = RGB(69, 75, 95); }
    }

    const int radius = S(6);
    HRGN shape = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SelectClipRgn(dc, shape);

    VGradient(dc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, top, bot, 255, 255);
    if (!pressed && !disabled)
        FillAlpha(dc, rc.left, rc.top + S(1), rc.right - rc.left,
                  (rc.bottom - rc.top) / 2, RGB(255, 255, 255), 45);

    // 底部内亮线：给按钮一点厚度，不像贴纸
    if (!disabled)
        FillAlpha(dc, rc.left + S(2), rc.bottom - S(2), rc.right - rc.left - S(4), S(1),
                  RGB(255, 255, 255), 110);

    SelectClipRgn(dc, nullptr);
    DeleteObject(shape);

    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBr = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, rc.left, rc.top, rc.right - 1, rc.bottom - 1, radius, radius);
    SelectObject(dc, oldBr);
    SelectObject(dc, oldPen);
    DeleteObject(pen);

    wchar_t text[128]{};
    int len = GetWindowTextW(di->hwndItem, text, 128);

    HFONT f = (HFONT)SendMessageW(di->hwndItem, WM_GETFONT, 0, 0);
    HGDIOBJ oldFont = f ? SelectObject(dc, f) : nullptr;
    int oldMode = SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, disabled ? C_DIM : C_TEXT);

    RECT tr = rc;
    if (pressed) OffsetRect(&tr, 0, S(1));
    DrawTextW(dc, text, len, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    SetBkMode(dc, oldMode);
    if (oldFont) SelectObject(dc, oldFont);

    if (focus && !pressed && !hover) {   // 鼠标点击后不留虚线框，键盘 Tab 过来才显示
        RECT fr = rc;
        InflateRect(&fr, -S(4), -S(4));
        DrawFocusRect(dc, &fr);
    }
}

static LRESULT CALLBACK BtnProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme{ sizeof(tme) };
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = h;
        TrackMouseEvent(&tme);
        if (!g_hoverBtns[h]) {
            g_hoverBtns[h] = true;
            InvalidateRect(h, nullptr, FALSE);      // 自己整块重画，不用系统先擦一遍（会闪）
        }
        break;
    }
    case WM_MOUSELEAVE:
        g_hoverBtns[h] = false;
        InvalidateRect(h, nullptr, FALSE);
        break;
    case WM_SETCURSOR:
        SetCursor(LoadCursorW(nullptr, IDC_HAND));
        return TRUE;
    }
    return DefSubclassProc(h, m, w, l);
}

// 行悬停：只在换了行的时候重画那两行，避免整表闪
static LRESULT CALLBACK ListProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme{ sizeof(tme) };
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = h;
        TrackMouseEvent(&tme);

        LVHITTESTINFO ht{};
        ht.pt.x = (short)LOWORD(l);
        ht.pt.y = (short)HIWORD(l);
        int row = ListView_HitTest(h, &ht);
        if (row != g_hoverRow) {
            auto repaint = [&](int r) {
                if (r < 0) return;
                RECT rc{};
                if (ListView_GetItemRect(h, r, &rc, LVIR_BOUNDS))
                    InvalidateRect(h, &rc, FALSE);
            };
            repaint(g_hoverRow);
            g_hoverRow = row;
            repaint(g_hoverRow);
        }
        break;
    }
    case WM_MOUSELEAVE:
        g_hoverRow = -1;
        InvalidateRect(h, nullptr, FALSE);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

// 表头自绘：系统表头是灰色渐变 + 居中，和玻璃卡片不是一套语言
static LRESULT OnHeaderDraw(NMCUSTOMDRAW* cd) {
    switch (cd->dwDrawStage) {
    case CDDS_PREPAINT: {
        RECT rc{};
        GetClientRect(cd->hdr.hwndFrom, &rc);
        HBRUSH b = CreateSolidBrush(g_theme.listHead);
        FillRect(cd->hdc, &rc, b);
        DeleteObject(b);
        return CDRF_NOTIFYITEMDRAW;
    }
    case CDDS_ITEMPREPAINT: {
        RECT rc = cd->rc;
        HBRUSH b = CreateSolidBrush(g_theme.listHead);
        FillRect(cd->hdc, &rc, b);
        DeleteObject(b);

        RECT line{ rc.right - S(1), rc.top + S(8), rc.right, rc.bottom - S(8) };
        HBRUSH lb = CreateSolidBrush(g_theme.listLine);
        FillRect(cd->hdc, &line, lb);
        DeleteObject(lb);

        wchar_t text[128]{};
        HDITEMW hi{};
        hi.mask = HDI_TEXT;
        hi.pszText = text;
        hi.cchTextMax = 128;
        Header_GetItem(cd->hdr.hwndFrom, (int)cd->dwItemSpec, &hi);

        HFONT f = CreateFontW(S(13), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH, L"Microsoft YaHei UI");
        HGDIOBJ of = SelectObject(cd->hdc, f);
        int oldMode = SetBkMode(cd->hdc, TRANSPARENT);
        COLORREF oldColor = SetTextColor(cd->hdc, C_MUTED);

        RECT tr = rc;
        tr.left += S(10);
        DrawTextW(cd->hdc, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        SetTextColor(cd->hdc, oldColor);
        SetBkMode(cd->hdc, oldMode);
        SelectObject(cd->hdc, of);
        DeleteObject(f);

        RECT bottom{ rc.left, rc.bottom - S(1), rc.right, rc.bottom };
        HBRUSH bb = CreateSolidBrush(g_theme.listLine);
        FillRect(cd->hdc, &bottom, bb);
        DeleteObject(bb);
        return CDRF_SKIPDEFAULT;
    }
    }
    return CDRF_DODEFAULT;
}

// 控件字体不会自己跟着 per-monitor DPI 走，得手工按缩放重建
static HFONT g_uiFont = nullptr, g_chatTextFont = nullptr;

static void ApplyControlFonts(HWND hwnd) {
    HFONT ui = CreateFontW(S(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH, L"Microsoft YaHei UI");
    HFONT chat = CreateFontW(S(15), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH, L"Microsoft YaHei UI");

    HWND ctrls[] = { g_list, g_input, g_status };
    for (HWND c : ctrls)
        if (c) SendMessageW(c, WM_SETFONT, (WPARAM)ui, TRUE);
    if (g_chat) SendMessageW(g_chat, WM_SETFONT, (WPARAM)chat, TRUE);

    const int ids[] = { ID_BTN_WHY, ID_BTN_MEM, ID_BTN_KILL, ID_BTN_CLEAN,
                        ID_BTN_ASK, ID_BTN_REFRESH, ID_BTN_COPY, ID_BTN_THEME };
    for (int id : ids)
        if (HWND b = GetDlgItem(hwnd, id)) SendMessageW(b, WM_SETFONT, (WPARAM)ui, TRUE);

    if (g_uiFont) DeleteObject(g_uiFont);
    if (g_chatTextFont) DeleteObject(g_chatTextFont);
    g_uiFont = ui;
    g_chatTextFont = chat;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

        // 先拿到这台显示器真实的 DPI，后面的 S() 才有意义
        if (!g_dpiForced) {
            using GetDpiFn = UINT(WINAPI*)(HWND);
            auto pGetDpi = (GetDpiFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow");
            UINT d = pGetDpi ? pGetDpi(hwnd) : 0;
            if (d >= 96) g_dpi = (int)d;
        }

        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 S(18), HEADER_H + S(10), S(600), S(400), hwnd, (HMENU)ID_LIST, hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowSubclass(g_list, ListProc, 1, 0);
        ListView_SetBkColor(g_list, g_theme.listBg);
        ListView_SetTextBkColor(g_list, g_theme.listBg);
        ListView_SetTextColor(g_list, C_TEXT);

        struct { const wchar_t* t; int w; } cols[] = {
            { L"进程", 230 }, { L"实例", 50 }, { L"内存 MB", 85 }, { L"CPU 秒", 70 }, { L"风险", 62 }
        };
        for (int i = 0; i < 5; ++i) {
            LVCOLUMNW c{};
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            c.pszText = (LPWSTR)cols[i].t;
            c.cx = S(cols[i].w);
            c.iSubItem = i;
            ListView_InsertColumn(g_list, i, &c);
        }

        g_chat = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                 WS_VSCROLL | ES_AUTOVSCROLL,
                                 S(630), HEADER_H + S(10), S(350), S(300), hwnd, (HMENU)ID_CHAT, hInst, nullptr);
        g_input = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                  S(630), S(500), S(270), S(28), hwnd, (HMENU)ID_INPUT, hInst, nullptr);

        struct { int id; const wchar_t* t; int x; int y; int w; int h; } btns[] = {
            { ID_BTN_WHY,     L"为什么卡", S(630), S(538), S(88), S(30) },
            { ID_BTN_MEM,     L"谁吃内存", S(722), S(538), S(88), S(30) },
            { ID_BTN_KILL,    L"结束选中", S(814), S(538), S(88), S(30) },
            { ID_BTN_CLEAN,   L"执行建议", S(906), S(538), S(88), S(30) },
            { ID_BTN_ASK,     L"提问",     S(906), S(500), S(88), S(28) },
            { ID_BTN_REFRESH, L"刷新",     S(630), S(574), S(88), S(30) },
            { ID_BTN_COPY,    L"复制快照", S(722), S(574), S(88), S(30) },
            { ID_BTN_THEME,   L"换主题",   S(814), S(574), S(88), S(30) },
        };
        for (auto& b : btns) {
            HWND btn = CreateWindowExW(0, L"BUTTON", b.t, WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                       b.x, b.y, b.w, b.h, hwnd, (HMENU)(INT_PTR)b.id, hInst, nullptr);
            if (btn) SetWindowSubclass(btn, BtnProc, 2, 0);
        }

        // 按钮上写的是"点了会切成什么"，启动时按当前主题同步
        SetWindowTextW(GetDlgItem(hwnd, ID_BTN_THEME), ModeName((g_mode + 1) % 3));

        g_status = CreateWindowExW(0, L"STATIC", L"正在采样…", WS_CHILD | WS_VISIBLE,
                                   S(18), S(600), S(960), S(20), hwnd, (HMENU)ID_STATUS, hInst, nullptr);

        ApplyControlFonts(hwnd);
        SendMessageW(g_chat, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(S(8), S(8)));

        AppendChat(L"我是这台机器的资源分析器，可以直接问我：");
        AppendChat(L"· 为什么卡？   · 谁在吃内存？");
        AppendChat(L"· 关掉哪些？   · 模型占多少？");
        AppendChat(L"顶部曲线是最近 3 分钟的内存 / 提交 / 显存走势。");
        AppendChat(L"点右上角 × 会收到托盘；双击托盘图标恢复，右键有菜单。");

        TrayAdd(hwnd);
        if (!g_trayAdded) AppendChat(L"托盘图标添加失败（Shell_NotifyIcon 返回失败）。");

        g_ballOn = !(RegGetStr(L"ball", nullptr, 0));   // 默认开
        wchar_t pref[8]{};
        if (RegGetStr(L"ball", pref, 8)) g_ballOn = (pref[0] != L'0');
        g_ballX = (int)RegGetDword(L"ballX", 0xFFFFFFFF);
        g_ballY = (int)RegGetDword(L"ballY", 0xFFFFFFFF);
        if (g_ballOn) CreateBall(hwnd);
        return 0;
    }
    case WM_APP_SNAPSHOT:
        if (lp) OnSnapshot(hwnd, (Snapshot*)lp);   // 防御：外部误投递会被丢弃
        return 0;

    case WM_APP_SNAPSHOT + 2: {                    // 清理内存结果
        auto* r = (CleanResult*)lp;
        if (r) {
            AppendChat(Fmt(L"整理完成：%d 个进程，工作集减少 %.1f GB（转入备用内存，可立即复用）。",
                           r->count, r->freedMB / 1024.0));
            delete r;
            RefreshAsync(hwnd);
        }
        return 0;
    }

    case WM_APP_SNAPSHOT + 1:               // 托盘回调
        if (LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_LBUTTONDBLCLK) {
            if (g_hiddenToTray) ShowFromTray(hwnd);
            else HideToTray(hwnd);
        } else if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU) {
            TrayMenu(hwnd);
        }
        return 0;

    case WM_CLOSE:                          // 关窗 = 收托盘，不退出
        HideToTray(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HGDIOBJ oldBmp = SelectObject(mem, bmp);

        if (g_theme.glass && rc.bottom > HEADER_H) {
            // 整窗：天蓝渐变 + 顶部更亮
            VGradient(mem, 0, 0, rc.right, rc.bottom, g_theme.bg1, g_theme.bg2, 255, 255);
            VGradient(mem, 0, 0, rc.right, S(120), RGB(255, 255, 255), RGB(255, 255, 255), 120, 0);
        } else {
            HBRUSH bg = CreateSolidBrush(C_BG);
            RECT all{ 0, 0, rc.right, rc.bottom };
            FillRect(mem, &all, bg);
            DeleteObject(bg);
        }

        PaintHeader(mem, rc.right, HEADER_H);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        static HBRUSH br = nullptr;
        static COLORREF cur = 0xFFFFFFFF;
        if (!br || cur != C_BG) { if (br) DeleteObject(br); br = CreateSolidBrush(C_BG); cur = C_BG; }
        return (LRESULT)br;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        COLORREF bg = g_theme.glass ? RGB(255, 255, 255) : C_PANEL;
        SetBkColor(dc, bg);
        static HBRUSH br = nullptr;
        static COLORREF cur = 0xFFFFFFFF;
        if (!br || cur != bg) { if (br) DeleteObject(br); br = CreateSolidBrush(bg); cur = bg; }
        return (LRESULT)br;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_BTN_REFRESH) RefreshAsync(hwnd);
        else if (id == ID_BTN_WHY) {
            AppendChat(L"你：为什么卡？");
            AppendChat(AnalyzeWhy(g_snap));
        } else if (id == ID_BTN_MEM) {
            AppendChat(L"你：谁在吃内存？");
            std::wstring out = L"内存前 8（同名合并）：\r\n\r\n";
            int i = 1;
            for (auto& r : g_snap.rows) {
                if (i > 8) break;
                out += Fmt(L"%d. %s —— %.1f MB × %d%s\r\n", i++, r.name.c_str(), r.memMB, r.count,
                           RiskTag(r.risk).empty() ? L"" : L" [" + RiskTag(r.risk) + L"]");
            }
            AppendChat(out);
        } else if (id == ID_BTN_ASK) {
            wchar_t q[512]{};
            SendMessageW(g_input, WM_GETTEXT, 511, (LPARAM)q);
            if (q[0] == 0) { AppendChat(L"先在输入框写个问题，比如「为什么卡」。"); break; }
            AppendChat(std::wstring(L"你：") + q);
            AppendChat(AnswerQuestion(q, g_snap));
            SetWindowTextW(g_input, L"");
        } else if (id == ID_BTN_CLEAN) {
            double gain = 0;
            int n = 0;
            for (auto& r : g_snap.rows)
                if (r.risk == RISK_SAFE && r.memMB >= 80) { gain += r.memMB; n++; }
            if (!n) { AppendChat(L"没有可清理的进程。"); break; }
            std::wstring q = Fmt(L"要结束 %d 组标记为「可关」的进程吗？\r\n预计释放 %.1f GB。", n, gain / 1024.0);
            if (MessageBoxW(hwnd, q.c_str(), L"确认清理", MB_YESNO | MB_ICONQUESTION) != IDYES) break;
            std::wstring err;
            int killed = 0;
            for (auto& r : g_snap.rows)
                if (r.risk == RISK_SAFE && r.memMB >= 80) { KillPids(r.pids, err); killed++; }
            AppendChat(Fmt(L"已结束 %d 组进程。%s", killed, err.empty() ? L"" : err.c_str()));
            RefreshAsync(hwnd);
        } else if (id == ID_BTN_KILL) {
            int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_snap.rows.size()) { AppendChat(L"先在列表里选一行。"); break; }
            ProcRow r = g_snap.rows[sel];
            if (r.risk == RISK_PROTECTED) {
                MessageBoxW(hwnd, L"这是系统/本程序进程，不允许结束。", L"已阻止", MB_ICONWARNING);
                break;
            }
            std::wstring q = Fmt(L"结束 %s 的 %d 个进程？\r\n%s", r.name.c_str(), r.count, r.why.c_str());
            if (MessageBoxW(hwnd, q.c_str(), L"确认结束", MB_YESNO | MB_ICONWARNING) != IDYES) break;
            std::wstring err;
            if (KillPids(r.pids, err)) AppendChat(Fmt(L"已结束 %s（%.1f MB）。", r.name.c_str(), r.memMB));
            else AppendChat(L"部分进程结束失败：\r\n" + err);
            RefreshAsync(hwnd);
        } else if (id == ID_BTN_THEME) {
            g_mode = (g_mode + 1) % 3;
            SaveThemePref(g_mode);
            ApplyMode(hwnd, g_mode);
            AppendChat(Fmt(L"已切到「%s」%s", ModeName(g_mode),
                           g_mode == 2 ? (g_theme.glass ? L"（系统当前是浅色）" : L"（系统当前是深色）")
                                       : L""));
        } else if (id == IDM_TRAY_BALL) {
            g_ballOn = !g_ballOn;
            RegSetStr(L"ball", g_ballOn ? L"1" : L"0");
            if (g_ballOn) CreateBall(hwnd);
            else ShowWindow(g_ball, SW_HIDE);
            AppendChat(g_ballOn ? L"悬浮球已显示：单击清理内存，双击打开窗口，右键有菜单。"
                                : L"悬浮球已隐藏（托盘菜单可再开）。");
        } else if (id == IDM_TRAY_CLEAN) {
            AppendChat(L"正在整理内存…");
            std::thread([hwnd]() {
                CleanResult r = CleanMemory();
                auto* payload = new CleanResult(r);
                PostMessageW(hwnd, WM_APP_SNAPSHOT + 2, 0, (LPARAM)payload);
            }).detach();
        } else if (id == IDM_TRAY_THERM) {
            AppendChat(L"你：温度与风扇");
            AppendChat(AnswerQuestion(L"散热", g_snap));
            if (g_hiddenToTray) ShowFromTray(hwnd);
        } else if (id == IDM_TRAY_AUTO) {
            bool on = !AutostartEnabled();
            SetAutostart(on);
            AppendChat(on ? L"已设为开机自启（登录后自动进托盘）。" : L"已取消开机自启。");
        } else if (id == ID_BTN_COPY) {
            std::wstring s = AnalyzeWhy(g_snap);
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t bytes = (s.size() + 1) * sizeof(wchar_t);
                HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
                memcpy(GlobalLock(h), s.c_str(), bytes);
                GlobalUnlock(h);
                SetClipboardData(CF_UNICODETEXT, h);
                CloseClipboard();
            }
            AppendChat(L"快照分析已复制到剪贴板。");
        }
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = (MINMAXINFO*)lp;
        RECT work{};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        int workW = work.right - work.left, workH = work.bottom - work.top;
        mm->ptMinTrackSize = POINT{ std::min(S(1000), workW > 0 ? workW : S(1000)),
                                    std::min(S(700),  workH > 0 ? workH : S(700)) };
        return 0;
    }
    case WM_DPICHANGED: {
        if (!g_dpiForced) {
            g_dpi = HIWORD(wp);
            RECT* want = (RECT*)lp;
            SetWindowPos(hwnd, nullptr, want->left, want->top,
                         want->right - want->left, want->bottom - want->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            ApplyControlFonts(hwnd);
            ApplyListColumns();
            SendMessageW(hwnd, WM_SIZE, 0, 0);
            InvalidateRect(hwnd, nullptr, TRUE);
        }
        return 0;
    }
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right, h = rc.bottom;
        int listW = w - S(470);
        if (g_list) MoveWindow(g_list, S(18), HEADER_H + S(10), listW, h - HEADER_H - S(80), TRUE);
        if (g_chat) MoveWindow(g_chat, w - S(368), HEADER_H + S(10), S(350), h - HEADER_H - S(160), TRUE);
        if (g_input) MoveWindow(g_input, w - S(368), h - S(138), S(270), S(28), TRUE);

        int bx = w - S(368);
        int by = h - S(100);
        const int row1[4] = { ID_BTN_WHY, ID_BTN_MEM, ID_BTN_KILL, ID_BTN_CLEAN };
        for (int i = 0; i < 4; ++i) {
            HWND c = GetDlgItem(hwnd, row1[i]);
            if (c) MoveWindow(c, bx + i * S(92), by, S(88), S(30), TRUE);
        }
        HWND ask = GetDlgItem(hwnd, ID_BTN_ASK);
        if (ask) MoveWindow(ask, bx + S(276), h - S(138), S(88), S(28), TRUE);

        const int row2[3] = { ID_BTN_REFRESH, ID_BTN_COPY, ID_BTN_THEME };
        for (int i = 0; i < 3; ++i) {
            HWND c = GetDlgItem(hwnd, row2[i]);
            if (c) MoveWindow(c, bx + i * S(92), by + S(36), S(88), S(30), TRUE);
        }
        if (g_status) MoveWindow(g_status, S(18), h - S(34), w - S(40), S(20), TRUE);

        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_DRAWITEM:
        OnDrawItem((LPDRAWITEMSTRUCT)lp);
        return TRUE;

    case WM_NOTIFY: {
        auto* nh = (LPNMHDR)lp;
        if (nh->code == NM_CUSTOMDRAW) {
            if (g_list && nh->hwndFrom == ListView_GetHeader(g_list))
                return OnHeaderDraw((LPNMCUSTOMDRAW)lp);

            if (nh->idFrom == ID_LIST) {
                auto* cd = (LPNMLVCUSTOMDRAW)lp;
                switch (cd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    return CDRF_NOTIFYITEMDRAW;
                case CDDS_ITEMPREPAINT: {
                    int row = (int)cd->nmcd.dwItemSpec;
                    BOOL sel = ListView_GetItemState(g_list, row, LVIS_SELECTED) == LVIS_SELECTED;
                    if (sel)                    cd->clrTextBk = g_theme.listSel;
                    else if (row == g_hoverRow) cd->clrTextBk = g_theme.listHover;
                    else                        cd->clrTextBk = (row % 2) ? g_theme.listAlt : g_theme.listBg;
                    cd->clrText = C_TEXT;
                    return CDRF_NEWFONT;
                }
                default:
                    return CDRF_DODEFAULT;
                }
            }
        }
        return 0;
    }

    case WM_SETTINGCHANGE:
        if (g_mode == 2 && wp == 0 /*SPI_SETTINGCHANGE*/) ApplyMode(hwnd, g_mode);
        return 0;

    case WM_TIMER:
        RefreshAsync(hwnd);
        return 0;
    case WM_DESTROY:
        TrayRemove();
        DestroyBall();
        KillTimer(hwnd, TIMER_ID);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif
#ifndef DWMWCP_ROUND
#define DWMWCP_ROUND 2
#endif

static void EnableDwmGlass(HWND hwnd) {
    // 不开系统亚克力：客户区整块自己画，亚克力只会让 PrintWindow/截图变白，
    // 还常驻占用 GPU。玻璃感由渐变 + 高光 + 半透明面板提供。

    int pref = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &pref, sizeof(pref));
}

// 标题栏跟随主题：Win11 22000+ 支持自定义字幕/文字/边框色；Win10 调用失败，忽略
static void ApplyCaptionTheme(HWND hwnd) {
    BOOL useDark = g_theme.glass ? FALSE : TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDark, sizeof(useDark));

    COLORREF cap = g_theme.glass ? RGB(0xDC, 0xEB, 0xF7) : RGB(0x18, 0x19, 0x1F);
    COLORREF txt = g_theme.glass ? RGB(0x0F, 0x17, 0x2A) : RGB(0xE6, 0xE6, 0xEB);
    COLORREF brd = g_theme.glass ? RGB(0x92, 0xBE, 0xDE) : RGB(0x33, 0x35, 0x3F);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &cap, sizeof(cap));
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &txt, sizeof(txt));
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &brd, sizeof(brd));
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR lpCmdLine, int) {
    InitializeCriticalSection(&g_lock);
    WriteTempScript();

    bool forced = false;
    if (lpCmdLine && wcsstr(lpCmdLine, L"glass")) { g_mode = 1; forced = true; }
    if (lpCmdLine && wcsstr(lpCmdLine, L"dark"))  { g_mode = 0; forced = true; }
    if (lpCmdLine && wcsstr(lpCmdLine, L"auto"))  { g_mode = 2; forced = true; }

    wchar_t env[16]{};
    if (!forced && GetEnvironmentVariableW(L"AITM_THEME", env, 16) && env[0]) {
        if (_wcsicmp(env, L"glass") == 0) g_mode = 1;
        else if (_wcsicmp(env, L"auto") == 0) g_mode = 2;
        else g_mode = 0;
        forced = true;
    }
    if (!forced) {
        int pref = LoadThemePref();
        if (pref >= 0) g_mode = pref;
    }
    ApplyTheme(ModeToGlass(g_mode));

    InitCommonControls();

    // 悬浮球用 GDI+ 画（圆和弧要抗锯齿），其他地方仍走纯 GDI
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR gdipToken = 0;
    Gdiplus::GdiplusStartup(&gdipToken, &gsi, nullptr);

    g_weightsGB = WeightsGB();

    HDC screenDC = GetDC(nullptr);
    g_dpi = GetDeviceCaps(screenDC, LOGPIXELSX);
    ReleaseDC(nullptr, screenDC);
    g_dpiForced = InitDpiFromEnvironment();
    if (!g_dpiForced) {
        using GetDpiForSystemFn = UINT(WINAPI*)();
        auto pDpi = (GetDpiForSystemFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForSystem");
        if (pDpi) {
            UINT d = pDpi();
            if (d >= 96) g_dpi = (int)d;
        }
    }

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(g_theme.glass ? 2 : 1),
                                 IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(g_theme.glass ? 2 : 1),
                                   IMAGE_ICON, 16, 16, LR_SHARED);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"AITaskManagerWnd";
    RegisterClassExW(&wc);

    // 高 DPI 下 1000x820 会超出屏幕，按工作区裁一下
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int workW = work.right - work.left, workH = work.bottom - work.top;
    if (workW <= 0 || workH <= 0) { workW = GetSystemMetrics(SM_CXSCREEN); workH = GetSystemMetrics(SM_CYSCREEN); }
    int w = std::min(S(1000), workW);
    int h = std::min(S(820), workH);
    int x = work.left + (workW - w) / 2;
    int y = work.top + std::max(0, (workH - h) / 2);

    HWND hwnd = CreateWindowExW(0, L"AITaskManagerWnd", APP_TITLE,
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, x, y, w, h,
                                nullptr, nullptr, hInst, nullptr);
    if (g_theme.glass) EnableDwmGlass(hwnd);
    ApplyCaptionTheme(hwnd);
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)wc.hIcon);
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)wc.hIconSm);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    RefreshAsync(hwnd);
    SetTimer(hwnd, TIMER_ID, 2000, nullptr);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    Gdiplus::GdiplusShutdown(gdipToken);
    return 0;
}
