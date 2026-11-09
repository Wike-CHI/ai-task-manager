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
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <cmath>
#include <fstream>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "dwmapi.lib")
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
#define HEADER_H   276
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

struct Sample { double ram, com, vram, gpu; };

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

static Sample g_hist[HIST_MAX];
static int g_histCount = 0;
static int g_histHead = 0;
static double g_weightsGB = 0;

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
    std::wstring path = std::wstring(tmp) + L"aitm_gpu.txt";
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

static void ReadGpu(Snapshot& s) {
    std::wstring out;
    RunHidden(L"cmd /c \"\"C:\\Windows\\System32\\nvidia-smi.exe\" --query-gpu=utilization.gpu,"
              L"memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits\"", out);
    if (out.empty()) { s.hasGpu = false; return; }
    double a = 0, b = 0, c = 0, d = 0;
    if (swscanf_s(out.c_str(), L"%lf , %lf , %lf , %lf", &a, &b, &c, &d) >= 3) {
        s.hasGpu = true;
        s.gpuUtil = a;
        s.vramUsed = b / 1024.0;
        s.vramTotal = c / 1024.0;
        s.gpuTemp = d;
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
              s.vramTotal > 0 ? s.vramUsed / s.vramTotal * 100.0 : 0.0, s.gpuUtil };
    g_hist[g_histHead] = x;
    g_histHead = (g_histHead + 1) % HIST_MAX;
    if (g_histCount < HIST_MAX) g_histCount++;
}

// ------------------------------------------------------------------ 主题
struct Theme {
    bool glass = false;
    COLORREF bg1, bg2, panel, text, muted, dim, grid, borderTop, borderBottom;
    COLORREF listBg, listAlt, listSel;
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
        g_theme.listBg  = RGB(247, 251, 254);
        g_theme.listAlt = RGB(236, 246, 252);
        g_theme.listSel = RGB(198, 226, 245);
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
        g_theme.listAlt = RGB(36, 38, 46);
        g_theme.listSel = RGB(45, 62, 84);
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
    VGradient(dc, 0, 0, w, 46, RGB(255, 255, 255), RGB(255, 255, 255), 138, 0);

    HRGN sheen = CreateEllipticRgn(w / 2 - 300, -46, w / 2 + 300, 62);
    SelectClipRgn(dc, sheen);
    FillAlpha(dc, 0, 0, w, 60, RGB(255, 255, 255), 85);
    SelectClipRgn(dc, nullptr);
    DeleteObject(sheen);

    HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
    HGDIOBJ old = SelectObject(dc, pen);
    MoveToEx(dc, 0, 46, nullptr);
    LineTo(dc, w, 46);
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
    TextAt(dc, x + 62, y, C_TEXT, value);
    DrawBar(dc, x, y + 18, 220, 10, pct, color);
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

    const int plotX = x + 48, plotW = w - 60, plotH = h - 10;
    auto toY = [&](double v) {
        v = std::max(vmin, std::min(vmax, v));
        return y + h - 4 - (int)((v - vmin) / (vmax - vmin) * (plotH - 8));
    };

    HPEN grid = CreatePen(PS_DOT, 1, C_GRID);
    HPEN oldPen = (HPEN)SelectObject(dc, grid);
    for (int i = 0; i <= 4; ++i) {
        int gy = y + 4 + (plotH - 8) * i / 4;
        MoveToEx(dc, plotX, gy, nullptr);
        LineTo(dc, plotX + plotW, gy);
        double v = vmax - (vmax - vmin) * i / 4;
        TextAt(dc, x + 4, gy - 7, C_DIM, Fmt(L"%.0f%%", v));
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
            int px = plotX + (int)(i * step);
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

    int lx = x + w - 300;
    TextAt(dc, lx, y + 2, C_GREEN, Fmt(L"● 内存 %.0f%%", ramNow));
    TextAt(dc, lx + 106, y + 2, C_AMBER, Fmt(L"● 提交 %.0f%%", comNow));
    TextAt(dc, lx + 214, y + 2, C_BLUE, Fmt(L"● 显存 %.0f%%", gpuNow));
}

static void PaintHeader(HDC dc, int w, int h) {
    HFONT font = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH, L"Microsoft YaHei UI");
    HGDIOBJ old = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);

    if (g_theme.glass) {
        GlossBand(dc, w);
        GlassPanel(dc, 14, 52, w - 28, h - 58, 10);
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

    PaintStat(dc, 30, 64, L"内存", Fmt(L"%.1f / %.1f GB (%.0f%%)", s.ramUsedGB, s.ramTotalGB, s.ramPct),
              s.ramPct, ramColor);
    PaintStat(dc, 30, 104, L"提交", Fmt(L"%.1f / %.1f GB (%.0f%%)", s.comUsedGB, s.comTotalGB, s.comPct),
              s.comPct, comColor);
    PaintStat(dc, 282, 64, L"显存", s.hasGpu ? Fmt(L"%.1f / %.1f GB", s.vramUsed, s.vramTotal) : L"无 N 卡",
              vpct, vColor);
    PaintStat(dc, 282, 104, L"GPU", s.hasGpu ? Fmt(L"%.0f%%  %.0f°C", s.gpuUtil, s.gpuTemp) : L"—",
              s.gpuUtil, C_BLUE);

    TextAt(dc, 532, 66, C_MUTED, Fmt(L"CPU %.0f%%    %d 个进程", s.cpuPct, s.procCount));
    TextAt(dc, 532, 94, C_MUTED, L"模型占用");
    if (s.modelRunning)
        TextAt(dc, 532, 112, C_TEXT,
               Fmt(L"显存 %.1f GB · 内存 %.2f GB · 权重 %.1f GB", s.vramUsed, s.modelMemGB, g_weightsGB));
    else
        TextAt(dc, 532, 112, C_DIM, Fmt(L"未运行（权重 %.1f GB）", g_weightsGB));

    PaintChart(dc, 24, 136, w - 48, 90);

    TextAt(dc, 28, 232, C_DIM, Fmt(L"最近 %.0f 秒", g_histCount * 2.0));
    TextAt(dc, w - 60, 232, C_DIM, L"现在");
    TextAt(dc, 24, 248, C_MUTED, Fmt(L"趋势：%s", TrendText().c_str()));

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
    SetWindowTextW(g_status, Fmt(L"%02d:%02d:%02d   内存 %.1f/%.1f GB（%.0f%%）   提交 %.1f/%.1f GB（%.0f%%）   进程 %d   CPU %.0f%%",
                                 st.wHour, st.wMinute, st.wSecond,
                                 g_snap.ramUsedGB, g_snap.ramTotalGB, g_snap.ramPct,
                                 g_snap.comUsedGB, g_snap.comTotalGB, g_snap.comPct,
                                 g_snap.procCount, g_snap.cpuPct).c_str());
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

static void ApplyMode(HWND hwnd, int mode) {
    ApplyTheme(ModeToGlass(mode));
    if (g_list) {
        ListView_SetBkColor(g_list, g_theme.listBg);
        ListView_SetTextBkColor(g_list, g_theme.listBg);
        ListView_SetTextColor(g_list, C_TEXT);
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
    if (icoBig) SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)icoBig);
    if (icoSmall) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)icoSmall);
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_FRAME);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 18, HEADER_H + 10, 600, 400, hwnd, (HMENU)ID_LIST, hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
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
            c.cx = cols[i].w;
            c.iSubItem = i;
            ListView_InsertColumn(g_list, i, &c);
        }

        g_chat = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                 WS_VSCROLL | ES_AUTOVSCROLL,
                                 630, HEADER_H + 10, 350, 300, hwnd, (HMENU)ID_CHAT, hInst, nullptr);
        g_input = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                  WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                  630, 500, 270, 28, hwnd, (HMENU)ID_INPUT, hInst, nullptr);

        struct { int id; const wchar_t* t; int x; int y; int w; int h; } btns[] = {
            { ID_BTN_WHY,     L"为什么卡", 630, 538, 88, 30 },
            { ID_BTN_MEM,     L"谁吃内存", 722, 538, 88, 30 },
            { ID_BTN_KILL,    L"结束选中", 814, 538, 88, 30 },
            { ID_BTN_CLEAN,   L"执行建议", 906, 538, 88, 30 },
            { ID_BTN_ASK,     L"提问",     906, 500, 88, 28 },
            { ID_BTN_REFRESH, L"刷新",     630, 574, 88, 30 },
            { ID_BTN_COPY,    L"复制快照", 722, 574, 88, 30 },
            { ID_BTN_THEME,   L"换主题",   814, 574, 88, 30 },
        };
        for (auto& b : btns)
            CreateWindowExW(0, L"BUTTON", b.t, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            b.x, b.y, b.w, b.h, hwnd, (HMENU)(INT_PTR)b.id, hInst, nullptr);

        // 按钮上写的是"点了会切成什么"，启动时按当前主题同步
        SetWindowTextW(GetDlgItem(hwnd, ID_BTN_THEME), ModeName((g_mode + 1) % 3));

        g_status = CreateWindowExW(0, L"STATIC", L"正在采样…", WS_CHILD | WS_VISIBLE,
                                   18, 600, 960, 20, hwnd, (HMENU)ID_STATUS, hInst, nullptr);

        HFONT chatFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                     OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                     DEFAULT_PITCH, L"Microsoft YaHei UI");
        SendMessageW(g_chat, WM_SETFONT, (WPARAM)chatFont, TRUE);
        SendMessageW(g_chat, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(8, 8));

        AppendChat(L"我是这台机器的资源分析器，可以直接问我：");
        AppendChat(L"· 为什么卡？   · 谁在吃内存？");
        AppendChat(L"· 关掉哪些？   · 模型占多少？");
        AppendChat(L"顶部曲线是最近 3 分钟的内存 / 提交 / 显存走势。");
        return 0;
    }
    case WM_APP_SNAPSHOT:
        OnSnapshot(hwnd, (Snapshot*)lp);
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
            VGradient(mem, 0, 0, rc.right, 120, RGB(255, 255, 255), RGB(255, 255, 255), 120, 0);
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
        mm->ptMinTrackSize = POINT{ 1000, 700 };
        return 0;
    }
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right, h = rc.bottom;
        int listW = w - 470;
        if (g_list) MoveWindow(g_list, 18, HEADER_H + 10, listW, h - HEADER_H - 80, TRUE);
        if (g_chat) MoveWindow(g_chat, w - 368, HEADER_H + 10, 350, h - HEADER_H - 160, TRUE);
        if (g_input) MoveWindow(g_input, w - 368, h - 138, 270, 28, TRUE);

        int bx = w - 368;
        int by = h - 100;
        const int row1[4] = { ID_BTN_WHY, ID_BTN_MEM, ID_BTN_KILL, ID_BTN_CLEAN };
        for (int i = 0; i < 4; ++i) {
            HWND c = GetDlgItem(hwnd, row1[i]);
            if (c) MoveWindow(c, bx + i * 92, by, 88, 30, TRUE);
        }
        HWND ask = GetDlgItem(hwnd, ID_BTN_ASK);
        if (ask) MoveWindow(ask, bx + 276, h - 138, 88, 28, TRUE);

        const int row2[3] = { ID_BTN_REFRESH, ID_BTN_COPY, ID_BTN_THEME };
        for (int i = 0; i < 3; ++i) {
            HWND c = GetDlgItem(hwnd, row2[i]);
            if (c) MoveWindow(c, bx + i * 92, by + 36, 88, 30, TRUE);
        }
        if (g_status) MoveWindow(g_status, 18, h - 34, w - 40, 20, TRUE);

        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_NOTIFY: {
        auto* nh = (LPNMHDR)lp;
        if (nh->idFrom == ID_LIST && nh->code == NM_CUSTOMDRAW) {
            auto* cd = (LPNMLVCUSTOMDRAW)lp;
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                int row = (int)cd->nmcd.dwItemSpec;
                BOOL sel = ListView_GetItemState(g_list, row, LVIS_SELECTED) == LVIS_SELECTED;
                cd->clrTextBk = sel ? g_theme.listSel : (row % 2 ? g_theme.listAlt : g_theme.listBg);
                cd->clrText = C_TEXT;
                return CDRF_NEWFONT;
            }
            default:
                return CDRF_DODEFAULT;
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
    g_weightsGB = WeightsGB();

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

    int w = 1000, h = 820;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = std::max(0, (GetSystemMetrics(SM_CYSCREEN) - h) / 2);

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
    return 0;
}
