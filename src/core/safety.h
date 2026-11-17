#pragma once
#include "collector.h"
#include "format.h"
struct KillReport {
    int killed = 0;      // 真结束了
    int pending = 0;     // termination requested; exit not yet observed
    int gone = 0;        // 动手前自己退出了，无需处理
    int skipped = 0;     // 身份对不上 / 系统关键进程，主动放过
    int failed = 0;      // 有权限但没结束成功
    std::wstring detail;
};

// Unknown critical status fails closed, including API failure.
enum class CriticalState { Unknown, Critical, NotCritical };
static CriticalState CriticalStatus(HANDLE h) {
    using Fn = BOOL (WINAPI*)(HANDLE, PBOOL);
    static Fn fn = (Fn)(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical");
    if (!fn) return CriticalState::Unknown;
    BOOL critical = FALSE;
    if (!fn(h, &critical)) return CriticalState::Unknown;
    return critical ? CriticalState::Critical : CriticalState::NotCritical;
}

// 校验的是「这个句柄指向的进程」是否还是快照里那一个：创建时间必须一致，映像名也要一致。
// 时间对不上说明 pid 已被复用，名字对不上说明记录本身就串了——两种情况都不许杀。
static bool VerifyIdentity(HANDLE h, const ProcIdent& want, std::wstring& why) {
    if (GetProcessId(h) != want.pid) {
        why = L"句柄 PID 与快照不同"; return false;
    }
    if (want.start == 0 || want.path.empty()) {
        why = L"快照身份不完整，无法核对";
        return false;
    }

    FILETIME ct{}, et{}, kt{}, ut{};
    if (!GetProcessTimes(h, &ct, &et, &kt, &ut)) {
        why = Fmt(L"读创建时间失败（%u）", GetLastError());
        return false;
    }
    if (FileTimeToU64(ct) != want.start) {
        why = L"创建时间对不上，pid 已被别的进程复用";
        return false;
    }

    wchar_t path[32768]{};
    DWORD n = (DWORD)(sizeof(path) / sizeof(path[0]));
    if (!QueryFullProcessImageNameW(h, 0, path, &n)) {
        why = Fmt(L"读映像路径失败（%u），无法确认是不是它", GetLastError());
        return false;
    }
    if (Lower(path) != want.path) {
        why = L"完整映像路径不一致"; return false;
    }
    std::wstring base = path;
    size_t slash = base.find_last_of(L"\\/");
    if (slash != std::wstring::npos) base = base.substr(slash + 1);
    if (Lower(base) != want.image) {
        why = Fmt(L"映像名是 %s，已经不是快照里那个进程", base.c_str());
        return false;
    }
    return true;
}

static KillReport KillPids(const std::vector<ProcIdent>& procs) {
    KillReport rep;
    const DWORD selfPid = GetCurrentProcessId();
    const auto deadline = GetTickCount64() + 250; // bounded across the entire group, not per PID

    for (const auto& want : procs) {
        if (want.pid == 0 || want.pid == 4 || want.pid == selfPid || ProtectedImage(want.image)) { rep.skipped++; continue; }

        HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                               FALSE, want.pid);
        if (!h) {
            DWORD e = GetLastError();
            if (e == ERROR_INVALID_PARAMETER) rep.gone++;   // 这个 pid 上已经没有进程了
            else {
                rep.failed++;
                rep.detail += Fmt(L"· pid %u 打不开（%u）\r\n", want.pid, e);
            }
            continue;
        }

        if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) {     // 打开即已退出
            rep.gone++;
            CloseHandle(h);
            continue;
        }

        std::wstring why;
        if (!VerifyIdentity(h, want, why)) {
            rep.skipped++;
            rep.detail += Fmt(L"· pid %u 已跳过：%s\r\n", want.pid, why.c_str());
            CloseHandle(h);
            continue;
        }

        const auto critical = CriticalStatus(h);
        if (critical != CriticalState::NotCritical) {
            rep.skipped++;
            rep.detail += Fmt(L"· pid %u（%s）%s，已拦截\r\n",
                              want.pid, want.image.c_str(), critical == CriticalState::Unknown ?
                              L"无法读取关键状态" : L"是系统关键进程");
            CloseHandle(h);
            continue;
        }

        if (TerminateProcess(h, 1)) {
            const auto tick = GetTickCount64();
            const DWORD remaining = tick < deadline ? (DWORD)(deadline - tick) : 0;
            if (WaitForSingleObject(h, remaining) == WAIT_OBJECT_0) rep.killed++;
            else { rep.pending++; rep.detail += Fmt(L"· pid %u 已请求终止，但尚未确认退出\r\n", want.pid); }
        } else {
            DWORD e = GetLastError();
            rep.failed++;
            rep.detail += Fmt(L"· pid %u 结束失败（%u）\r\n", want.pid, e);
        }
        CloseHandle(h);
    }
    return rep;
}

static void MergeKillReport(KillReport& dst, const KillReport& src) {
    dst.killed += src.killed;
    dst.pending += src.pending;
    dst.gone += src.gone;
    dst.skipped += src.skipped;
    dst.failed += src.failed;
    dst.detail += src.detail;
}

static std::wstring KillSummary(const KillReport& rep) {
    std::wstring s = Fmt(L"结束 %d 个", rep.killed);
    if (rep.pending) s += Fmt(L"，%d 个已请求终止但退出待确认", rep.pending);
    if (rep.gone)    s += Fmt(L"，%d 个已自行退出", rep.gone);
    if (rep.skipped) s += Fmt(L"，%d 个身份核对不通过已放过", rep.skipped);
    if (rep.failed)  s += Fmt(L"，%d 个失败（权限或系统保护）", rep.failed);
    s += L"。";
    if (!rep.detail.empty()) s += L"\r\n" + rep.detail;
    return s;
}

// 确认框里把目标摊开写：名字、个数、占用。默认按钮落在「否」，回车不会误成「是」。
// 目标按值传进来：确认框是模态的，这期间定时刷新会重建 g_snap.rows，
// 外面还拿着行指针就会指向已释放的内存。
static bool ConfirmTerminate(HWND owner, const wchar_t* title, const std::wstring& head,
                             const std::vector<ProcRow>& rows, const std::wstring& tail) {
    // One bounded page per target: no hidden/truncated targets can be approved.
    // Collect all approvals before returning; cancellation performs zero terminations.
    for (const auto& row : rows) {
        for (const auto& id : row.pids) {
            std::wstring text = head + L"\r\n\r\n" + row.name +
                Fmt(L"\r\nPID %u · creation %llu\r\n", id.pid, id.start) +
                id.path + L"\r\n\r\n" + tail;
            if (text.size() > 3000) {
                MessageBoxW(owner, L"目标信息过长，无法完整展示，已取消。", title, MB_ICONWARNING);
                return false;
            }
            if (MessageBoxW(owner, text.c_str(), title,
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return false;
        }
    }
    return !rows.empty();
}



