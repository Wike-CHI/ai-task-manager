#pragma once
#include <utility>
#include "process_identity.h"
#include "policy.h"
#include <algorithm>
#include "format.h"
struct KillReport {
    int closed = 0;      // exited after a normal close request
    int kept = 0;        // still running; force not approved
    int killed = 0;      // 真结束了
    int pending = 0;     // termination requested; exit not yet observed
    int gone = 0;        // 动手前自己退出了，无需处理
    int skipped = 0;     // 身份对不上 / 系统关键进程，主动放过
    int failed = 0;      // 有权限但没结束成功
    std::wstring detail;
};

enum class ForceAuthorization { None, ExplicitUserApproval };
static KillReport KillPids(const std::vector<ProcIdent>& procs, ForceAuthorization authorization) {
    KillReport rep;
    if (authorization != ForceAuthorization::ExplicitUserApproval) {
        rep.skipped = (int)procs.size(); return rep;
    }
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

struct GracefulReport {
    KillReport report;
    std::vector<ProcIdent> remaining;
};
struct CloseWindowContext { HANDLE process; const ProcIdent* identity; int posted = 0; };
static BOOL CALLBACK PostVerifiedClose(HWND window, LPARAM data) {
    auto& ctx = *reinterpret_cast<CloseWindowContext*>(data);
    DWORD pid = 0;
    const DWORD thread = GetWindowThreadProcessId(window, &pid);
    if (!thread || pid != ctx.identity->pid) return TRUE;
    std::wstring why;
    // Keep the process handle alive while discovering and messaging its windows.
    if (WaitForSingleObject(ctx.process, 0) != WAIT_TIMEOUT ||
        !VerifyIdentity(ctx.process, *ctx.identity, why)) return TRUE;
    // HWNDs can be recycled independently of retained process handles. Recheck
    // both owner identifiers after identity I/O, immediately before posting.
    // Win32 provides no atomic external HWND ownership lock; this is best-effort.
    DWORD currentPid = 0;
    const DWORD currentThread = GetWindowThreadProcessId(window, &currentPid);
    if (currentPid != pid || currentThread != thread) return TRUE;
    if (PostMessageW(window, WM_CLOSE, 0, 0)) ++ctx.posted;
    return TRUE;
}
static GracefulReport RequestGracefulClose(const std::vector<ProcIdent>& procs, DWORD waitMs = 1500) {
    GracefulReport result;
    struct Pending { HANDLE handle; ProcIdent identity; };
    std::vector<Pending> pending;
    for (const auto& want : procs) {
        if (!want.pid || want.pid == 4 || want.pid == GetCurrentProcessId() || ProtectedImage(want.image)) {
            ++result.report.skipped; continue;
        }
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, want.pid);
        if (!h) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) ++result.report.gone;
            else ++result.report.failed;
            continue;
        }
        if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) {
            ++result.report.gone; CloseHandle(h); continue;
        }
        std::wstring why;
        if (!VerifyIdentity(h, want, why) || CriticalStatus(h) != CriticalState::NotCritical) {
            ++result.report.skipped; CloseHandle(h); continue;
        }
        CloseWindowContext ctx{h, &want};
        EnumWindows(PostVerifiedClose, reinterpret_cast<LPARAM>(&ctx));
        result.report.detail += Fmt(ctx.posted ? L"· pid %u 已请求正常关闭（WM_CLOSE）\r\n" :
            L"· pid %u 没有可发送关闭请求的窗口，不自动强制结束\r\n", want.pid);
        pending.push_back({h, want});
    }
    // One bounded observation budget for the batch; apps may keep save prompts open.
    const auto deadline = GetTickCount64() + std::min<DWORD>(waitMs, 1500);
    for (const auto& item : pending) {
        const auto now = GetTickCount64();
        if (WaitForSingleObject(item.handle, now < deadline ? (DWORD)(deadline - now) : 0) == WAIT_OBJECT_0)
            ++result.report.closed;
        else result.remaining.push_back(item.identity);
        CloseHandle(item.handle);
    }
    return result;
}

static void MergeKillReport(KillReport& dst, const KillReport& src) {
    dst.closed += src.closed;
    dst.kept += src.kept;
    dst.killed += src.killed;
    dst.pending += src.pending;
    dst.gone += src.gone;
    dst.skipped += src.skipped;
    dst.failed += src.failed;
    dst.detail += src.detail;
}

static std::wstring KillSummary(const KillReport& rep) {
    std::wstring s = Fmt(L"观察到退出 %d 个，强制结束 %d 个", rep.closed, rep.killed);
    if (rep.kept) s += Fmt(L"，%d 个保留运行（未授权强制）", rep.kept);
    if (rep.pending) s += Fmt(L"，%d 个已请求终止但退出待确认", rep.pending);
    if (rep.gone)    s += Fmt(L"，%d 个已自行退出", rep.gone);
    if (rep.skipped) s += Fmt(L"，%d 个身份核对不通过已放过", rep.skipped);
    if (rep.failed)  s += Fmt(L"，%d 个失败（权限或系统保护）", rep.failed);
    s += L"。";
    if (!rep.detail.empty()) s += L"\r\n" + rep.detail;
    return s;
}

#include "confirmation.h"
#include "signature.h"
static constexpr UINT TerminationPromptFlags = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2;

// Every action starts with normal WM_CLOSE, never implicit force. Signature is
// file evidence only, not proof of application state or permission to terminate.
static bool ConfirmAndTerminate(HWND owner, const wchar_t* title, const std::wstring& head,
                               std::vector<ProcRow> rows, const std::wstring& tail,
                               KillReport& report) {
    auto prompt = [&](const ProcRow& row, const ProcIdent& id, bool force) {
        const auto signature = InspectExecutableSignature(id.path);
        const std::wstring text = (force ? L"正常退出未完成。是否确实需要强制结束？未保存内容可能丢失。" :
            L"先请求正常关闭，应用可显示保存提示；此批准不包含强制结束。") +
            std::wstring(L"\r\n") + head + L"\r\n" + row.name +
            Fmt(L"\r\nPID %u · Parent PID %u · creation %llu\r\n", id.pid, id.parentPid, id.start) +
            id.path + L"\r\n" + ClassificationEvidence(id.image) + L"\r\n" +
            SignatureEvidenceText(signature) + L"\r\n\r\n" + tail;
        if (text.size() > 3000) {
            MessageBoxW(owner, L"目标信息过长，无法完整展示，已取消。", title, MB_ICONWARNING);
            return ConfirmationDecision::Reject;
        }
        return MessageBoxW(owner, text.c_str(), force ? L"单独授权强制结束" : title,
            TerminationPromptFlags) == IDYES ? ConfirmationDecision::Approve : ConfirmationDecision::Reject;
    };
    const auto result = RunConfirmedTermination(std::move(rows),
        [&](const ProcRow& row, const ProcIdent& id) { return prompt(row, id, false); },
        [&](const std::vector<ProcIdent>& identities) {
            auto normal = RequestGracefulClose(identities);
            report = normal.report;
            if (normal.remaining.empty()) return;
            ProcRow unresolved; unresolved.name = L"正常退出未完成的冻结目标";
            unresolved.pids = normal.remaining;
            auto force = RunConfirmedTermination({unresolved},
                [&](const ProcRow& row, const ProcIdent& id) { return prompt(row, id, true); },
                [&](const std::vector<ProcIdent>& approved) {
                    MergeKillReport(report, KillPids(approved, ForceAuthorization::ExplicitUserApproval));
                });
            if (force == ConfirmationResult::Cancelled) report.kept += (int)normal.remaining.size();
        });
    return result == ConfirmationResult::Executed;
}
