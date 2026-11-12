// 结束进程前的身份核对 —— 自检程序
// 直接 #include 主程序，用真实进程跑一遍「该杀 / 不该杀」的判定，避免只靠肉眼读代码。
// 编译运行（先跑一次 build.bat 生成 build 目录）：
//   cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 ^
//      /Fo:build\ tools\safety_selftest.cpp /Fe:build\safety_selftest.exe
//   build\safety_selftest.exe
// 全部通过时退出码 0，有失败用例时非 0，可以直接挂到 CI 上。
#define AITM_NO_ENTRY
#include "../src/main.cpp"

#include <cstdio>

static int g_fail = 0;

static void Check(bool cond, const wchar_t* what, const std::wstring& note = L"") {
    wprintf(L"[%s] %s%s%s\n", cond ? L"PASS" : L"FAIL", what,
            note.empty() ? L"" : L"  —— ", note.c_str());
    if (!cond) g_fail++;
}

// 用 ping 当靶子：它自己会睡 40 秒，没有子进程，杀了不留孤儿
static bool SpawnSleeper(DWORD& pid) {
    wchar_t cmd[] = L"ping.exe -n 40 127.0.0.1";
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    pid = pi.dwProcessId;
    return true;
}

static ProcIdent IdentOf(DWORD pid, const wchar_t* image) {
    ProcIdent id;
    id.pid = pid;
    id.image = image;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        FILETIME c{}, e{}, k{}, u{};
        if (GetProcessTimes(h, &c, &e, &k, &u)) id.start = FileTimeToU64(c);
        CloseHandle(h);
    }
    return id;
}

static bool StillAlive(DWORD pid) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    bool alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return alive;
}

static void KillRaw(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) { TerminateProcess(h, 0); CloseHandle(h); }
}

static bool DeadWithin(DWORD pid, DWORD ms) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return true;
    bool dead = WaitForSingleObject(h, ms) == WAIT_OBJECT_0;
    CloseHandle(h);
    return dead;
}

int wmain() {
    // 1. 身份对得上：应该杀掉
    {
        DWORD pid = 0;
        if (!SpawnSleeper(pid)) { Check(false, L"启动测试进程"); return 1; }
        KillReport r = KillPids({ IdentOf(pid, L"ping.exe") });
        Check(r.killed == 1, L"身份一致的目标被结束", Fmt(L"killed=%d", r.killed));
        Check(DeadWithin(pid, 3000), L"目标确实退出了");
    }

    // 2. pid 复用的等价场景：创建时间对不上，必须放过
    {
        DWORD pid = 0;
        if (!SpawnSleeper(pid)) { Check(false, L"启动测试进程"); return 1; }
        ProcIdent id = IdentOf(pid, L"ping.exe");
        id.start += 10000000;                    // 往前错 1 秒 = 另一个进程的创建时间
        KillReport r = KillPids({ id });
        Check(r.killed == 0 && r.skipped == 1, L"创建时间不符的目标被跳过",
              Fmt(L"killed=%d skipped=%d", r.killed, r.skipped));
        Check(StillAlive(pid), L"被跳过的进程还活着");
        KillRaw(pid);
    }

    // 3. 映像名对不上：也放过
    {
        DWORD pid = 0;
        if (!SpawnSleeper(pid)) { Check(false, L"启动测试进程"); return 1; }
        KillReport r = KillPids({ IdentOf(pid, L"notepad.exe") });
        Check(r.killed == 0 && r.skipped == 1, L"映像名不符的目标被跳过",
              Fmt(L"killed=%d skipped=%d", r.killed, r.skipped));
        Check(StillAlive(pid), L"被跳过的进程还活着");
        KillRaw(pid);
    }

    // 4. 快照时读不到创建时间：身份未知，宁可不动
    {
        DWORD pid = 0;
        if (!SpawnSleeper(pid)) { Check(false, L"启动测试进程"); return 1; }
        ProcIdent id = IdentOf(pid, L"ping.exe");
        id.start = 0;
        KillReport r = KillPids({ id });
        Check(r.killed == 0 && r.skipped == 1, L"身份未知的目标被跳过",
              Fmt(L"killed=%d skipped=%d", r.killed, r.skipped));
        Check(StillAlive(pid), L"被跳过的进程还活着");
        KillRaw(pid);
    }

    // 5. 目标是本程序自己：绝不下手
    {
        DWORD self = GetCurrentProcessId();
        KillReport r = KillPids({ IdentOf(self, L"safety_selftest.exe") });
        Check(r.killed == 0 && r.skipped == 1, L"拒绝结束自身进程",
              Fmt(L"killed=%d skipped=%d", r.killed, r.skipped));
    }

    // 6. 目标已经自己退出：算 gone，不当失败
    {
        DWORD pid = 0;
        if (!SpawnSleeper(pid)) { Check(false, L"启动测试进程"); return 1; }
        ProcIdent id = IdentOf(pid, L"ping.exe");
        KillRaw(pid);
        DeadWithin(pid, 3000);
        KillReport r = KillPids({ id });
        Check(r.killed == 0 && r.gone == 1, L"已退出的目标记为 gone",
              Fmt(L"killed=%d gone=%d", r.killed, r.gone));
    }

    wprintf(L"\n%s（失败 %d 项）\n", g_fail ? L"存在失败用例" : L"全部通过", g_fail);
    return g_fail ? 1 : 0;
}
