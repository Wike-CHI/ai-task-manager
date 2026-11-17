// Windows integration tests. Every target is a child created by this executable.
// No existing user application or system process is used as a termination target.
#include "../src/core/safety.h"
#include <cstdio>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")

static int failures = 0, cases = 0;
static void Check(bool condition, const char* name) {
    ++cases;
    if (!condition) ++failures;
    printf("%s %s\n", condition ? "PASS" : "FAIL", name);
}

static HANDLE childReceived = nullptr;
static bool childReject = false;
static LRESULT CALLBACK ChildWindow(HWND window, UINT message, WPARAM w, LPARAM l) {
    if (message == WM_CLOSE) {
        SetEvent(childReceived);
        if (!childReject) DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(window, message, w, l);
}
static int ChildMain(const wchar_t* mode, const wchar_t* readyName, const wchar_t* receivedName) {
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyName);
    childReceived = OpenEventW(EVENT_MODIFY_STATE, FALSE, receivedName);
    if (!ready || !childReceived) return 10;
    if (wcscmp(mode, L"no-window") == 0) {
        SetEvent(ready); CloseHandle(ready);
        Sleep(60000); // Bounded lifetime even if the parent test crashes.
        CloseHandle(childReceived); return 0;
    }
    childReject = wcscmp(mode, L"reject") == 0;
    WNDCLASSW wc{};
    wc.lpfnWndProc = ChildWindow;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"AITM_Disposable_Graceful_Test";
    if (!RegisterClassW(&wc)) return 11;
    HWND window = CreateWindowExW(0, wc.lpszClassName, L"Disposable test child", WS_OVERLAPPED,
        0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
    if (!window) return 12;
    // Hidden top-level window. The application itself decides how to honor WM_CLOSE.
    SetTimer(window, 1, 60000, nullptr);
    SetEvent(ready); CloseHandle(ready);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_TIMER) { DestroyWindow(window); continue; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    CloseHandle(childReceived); return 0;
}

struct Child {
    HANDLE process = nullptr, ready = nullptr, received = nullptr;
    DWORD pid = 0;
    Child() = default;
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    ~Child() {
        // Only the CreateProcess handle owned by this fixture is ever cleaned up.
        if (process) {
            if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                TerminateProcess(process, 99);
                WaitForSingleObject(process, 3000);
            }
            CloseHandle(process);
        }
        if (ready) CloseHandle(ready);
        if (received) CloseHandle(received);
    }
    bool Start(const wchar_t* mode) {
        static unsigned sequence = 0;
        const auto prefix = Fmt(L"Local\\AITM_grace_%u_%llu_%u", GetCurrentProcessId(),
                               GetTickCount64(), ++sequence);
        const auto readyName = prefix + L"_ready", receivedName = prefix + L"_received";
        ready = CreateEventW(nullptr, TRUE, FALSE, readyName.c_str());
        received = CreateEventW(nullptr, TRUE, FALSE, receivedName.c_str());
        if (!ready || !received) return false;
        wchar_t exe[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, exe, 32768);
        if (!length || length >= 32768) return false;
        std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --child " + mode +
            L" \"" + readyName + L"\" \"" + receivedName + L"\"";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        if (!CreateProcessW(exe, &cmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &startup, &info)) return false;
        CloseHandle(info.hThread); process = info.hProcess; pid = info.dwProcessId;
        return WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
    }
    bool Alive() const { return process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT; }
    bool Received(DWORD timeout = 0) const { return WaitForSingleObject(received, timeout) == WAIT_OBJECT_0; }
    ProcIdent Identity() const {
        ProcIdent id; id.pid = pid;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (GetProcessTimes(process, &created, &exited, &kernel, &user)) id.start = FileTimeToU64(created);
        wchar_t path[32768]{}; DWORD size = 32768;
        if (QueryFullProcessImageNameW(process, 0, path, &size)) {
            id.path = Lower(path);
            const auto slash = id.path.find_last_of(L"\\/");
            id.image = slash == std::wstring::npos ? id.path : id.path.substr(slash + 1);
        }
        return id;
    }
};

int wmain(int argc, wchar_t** argv) {
    if (argc == 5 && wcscmp(argv[1], L"--child") == 0)
        return ChildMain(argv[2], argv[3], argv[4]);
    {
        Child child;
        if (!child.Start(L"accept")) { Check(false, "start accepting fixture"); return 1; }
        auto result = RequestGracefulClose({child.Identity()}, 1500);
        Check(child.Received() && !child.Alive() && result.remaining.empty(),
              "WM_CLOSE is delivered and accepting child exits without force");
    }
    {
        Child child;
        if (!child.Start(L"reject")) { Check(false, "start rejecting fixture"); return 1; }
        auto id = child.Identity();
        auto result = RequestGracefulClose({id}, 100);
        Check(child.Received(500) && child.Alive() && result.remaining.size() == 1,
              "rejecting child stays alive and is returned for separate authorization");
        // No second-stage authorization means no TerminateProcess call in production.
        Sleep(100);
        Check(child.Alive(), "graceful timeout never silently escalates to force");
        auto denied = KillPids({id}, ForceAuthorization::None);
        Check(child.Alive() && denied.killed == 0 && denied.pending == 0,
              "missing force authorization performs no termination");
        auto forced = KillPids({id}, ForceAuthorization::ExplicitUserApproval);
        Check(forced.killed + forced.pending == 1 &&
              WaitForSingleObject(child.process, 3000) == WAIT_OBJECT_0,
              "explicit force authorization terminates only the owned rejecting child");
    }
    {
        Child child;
        if (!child.Start(L"accept")) { Check(false, "start identity fixture"); return 1; }
        auto wrong = child.Identity(); ++wrong.start;
        auto result = RequestGracefulClose({wrong}, 100);
        Check(!child.Received(150) && child.Alive() && result.remaining.empty() && result.report.skipped == 1,
              "creation-time mismatch sends no WM_CLOSE and cannot enter force candidates");
    }
    {
        Child child;
        if (!child.Start(L"no-window")) { Check(false, "start windowless fixture"); return 1; }
        auto result = RequestGracefulClose({child.Identity()}, 100);
        Check(!child.Received() && child.Alive() && result.remaining.size() == 1,
              "windowless child remains alive rather than being forcibly terminated");
    }
    printf("%d graceful integration checks, %d failures (owned test processes only)\n", cases, failures);
    return failures ? 1 : 0;
}
