#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include "types.h"
#include "policy.h"
#include "io_metrics.h"
static ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

struct CpuSample { ULONGLONG kernel, user, start; };

static void CollectProcesses(Snapshot& s) {
    static std::map<DWORD, CpuSample> prevCpu;
    static std::map<DWORD, ProcessIoSample> prevIo;
    static ULONGLONG previousTick = 0;
    const auto tick = GetTickCount64();
    const double elapsed = previousTick ? (tick - previousTick) / 1000.0 : 0;
    previousTick = tick;
    SYSTEM_INFO sys{}; GetSystemInfo(&sys);
    std::map<DWORD, CpuSample> curCpu;
    std::map<DWORD, ProcessIoSample> curIo;
    std::map<std::wstring, ProcRow> groups;

    s.processes.clear();
    FILETIME started{}; GetSystemTimeAsFileTime(&started);
    const auto snapshotStarted = FileTimeToU64(started);
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
                row.pids.push_back(ProcIdent{ pid, 0, key });
                row.pids.back().parentPid = pe.th32ParentProcessID;

                s.processes.push_back(ProcessNode{row.pids.back(), pe.th32ParentProcessID});
                auto& node = s.processes.back();
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (!h) continue;   // 打不开就留着 start=0，结束前会因身份未知跳过

                wchar_t imagePath[32768]{};
                DWORD pathSize = 32768;
                if (QueryFullProcessImageNameW(h, 0, imagePath, &pathSize))
                    row.pids.back().path = Lower(imagePath);
                FILETIME ct{}, et{}, kt{}, ut{};
                if (GetProcessTimes(h, &ct, &et, &kt, &ut)) {
                    if (!AcceptSampleIdentity(FileTimeToU64(ct), snapshotStarted,
                            row.pids.back().path, key)) { CloseHandle(h); continue; }
                    row.pids.back().start = FileTimeToU64(ct);
                    CpuSample now{ FileTimeToU64(kt), FileTimeToU64(ut), FileTimeToU64(ct) };
                    curCpu[pid] = now;
                    auto it = prevCpu.find(pid);
                    if (it != prevCpu.end() && it->second.start == now.start && elapsed > 0 &&
                        now.kernel >= it->second.kernel && now.user >= it->second.user) {
                        double ds = (double)((now.kernel - it->second.kernel) +
                                             (now.user - it->second.user)) / 10000000.0;
                        if (ds >= 0) {
                            node.cpuPct = ds / elapsed / std::max(1u, (unsigned)sys.dwNumberOfProcessors) * 100.0;
                            row.cpuPct += node.cpuPct;
                        }
                    }
                }

                // Keep a per-process observation timestamp: enumeration duration
                // is not necessarily identical between successive snapshots.
                IO_COUNTERS io{};
                if (row.pids.back().start && GetProcessIoCounters(h, &io)) {
                    node.ioCounters = {pid, row.pids.back().start, GetTickCount64(),
                        io.ReadTransferCount, io.WriteTransferCount, true};
                    auto prior = prevIo.find(pid);
                    node.ioRate = CalculateIoRate(prior == prevIo.end() ? nullptr : &prior->second,
                                                 node.ioCounters);
                    curIo[pid] = node.ioCounters;
                }
                // Failed samples are deliberately absent from curIo, breaking
                // the baseline so later recovery cannot look like a fresh rate.
                PROCESS_MEMORY_COUNTERS_EX pmc{};
                if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    double mb = pmc.WorkingSetSize / 1048576.0;
                    row.memMB += mb; node.memMB = mb;
                    if (key == L"llama-server.exe") {
                        s.modelRunning = true;
                        s.modelMemGB += mb / 1024.0;
                    }
                }
                node.identity = row.pids.back();
                CloseHandle(h);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        s.procCount = count;
    }
    prevCpu.swap(curCpu);
    prevIo.swap(curIo);

    s.rows.clear();
    for (auto& kv : groups) {
        ProcRow r = kv.second;
        auto it = RISK_TABLE.find(kv.first);
        if (it != RISK_TABLE.end()) {
            r.risk = it->second.first;
            r.why = ClassificationEvidence(kv.first);
        }
        if (r.why.empty()) r.why = ClassificationEvidence(kv.first);
        s.rows.push_back(r);
    }

    // 本程序自己也在进程表里。RISK_TABLE 里写死的 exe 名不一定对得上（换个名字编译就漏了），
    // 直接按 pid 认：谁身上带着自己的 pid，谁就是「本程序」，不允许被结束。
    const DWORD selfPid = GetCurrentProcessId();
    for (auto& r : s.rows) {
        for (const auto& p : r.pids) {
            if (p.pid == selfPid) { r.risk = RISK_PROTECTED; r.why = L"分类依据：PID 等于当前程序 PID，禁止结束自身"; break; }
        }
    }

    std::sort(s.rows.begin(), s.rows.end(),
              [](const ProcRow& a, const ProcRow& b) { return a.memMB > b.memMB; });
}
