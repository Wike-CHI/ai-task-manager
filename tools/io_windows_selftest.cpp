#include "../src/core/collector.h"
#include "../src/core/io_evidence.h"
#include "../src/core/diagnosis.h"
#include <iostream>
#pragma comment(lib, "psapi.lib")
int main() {
    Snapshot empty; DiagnosticContext context{};
    const bool routes = DiagnoseQuestion(L"GPU allocation failure",empty,context).find(L"GPU 显存分配失败未确诊") != std::wstring::npos &&
        DiagnoseQuestion(L"version",empty,context).find(L"证据诊断") != std::wstring::npos &&
        DiagnoseQuestion(L"IO",empty,context).find(L"进程 I/O 观测") != std::wstring::npos;
    std::cout << (routes ? "PASS" : "FAIL") << " production diagnostic query routing\n";
    if (!routes) return 1;
    const auto logged = DiagnoseQuestion(L"日志证据: Error: listen EADDRINUSE: address already in use",empty,context);
    const bool logRoute = logged.find(L"提供的文本包含") != std::wstring::npos &&
        logged.find(L"非实时确诊") != std::wstring::npos;
    std::cout << (logRoute ? "PASS" : "FAIL") << " explicit provided log routing remains unverified text evidence\n";
    if (!logRoute) return 1;
    Snapshot first, second; CollectProcesses(first); Sleep(30); CollectProcesses(second);
    const auto firstSelf = std::find_if(first.processes.begin(), first.processes.end(), [](const ProcessNode& n) { return n.identity.pid == GetCurrentProcessId(); });
    const bool firstCpuUnknown = firstSelf != first.processes.end() && !firstSelf->cpuSampleValid;
    for (const auto& node : second.processes) {
        if(node.identity.pid != GetCurrentProcessId()) continue;
        const bool ok = firstCpuUnknown && node.cpuSampleValid && node.ioCounters.valid && node.identity.start != 0 &&
            node.ioRate.available() && node.ioRate.elapsedSeconds > 0 &&
            node.ioCounters.creation == node.identity.start &&
            BuildIoFinding(node).state == FindingState::Observed;
        std::cout << (ok ? "PASS" : "FAIL") << " own-process identity-bound Windows IO sampling\n";
        return ok ? 0 : 1;
    }
    std::cout << "FAIL own process not collected\n"; return 1;
}
