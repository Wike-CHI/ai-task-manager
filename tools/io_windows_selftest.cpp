#include "../src/core/collector.h"
#include "../src/core/io_evidence.h"
#include <iostream>
#pragma comment(lib, "psapi.lib")
int main() {
    Snapshot first, second; CollectProcesses(first); Sleep(30); CollectProcesses(second);
    for (const auto& node : second.processes) {
        if(node.identity.pid != GetCurrentProcessId()) continue;
        const bool ok = node.ioCounters.valid && node.identity.start != 0 &&
            node.ioRate.available() && node.ioRate.elapsedSeconds > 0 &&
            node.ioCounters.creation == node.identity.start &&
            BuildIoFinding(node).state == FindingState::Observed;
        std::cout << (ok ? "PASS" : "FAIL") << " own-process identity-bound Windows IO sampling\n";
        return ok ? 0 : 1;
    }
    std::cout << "FAIL own process not collected\n"; return 1;
}
