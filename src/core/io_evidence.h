#pragma once
#include <algorithm>
#include "diagnostic_evidence.h"
inline std::wstring IoUnknownReason(IoRateState state) {
    switch(state) {
    case IoRateState::FirstSample: return L"需要第二次有效样本";
    case IoRateState::IdentityChanged: return L"PID/创建时间变化，旧基线不适用";
    case IoRateState::CounterReset: return L"计数器下降，不能计算速率";
    case IoRateState::InvalidInterval: return L"采样时间间隔无效";
    default: return L"计数器不可读取或身份未知";
    }
}
inline DiagnosticFinding BuildIoFinding(const ProcessNode& node) {
    DiagnosticFinding f;
    f.id = L"process_io." + std::to_wstring(node.identity.pid) + L"." + std::to_wstring(node.identity.start);
    f.conclusion = node.identity.image + L" 进程 I/O（PID " + std::to_wstring(node.identity.pid) + L"）";
    f.evidence = {{L"pid",std::to_wstring(node.identity.pid),L"",L"进程快照"},
        {L"creation",std::to_wstring(node.identity.start),L"FILETIME",L"GetProcessTimes"}};
    if (node.ioRate.available()) {
        f.state = FindingState::Observed; f.confidence = EvidenceConfidence::DirectMeasurement;
        f.evidence.push_back({L"read",EvidenceNumber(node.ioRate.readBytesPerSecond),L"bytes/s",L"GetProcessIoCounters 差值"});
        f.evidence.push_back({L"write",EvidenceNumber(node.ioRate.writeBytesPerSecond),L"bytes/s",L"GetProcessIoCounters 差值"});
        f.evidence.push_back({L"interval",EvidenceNumber(node.ioRate.elapsedSeconds),L"s",L"GetTickCount64 差值"});
    } else f.unknowns.push_back(IoUnknownReason(node.ioRate.state));
    f.unknowns.push_back(L"这些I/O计数可含缓存及设备访问，不是物理磁盘吞吐、延迟或硬缺页；不证明瓶颈");
    f.nextSteps = {L"结合连续样本和独立磁盘/硬缺页证据；不据此结束进程"};
    return f;
}
inline std::wstring ProcessIoReport(const Snapshot& snapshot) {
    std::vector<const ProcessNode*> sorted;
    size_t unknown = 0;
    for (const auto& n : snapshot.processes) {
        if (!n.ioRate.available()) ++unknown;
        else sorted.push_back(&n);
    }
    std::sort(sorted.begin(), sorted.end(), [](const ProcessNode* a, const ProcessNode* b) {
        return a->ioRate.readBytesPerSecond+a->ioRate.writeBytesPerSecond >
               b->ioRate.readBytesPerSecond+b->ioRate.writeBytesPerSecond;
    });
    std::wstring out = L"进程 I/O 观测：有效 " + std::to_wstring(sorted.size()) + L"，未知 " + std::to_wstring(unknown) +
        L"。显示速率前5，不是物理磁盘排名。\r\n";
    std::vector<DiagnosticFinding> findings;
    for(size_t i=0;i<sorted.size() && i<5;++i) findings.push_back(BuildIoFinding(*sorted[i]));
    if (sorted.empty()) out += L"暂无可计算速率，需要至少两次同身份有效采样；读取失败不填零。\r\n";
    return out + RenderDiagnosticFindings(findings);
}
