#pragma once
#include "types.h"
#include <cmath>
#include <sstream>
#include <iomanip>

enum class FindingState { Observed, Risk, Unknown };
enum class EvidenceConfidence { None, DirectMeasurement, Heuristic };
struct DiagnosticEvidence {
    std::wstring metric, value, unit, source;
};
struct DiagnosticFinding {
    std::wstring id, conclusion;
    FindingState state = FindingState::Unknown;
    EvidenceConfidence confidence = EvidenceConfidence::None;
    std::vector<DiagnosticEvidence> evidence;
    std::vector<std::wstring> unknowns, nextSteps;
};
inline std::wstring EvidenceNumber(double value) {
    std::wostringstream out; out << std::fixed << std::setprecision(2) << value; return out.str();
}
inline bool ValidCapacity(double used, double total) {
    return std::isfinite(used) && std::isfinite(total) && used >= 0 && total > 0 && used <= total;
}
inline DiagnosticFinding CapacityFinding(const wchar_t* id, const wchar_t* label,
    double used, double total, double threshold, const wchar_t* source) {
    DiagnosticFinding f; f.id = id;
    if (!ValidCapacity(used, total)) {
        f.conclusion = std::wstring(label) + L"采样缺失或无效";
        f.unknowns = {L"无有效容量数据，不能将零或读取失败视为正常"};
        f.nextSteps = {L"重新采样并检查数据源可用性"};
        return f;
    }
    const double ratio = used / total;
    const bool atThreshold = ratio + 1e-12 >= threshold; // tolerate representation noise only
    f.state = atThreshold ? FindingState::Risk : FindingState::Observed;
    f.confidence = EvidenceConfidence::DirectMeasurement;
    f.conclusion = std::wstring(label) + (atThreshold ? L"本次占用达到观察阈值" : L"本次占用未达观察阈值");
    f.evidence = {{L"used", EvidenceNumber(used), L"GB", source},
        {L"capacity", EvidenceNumber(total), L"GB", source},
        {L"ratio", EvidenceNumber(ratio * 100), L"%", source},
        {L"threshold", EvidenceNumber(threshold * 100), L"%", L"确定性规则（非故障概率）"}};
    f.unknowns = {L"单次占用不证明卡顿原因、分配失败、泄漏或可释放量", L"未提供采样时间戳，不能据此保证新鲜度"};
    f.nextSteps = {L"结合实际错误记录和连续样本判断，不依据阈值自动结束进程"};
    return f;
}
inline DiagnosticFinding UnknownFinding(const wchar_t* id, const wchar_t* conclusion,
    const wchar_t* missing, const wchar_t* next) {
    DiagnosticFinding f; f.id = id; f.conclusion = conclusion;
    f.unknowns = {missing}; f.nextSteps = {next}; return f;
}
// Only these measurements are collected. No injected text can grant write actions.
inline std::vector<DiagnosticFinding> BuildDiagnosticFindings(const Snapshot& snapshot) {
    std::vector<DiagnosticFinding> out;
    out.push_back(CapacityFinding(L"physical_memory", L"物理内存", snapshot.ramUsedGB,
        snapshot.ramTotalGB, .88, L"GlobalMemoryStatusEx"));
    out.push_back(CapacityFinding(L"commit", L"提交内存估计", snapshot.comUsedGB,
        snapshot.comTotalGB, .85, L"GlobalMemoryStatusEx PageFile 字段差值（提交估计）"));
    out.push_back(CapacityFinding(L"gpu_memory", L"设备显存", snapshot.hasGpu ? snapshot.vramUsed : -1,
        snapshot.hasGpu ? snapshot.vramTotal : 0, .92, L"nvidia-smi 设备总量（非进程归属）"));
    out.push_back(UnknownFinding(L"node_oom", L"Node.js OOM 未确诊",
        L"未采集运行时 heap limit、退出原因或 OOM 错误记录；RSS 高不等于 V8 heap OOM",
        L"检查目标 Node 进程的错误日志/退出状态并关联创建时间"));
    out.push_back(UnknownFinding(L"port_conflict", L"端口冲突未确诊",
        L"未采集 bind/listen 失败证据、协议/地址/端口和拥有者；进程名不是证据",
        L"取得具体 bind 错误后只读查询对应 socket 与进程身份"));
    out.push_back(UnknownFinding(L"gpu_allocation", L"GPU 显存分配失败未确诊",
        L"设备占用不能证明某个应用分配失败，未采集 CUDA/驱动错误",
        L"检查应用分配失败记录；不要把设备总显存归给单个模型"));
    out.push_back(UnknownFinding(L"background_anomaly", L"异常后台进程未确诊",
        L"缺少工作负载基线、用户意图和连续资源事件；陌生名称不等于恶意",
        L"先查看身份、父子关系和持续变化，不自动结束或定性恶意"));
    out.push_back(UnknownFinding(L"hard_faults", L"硬缺页及磁盘瓶颈未确诊",
        L"尚未采集硬缺页事件/物理磁盘延迟；进程 I/O 字节和总缺页不能代替它们",
        L"后续接入经验证的 ETW/性能计数器，并保留缺失状态"));
    for(size_t i=0; i<3; ++i) {
        if(snapshot.sampleComplete && snapshot.sampleEndMs>=snapshot.sampleStartMs) {
            auto& f=out[i];
            f.evidence.push_back({L"sample_start",std::to_wstring(snapshot.sampleStartMs),L"ms",L"GetTickCount64（同一次运行）"});
            f.evidence.push_back({L"sample_end",std::to_wstring(snapshot.sampleEndMs),L"ms",L"GetTickCount64（同一次运行）"});
            for(auto& missing:f.unknowns)
                if(missing==L"未提供采样时间戳，不能据此保证新鲜度") missing=L"时间戳不保证完整采样；请结合新鲜度及数据源有效性";
        }
    }
    return out;
}
inline std::wstring RenderDiagnosticFindings(const std::vector<DiagnosticFinding>& findings) {
    std::wstring out = L"证据诊断（文本或快照证据；无故障概率估计）：\r\n";
    for (const auto& f : findings) {
        const wchar_t* status = f.state == FindingState::Risk ? L"风险提示" :
            f.state == FindingState::Observed ? L"观测" : L"未知";
        const wchar_t* confidence = f.confidence == EvidenceConfidence::DirectMeasurement ? L"直接测量，仅对所列数值" :
            f.confidence == EvidenceConfidence::Heuristic ? L"启发式" : L"无足够证据";
        out += L"\r\n[" + std::wstring(status) + L"] " + f.conclusion + L"\r\n置信依据：" + confidence + L"\r\n";
        for (const auto& e : f.evidence)
            out += L"· " + e.metric + L" = " + e.value + L" " + e.unit + L"（" + e.source + L"）\r\n";
        for (const auto& u : f.unknowns) out += L"未知：" + u + L"\r\n";
        for (const auto& n : f.nextSteps) out += L"下一步：" + n + L"\r\n";
    }
    return out;
}
