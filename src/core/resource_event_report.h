#pragma once
#include "resource_events.h"
#include "diagnostic_evidence.h"
inline std::wstring SnapshotTimingReport(const Snapshot& s, uint64_t nowMs) {
    const auto freshness = SnapshotFreshness(s, nowMs);
    std::wstring out = L"采样新鲜度：" + std::wstring(freshness == SampleFreshness::Fresh ? L"新鲜（10秒策略内）" :
        freshness == SampleFreshness::Stale ? L"过期，不应视为当前状态" : L"未知（未完成/时序无效/采样超过10秒）");
    if (ValidSampleWindow(s) && nowMs >= s.sampleEndMs)
        out += L"；样本年龄 " + std::to_wstring(nowMs-s.sampleEndMs) + L" ms";
    out += L"。年龄按采样完成计；不保证独立缓存硬件读数的新鲜度，也不代表每项指标可读取。\r\n";
    out += L"进程枚举：" + std::wstring(s.processEnumerationComplete ? L"完成" : L"不完整或未知") + L"（不代表所有身份/指标完整）。\r\n";
    return out;
}
inline std::wstring ResourceEventReport(const Snapshot& s, uint64_t nowMs) {
    std::wstring out=SnapshotTimingReport(s,nowMs);
    const wchar_t* state=L"首次样本，需要下一次采样";
    switch(s.resourceEventState) {
    case ResourceEventState::Comparable: state=L"相邻样本可比较"; break;
    case ResourceEventState::Incomplete: state=L"样本或枚举不完整，未生成事件"; break;
    case ResourceEventState::InvalidTime: state=L"采样时序无效，未生成事件"; break;
    case ResourceEventState::GapTooLarge: state=L"间隔超过30秒，未生成事件"; break;
    default: break;
    }
    out+=std::wstring(L"资源事件：")+state+L"。仅最近一次比较，不是持久审计日志。\r\n";
    if(s.resourceEventState==ResourceEventState::Comparable && s.resourceEvents.empty())
        out+=L"未观察到满足规则的变化，不代表没有变化。\r\n";
    for(const auto& e:s.resourceEvents) {
        const wchar_t* kind=e.kind==ResourceEventKind::ObservedNew ? L"新观测到" :
            e.kind==ResourceEventKind::NoLongerObserved ? L"不再观测到" : L"工作集变化";
        out+=std::wstring(kind)+L"："+e.identity.image+L" PID "+std::to_wstring(e.identity.pid)+
            L" creation "+std::to_wstring(e.identity.start)+L"（"+std::to_wstring(e.previousSampleMs)+L"→"+
            std::to_wstring(e.currentSampleMs)+L" ms，单调时钟）";
        if(e.kind==ResourceEventKind::WorkingSetChanged)
            out+=L" "+EvidenceNumber(e.previousMemoryMB)+L"→"+EvidenceNumber(e.currentMemoryMB)+L" MB";
        out+=L"\r\n";
    }
    if(s.resourceEventsOmitted) out+=L"因数量上限省略 "+std::to_wstring(s.resourceEventsOmitted)+L" 项；不是完整事件流。\r\n";
    return out+L"进程观测变化不等于确定启动/退出；工作集变化不证明泄漏、分配失败或可释放量。\r\n";
}
