#pragma once
#include "types.h"
#include "workloads.h"
#include "policy.h"
#include "format.h"
#include "diagnostic_evidence.h"
#include "io_evidence.h"
#include "diagnostic_query.h"
#include "resource_event_report.h"
#include "fault_evidence.h"
struct DiagnosticContext {
    const Sample* history;
    int historyCount, historyHead, historyCapacity;
    double gpuTemp, fan, diskTemp, cpuTemp, weightsGB;
};
static std::wstring RiskTag(Risk r) {
    switch (r) {
    case RISK_PROTECTED: return L"勿动";
    case RISK_MODEL:     return L"模型";
    case RISK_SAFE:      return L"可关";
    case RISK_CAREFUL:   return L"慎关";
    default:             return L"";
    }
}

static std::wstring TrendText(const DiagnosticContext& ctx) {
    if (ctx.historyCount < 10) return L"（样本还不够，稍等半分钟）";
    auto at = [&](int back) {
        int idx = (ctx.historyHead - 1 - back + ctx.historyCapacity * 2) % ctx.historyCapacity;
        return ctx.history[idx];
    };
    double recent = 0, older = 0;
    for (int i = 0; i < 5; ++i) recent += at(i).com;
    for (int i = 5; i < 10; ++i) older += at(i).com;
    recent /= 5; older /= 5;
    double d = recent - older;
    if (d > 1.5) return Fmt(L"提交 30 秒内上升 %.0f%%，还在恶化", d);
    if (d < -1.5) return Fmt(L"提交 30 秒内下降 %.0f%%，在缓解", -d);
    return L"提交最近 30 秒基本持平";
}

static std::wstring TempTrendText(const DiagnosticContext& ctx) {
    if (ctx.historyCount < 12 || ctx.gpuTemp <= 0) return L"";
    auto at = [&](int back) {
        int idx = (ctx.historyHead - 1 - back + ctx.historyCapacity * 2) % ctx.historyCapacity;
        return ctx.history[idx];
    };
    double now = ctx.gpuTemp, before = at(10).gpuT;   // 约 20 秒前
    if (before <= 0) return L"";
    double d = now - before;
    if (d >= 2) return Fmt(L"（GPU 20 秒内升 %.0f°C，%.0f→%.0f）", d, before, now);
    if (d <= -2) return Fmt(L"（GPU 20 秒内降 %.0f°C，%.0f→%.0f）", -d, before, now);
    return L"（GPU 温度平稳）";
}

static std::wstring Diagnose(const Snapshot& s, const DiagnosticContext& ctx) {
    std::wstring out = SnapshotTimingReport(s, GetTickCount64()) + RenderDiagnosticFindings(BuildDiagnosticFindings(s));

    if (ctx.gpuTemp > 0) {
        out += Fmt(L"· 温度：GPU %.0f°C（风扇 %.0f%%）", ctx.gpuTemp, ctx.fan);
        if (ctx.diskTemp > 0) out += Fmt(L"，磁盘 %.0f°C", ctx.diskTemp);
        if (ctx.cpuTemp > 0) out += Fmt(L"，ACPI %.0f°C", ctx.cpuTemp);
        out += TempTrendText(ctx);
        out += L"\r\n";

        if (ctx.gpuTemp >= 83 && ctx.fan >= 85)
            out += L"  ⚠ 显卡高温 + 高转速同时出现，散热可能受阻（积灰 / 风道 / 环境温度）\r\n";
        else if (ctx.gpuTemp >= 83)
            out += L"  ⚠ 显卡温度偏高而风扇未拉满，可检查风扇曲线\r\n";
        else if (ctx.fan >= 90 && ctx.gpuTemp < 60)
            out += L"  散热余量充足（风扇高转速但温度低）\r\n";
    }

    out += L"\r\n内存前 5：\r\n";
    int n = 0;
    for (auto& r : s.rows) {
        if (n++ >= 5) break;
        std::wstring tag = RiskTag(r.risk);
        out += Fmt(L"· %s —— %.1f GB（%d 个进程）%s\r\n", r.name.c_str(), r.memMB / 1024.0, r.count,
                   tag.empty() ? L"" : (L"[" + tag + L"]").c_str());
    }

    out += L"\r\n候选与策略（工作集不等于可释放量）：\r\n";
    int idx = 1;
    double gain = 0;
    for (auto& r : s.rows) {
        if (r.risk != RISK_SAFE || r.memMB < 80) continue;
        if (idx > 4) break;
        out += Fmt(L"%d. 候选 %s —— 工作集 %.1f GB（%s）\r\n",
                   idx++, r.name.c_str(), r.memMB / 1024.0, r.why.c_str());
        gain += r.memMB;
    }
    for (auto& r : s.rows) {
        if (r.risk != RISK_CAREFUL || r.memMB < 300) continue;
        out += Fmt(L"   谨慎：%s —— %.1f GB（%s）\r\n", r.name.c_str(), r.memMB / 1024.0, r.why.c_str());
        break;
    }
    if (gain > 200)
        out += Fmt(L"\r\n候选工作集合计 %.1f GB；共享页可能重复，不能推算提交下降量。\r\n",
                   gain / 1024.0);

    if (s.modelRunning)
        out += Fmt(L"\r\n模型在跑：显存 %.1f GB · 内存 %.2f GB · 权重 %.1f GB，别按内存大小误杀。\r\n",
                   s.vramUsed, s.modelMemGB, ctx.weightsGB);
    return out;
}

static std::wstring WorkloadReport(const Snapshot& s) {
    std::wstring out = L"开发者工作负载（父子关系 + 名称启发式，不代表项目/任务身份）：\r\n";
    const auto workloads = AttributeWorkloads(s.processes);
    for (const auto& w : workloads)
        out += Fmt(L"· %s root PID %u：%u 个进程，工作集 %.1f MB，CPU %.1f%%\r\n",
            w.kind.c_str(), w.rootPid, (unsigned)w.members.size(), w.memMB, w.cpuPct);
    if (workloads.empty()) out += L"未发现可归因工作负载。\r\n";
    out += L"\r\n进程树边（PID → 父 PID；缺失/创建时间未知/父进程较新均不关联）：\r\n";
    std::map<uint32_t, const ProcessNode*> index;
    for (const auto& n : s.processes) index[n.identity.pid] = &n;
    for (const auto& n : s.processes) {
        const auto* parent = VerifiedParent(n, index);
        out += Fmt(L"%s [%u] → %u%s\r\n", n.identity.image.c_str(), n.identity.pid,
            n.parentPid, parent ? L"" : L"（未验证）");
    }
    out += L"工作集含共享页，求和不是可释放内存；不采集命令行或凭据。";
    return out;
}

static std::wstring DiagnoseQuestion(const std::wstring& q, const Snapshot& s, const DiagnosticContext& ctx) {
    const auto faultPrefix = ProvidedFaultPrefixLength(q);
    if (faultPrefix) return RenderDiagnosticFindings(ParseProvidedFaultEvidence(q.substr(faultPrefix)));
    std::wstring low = Lower(q);
    auto has = [&](const wchar_t* k) { return low.find(k) != std::wstring::npos; };

    if (has(L"事件") || has(L"变化") || has(L"新鲜") || has(L"event"))
        return ResourceEventReport(s, GetTickCount64());
    const auto route = RouteDiagnosticQuery(q);
    if (route == DiagnosticQueryRoute::Evidence) return SnapshotTimingReport(s, GetTickCount64()) + RenderDiagnosticFindings(BuildDiagnosticFindings(s));
    if (route == DiagnosticQueryRoute::ProcessIo) return ProcessIoReport(s);

    if (has(L"开发") || has(L"进程树") || has(L"归因") || has(L"workload")) return WorkloadReport(s);
    if (has(L"模型")) {
        if (!s.modelRunning) return L"当前快照未收集到 llama-server 的有效资源数据；不能据此证明没有模型任务。";
        return Fmt(L"模型占用：\r\n\r\n· 设备显存 %.1f / %.1f GB（不代表模型独占）\r\n"
                   L"· 进程内存 %.2f GB\r\n· 权重文件 %.1f GB（磁盘）\r\n\r\n"
                   L"仅凭设备显存和进程工作集不能推断模型内存布局、KV缓存或瓶颈。",
                   s.vramUsed, s.vramTotal, s.modelMemGB, ctx.weightsGB);
    }
    if (has(L"显存") || has(L"gpu") || has(L"显卡")) {
        if (!s.hasGpu) return L"未取得 NVIDIA GPU 数据，可能数据源不可用或设备不受支持；不能据此证明没有 GPU。";
        return Fmt(L"GPU 利用率 %.0f%%，显存 %.1f / %.1f GB（%.0f%%），温度 %.0f°C。\r\n\r\n"
                   L"这是设备总量，不是模型专属占用。高占用不能确诊分配失败、推理变慢或打字卡顿原因。",
                   s.gpuUtil, s.vramUsed, s.vramTotal,
                   s.vramTotal > 0 ? s.vramUsed / s.vramTotal * 100 : 0, s.gpuTemp);
    }
    if (has(L"关") || has(L"清理") || has(L"释放") || has(L"杀")) {
        std::wstring out = L"分类仅名称启发式，不保证无损；先保存任务：\r\n\r\n";
        double gain = 0;
        int i = 1;
        for (auto& r : s.rows) {
            if (r.risk != RISK_SAFE) continue;
            out += Fmt(L"%d. %s —— %.1f GB，%d 个进程\r\n   %s\r\n",
                       i++, r.name.c_str(), r.memMB / 1024.0, r.count, r.why.c_str());
            gain += r.memMB;
        }
        if (i == 1) out += L"• 目前没有标记为「可关」的进程。\r\n";
        out += Fmt(L"\r\n候选工作集合计 %.1f GB，不是可释放量；无默认安全名单，不自动结束。", gain / 1024.0);
        return out;
    }
    if (has(L"风扇") || has(L"散热") || has(L"温度")) {
        std::wstring out = L"当前温度：\r\n\r\n";
        if (ctx.gpuTemp > 0)
            out += Fmt(L"· GPU %.0f°C，风扇 %.0f%%\r\n", ctx.gpuTemp, ctx.fan);
        if (ctx.diskTemp > 0) out += Fmt(L"· NVMe %.0f°C\r\n", ctx.diskTemp);
        if (ctx.cpuTemp > 0) out += Fmt(L"· ACPI 热区 %.0f°C（主板/机箱附近，不是核心温度）\r\n", ctx.cpuTemp);

        out += L"\r\n关于控制风扇：\r\n"
               L"· GPU：Windows 下 nvidia-smi 只能读不能写（本机确认无 --fan-speed），"
               L"要改转速得用 NVIDIA 控制面板或 MSI Afterburner。\r\n"
               L"· 主板/CPU 风扇：没有标准接口，得用厂商工具（华硕 AI Suite、微星 Center、"
               L"联想 Vantage）或进 BIOS 调风扇曲线。\r\n"
               L"· 通用做法要装内核驱动直接读写 Super I/O（如 WinRing0），"
               L"这类驱动会被杀软拦、也有蓝屏风险，本工具不做。\r\n";
        return out;
    }
    if (has(L"内存") || has(L"卡") || has(L"慢") || has(L"为什么")) return Diagnose(s, ctx);
    if (has(L"趋势") || has(L"曲线") || has(L"历史"))
        return Fmt(L"曲线保留最近 %d 个点（约 %d 秒）：绿色=内存，黄色=提交，蓝色=显存。\r\n当前趋势：%s",
                   ctx.historyCount, ctx.historyCount * 2, TrendText(ctx).c_str());
    if (has(L"进程") || has(L"多少"))
        return Fmt(L"当前 %d 个进程，合并同名后 %d 项，内存总量 %.1f GB。",
                   s.procCount, (int)s.rows.size(), s.ramUsedGB);
    return Diagnose(s, ctx);
}

