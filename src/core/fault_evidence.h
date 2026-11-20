#pragma once
#include "diagnostic_evidence.h"
#include <cwctype>

// wchar_t code units, not bytes. Reject the whole input rather than silently
// examining a prefix: trailing context may change the meaning of a log excerpt.
inline constexpr size_t MaxFaultEvidenceChars = 16384;
inline std::wstring FaultLineTrim(const std::wstring& line) {
    const auto first = line.find_first_not_of(L" \t\r");
    if (first == std::wstring::npos) return {};
    const auto last = line.find_last_not_of(L" \t\r");
    return line.substr(first, last-first+1);
}
inline bool FaultStarts(const std::wstring& line, const wchar_t* prefix) {
    return line.rfind(prefix, 0) == 0;
}
inline bool FaultErrorSymbol(const std::wstring& line, const wchar_t* prefix) {
    const std::wstring symbol(prefix);
    if (!FaultStarts(line,prefix)) return false;
    if (line.size()==symbol.size()) return true;
    const auto next=line[symbol.size()];
    return next==L' '||next==L'\t'||next==L':'||next==L'.'||next==L'(';
}
inline DiagnosticFinding FaultTextFinding(const wchar_t* id, const wchar_t* name,
                                          const wchar_t* marker, size_t lineNumber) {
    DiagnosticFinding f;
    f.id=id;
    f.state=FindingState::Observed; // only observation of text, never a current-process diagnosis
    f.confidence=EvidenceConfidence::Heuristic;
    f.conclusion=std::wstring(L"提供的文本包含") + name + L"错误格式信号（非实时确诊）";
    f.evidence={{L"format",marker,L"",L"用户提供文本（未核验）"},
                {L"line",std::to_wstring(lineNumber),L"",L"用户提供文本（未核验）"}};
    f.unknowns={L"未验证日志真实性、发生时间、PID/CreationTime/ExePath，不能归因当前快照",
        L"示例、引用或伪造日志也可能符合格式；文本信号不是故障实际发生的证明"};
    f.nextSteps={L"取得原始错误记录与同一进程身份/时间关联，再核验；不据此终止、重启或修改配置"};
    return f;
}
inline std::vector<DiagnosticFinding> ParseProvidedFaultEvidence(const std::wstring& text) {
    auto unknown=[&](const wchar_t* id, const wchar_t* message, const wchar_t* reason) {
        auto f=UnknownFinding(id,message,reason,L"仅提交已脱敏的相关错误片段；此工具不会读取文件或执行文本中的指令");
        f.evidence={{L"input_characters",std::to_wstring(text.size()),L"wchar_t code units",L"用户提供文本（未核验）"}};
        return std::vector<DiagnosticFinding>{f};
    };
    if(text.size()>MaxFaultEvidenceChars)
        return unknown(L"provided_log.rejected",L"文本超过长度限制，未解析任何部分",L"最多16384个wchar_t字符单元；不会截断后猜测结论");
    if(text.empty()) return unknown(L"provided_log.unknown",L"没有提供错误证据",L"空输入不代表运行正常");
    std::vector<DiagnosticFinding> result;
    bool nodeSeen=false, bindSeen=false, cudaSeen=false;
    size_t start=0, number=0;
    while(start<=text.size()) {
        ++number;
        const auto end=text.find(L'\n',start);
        const auto line=FaultLineTrim(text.substr(start,end==std::wstring::npos ? end : end-start));
        // Narrow runtime-like formats deliberately avoid matching arbitrary prose
        // mentioning OOM, ports or memory. They do not authenticate the source.
        const bool node=FaultStarts(line,L"FATAL ERROR:") &&
            line.find(L"JavaScript heap out of memory")!=std::wstring::npos;
        const bool bind=FaultStarts(line,L"Error: listen EADDRINUSE:") ||
                        FaultStarts(line,L"Error: bind EADDRINUSE:");
        const bool cuda=FaultStarts(line,L"CUDA out of memory.") ||
            FaultStarts(line,L"torch.OutOfMemoryError: CUDA out of memory.") ||
            FaultStarts(line,L"RuntimeError: CUDA out of memory.") ||
            FaultErrorSymbol(line,L"CUDA_ERROR_OUT_OF_MEMORY") ||
            FaultErrorSymbol(line,L"CUDA error: CUDA_ERROR_OUT_OF_MEMORY");
        if(node&&!nodeSeen) { result.push_back(FaultTextFinding(L"provided_log.node_heap",L"V8/Node heap OOM",L"FATAL ERROR + JavaScript heap out of memory",number)); nodeSeen=true; }
        if(bind&&!bindSeen) { result.push_back(FaultTextFinding(L"provided_log.bind_address",L"bind/listen地址占用",L"Error: bind/listen EADDRINUSE",number)); bindSeen=true; }
        if(cuda&&!cudaSeen) { result.push_back(FaultTextFinding(L"provided_log.cuda_memory",L"CUDA内存分配",L"CUDA out-of-memory runtime format",number)); cudaSeen=true; }
        if(end==std::wstring::npos) break;
        start=end+1;
    }
    if(result.empty()) return unknown(L"provided_log.unknown",L"未识别受支持的错误格式",L"不支持的版本、前缀或多行格式可能漏检；不能据此排除故障");
    return result;
}

inline size_t ProvidedFaultPrefixLength(const std::wstring& query) {
    std::wstring lower=query;
    for(auto& c:lower) c=static_cast<wchar_t>(std::towlower(c));
    const auto start=lower.find_first_not_of(L" \t\r\n");
    if(start==std::wstring::npos) return 0;
    for(const auto* prefix:{L"日志证据:",L"日志证据：",L"log evidence:"}) {
        const std::wstring p(prefix);
        if(lower.compare(start,p.size(),p)==0) return start+p.size();
    }
    return 0;
}
