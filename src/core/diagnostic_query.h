#pragma once
#include <string>
#include <cwctype>
enum class DiagnosticQueryRoute { Other, Evidence, ProcessIo };
inline DiagnosticQueryRoute RouteDiagnosticQuery(std::wstring query) {
    for(auto& c:query) c=static_cast<wchar_t>(std::towlower(c));
    auto has=[&](const wchar_t* s){return query.find(s)!=std::wstring::npos;};
    if(has(L"证据")||has(L"诊断")||has(L"oom")||has(L"端口")||has(L"异常")||
       has(L"diagnos")||has(L"allocation")||has(L"port conflict")) return DiagnosticQueryRoute::Evidence;
    auto asciiWord=[](wchar_t c){return (c>=L'a'&&c<=L'z')||(c>=L'0'&&c<=L'9')||c==L'_';};
    for(const auto* token:{L"io",L"i/o"}) {
        const std::wstring word(token);
        for(size_t at=query.find(word);at!=std::wstring::npos;at=query.find(word,at+1)) {
            const auto end=at+word.size();
            if((at==0||!asciiWord(query[at-1]))&&(end==query.size()||!asciiWord(query[end])))
                return DiagnosticQueryRoute::ProcessIo;
        }
    }
    return has(L"磁盘") ? DiagnosticQueryRoute::ProcessIo : DiagnosticQueryRoute::Other;
}
