#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cwctype>
#include "types.h"

inline ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER value{}; value.LowPart=ft.dwLowDateTime; value.HighPart=ft.dwHighDateTime;
    return value.QuadPart;
}
// Case normalization only, not filesystem canonicalization or signature trust.
inline std::wstring NormalizeIdentityText(std::wstring text) {
    for(auto& c:text) c=static_cast<wchar_t>(std::towlower(c));
    return text;
}
// The caller owns the handle. Reading an identity is not proof of liveness,
// current workload, ancestry or authorization. No PID is reopened in this API.
inline bool ReadProcessIdentity(HANDLE handle, ProcIdent& identity, std::wstring& why) {
    identity={}; why.clear();
    const DWORD pid=GetProcessId(handle);
    if(!pid) { why=L"无法读取句柄 PID"; return false; }
    FILETIME created{},exited{},kernel{},user{};
    if(!GetProcessTimes(handle,&created,&exited,&kernel,&user)) {
        why=L"读创建时间失败（"+std::to_wstring(GetLastError())+L"）"; return false;
    }
    const auto start=FileTimeToU64(created);
    wchar_t path[32768]{}; DWORD size=32768;
    if(!start || !QueryFullProcessImageNameW(handle,0,path,&size) || !size) {
        why=L"创建时间或完整路径未知"; return false;
    }
    const auto normalized=NormalizeIdentityText(std::wstring(path,size));
    const auto slash=normalized.find_last_of(L"\\/");
    const auto image=slash==std::wstring::npos ? normalized : normalized.substr(slash+1);
    if(image.empty()) { why=L"映像名未知"; return false; }
    identity={pid,start,image,normalized};
    return true;
}
inline bool VerifyIdentity(HANDLE handle,const ProcIdent& want,std::wstring& why) {
    if(!want.pid || !want.start || want.path.empty() || want.image.empty()) {
        why=L"快照身份不完整，无法核对"; return false;
    }
    ProcIdent actual;
    if(!ReadProcessIdentity(handle,actual,why)) return false;
    if(actual.pid!=want.pid) { why=L"句柄 PID 与快照不同"; return false; }
    if(actual.start!=want.start) { why=L"创建时间对不上，PID 身份已变化"; return false; }
    if(actual.path!=want.path) { why=L"完整映像路径不一致"; return false; }
    if(actual.image!=want.image) { why=L"映像名不一致"; return false; }
    return true;
}
enum class CriticalState { Unknown,Critical,NotCritical };
inline CriticalState CriticalStatus(HANDLE handle) {
    using Fn=BOOL (WINAPI*)(HANDLE,PBOOL);
    static Fn fn=reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"IsProcessCritical"));
    if(!fn) return CriticalState::Unknown;
    BOOL critical=FALSE;
    if(!fn(handle,&critical)) return CriticalState::Unknown;
    return critical ? CriticalState::Critical : CriticalState::NotCritical;
}
