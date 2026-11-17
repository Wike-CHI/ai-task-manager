#pragma once
// Include before a non-lean windows.h. The application already uses LEAN_AND_MEAN.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include "port_query.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct TcpListenerEvidence {
    DWORD family = 0, pid = 0, scope = 0;
    unsigned char address[16]{};
    uint16_t port = 0;
    uint64_t creation = 0;
    std::wstring path;
    bool endpointReobserved = false, identityKnown = false;
    std::wstring identityUnknown;
};
struct TcpListenerQuery {
    uint16_t port = 0;
    uint64_t startMs = 0, endMs = 0;
    DWORD ipv4Status = ERROR_NOT_READY, ipv6Status = ERROR_NOT_READY;
    DWORD ipv4RecheckStatus = ERROR_NOT_READY, ipv6RecheckStatus = ERROR_NOT_READY;
    size_t omitted = 0;
    std::vector<TcpListenerEvidence> listeners;
};
inline uint64_t PortFileTime(const FILETIME& ft) {
    ULARGE_INTEGER n{}; n.LowPart=ft.dwLowDateTime; n.HighPart=ft.dwHighDateTime; return n.QuadPart;
}
inline bool SameTcpEndpoint(const TcpListenerEvidence& a, const TcpListenerEvidence& b) {
    return a.family==b.family && a.pid==b.pid && a.port==b.port && a.scope==b.scope &&
        std::memcmp(a.address,b.address,a.family==AF_INET ? 4 : 16)==0;
}
// Bounded retries handle normal table growth without indefinite UI work.
inline DWORD ReadTcpListenerTable(DWORD family, uint16_t port, std::vector<TcpListenerEvidence>& rows) {
    DWORD size=0;
    DWORD status=GetExtendedTcpTable(nullptr,&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0);
    if(status!=ERROR_INSUFFICIENT_BUFFER && status!=NO_ERROR) return status;
    constexpr DWORD limit=8*1024*1024;
    for(int attempt=0;attempt<3;++attempt) {
        if(size<sizeof(DWORD) || size>limit) return ERROR_INVALID_DATA;
        std::vector<unsigned char> buffer(size);
        DWORD available=size;
        status=GetExtendedTcpTable(buffer.data(),&available,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0);
        if(status==ERROR_INSUFFICIENT_BUFFER) { size=available; continue; }
        if(status!=NO_ERROR) return status;
        DWORD count=0; std::memcpy(&count,buffer.data(),sizeof(count));
        const size_t offset=family==AF_INET ? offsetof(MIB_TCPTABLE_OWNER_PID,table) : offsetof(MIB_TCP6TABLE_OWNER_PID,table);
        const size_t rowSize=family==AF_INET ? sizeof(MIB_TCPROW_OWNER_PID) : sizeof(MIB_TCP6ROW_OWNER_PID);
        if(buffer.size()<offset || count>(buffer.size()-offset)/rowSize) return ERROR_INVALID_DATA;
        for(DWORD i=0;i<count;++i) {
            TcpListenerEvidence e; e.family=family;
            DWORD networkPort=0;
            if(family==AF_INET) {
                MIB_TCPROW_OWNER_PID row{}; std::memcpy(&row,buffer.data()+offset+i*rowSize,sizeof(row));
                e.pid=row.dwOwningPid; networkPort=row.dwLocalPort;
                std::memcpy(e.address,&row.dwLocalAddr,4);
            } else {
                MIB_TCP6ROW_OWNER_PID row{}; std::memcpy(&row,buffer.data()+offset+i*rowSize,sizeof(row));
                e.pid=row.dwOwningPid; networkPort=row.dwLocalPort; e.scope=row.dwLocalScopeId;
                std::memcpy(e.address,row.ucLocalAddr,16);
            }
            e.port=ntohs(static_cast<u_short>(networkPort));
            if(e.port==port) rows.push_back(e);
        }
        return NO_ERROR;
    }
    return ERROR_RETRY;
}
inline void ReadListenerIdentity(TcpListenerEvidence& row, uint64_t tableStarted) {
    if(!row.endpointReobserved) { row.identityUnknown=L"端点未被再次观测或复查失败"; return; }
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,row.pid);
    if(!h) { row.identityUnknown=L"进程不可读取（权限/已退出）"; return; }
    FILETIME created{},exited{},kernel{},user{};
    wchar_t path[32768]{}; DWORD length=32768;
    const bool ok=GetProcessId(h)==row.pid && WaitForSingleObject(h,0)==WAIT_TIMEOUT &&
        GetProcessTimes(h,&created,&exited,&kernel,&user) &&
        QueryFullProcessImageNameW(h,0,path,&length);
    const auto creation=PortFileTime(created);
    if(ok && creation && creation<=tableStarted && length && WaitForSingleObject(h,0)==WAIT_TIMEOUT) {
        row.creation=creation; row.path.assign(path,length); row.identityKnown=true;
    } else row.identityUnknown=L"创建时间/路径/存活状态无法确认，或进程晚于表采样边界创建";
    CloseHandle(h);
}
inline TcpListenerQuery QueryTcpListeners(uint16_t port) {
    TcpListenerQuery query; query.port=port; query.startMs=GetTickCount64();
    if(!port) { query.ipv4Status=query.ipv6Status=ERROR_INVALID_PARAMETER; query.endMs=GetTickCount64(); return query; }
    FILETIME boundary{}; GetSystemTimeAsFileTime(&boundary);
    std::vector<TcpListenerEvidence> initial4,initial6,again4,again6;
    query.ipv4Status=ReadTcpListenerTable(AF_INET,port,initial4);
    query.ipv6Status=ReadTcpListenerTable(AF_INET6,port,initial6);
    query.ipv4RecheckStatus=ReadTcpListenerTable(AF_INET,port,again4);
    query.ipv6RecheckStatus=ReadTcpListenerTable(AF_INET6,port,again6);
    auto add=[&](std::vector<TcpListenerEvidence>& initial,const std::vector<TcpListenerEvidence>& again,DWORD status) {
        for(auto& row:initial) {
            if(query.listeners.size()>=128) { ++query.omitted; continue; }
            row.endpointReobserved=status==NO_ERROR && std::any_of(again.begin(),again.end(),[&](const TcpListenerEvidence& next){return SameTcpEndpoint(row,next);});
            ReadListenerIdentity(row,PortFileTime(boundary));
            query.listeners.push_back(row);
        }
    };
    add(initial4,again4,query.ipv4RecheckStatus); add(initial6,again6,query.ipv6RecheckStatus);
    query.endMs=GetTickCount64(); return query;
}
inline std::wstring RenderTcpListenerEvidence(const TcpListenerQuery& query) {
    std::wstring out=L"TCP监听端点观测，端口 "+std::to_wstring(query.port)+L"；单调采样 "+
        std::to_wstring(query.startMs)+L"→"+std::to_wstring(query.endMs)+L" ms\r\n";
    out+=L"来源：GetExtendedTcpTable OWNER_PID_LISTENER；IPv4状态 "+std::to_wstring(query.ipv4Status)+
        L"，IPv6状态 "+std::to_wstring(query.ipv6Status)+L"（0=成功，非0=未知/失败）。\r\n";
    out+=L"二次端点复查：IPv4 "+std::to_wstring(query.ipv4RecheckStatus)+L"，IPv6 "+std::to_wstring(query.ipv6RecheckStatus)+L"。\r\n";
    for(const auto& row:query.listeners) {
        wchar_t address[64]{};
        const auto* formatted=InetNtopW(static_cast<INT>(row.family),const_cast<unsigned char*>(row.address),address,64);
        out+=std::wstring(row.family==AF_INET ? L"IPv4 " : L"IPv6 [")+(formatted?address:L"地址格式未知");
        if(row.family==AF_INET6 && row.scope) out+=L"%"+std::to_wstring(row.scope);
        if(row.family==AF_INET6) out+=L"]";
        out+=L":"+std::to_wstring(row.port)+L" PID "+std::to_wstring(row.pid);
        if(row.identityKnown) out+=L" creation "+std::to_wstring(row.creation)+L" 路径 "+row.path;
        else out+=L" 身份未知："+row.identityUnknown;
        out+=L"\r\n";
    }
    if(query.listeners.empty()) out+=L"本次未观测到匹配监听端点；不代表端口可绑定，查询失败也不是空表证据。\r\n";
    if(query.omitted) out+=L"超过128项上限，省略 "+std::to_wstring(query.omitted)+L" 项。\r\n";
    return out+L"未知：端点表与进程身份不是原子快照，二次观测只缩小竞态；监听不等于冲突，未绑定日志时间/发起进程，也未查询UDP、保留端口或防火墙。不会连接远端、关闭端点或结束进程。\r\n";
}
inline std::wstring QueryTcpListenerEvidence(uint16_t port) { return RenderTcpListenerEvidence(QueryTcpListeners(port)); }
