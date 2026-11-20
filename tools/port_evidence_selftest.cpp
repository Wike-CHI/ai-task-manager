// Own temporary loopback listeners only; no remote connection or process action.
#include "../src/core/port_evidence.h"
#include <iostream>
struct TestSocket { SOCKET value=INVALID_SOCKET; ~TestSocket(){if(value!=INVALID_SOCKET)closesocket(value);} };
int main() {
    WSADATA data{};
    if(WSAStartup(MAKEWORD(2,2),&data)!=0) {std::cout<<"FAIL WSAStartup\n";return 1;}
    int failures=0,count=0;
    auto check=[&](bool ok,const char* name){++count;if(!ok)++failures;std::cout<<(ok?"PASS ":"FAIL ")<<name<<'\n';};
    auto exercise=[&](DWORD family) {
        TestSocket listener; listener.value=socket(static_cast<int>(family),SOCK_STREAM,IPPROTO_TCP);
        if(listener.value==INVALID_SOCKET) {
            const int error=WSAGetLastError();
            if(family==AF_INET6&&(error==WSAEAFNOSUPPORT||error==WSAEPROTONOSUPPORT)) {std::cout<<"SKIP IPv6 unsupported by runner\n";return;}
            check(false,"create loopback listener");return;
        }
        uint16_t port=0;
        if(family==AF_INET) {
            sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            if(bind(listener.value,reinterpret_cast<sockaddr*>(&local),sizeof(local))!=0) {check(false,"bind IPv4 loopback");return;}
            int size=sizeof(local);
            if(getsockname(listener.value,reinterpret_cast<sockaddr*>(&local),&size)!=0) {check(false,"resolve ephemeral IPv4 port");return;}
            port=ntohs(local.sin_port);
        } else {
            DWORD only=1;setsockopt(listener.value,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<const char*>(&only),sizeof(only));
            sockaddr_in6 local{};local.sin6_family=AF_INET6;local.sin6_addr=in6addr_loopback;
            if(bind(listener.value,reinterpret_cast<sockaddr*>(&local),sizeof(local))!=0) {
                const int error=WSAGetLastError();
                if(error==WSAEADDRNOTAVAIL||error==WSAEAFNOSUPPORT) {std::cout<<"SKIP IPv6 loopback unavailable\n";return;}
                check(false,"bind IPv6 loopback");return;
            }
            int size=sizeof(local);
            if(getsockname(listener.value,reinterpret_cast<sockaddr*>(&local),&size)!=0) {check(false,"resolve ephemeral IPv6 port");return;}
            port=ntohs(local.sin6_port);
        }
        if(listen(listener.value,1)!=0) {check(false,"listen on own socket");return;}
        const auto q=QueryTcpListeners(port);
        const auto row=std::find_if(q.listeners.begin(),q.listeners.end(),[&](const TcpListenerEvidence& e){return e.family==family&&e.pid==GetCurrentProcessId()&&e.port==port;});
        check((family==AF_INET?q.ipv4Status:q.ipv6Status)==NO_ERROR,"requested address family table is readable");
        FILETIME ownCreated{},ownExited{},ownKernel{},ownUser{};
        const bool ownTimes=GetProcessTimes(GetCurrentProcess(),&ownCreated,&ownExited,&ownKernel,&ownUser)!=FALSE;
        check(row!=q.listeners.end()&&row->endpointReobserved&&row->identityKnown&&ownTimes&&
              row->creation==PortFileTime(ownCreated)&&!row->path.empty(),
              "own listener carries reobserved endpoint and matching process identity");
        const auto text=RenderTcpListenerEvidence(q);
        check(text.find(L"监听不等于冲突")!=std::wstring::npos&&text.find(L"不是原子快照")!=std::wstring::npos,"renderer retains non-atomic and non-conflict limitations");
        if(family==AF_INET6)
            check(text.find(L"IPv6 [::1]:"+std::to_wstring(port))!=std::wstring::npos,
                  "IPv6 endpoint uses unambiguous brackets");
        closesocket(listener.value);listener.value=INVALID_SOCKET;
        const auto after=QueryTcpListeners(port);
        const bool owned=std::any_of(after.listeners.begin(),after.listeners.end(),[&](const TcpListenerEvidence& e){return e.family==family&&e.pid==GetCurrentProcessId()&&e.port==port;});
        check(!owned,"closed owned listener is no longer observed, not proof port is bindable");
    };
    exercise(AF_INET);exercise(AF_INET6);
    check(QueryTcpListeners(0).ipv4Status==ERROR_INVALID_PARAMETER,"zero port rejected without query");
    WSACleanup();
    std::cout<<count<<" TCP listener checks, "<<failures<<" failures (loopback fixtures only)\n";
    return failures?1:0;
}
