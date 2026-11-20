// A real bounded bind-failure fixture, using only this process's loopback sockets.
#include "../src/core/port_evidence.h"
#include <iostream>
struct WinsockSession {
    bool ready=false;
    WinsockSession(){WSADATA data{};ready=WSAStartup(MAKEWORD(2,2),&data)==0;}
    ~WinsockSession(){if(ready)WSACleanup();}
};
struct OwnedSocket {
    SOCKET value=INVALID_SOCKET;
    ~OwnedSocket(){close();}
    void close(){if(value!=INVALID_SOCKET){closesocket(value);value=INVALID_SOCKET;}}
};
int main(){
    WinsockSession winsock;
    if(!winsock.ready){std::cerr<<"FAIL Winsock initialization\n";return 1;}
    OwnedSocket owner, contender;
    owner.value=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    contender.value=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(owner.value==INVALID_SOCKET||contender.value==INVALID_SOCKET){std::cerr<<"FAIL owned sockets\n";return 1;}
    BOOL exclusive=TRUE;
    if(setsockopt(owner.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))!=0){std::cerr<<"FAIL exclusive bind option\n";return 1;}
    sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(owner.value,reinterpret_cast<sockaddr*>(&local),sizeof(local))!=0 || listen(owner.value,1)!=0){std::cerr<<"FAIL owned listener\n";return 1;}
    int length=sizeof(local);
    if(getsockname(owner.value,reinterpret_cast<sockaddr*>(&local),&length)!=0){std::cerr<<"FAIL ephemeral endpoint\n";return 1;}
    const int result=bind(contender.value,reinterpret_cast<sockaddr*>(&local),sizeof(local));
    const int error=result==SOCKET_ERROR ? WSAGetLastError() : 0;
    if(result!=SOCKET_ERROR || (error!=WSAEADDRINUSE && error!=WSAEACCES)){
        std::cerr<<"FAIL expected exclusive endpoint rejection; error="<<error<<'\n';return 1;
    }
    const auto observed=QueryTcpListeners(ntohs(local.sin_port));
    const auto own=std::find_if(observed.listeners.begin(),observed.listeners.end(),[](const TcpListenerEvidence& row){
        return row.family==AF_INET && row.pid==GetCurrentProcessId() && row.identityKnown && row.endpointAssociated;
    });
    if(own==observed.listeners.end()){std::cerr<<"FAIL bind failure lacks owned listener evidence\n";return 1;}
    std::cout<<"PASS actual loopback bind rejection error="<<error<<" with same-process identity association\n";
    owner.close();
    if(bind(contender.value,reinterpret_cast<sockaddr*>(&local),sizeof(local))!=0){
        std::cerr<<"FAIL retry after owned listener closed; error="<<WSAGetLastError()<<'\n';return 1;
    }
    std::cout<<"PASS bind succeeds after only the owned listener closes; no remediation of user processes\n";
    return 0;
}
