#include "../src/core/port_query.h"
#include <iostream>
int main() {
    int failures=0,count=0;
    auto check=[&](bool ok,const char* name){++count;if(!ok)++failures;std::cout<<(ok?"PASS ":"FAIL ")<<name<<'\n';};
    uint16_t p=99;
    check(ParsePortQuery(L"端口 3000",p)&&p==3000,"Chinese explicit query");
    check(ParsePortQuery(L"port 65535",p)&&p==65535,"upper boundary");
    check(ParsePortQuery(L"port 1",p)&&p==1,"lower boundary");
    for(const auto* q:{L"port 0",L"port 65536",L"port -1",L"port 123456",L"port ",L"port  80",L"port 80 ",L"port 80; kill",L"port example.com:80",L"report 80",L"端口８０",L"PORT 80"}) {
        p=99; check(!ParsePortQuery(q,p)&&p==99,"invalid query is rejected without changing output");
    }
    std::cout<<count<<" port query checks, "<<failures<<" failures\n";return failures?1:0;
}
