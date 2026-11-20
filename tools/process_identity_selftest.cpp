// Read-only tests using this test process; no termination or external process.
#include "../src/core/process_identity.h"
#include <iostream>
int main() {
    int count=0, failures=0;
    auto check=[&](bool ok,const char* name){++count;if(!ok)++failures;std::cout<<(ok?"PASS ":"FAIL ")<<name<<'\n';};
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,GetCurrentProcessId());
    if(!h) { check(false,"open own process read-only"); return 1; }
    ProcIdent identity; std::wstring why;
    check(ReadProcessIdentity(h,identity,why)&&identity.pid==GetCurrentProcessId()&&identity.start&&
        !identity.path.empty()&&!identity.image.empty(),"read own complete identity from supplied handle");
    check(VerifyIdentity(h,identity,why),"matching complete identity verifies");
    auto wrong=identity; wrong.pid+=1;
    check(!VerifyIdentity(h,wrong,why),"wrong PID rejected");
    wrong=identity; ++wrong.start;
    check(!VerifyIdentity(h,wrong,why),"wrong creation rejected");
    wrong=identity; wrong.path+=L".different";
    check(!VerifyIdentity(h,wrong,why),"wrong full path rejected");
    wrong=identity; wrong.image=L"different.exe";
    check(!VerifyIdentity(h,wrong,why),"wrong image rejected");
    wrong=identity; wrong.start=0;
    check(!VerifyIdentity(h,wrong,why),"unknown creation rejected");
    wrong=identity; wrong.path.clear();
    check(!VerifyIdentity(h,wrong,why),"unknown path rejected");
    wrong=identity; wrong.image.clear();
    check(!VerifyIdentity(h,wrong,why),"unknown image rejected");
    ProcIdent bad=identity;
    check(!ReadProcessIdentity(nullptr,bad,why)&&!bad.pid&&bad.path.empty(),"invalid read resets output rather than keeping stale identity");
    check(CriticalStatus(nullptr)==CriticalState::Unknown,"critical API failure remains unknown");
    check(NormalizeIdentityText(L"C:\\App\\DEMO.EXE")==L"c:\\app\\demo.exe","case normalization has a stable result");
    check(CriticalStatus(h)==CriticalState::NotCritical,"owned ordinary test process is noncritical");
    CloseHandle(h);
    std::cout<<count<<" identity checks, "<<failures<<" failures (read-only owned process)\n";
    return failures?1:0;
}
