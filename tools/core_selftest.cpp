#include "../src/core/workloads.h"
#include <cassert>
#include <iostream>
static ProcessNode N(uint32_t pid, uint32_t parent, uint64_t start, const wchar_t* name) {
    return {{pid, start, name, L"C:\\test.exe"}, parent, 10, 1};
}
int main() {
    auto n = std::vector<ProcessNode>{N(1,0,10,L"code.exe"), N(2,1,20,L"node.exe"), N(3,2,30,L"worker.exe")};
    auto w = AttributeWorkloads(n);
    assert(w.size()==1 && w[0].rootPid==1 && w[0].members.size()==3 && w[0].memMB==30);
    n[0].identity.start=40; // reused parent PID must not attach old children
    w = AttributeWorkloads(n); assert(w.size()==2);
    n[0].identity.start=0; w=AttributeWorkloads(n); assert(w.size()==1 && w[0].rootPid==2);
    n = {N(1,2,10,L"code.exe"),N(2,1,10,L"node.exe")};
    assert(AttributeWorkloads(n).empty());
    assert(AcceptSampleIdentity(10, 20, L"C:\\app\\node.exe", L"NODE.EXE"));
    assert(!AcceptSampleIdentity(21, 20, L"C:\\app\\node.exe", L"node.exe"));
    assert(!AcceptSampleIdentity(10, 20, L"C:\\app\\other.exe", L"node.exe"));
    assert(!AcceptSampleIdentity(0, 20, L"", L"node.exe"));
    assert(ProtectedImage(L"LSASS.EXE"));
    assert(RISK_TABLE.at(L"codex.exe").first==RISK_CAREFUL);
    assert(RISK_TABLE.at(L"msedgewebview2.exe").first==RISK_CAREFUL);
    std::cout << "core policy/tree tests passed\n";
}
