#include "../src/core/resource_events.h"
#include "../src/core/resource_event_report.h"
#include <iostream>
#include <limits>
static ProcessNode Node(uint32_t pid, uint64_t creation, double memory) {
    ProcessNode n; n.identity={pid,creation,L"test.exe",L"c:\\test.exe"};
    n.memMB=memory; n.memorySampleValid=true; return n;
}
static Snapshot Sample(uint64_t start, uint64_t end) {
    Snapshot s; s.sampleStartMs=start; s.sampleEndMs=end;
    s.sampleComplete=true; s.processEnumerationComplete=true; return s;
}
int main() {
    int cases=0, failures=0;
    auto check=[&](bool ok,const char* name){++cases; if(!ok) ++failures;
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<'\n';};
    auto a=Sample(1000,1100), b=Sample(2000,2100);
    a.processes={Node(10,1,256)}; b.processes=a.processes;
    auto events=CompareResourceSnapshots(nullptr,b);
    check(events.state==ResourceEventState::FirstSample && events.events.empty(),"first sample is not a process-start storm");
    events=CompareResourceSnapshots(&a,b);
    check(events.state==ResourceEventState::Comparable && events.events.empty(),"unchanged comparable pair has no events");
    b.processes[0].memMB=384;
    events=CompareResourceSnapshots(&a,b);
    check(events.events.size()==1 && events.events[0].kind==ResourceEventKind::WorkingSetChanged &&
        events.events[0].previousMemoryMB==256 && events.events[0].currentMemoryMB==384,
        "threshold memory rise retains both observations");
    b.processes[0].memMB=128;
    check(CompareResourceSnapshots(&a,b).events.size()==1,"threshold memory fall is an observation not reclaimed memory");
    b.processes[0].memorySampleValid=false;
    check(CompareResourceSnapshots(&a,b).events.empty(),"failed memory read cannot synthesize a drop");
    b.processes[0].memorySampleValid=true; b.processes[0].memMB=std::numeric_limits<double>::quiet_NaN();
    check(CompareResourceSnapshots(&a,b).events.empty(),"nonfinite memory is unknown");
    b.processes[0].memMB=300;
    check(CompareResourceSnapshots(&a,b).events.empty(),"small working-set noise stays below threshold");
    b.processes[0]=Node(10,2,1024);
    events=CompareResourceSnapshots(&a,b);
    check(events.events.size()==2 && events.events[0].kind==ResourceEventKind::NoLongerObserved &&
        events.events[1].kind==ResourceEventKind::ObservedNew,"PID reuse generates identity observations not cross-process memory delta");
    b.processes[0].identity.start=0;
    check(CompareResourceSnapshots(&a,b).events.empty(),"unreadable present PID is not an exit");
    b.processes.clear();
    events=CompareResourceSnapshots(&a,b);
    check(events.events.size()==1 && events.events[0].kind==ResourceEventKind::NoLongerObserved,"complete enumeration can report an identity no longer observed");
    b.processEnumerationComplete=false;
    events=CompareResourceSnapshots(&a,b);
    check(events.state==ResourceEventState::Incomplete && events.events.empty(),"failed enumeration cannot synthesize exits");
    b=Sample(2000,2100); b.processes={Node(20,3,100)};
    a.processes.clear();
    events=CompareResourceSnapshots(&a,b);
    check(events.events.size()==1 && events.events[0].kind==ResourceEventKind::ObservedNew,"newly observed complete identity is recorded without start claim");
    a.processes={Node(20,0,100)};
    check(CompareResourceSnapshots(&a,b).events.empty(),"identity recovery is not a process start");
    a.processes={Node(20,3,100)}; b.processes[0].identity.path=L"c:\\different.exe";
    b.processes[0].memMB=1024;
    check(CompareResourceSnapshots(&a,b).events.empty(),"path inconsistency suppresses memory inference");
    b=Sample(32000,32100);
    check(CompareResourceSnapshots(&a,b).state==ResourceEventState::GapTooLarge,"long sample gap stays unknown");
    b=Sample(1050,2100);
    check(CompareResourceSnapshots(&a,b).state==ResourceEventState::InvalidTime,"overlapping sample windows stay unknown");
    b=Sample(2000,13001);
    check(CompareResourceSnapshots(&a,b).state==ResourceEventState::InvalidTime,"slow collection window cannot masquerade as a point sample");
    b=Sample(2000,2100); b.processes={Node(20,3,100),Node(20,3,100)};
    check(CompareResourceSnapshots(&a,b).state==ResourceEventState::Incomplete,"duplicate PID evidence is rejected");
    a=Sample(1000,1100); b=Sample(2000,2100);
    for(uint32_t i=1;i<=150;++i) b.processes.push_back(Node(i,i,100));
    events=CompareResourceSnapshots(&a,b);
    check(events.events.size()==100 && events.omitted==50,"events are capped and omitted count is explicit");
    check(SnapshotFreshness(b,2100)==SampleFreshness::Fresh,"completed current sample is fresh");
    check(SnapshotFreshness(b,12101)==SampleFreshness::Stale,"aged sample is stale");
    check(SnapshotFreshness(b,2000)==SampleFreshness::Unknown,"clock reversal is unknown");
    b.sampleComplete=false;
    check(SnapshotFreshness(b,2100)==SampleFreshness::Unknown,"unfinished sample is not fresh");
    b.sampleComplete=true; b.resourceEventState=ResourceEventState::Comparable;
    b.resourceEvents=events.events; b.resourceEventsOmitted=events.omitted;
    check(ResourceEventReport(b,12101).find(L"过期")!=std::wstring::npos &&
          ResourceEventReport(b,12101).find(L"省略 50")!=std::wstring::npos,
          "report preserves staleness and truncation evidence");
    check(SnapshotTimingReport(b,2100).find(L"不代表所有身份")!=std::wstring::npos,
          "enumeration completion does not imply metric coverage");
    std::cout<<cases<<" resource event checks, "<<failures<<" failures (observations, not lifecycle diagnoses)\n";
    return failures?1:0;
}
