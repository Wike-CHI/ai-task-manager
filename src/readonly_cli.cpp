// Local one-shot read-only CLI. No main.cpp/safety.h, server, LLM or configuration.
#include "core/collector.h"
#include "core/resource_events.h"
#include "core/readonly_command.h"
#include "core/readonly_json.h"
#include <iostream>
#pragma comment(lib, "psapi.lib")
static Snapshot ReadLocalSnapshot() {
    Snapshot s; s.sampleStartMs=GetTickCount64();
    MEMORYSTATUSEX memory{}; memory.dwLength=sizeof(memory);
    if(GlobalMemoryStatusEx(&memory)) {
        s.ramTotalGB=memory.ullTotalPhys/1073741824.0;
        s.ramUsedGB=(memory.ullTotalPhys-memory.ullAvailPhys)/1073741824.0;
        s.ramPct=static_cast<double>(memory.dwMemoryLoad);
        s.comTotalGB=memory.ullTotalPageFile/1073741824.0;
        s.comUsedGB=(memory.ullTotalPageFile-memory.ullAvailPageFile)/1073741824.0;
        s.comPct=s.comTotalGB>0 ? s.comUsedGB/s.comTotalGB*100.0 : 0;
    }
    CollectProcesses(s);
    s.sampleEndMs=GetTickCount64(); s.sampleComplete=true;
    return s;
}
int wmain(int argc,wchar_t** argv) {
    std::vector<std::wstring> args;
    for(int i=1;i<argc;++i) args.emplace_back(argv[i]);
    const auto command=ParseReadOnlyCommand(args);
    if(command==ReadOnlyCommand::Help) {
        std::cout<<"AITaskManagerReadOnly: snapshot | report | --help\n"
                   "One-shot local JSON v1. No write actions, server, LLM, file writes or automatic uploads.\n"
                   "Snapshot includes local process paths. Protect stdout; GPU/temperature data is not collected.\n";
        return 0;
    }
    if(command==ReadOnlyCommand::Invalid) {
        std::cerr<<"Unsupported command. Only snapshot, report and --help are accepted; no action was performed.\n";
        return 2;
    }
    // Fixed short observation pair for delta counters, not a continuous monitor.
    const auto first=ReadLocalSnapshot(); Sleep(100);
    auto snapshot=ReadLocalSnapshot();
    const auto events=CompareResourceSnapshots(&first,snapshot);
    snapshot.resourceEvents=events.events; snapshot.resourceEventState=events.state;
    snapshot.resourceEventsOmitted=events.omitted;
    if(command==ReadOnlyCommand::Snapshot) std::cout<<SerializeSnapshotJson(snapshot)<<'\n';
    else std::cout<<SerializeFindingsJson(BuildDiagnosticFindings(snapshot))<<'\n';
    if(!std::cout) return 4;
    return snapshot.processEnumerationComplete ? 0 : 3;
}
