#include "../src/core/readonly_json.h"
#include <iostream>
#include <limits>
struct CommaDecimal : std::numpunct<char> { char do_decimal_point() const override { return ','; } };
int main(int argc,char**) {
    int failures=0,count=0;
    auto check=[&](bool ok,const char* name){++count;if(!ok)++failures;std::cout<<(ok?"PASS ":"FAIL ")<<name<<'\n';};
    using namespace readonly_json;
    check(Quote(L"\"\\\n\r\t\b\f")=="\"\\\"\\\\\\u000a\\u000d\\u0009\\u0008\\u000c\"","quotes slash and controls escaped");
    check(Quote(std::wstring(1,L'\0'))=="\"\\u0000\"","embedded NUL survives as JSON escape");
    check(Quote(L"中文")=="\"\\u4e2d\\u6587\"","non-ASCII uses ASCII escapes");
    std::wstring pair;pair.push_back(static_cast<wchar_t>(0xd83d));pair.push_back(static_cast<wchar_t>(0xde00));
    check(Quote(pair)=="\"\\ud83d\\ude00\"","valid UTF16 surrogate pair preserved");
    if(sizeof(wchar_t)>2) check(Quote(std::wstring(1,static_cast<wchar_t>(0x1f600)))=="\"\\ud83d\\ude00\"","wide scalar becomes UTF16 pair");
    check(Quote(std::wstring(1,static_cast<wchar_t>(0xd800)))=="\"\\ufffd\""&&
          Quote(std::wstring(1,static_cast<wchar_t>(0xdc00)))=="\"\\ufffd\"","unpaired surrogates replaced");
    check(Number(std::numeric_limits<double>::quiet_NaN())=="null"&&Number(std::numeric_limits<double>::infinity())=="null"&&
          Number(-std::numeric_limits<double>::infinity())=="null","nonfinite numbers serialize as null");
    const std::locale prior = std::locale();
    std::locale::global(std::locale(prior,new CommaDecimal));
    const auto decimal=Number(1.5);
    std::locale::global(prior);
    check(decimal=="1.5","numbers ignore global comma decimal locale");
    check(Integer(std::numeric_limits<uint64_t>::max())=="\"18446744073709551615\"","64bit integer is quoted without precision loss");
    Snapshot s;s.sampleEndMs=9007199254740993ULL;
    ProcessNode node;node.identity={42,9007199254740993ULL,L"a.exe",L"C:\\私有\\a.exe",7};
    node.cpuPct=std::numeric_limits<double>::infinity(); s.processes.push_back(node);
    auto json=SerializeSnapshotJson(s);
    check(json.find("\"schemaVersion\":1,\"readOnly\":true,\"kind\":\"snapshot\"")==1,"snapshot envelope stable");
    check(json.find("\"creationTime\":\"9007199254740993\"")!=std::string::npos&&json.find("\"endMs\":\"9007199254740993\"")!=std::string::npos,"identity and clocks use string integers");
    check(json.find("\"workingSetMB\":null")!=std::string::npos&&json.find("\"readBytes\":null")!=std::string::npos&&
          json.find("\"readBytesPerSecond\":null")!=std::string::npos,"missing memory and IO stay null");
    check(json.find("\"ramUsedGB\":null")!=std::string::npos && json.find("\"commitTotalGB\":null")!=std::string::npos,
          "invalid system capacities stay null");
    check(json.find("\"gpuAvailable\":false,\"gpuUtilPercent\":null")!=std::string::npos,"unavailable GPU not measured zero");
    check(json.find("\"cpuPercent\":null")!=std::string::npos,"nonfinite node metric stays null");
    bool ascii=true;for(unsigned char c:json)ascii&=c<128;check(ascii,"entire output ASCII only");
    s.processes[0].cpuSampleValid=true;s.processes[0].cpuPct=0;
    check(SerializeSnapshotJson(s).find("\"memorySampleValid\":false,\"cpuPercent\":0")!=std::string::npos,
          "valid measured zero CPU is distinguishable from missing baseline");
    s.processes[0].memorySampleValid=true;s.processes[0].memMB=0;
    s.processes[0].ioCounters={42,2,3,std::numeric_limits<uint64_t>::max(),0,true};
    s.processes[0].ioRate={IoRateState::Measured,0,1,2};
    s.resourceEventState=ResourceEventState::Comparable;s.resourceEventsOmitted=3;
    s.resourceEvents.push_back({ResourceEventKind::WorkingSetChanged,node.identity,1,2,128,256});
    ProcRow row;row.name=L"x";row.risk=RISK_CAREFUL;row.pids.push_back(node.identity);s.rows.push_back(row);
    json=SerializeSnapshotJson(s);
    check(json.find("\"readBytes\":\"18446744073709551615\"")!=std::string::npos&&json.find("\"readBytesPerSecond\":0")!=std::string::npos,"valid zero and cumulative uint64 retained");
    check(json.find("\"resourceEventState\":\"comparable\"")!=std::string::npos&&json.find("\"resourceEventsOmitted\":\"3\"")!=std::string::npos&&
          json.find("\"kind\":\"workingSetChanged\"")!=std::string::npos,"event schema and omission count retained");
    check(json.find("\"classification\":\"careful\"")!=std::string::npos&&json.find("\"identities\":[")!=std::string::npos,"group identity and classification stable");
    DiagnosticFinding finding;finding.id=L"fault";finding.conclusion=L"unknown";finding.evidence={{L"a",L"b",L"c",L"d"}};
    finding.unknowns={L"missing"};finding.nextSteps={L"observe"};
    const auto out=SerializeFindingsJson({finding});
    check(out.find("\"state\":\"unknown\",\"confidenceBasis\":\"none\"")!=std::string::npos&&
          out.find("\"unknowns\":[\"missing\"],\"nextSteps\":[\"observe\"]")!=std::string::npos,"finding uncertainty preserved");
    check(out.find("{\"metric\":\"a\",\"value\":\"b\",\"unit\":\"c\",\"source\":\"d\"}")!=std::string::npos,"evidence names stable");
    check(SerializeFindingsJson({}).find("\"findings\":[]")!=std::string::npos,"empty findings valid array");
    check(SerializeFindingsJson({}, &s).find("\"sampling\":{\"startMs\":\"0\",\"endMs\":\"9007199254740993\"")!=std::string::npos, "report can retain exact sample metadata");
    if(argc>1) std::cout<<"SNAPSHOT_JSON="<<json<<"\nFINDINGS_JSON="<<out<<'\n';
    std::cout<<count<<" readonly JSON checks, "<<failures<<" failures\n";
    return failures?1:0;
}
