#pragma once
#include "diagnostic_evidence.h"
#include <limits>
#include <locale>
#include <type_traits>

// ASCII-only JSON. No OS calls, file access, network access or action dispatch.
namespace readonly_json {
inline std::string HexUnit(uint32_t value) {
    static const char* hex="0123456789abcdef";
    std::string out="\\u0000";
    for(int i=0;i<4;++i) out[5-i]=hex[(value>>(i*4))&15];
    return out;
}
inline std::string Quote(const std::wstring& value) {
    std::string out="\"";
    for(size_t i=0;i<value.size();++i) {
        uint32_t c=static_cast<uint32_t>(value[i]);
        if(c>=0xd800 && c<=0xdbff) {
            if(i+1<value.size()) {
                const auto low=static_cast<uint32_t>(value[i+1]);
                if(low>=0xdc00 && low<=0xdfff) {
                    out+=HexUnit(c)+HexUnit(low); ++i; continue;
                }
            }
            c=0xfffd;
        } else if((c>=0xdc00 && c<=0xdfff)||c>0x10ffff) c=0xfffd;
        if(c=='"') out+="\\\"";
        else if(c=='\\') out+="\\\\";
        else if(c>=0x20 && c<0x7f) out.push_back(static_cast<char>(c));
        else if(c<=0xffff) out+=HexUnit(c);
        else {
            c-=0x10000;
            out+=HexUnit(0xd800+(c>>10))+HexUnit(0xdc00+(c&0x3ff));
        }
    }
    return out+'"';
}
inline std::string Number(double value) {
    if(!std::isfinite(value)) return "null";
    std::ostringstream stream; stream.imbue(std::locale::classic());
    stream<<std::setprecision(std::numeric_limits<double>::max_digits10)<<value;
    return stream.str();
}
inline std::string Integer(uint64_t value) {return '"'+std::to_string(value)+'"';}
inline std::string Boolean(bool value) {return value?"true":"false";}
inline void Item(std::string& out, bool& first, const std::string& value) {
    if(!first) out+=',';
    first=false; out+=value;
}
inline std::string Strings(const std::vector<std::wstring>& values) {
    std::string out="["; bool first=true;
    for(const auto& value:values) Item(out,first,Quote(value));
    return out+"]";
}
inline std::string Identity(const ProcIdent& id) {
    return "{\"pid\":"+Integer(id.pid)+",\"creationTime\":"+Integer(id.start)+
        ",\"exePath\":"+Quote(id.path)+",\"image\":"+Quote(id.image)+",\"parentPid\":"+Integer(id.parentPid)+"}";
}
inline const char* IoState(IoRateState state) {
    switch(state) {
    case IoRateState::FirstSample:return "firstSample";
    case IoRateState::IdentityChanged:return "identityChanged";
    case IoRateState::CounterReset:return "counterReset";
    case IoRateState::InvalidInterval:return "invalidInterval";
    case IoRateState::Measured:return "measured";
    default:return "unavailable";
    }
}
inline const char* EventState(ResourceEventState state) {
    switch(state) {
    case ResourceEventState::Incomplete:return "incomplete";
    case ResourceEventState::InvalidTime:return "invalidTime";
    case ResourceEventState::GapTooLarge:return "gapTooLarge";
    case ResourceEventState::Comparable:return "comparable";
    default:return "firstSample";
    }
}
inline const char* EventKind(ResourceEventKind kind) {
    switch(kind) {
    case ResourceEventKind::NoLongerObserved:return "noLongerObserved";
    case ResourceEventKind::WorkingSetChanged:return "workingSetChanged";
    default:return "observedNew";
    }
}
inline const char* RiskName(Risk risk) {
    switch(risk) {
    case RISK_PROTECTED:return "protected";
    case RISK_MODEL:return "model";
    case RISK_SAFE:return "legacySafe";
    case RISK_CAREFUL:return "careful";
    default:return "unknown";
    }
}
inline std::string Node(const ProcessNode& node) {
    const auto& c=node.ioCounters; const auto& r=node.ioRate;
    return "{\"identity\":"+Identity(node.identity)+",\"observedParentPid\":"+Integer(node.parentPid)+
        ",\"workingSetMB\":"+(node.memorySampleValid?Number(node.memMB):"null")+
        ",\"memorySampleValid\":"+Boolean(node.memorySampleValid)+",\"cpuPercent\":"+(node.cpuSampleValid?Number(node.cpuPct):"null")+
        ",\"io\":{\"source\":\"GetProcessIoCounters\",\"countersValid\":"+Boolean(c.valid)+
        ",\"pid\":"+Integer(c.pid)+",\"creationTime\":"+Integer(c.creation)+",\"sampleTickMs\":"+Integer(c.tickMs)+
        ",\"readBytes\":"+(c.valid?Integer(c.readBytes):"null")+",\"writeBytes\":"+(c.valid?Integer(c.writeBytes):"null")+
        ",\"state\":\""+IoState(r.state)+"\",\"readBytesPerSecond\":"+(r.available()?Number(r.readBytesPerSecond):"null")+
        ",\"writeBytesPerSecond\":"+(r.available()?Number(r.writeBytesPerSecond):"null")+
        ",\"intervalSeconds\":"+(r.available()?Number(r.elapsedSeconds):"null")+"}}";
}
inline std::string Row(const ProcRow& row) {
    std::string ids="["; bool first=true;
    for(const auto& id:row.pids) Item(ids,first,Identity(id));
    ids+=']';
    return "{\"name\":"+Quote(row.name)+",\"count\":"+std::to_string(row.count)+
        ",\"workingSetMB\":"+Number(row.memMB)+",\"cpuPercent\":"+std::string("null")+
        ",\"ageMinutes\":"+std::to_string(row.ageMin)+",\"classification\":\""+RiskName(row.risk)+
        "\",\"coverage\":\"partialOrUnknown\",\"classificationBasis\":"+Quote(row.why)+",\"identities\":"+ids+"}";
}
inline std::string Finding(const DiagnosticFinding& f) {
    const char* state=f.state==FindingState::Observed?"observed":f.state==FindingState::Risk?"risk":"unknown";
    const char* confidence=f.confidence==EvidenceConfidence::DirectMeasurement?"directMeasurement":
        f.confidence==EvidenceConfidence::Heuristic?"heuristic":"none";
    std::string evidence="["; bool first=true;
    for(const auto& e:f.evidence) Item(evidence,first,"{\"metric\":"+Quote(e.metric)+",\"value\":"+Quote(e.value)+
        ",\"unit\":"+Quote(e.unit)+",\"source\":"+Quote(e.source)+"}");
    evidence+=']';
    return "{\"id\":"+Quote(f.id)+",\"conclusion\":"+Quote(f.conclusion)+",\"state\":\""+state+
        "\",\"confidenceBasis\":\""+confidence+"\",\"evidence\":"+evidence+
        ",\"unknowns\":"+Strings(f.unknowns)+",\"nextSteps\":"+Strings(f.nextSteps)+"}";
}
} // namespace readonly_json

inline std::string SerializeSnapshotJson(const Snapshot& s) {
    using namespace readonly_json;
    std::string processes="[",rows="[",events="["; bool first=true;
    for(const auto& n:s.processes) Item(processes,first,Node(n));
    processes+=']';
    first=true; for(const auto& r:s.rows) Item(rows,first,Row(r)); rows+=']';
    first=true;
    for(const auto& e:s.resourceEvents) Item(events,first,"{\"kind\":\""+std::string(EventKind(e.kind))+
        "\",\"identity\":"+Identity(e.identity)+",\"previousSampleMs\":"+Integer(e.previousSampleMs)+
        ",\"currentSampleMs\":"+Integer(e.currentSampleMs)+",\"previousWorkingSetMB\":"+Number(e.previousMemoryMB)+
        ",\"currentWorkingSetMB\":"+Number(e.currentMemoryMB)+"}");
    events+=']';
    return "{\"schemaVersion\":1,\"readOnly\":true,\"kind\":\"snapshot\",\"source\":\"local deterministic Win32 collector\","
        "\"limitations\":[\"No write authorization is represented by this output.\",\"Paths may identify private local work; no data is transmitted by this serializer.\","
        "\"Timestamps are monotonic and meaningful only within the same run/boot.\",\"Sampling completion is not metric or identity completeness.\","
        "\"System CPU is not exported without a validity flag; process CPU requires a valid same-identity baseline.\",\"Group working sets may be partial and shared pages may be counted more than once.\","
        "\"Process IO is not physical disk traffic or hard faults; events are observations, not lifecycle or fault proof.\"],"
        "\"sampling\":{\"startMs\":"+Integer(s.sampleStartMs)+",\"endMs\":"+Integer(s.sampleEndMs)+
        ",\"complete\":"+Boolean(s.sampleComplete)+",\"processEnumerationComplete\":"+Boolean(s.processEnumerationComplete)+"},"
        "\"resources\":{\"ramUsedGB\":"+(ValidCapacity(s.ramUsedGB,s.ramTotalGB)?Number(s.ramUsedGB):"null")+",\"ramTotalGB\":"+(ValidCapacity(s.ramUsedGB,s.ramTotalGB)?Number(s.ramTotalGB):"null")+
        ",\"ramPercent\":"+(ValidCapacity(s.ramUsedGB,s.ramTotalGB)?Number(s.ramUsedGB/s.ramTotalGB*100):"null")+",\"commitUsedGB\":"+(ValidCapacity(s.comUsedGB,s.comTotalGB)?Number(s.comUsedGB):"null")+
        ",\"commitTotalGB\":"+(ValidCapacity(s.comUsedGB,s.comTotalGB)?Number(s.comTotalGB):"null")+",\"commitPercent\":"+(ValidCapacity(s.comUsedGB,s.comTotalGB)?Number(s.comUsedGB/s.comTotalGB*100):"null")+
        ",\"cpuPercent\":"+std::string("null")+",\"processCount\":"+std::to_string(s.procCount)+
        ",\"gpuAvailable\":"+Boolean(s.hasGpu)+",\"gpuUtilPercent\":"+(s.hasGpu?Number(s.gpuUtil):"null")+
        ",\"vramUsedGB\":"+(s.hasGpu&&ValidCapacity(s.vramUsed,s.vramTotal)?Number(s.vramUsed):"null")+",\"vramTotalGB\":"+(s.hasGpu&&ValidCapacity(s.vramUsed,s.vramTotal)?Number(s.vramTotal):"null")+
        ",\"gpuTemperatureC\":"+(s.hasGpu?Number(s.gpuTemp):"null")+",\"modelObserved\":"+Boolean(s.modelRunning)+
        ",\"modelWorkingSetGB\":"+(s.modelRunning?Number(s.modelMemGB):"null")+"},\"groups\":"+rows+",\"processes\":"+processes+
        ",\"resourceEventState\":\""+EventState(s.resourceEventState)+"\",\"resourceEventsOmitted\":"+Integer(s.resourceEventsOmitted)+
        ",\"resourceEvents\":"+events+"}";
}
inline std::string SerializeFindingsJson(const std::vector<DiagnosticFinding>& findings) {
    using namespace readonly_json;
    std::string items="["; bool first=true;
    for(const auto& f:findings) Item(items,first,Finding(f));
    items+=']';
    return "{\"schemaVersion\":1,\"readOnly\":true,\"kind\":\"findings\",\"source\":\"local deterministic diagnosis engine\","
        "\"limitations\":[\"Confidence is an evidence category, not a probability.\",\"Unknowns remain explicit; findings never authorize writes.\","
        "\"Provided text signals do not prove current runtime faults.\"],\"findings\":"+items+"}";
}
