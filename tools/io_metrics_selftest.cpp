#include "../src/core/io_metrics.h"
#include "../src/core/io_evidence.h"
#include <iostream>
#include <limits>

int main() {
    int cases = 0, failures = 0;
    auto check = [&](bool condition, const char* name) {
        ++cases; if (!condition) ++failures;
        std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
    };
    ProcessIoSample a{42,100,1000,1000,2000,true};
    ProcessIoSample b{42,100,3500,6000,12000,true};
    auto rate = CalculateIoRate(&a,b);
    check(rate.available() && rate.elapsedSeconds == 2.5 && rate.readBytesPerSecond == 2000 &&
          rate.writeBytesPerSecond == 4000, "actual interval normalizes cumulative deltas");
    check(CalculateIoRate(nullptr,b).state == IoRateState::FirstSample, "first sample is unknown, not zero I/O");
    auto invalid = b; invalid.valid = false;
    check(CalculateIoRate(&a,invalid).state == IoRateState::Unavailable, "failed current counter read is unavailable");
    invalid = a; invalid.valid = false;
    check(CalculateIoRate(&invalid,b).state == IoRateState::FirstSample, "recovery requires a new baseline");
    invalid = b; ++invalid.creation;
    check(CalculateIoRate(&a,invalid).state == IoRateState::IdentityChanged, "PID reuse cannot inherit counters");
    invalid = b; ++invalid.pid;
    check(CalculateIoRate(&a,invalid).state == IoRateState::IdentityChanged, "different PID cannot inherit counters");
    invalid = b; invalid.readBytes = 999;
    check(CalculateIoRate(&a,invalid).state == IoRateState::CounterReset, "read counter reset stays unknown");
    invalid = b; invalid.writeBytes = 1999;
    check(CalculateIoRate(&a,invalid).state == IoRateState::CounterReset, "write counter reset stays unknown");
    invalid = b; invalid.tickMs = a.tickMs;
    check(CalculateIoRate(&a,invalid).state == IoRateState::InvalidInterval, "zero interval is invalid");
    invalid.tickMs = a.tickMs - 1;
    check(CalculateIoRate(&a,invalid).state == IoRateState::InvalidInterval, "reversed time is invalid");
    invalid = b; invalid.creation = 0;
    check(!CalculateIoRate(&a,invalid).available(), "unknown creation time cannot produce a rate");
    invalid = b; invalid.pid = 0;
    check(!CalculateIoRate(&a,invalid).available(), "unknown PID cannot produce a rate");
    invalid = a; invalid.tickMs += 1000;
    rate = CalculateIoRate(&a,invalid);
    check(rate.available() && rate.readBytesPerSecond == 0 && rate.writeBytesPerSecond == 0,
          "valid unchanged counters are measured zero, distinct from unknown");
    const auto max = std::numeric_limits<uint64_t>::max();
    a = {42,100,1000,max-1000,max-2000,true}; b = {42,100,2000,max,max,true};
    rate = CalculateIoRate(&a,b);
    check(rate.available() && rate.readBytesPerSecond == 1000 && rate.writeBytesPerSecond == 2000,
          "subtract integers before conversion preserves large counter deltas");
    ProcessNode node; node.identity.pid = 42; node.identity.start = 100;
    check(BuildIoFinding(node).state == FindingState::Unknown, "unavailable rendering stays unknown");
    node.ioRate = rate;
    check(BuildIoFinding(node).state == FindingState::Observed && !BuildIoFinding(node).unknowns.empty(),
          "measured IO retains physical-disk limitations");
    Snapshot snapshot; snapshot.processes.push_back(node); snapshot.processes.push_back(ProcessNode{});
    const auto report = ProcessIoReport(snapshot);
    check(report.find(L"有效 1，未知 1") != std::wstring::npos, "report counts unavailable processes without inventing zero rates");
    std::cout << cases << " process-I/O checks, " << failures << " failures (not physical disk or hard faults)\n";
    return failures ? 1 : 0;
}
