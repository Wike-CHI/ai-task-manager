#include "../src/core/diagnostic_evidence.h"
#include <iostream>
#include <limits>
int main() {
    int failures = 0, cases = 0;
    auto check = [&](bool ok, const char* name) { ++cases; if (!ok) ++failures;
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n'; };
    Snapshot s;
    auto f = BuildDiagnosticFindings(s);
    check(f.size() == 8, "stable finding IDs include unsupported detectors");
    check(f[0].state == FindingState::Unknown && f[1].state == FindingState::Unknown &&
        f[2].state == FindingState::Unknown, "missing sample is not healthy zero");
    s.ramUsedGB = 8.8; s.ramTotalGB = 10; s.comUsedGB=5; s.comTotalGB=10;
    s.hasGpu=true; s.vramUsed=9.2; s.vramTotal=10;
    f=BuildDiagnosticFindings(s);
    check(f[0].state == FindingState::Risk && f[2].state==FindingState::Risk, "threshold boundaries yield risk not diagnosis");
    check(f[1].state == FindingState::Observed, "below threshold only means observed");
    check(f[0].evidence.size()==4 && !f[0].unknowns.empty() && !f[0].nextSteps.empty(), "finding retains source and unknowns");
    bool unknown=true; for(size_t i=3;i<f.size();++i) unknown &= f[i].state==FindingState::Unknown && f[i].confidence==EvidenceConfidence::None;
    check(unknown, "capacity pressure does not confirm OOM port or anomaly");
    for(double value : {-1., 11., std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN()}) {
        s.ramUsedGB=value;
        check(BuildDiagnosticFindings(s)[0].state==FindingState::Unknown, "invalid capacity stays unknown");
    }
    s.hasGpu=false;
    check(BuildDiagnosticFindings(s)[2].state==FindingState::Unknown, "stale GPU numbers ignored when source unavailable");
    auto report=RenderDiagnosticFindings(BuildDiagnosticFindings(s));
    check(report.find(L"未知")!=std::wstring::npos && report.find(L"下一步")!=std::wstring::npos, "renderer preserves uncertainty and next steps");
    std::cout << cases << " evidence checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
