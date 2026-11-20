#include "../src/core/policy.h"
#include <iostream>
int main() {
    int failures = 0;
    auto check = [&](bool ok, const char* name) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
        if (!ok) ++failures;
    };
    bool noneSafe = true;
    for (const auto& item : RISK_TABLE) noneSafe &= item.second.first != RISK_SAFE;
    check(noneSafe, "no executable name grants safe termination");
    check(ClassificationEvidence(L"CHATGPT.EXE").find(L"启发式") != std::wstring::npos,
          "known names are labeled heuristic");
    check(ClassificationEvidence(L"unlisted.exe").find(L"未知") != std::wstring::npos,
          "unrecognized names remain unknown");
    check(ProtectedImage(L"LSASS.EXE"), "protective name block stays conservative");
    check(AcceptSampleIdentity(10, 20, L"C:\\node.exe", L"node.exe"), "identity boundary remains usable");
    ProcIdent id{1, 2, L"app.exe", L"C:\\app.exe", 10};
    check(id.parentPid == 10 && id.pid == 1 && id.start == 2, "parent evidence preserves identity tuple");
    return failures ? 1 : 0;
}
