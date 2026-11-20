#include "../src/core/signature.h"
#include <iostream>
int main() {
    int failures = 0;
    auto check = [&](bool ok, const char* name) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
        if (!ok) ++failures;
    };
    check(InspectExecutableSignature(L"").state == SignatureState::Unknown,
          "empty path stays unknown");
    check(InspectExecutableSignature(L"\\\\?\\GLOBALROOT\\nonexistent-aitm-signature-test").state == SignatureState::Unknown,
          "inaccessible path stays unknown");
    wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, 32768);
    check(length > 0 && length < 32768, "identify this test executable");
    if (length > 0 && length < 32768) {
        const auto evidence = InspectExecutableSignature(path);
        check(evidence.state == SignatureState::NoEmbeddedSignature,
              "CI-built unsigned executable has no embedded signature");
    }
    check(SignatureEvidenceText({SignatureState::TrustedOffline, 0}).find(L"未查在线吊销") != std::wstring::npos,
          "offline trust text retains revocation limitation");
    check(SignatureEvidenceText({SignatureState::Unknown, 5}).find(L"未知") != std::wstring::npos,
          "unknown text is not called trusted");
    return failures ? 1 : 0;
}
