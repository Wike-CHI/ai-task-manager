#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#pragma comment(lib, "wintrust.lib")

enum class SignatureState { TrustedOffline, NoEmbeddedSignature, Invalid, Unknown };
struct SignatureEvidence {
    SignatureState state = SignatureState::Unknown;
    LONG status = ERROR_INVALID_PARAMETER;
};

// On-demand only, not in the sampling loop. The file handle prevents write/delete
// while verifying. This checks the current on-disk file, not loaded memory, and
// does not verify catalog signatures or online certificate revocation.
static SignatureEvidence InspectExecutableSignature(const std::wstring& path) {
    SignatureEvidence result;
    if (path.empty()) return result;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result.status = static_cast<LONG>(GetLastError());
        return result;
    }
    WINTRUST_FILE_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path.c_str();
    info.hFile = file;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    result.status = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    if (result.status == ERROR_SUCCESS) result.state = SignatureState::TrustedOffline;
    else if (result.status == TRUST_E_NOSIGNATURE) result.state = SignatureState::NoEmbeddedSignature;
    else if (result.status == TRUST_E_BAD_DIGEST || result.status == TRUST_E_EXPLICIT_DISTRUST)
        result.state = SignatureState::Invalid;
    // Certificate chain, policy/provider, filesystem and other failures remain
    // Unknown, rather than being misreported as unsigned or malicious.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    CloseHandle(file);
    return result;
}

static std::wstring SignatureEvidenceText(const SignatureEvidence& evidence) {
    const wchar_t* state = L"未知（离线校验未完成或失败）";
    switch (evidence.state) {
    case SignatureState::TrustedOffline: state = L"嵌入签名通过本机离线信任策略"; break;
    case SignatureState::NoEmbeddedSignature: state = L"未检出可验证嵌入签名（未查目录签名）"; break;
    case SignatureState::Invalid: state = L"嵌入签名摘要不符或本机明确不信任"; break;
    default: break;
    }
    return std::wstring(L"签名证据：") + state + L"；状态码 " +
        std::to_wstring(static_cast<unsigned long>(evidence.status)) +
        L"。仅当前磁盘文件；未查在线吊销，不证明程序用途或可安全结束。";
}
