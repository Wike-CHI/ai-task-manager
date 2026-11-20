#pragma once
#include "types.h"
#include <map>
#include <cwctype>
static const std::map<std::wstring, std::pair<Risk, const wchar_t*>> RISK_TABLE = {
    { L"system",              { RISK_PROTECTED, L"系统进程" } },
    { L"registry",            { RISK_PROTECTED, L"系统进程" } },
    { L"memory compression",  { RISK_PROTECTED, L"系统进程" } },
    { L"csrss.exe",           { RISK_PROTECTED, L"系统关键进程" } },
    { L"wininit.exe",         { RISK_PROTECTED, L"系统关键进程" } },
    { L"winlogon.exe",        { RISK_PROTECTED, L"系统关键进程" } },
    { L"services.exe",        { RISK_PROTECTED, L"系统关键进程" } },
    { L"lsass.exe",           { RISK_PROTECTED, L"系统关键进程" } },
    { L"smss.exe",            { RISK_PROTECTED, L"系统关键进程" } },
    { L"dwm.exe",             { RISK_PROTECTED, L"桌面合成器" } },
    { L"explorer.exe",        { RISK_PROTECTED, L"桌面外壳" } },
    { L"svchost.exe",         { RISK_PROTECTED, L"系统服务宿主" } },
    { L"msmpeng.exe",         { RISK_PROTECTED, L"Defender 引擎" } },
    { L"pythonw.exe",         { RISK_PROTECTED, L"本程序" } },
    { L"llama-server.exe",    { RISK_MODEL,     L"模型服务，可能同时占用内存与显存" } },
    { L"chatgpt.exe",         { RISK_CAREFUL,      L"聊天应用，可能有未保存内容或正在运行的任务" } },
    { L"qoderwake-cn.exe",    { RISK_CAREFUL,      L"后台组件，恢复行为未知" } },
    { L"feishu.exe",          { RISK_CAREFUL,      L"协作应用，未发送内容和本地任务可能丢失" } },
    { L"wxwork.exe",          { RISK_CAREFUL,      L"协作应用，未发送内容和本地任务可能丢失" } },
    { L"wechatappex.exe",     { RISK_CAREFUL,      L"小程序容器，可能承载未保存任务" } },
    { L"msedgewebview2.exe",  { RISK_CAREFUL,   L"内嵌浏览器，可能承载未保存任务" } },
    { L"codex.exe",           { RISK_CAREFUL,   L"命令行 agent 可能正在执行任务" } },
    { L"code.exe",            { RISK_CAREFUL,   L"VS Code，可能有未保存文件" } },
    { L"qoderclicn-1.1.81.exe", { RISK_CAREFUL, L"Qoder IDE，可能有未保存文件" } },
    { L"cursor.exe",          { RISK_CAREFUL,   L"Cursor，可能有未保存文件" } },
    { L"workbuddy.exe",       { RISK_CAREFUL,   L"WorkBuddy，可能正在跑任务" } },
    { L"chrome.exe",          { RISK_CAREFUL,   L"浏览器，可能有未保存表单或下载" } },
    { L"msedge.exe",          { RISK_CAREFUL,   L"浏览器，可能有未保存表单或下载" } },
};

static std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}


static bool ProtectedImage(const std::wstring& image) {
    auto it = RISK_TABLE.find(Lower(image));
    return it != RISK_TABLE.end() && it->second.first == RISK_PROTECTED;
}

// Snapshot enumeration and OpenProcess are not atomic. A new process born
// after enumeration began must wait for the next refresh, even with the same PID.
static bool AcceptSampleIdentity(uint64_t creation, uint64_t snapshotStarted,
        const std::wstring& imagePath, const std::wstring& snapshotName) {
    auto slash = imagePath.find_last_of(L"\\/");
    const auto base = slash == std::wstring::npos ? imagePath : imagePath.substr(slash + 1);
    return creation != 0 && creation <= snapshotStarted && !imagePath.empty() &&
        Lower(base) == Lower(snapshotName);
}

// Classification is advisory evidence, never permission to terminate.
inline std::wstring ClassificationEvidence(const std::wstring& image) {
    auto it = RISK_TABLE.find(Lower(image));
    if (it == RISK_TABLE.end())
        return L"分类依据：名称未匹配策略表；用途、发布者与未保存状态未知";
    return std::wstring(L"分类依据：仅映像名称匹配（启发式，未验证程序用途）；") + it->second.second;
}
