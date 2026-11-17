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
    { L"llama-server.exe",    { RISK_MODEL,     L"翻译模型，占显存不占内存" } },
    { L"chatgpt.exe",         { RISK_SAFE,      L"对话在云端，重开无损" } },
    { L"qoderwake-cn.exe",    { RISK_SAFE,      L"后台守护，用到时自恢复" } },
    { L"feishu.exe",          { RISK_SAFE,      L"消息会同步，重开不丢" } },
    { L"wxwork.exe",          { RISK_SAFE,      L"消息会同步，重开不丢" } },
    { L"wechatappex.exe",     { RISK_SAFE,      L"小程序容器，可重开" } },
    { L"msedgewebview2.exe",  { RISK_CAREFUL,   L"内嵌浏览器，可能承载未保存任务" } },
    { L"codex.exe",           { RISK_CAREFUL,   L"命令行 agent 可能正在执行任务" } },
    { L"code.exe",            { RISK_CAREFUL,   L"VS Code，可能有未保存文件" } },
    { L"qoderclicn-1.1.81.exe", { RISK_CAREFUL, L"Qoder IDE，可能有未保存文件" } },
    { L"cursor.exe",          { RISK_CAREFUL,   L"Cursor，可能有未保存文件" } },
    { L"workbuddy.exe",       { RISK_CAREFUL,   L"WorkBuddy，可能正在跑任务" } },
    { L"chrome.exe",          { RISK_CAREFUL,   L"浏览器标签会丢" } },
    { L"msedge.exe",          { RISK_CAREFUL,   L"浏览器标签会丢" } },
};

static std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}


static bool ProtectedImage(const std::wstring& image) {
    auto it = RISK_TABLE.find(Lower(image));
    return it != RISK_TABLE.end() && it->second.first == RISK_PROTECTED;
}
