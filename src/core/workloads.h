#pragma once
#include "types.h"
#include "policy.h"
#include <map>
#include <set>

struct Workload {
    uint32_t rootPid = 0;
    std::wstring kind;
    std::vector<uint32_t> members;
    double memMB = 0, cpuPct = 0;
};
static std::wstring DeveloperKind(const std::wstring& image) {
    const auto name = Lower(image);
    if (name == L"code.exe" || name == L"cursor.exe" || name == L"workbuddy.exe") return L"IDE";
    if (name == L"codex.exe" || name == L"codebuddy.exe" || name == L"claude.exe") return L"Coding Agent";
    if (name == L"cl.exe" || name == L"msbuild.exe" || name == L"ninja.exe" || name == L"cmake.exe") return L"Build";
    if (name == L"node.exe" || name == L"python.exe" || name == L"pythonw.exe") return L"Runtime (heuristic)";
    return L"";
}
// Parent PID alone is not proof: reject absent/unknown/newer parents and cycles.
static const ProcessNode* VerifiedParent(const ProcessNode& node,
        const std::map<uint32_t, const ProcessNode*>& index) {
    auto it = index.find(node.parentPid);
    if (it == index.end() || !node.identity.start || !it->second->identity.start ||
        node.identity.pid == node.parentPid || it->second->identity.start > node.identity.start) return nullptr;
    return it->second;
}
static std::vector<Workload> AttributeWorkloads(const std::vector<ProcessNode>& nodes) {
    std::map<uint32_t, const ProcessNode*> index;
    for (const auto& node : nodes) index[node.identity.pid] = &node;
    std::map<uint32_t, Workload> groups;
    for (const auto& node : nodes) {
        if (!node.identity.start) continue;
        const ProcessNode* cursor = &node;
        const ProcessNode* root = nullptr;
        std::set<uint32_t> seen;
        bool cycle = false;
        while (cursor) {
            if (!seen.insert(cursor->identity.pid).second) { cycle = true; break; }
            if (!DeveloperKind(cursor->identity.image).empty()) root = cursor;
            cursor = VerifiedParent(*cursor, index);
        }
        if (!root || cycle) continue;
        auto& group = groups[root->identity.pid];
        group.rootPid = root->identity.pid;
        group.kind = DeveloperKind(root->identity.image);
        group.members.push_back(node.identity.pid);
        group.memMB += node.memMB; group.cpuPct += node.cpuPct;
    }
    std::vector<Workload> result;
    for (const auto& pair : groups) result.push_back(pair.second);
    return result;
}
