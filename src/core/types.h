#pragma once
#include <cstdint>
#include <string>
#include <vector>
enum Risk { RISK_PROTECTED, RISK_MODEL, RISK_SAFE, RISK_CAREFUL, RISK_NORMAL };

// 进程身份。pid 只是编号：进程退出后系统会把这个号发给新进程，
// 而快照到用户点「结束」之间隔着几秒，光凭 pid 下手可能杀到刚复用了这个号的新进程。
// 所以连创建时间和映像名一起记下来，动手前再核一遍。
struct ProcIdent {
    uint32_t     pid   = 0;
    uint64_t     start = 0;     // 创建时间；0 = 快照时打不开，身份未知，后面一律不杀
    std::wstring image;         // 快照时的映像名（小写）
    std::wstring path;          // normalized full image path; empty means unknown
};

struct ProcRow {
    std::wstring name;
    int    count = 0;
    double memMB = 0;
    double cpuPct = 0;
    int    ageMin = 0;
    Risk   risk = RISK_NORMAL;
    std::wstring why;
    std::vector<ProcIdent> pids;
};

struct Sample { double ram, com, vram, gpu, gpuT, cpuT, fan; };

struct ProcessNode {
    ProcIdent identity;
    uint32_t parentPid = 0;
    double memMB = 0, cpuPct = 0;
};

struct Snapshot {
    double ramUsedGB = 0, ramTotalGB = 0, ramPct = 0;
    double comUsedGB = 0, comTotalGB = 0, comPct = 0;
    double cpuPct = 0;
    int    procCount = 0;
    bool   hasGpu = false;
    double gpuUtil = 0, vramUsed = 0, vramTotal = 0, gpuTemp = 0;
    double modelMemGB = 0;
    bool   modelRunning = false;
    std::vector<ProcRow> rows;
    std::vector<ProcessNode> processes;
};

