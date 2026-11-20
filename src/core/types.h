#pragma once
#include <cstdint>
#include <cstddef>
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
    uint32_t parentPid = 0;     // observed parent PID, not proof of parent identity
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

// GetProcessIoCounters includes cached, network and device I/O. These counters
// are NOT physical disk traffic or hard-page-fault measurements.
struct ProcessIoSample {
    uint32_t pid = 0;
    uint64_t creation = 0, tickMs = 0;
    uint64_t readBytes = 0, writeBytes = 0;
    bool valid = false;
};
enum class IoRateState { Unavailable, FirstSample, IdentityChanged, CounterReset, InvalidInterval, Measured };
struct ProcessIoRate {
    IoRateState state = IoRateState::Unavailable;
    double readBytesPerSecond = 0, writeBytesPerSecond = 0, elapsedSeconds = 0;
    bool available() const { return state == IoRateState::Measured; }
};

struct ProcessNode {
    ProcIdent identity;
    uint32_t parentPid = 0;
    double memMB = 0, cpuPct = 0;
    ProcessIoSample ioCounters{};
    ProcessIoRate ioRate{};
    bool memorySampleValid = false; // false is unknown, not measured zero working set
    bool cpuSampleValid = false; // false is unknown, not measured zero CPU
};

enum class ResourceEventKind { ObservedNew, NoLongerObserved, WorkingSetChanged };
struct ResourceEvent {
    ResourceEventKind kind = ResourceEventKind::ObservedNew;
    ProcIdent identity;
    uint64_t previousSampleMs = 0, currentSampleMs = 0;
    double previousMemoryMB = 0, currentMemoryMB = 0;
};
enum class ResourceEventState { FirstSample, Incomplete, InvalidTime, GapTooLarge, Comparable };
struct ResourceEventBatch {
    ResourceEventState state = ResourceEventState::FirstSample;
    std::vector<ResourceEvent> events;
    std::size_t omitted = 0;
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
    // Monotonic timestamps, meaningful only within this run/boot. Completion
    // does not imply that every metric or per-process identity was readable.
    uint64_t sampleStartMs = 0, sampleEndMs = 0;
    bool sampleComplete = false;
    bool processEnumerationComplete = false;
    std::vector<ResourceEvent> resourceEvents; // only the latest comparison, capped
    ResourceEventState resourceEventState = ResourceEventState::FirstSample;
    std::size_t resourceEventsOmitted = 0;
};

