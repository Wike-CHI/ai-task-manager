#pragma once
#include "types.h"
#include <map>
#include <cmath>
#include <algorithm>

enum class SampleFreshness { Unknown, Fresh, Stale };
inline bool ValidSampleWindow(const Snapshot& s) {
    return s.sampleComplete && s.sampleEndMs >= s.sampleStartMs &&
        s.sampleEndMs - s.sampleStartMs <= 10000;
}
inline SampleFreshness SnapshotFreshness(const Snapshot& s, uint64_t nowMs, uint64_t maxAgeMs = 10000) {
    if (!ValidSampleWindow(s) || nowMs < s.sampleEndMs) return SampleFreshness::Unknown;
    return nowMs - s.sampleEndMs <= maxAgeMs ? SampleFreshness::Fresh : SampleFreshness::Stale;
}
inline bool EventIdentityKnown(const ProcIdent& id) {
    return id.pid && id.start && !id.image.empty() && !id.path.empty();
}
inline ResourceEventBatch CompareResourceSnapshots(const Snapshot* previous, const Snapshot& current) {
    ResourceEventBatch result;
    if (!previous) return result;
    if (!previous->sampleComplete || !current.sampleComplete ||
        !previous->processEnumerationComplete || !current.processEnumerationComplete) {
        result.state = ResourceEventState::Incomplete; return result;
    }
    if (!ValidSampleWindow(*previous) || !ValidSampleWindow(current) ||
        current.sampleStartMs < previous->sampleEndMs || current.sampleEndMs <= previous->sampleEndMs) {
        result.state = ResourceEventState::InvalidTime; return result;
    }
    if (current.sampleEndMs - previous->sampleEndMs > 30000) {
        result.state = ResourceEventState::GapTooLarge; return result;
    }
    std::map<uint32_t, const ProcessNode*> before, after;
    for (const auto& n : previous->processes) {
        if (!before.emplace(n.identity.pid, &n).second) {
            result.state = ResourceEventState::Incomplete; return result;
        }
    }
    for (const auto& n : current.processes) {
        if (!after.emplace(n.identity.pid, &n).second) {
            result.state = ResourceEventState::Incomplete; return result;
        }
    }
    result.state = ResourceEventState::Comparable;
    auto add = [&](ResourceEventKind kind, const ProcIdent& identity, double oldMB = 0, double newMB = 0) {
        if (result.events.size() >= 100) { ++result.omitted; return; }
        result.events.push_back({kind, identity, previous->sampleEndMs, current.sampleEndMs, oldMB, newMB});
    };
    for (const auto& entry : before) {
        const auto& old = *entry.second;
        if (!EventIdentityKnown(old.identity)) continue;
        auto found = after.find(entry.first);
        if (found == after.end()) { add(ResourceEventKind::NoLongerObserved, old.identity); continue; }
        const auto& now = *found->second;
        // A present but unreadable PID is not evidence that its old identity vanished.
        if (!EventIdentityKnown(now.identity)) continue;
        if (old.identity.start != now.identity.start) {
            add(ResourceEventKind::NoLongerObserved, old.identity);
            continue;
        }
        if (old.identity.path != now.identity.path || old.identity.image != now.identity.image) continue;
        if (!old.memorySampleValid || !now.memorySampleValid ||
            !std::isfinite(old.memMB) || !std::isfinite(now.memMB) || old.memMB < 0 || now.memMB < 0) continue;
        const auto delta = std::fabs(now.memMB - old.memMB);
        // Observable change, not leakage/reclaimable memory: require both thresholds.
        if (delta >= 128 && delta >= std::max(1.0, old.memMB) * .25)
            add(ResourceEventKind::WorkingSetChanged, now.identity, old.memMB, now.memMB);
    }
    for (const auto& entry : after) {
        const auto& now = *entry.second;
        if (!EventIdentityKnown(now.identity)) continue;
        auto found = before.find(entry.first);
        if (found == before.end()) { add(ResourceEventKind::ObservedNew, now.identity); continue; }
        const auto& old = *found->second;
        if (EventIdentityKnown(old.identity) && old.identity.start != now.identity.start)
            add(ResourceEventKind::ObservedNew, now.identity);
    }
    return result;
}
