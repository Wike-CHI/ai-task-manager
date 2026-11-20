#pragma once
#include "types.h"
#include <set>

enum class ConfirmationDecision { Reject, Approve };
enum class ConfirmationResult { Cancelled, Executed };

// Copy before invoking modal/UI code: a refresh cannot enlarge the approved set.
// This is an approval barrier, not rollback: OS termination may partially fail.
// Execution must still revalidate every identity using the opened process handle.
template<class Prompt, class Execute>
ConfirmationResult RunConfirmedTermination(std::vector<ProcRow> rows, Prompt prompt, Execute execute) {
    std::vector<ProcIdent> identities;
    std::set<uint32_t> pids;
    if (rows.empty()) return ConfirmationResult::Cancelled;
    for (const auto& row : rows) {
        if (row.pids.empty()) return ConfirmationResult::Cancelled;
        for (const auto& id : row.pids) {
            if (!id.pid || !id.start || id.image.empty() || id.path.empty() ||
                !pids.insert(id.pid).second) return ConfirmationResult::Cancelled;
            identities.push_back(id);
        }
    }
    for (const auto& row : rows)
        for (const auto& id : row.pids)
            if (prompt(row, id) != ConfirmationDecision::Approve)
                return ConfirmationResult::Cancelled;
    execute(identities);
    return ConfirmationResult::Executed;
}
