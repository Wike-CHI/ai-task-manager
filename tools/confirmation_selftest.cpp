// Portable transaction tests, not an interactive Win32 UI acceptance test.
#include "../src/core/confirmation.h"
#include <iostream>
#include <stdexcept>
#include <string>

static int cases = 0, failures = 0;
static void Check(bool condition, const char* name) {
    ++cases;
    if (!condition) ++failures;
    std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
}
static std::vector<ProcRow> Targets() {
    ProcRow a, b;
    a.name = L"editor.exe";
    a.pids = {{100, 10, L"editor.exe", L"c:\\apps\\editor.exe"},
              {101, 11, L"editor.exe", L"c:\\apps\\editor.exe"}};
    b.name = L"worker.exe";
    b.pids = {{102, 12, L"worker.exe", L"c:\\apps\\worker.exe"}};
    return {a, b};
}
static bool Same(const ProcIdent& a, const ProcIdent& b) {
    return a.pid == b.pid && a.start == b.start && a.image == b.image && a.path == b.path;
}
int main() {
    for (int rejectAt : {1, 3}) {
        int prompted = 0, executed = 0;
        auto result = RunConfirmedTermination(Targets(),
            [&](const ProcRow&, const ProcIdent&) {
                return ++prompted == rejectAt ? ConfirmationDecision::Reject : ConfirmationDecision::Approve;
            }, [&](const std::vector<ProcIdent>&) { ++executed; });
        Check(result == ConfirmationResult::Cancelled && executed == 0 && prompted == rejectAt,
              rejectAt == 1 ? "first rejection executes nothing" : "last rejection cancels entire batch");
    }
    {
        int executed = 0;
        auto result = RunConfirmedTermination(Targets(),
            [](const ProcRow&, const ProcIdent&) { return ConfirmationDecision{}; },
            [&](const std::vector<ProcIdent>&) { ++executed; });
        Check(result == ConfirmationResult::Cancelled && executed == 0, "default decision fails closed");
    }
    auto invalid = [](std::vector<ProcRow> rows, const char* label) {
        int prompted = 0, executed = 0;
        auto result = RunConfirmedTermination(rows,
            [&](const ProcRow&, const ProcIdent&) { ++prompted; return ConfirmationDecision::Approve; },
            [&](const std::vector<ProcIdent>&) { ++executed; });
        Check(result == ConfirmationResult::Cancelled && prompted == 0 && executed == 0, label);
    };
    invalid({}, "empty request rejected before prompt");
    {
        auto rows = Targets(); rows.back().pids.clear();
        invalid(rows, "empty row rejected before any prompt");
    }
    {
        auto rows = Targets(); rows.back().pids.back().pid = 0;
        invalid(rows, "missing PID rejected before any prompt");
        rows = Targets(); rows.back().pids.back().start = 0;
        invalid(rows, "missing creation time rejected before any prompt");
        rows = Targets(); rows.back().pids.back().image.clear();
        invalid(rows, "missing image rejected before any prompt");
        rows = Targets(); rows.back().pids.back().path.clear();
        invalid(rows, "missing full path rejected before any prompt");
        rows = Targets(); rows.back().pids.back() = rows.front().pids.front();
        invalid(rows, "duplicate identity rejected across rows");
        rows.back().pids.back().start += 1;
        invalid(rows, "conflicting identity for same PID rejected");
        rows = Targets(); rows.front().pids.push_back(rows.front().pids.front());
        invalid(rows, "duplicate identity rejected within row");
    }
    {
        auto source = Targets();
        const auto original = source;
        int prompted = 0, executed = 0;
        bool unchanged = true, afterAll = false;
        auto result = RunConfirmedTermination(source,
            [&](const ProcRow& row, const ProcIdent& id) {
                const auto& expectedRow = prompted < 2 ? original[0] : original[1];
                const auto& expectedId = prompted < 2 ? original[0].pids[prompted] : original[1].pids[0];
                unchanged = unchanged && row.name == expectedRow.name && Same(id, expectedId);
                ++prompted;
                source.clear(); // Simulate a refresh/reallocation during a modal prompt.
                ProcRow replacement; replacement.name = L"new.exe";
                replacement.pids = {{999, 99, L"new.exe", L"c:\\new.exe"}};
                source.push_back(replacement);
                return ConfirmationDecision::Approve;
            }, [&](const std::vector<ProcIdent>& ids) {
                ++executed;
                afterAll = prompted == 3;
                unchanged = unchanged && ids.size() == 3;
                if (ids.size() == 3)
                    unchanged = unchanged && Same(ids[0], original[0].pids[0]) &&
                        Same(ids[1], original[0].pids[1]) && Same(ids[2], original[1].pids[0]);
            });
        Check(result == ConfirmationResult::Executed && executed == 1 && afterAll,
              "execute once only after every approval");
        Check(unchanged && prompted == 3, "external refresh cannot replace or expand frozen targets");
    }
    {
        int prompted = 0, executed = 0;
        bool propagated = false;
        try {
            RunConfirmedTermination(Targets(), [&](const ProcRow&, const ProcIdent&) {
                if (++prompted == 2) throw std::runtime_error("prompt failed");
                return ConfirmationDecision::Approve;
            }, [&](const std::vector<ProcIdent>&) { ++executed; });
        } catch (const std::runtime_error&) { propagated = true; }
        Check(propagated && prompted == 2 && executed == 0, "prompt failure propagates without execution");
    }
    std::cout << cases << " transaction checks, " << failures
              << " failures (not interactive UI verification)\n";
    return failures == 0 ? 0 : 1;
}
