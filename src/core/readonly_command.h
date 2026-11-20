#pragma once
#include <string>
#include <vector>
enum class ReadOnlyCommand { Invalid, Help, Snapshot, Report };
inline ReadOnlyCommand ParseReadOnlyCommand(const std::vector<std::wstring>& args) {
    if(args.empty() || (args.size()==1 && args[0]==L"--help")) return ReadOnlyCommand::Help;
    if(args.size()!=1) return ReadOnlyCommand::Invalid;
    if(args[0]==L"snapshot") return ReadOnlyCommand::Snapshot;
    if(args[0]==L"report") return ReadOnlyCommand::Report;
    return ReadOnlyCommand::Invalid;
}
