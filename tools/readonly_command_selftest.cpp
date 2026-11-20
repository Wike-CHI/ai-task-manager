#include "../src/core/readonly_command.h"
#include <iostream>
int main(){
    int cases=0,failures=0;
    auto check=[&](bool ok){++cases;if(!ok)++failures;};
    check(ParseReadOnlyCommand({})==ReadOnlyCommand::Help);
    check(ParseReadOnlyCommand({L"--help"})==ReadOnlyCommand::Help);
    check(ParseReadOnlyCommand({L"snapshot"})==ReadOnlyCommand::Snapshot);
    check(ParseReadOnlyCommand({L"report"})==ReadOnlyCommand::Report);
    for(const auto& args:std::vector<std::vector<std::wstring>>{
        {L"kill"},{L"terminate",L"123"},{L"trim"},{L"snapshot",L"--force"},
        {L"report",L"http://example.invalid"},{L"--config",L"file"},{L"snapshot; kill"},
        {L"server"},{L"mcp"},{L"--help",L"kill"}})
        check(ParseReadOnlyCommand(args)==ReadOnlyCommand::Invalid);
    std::cout<<cases<<" readonly command checks, "<<failures<<" failures\n";
    return failures?1:0;
}
