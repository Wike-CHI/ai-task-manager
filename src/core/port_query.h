#pragma once
#include <string>
#include <cstdint>
// Explicit, narrow read-only query. No ranges, hostnames or extra commands.
inline bool ParsePortQuery(const std::wstring& query, uint16_t& port) {
    size_t prefix = 0;
    if (query.rfind(L"端口 ", 0) == 0) prefix = 3;
    else if (query.rfind(L"port ", 0) == 0) prefix = 5;
    else return false;
    const auto digits = query.size() - prefix;
    if (!digits || digits > 5) return false;
    uint32_t number = 0;
    for (size_t i = prefix; i < query.size(); ++i) {
        if (query[i] < L'0' || query[i] > L'9') return false;
        number = number * 10 + static_cast<uint32_t>(query[i] - L'0');
    }
    if (!number || number > 65535) return false;
    port = static_cast<uint16_t>(number);
    return true;
}
