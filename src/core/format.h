#pragma once
#include <string>
#include <cstdarg>
static std::wstring Fmt(const wchar_t* f, ...) {
    wchar_t buf[1024]{};
    va_list ap;
    va_start(ap, f);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, f, ap);
    va_end(ap);
    return buf;
}

