#include "includes.hpp"

BOOL axisdefender::hooks::query_performance_counter(LARGE_INTEGER *lpPerformanceCount)
{
    io::log(XOR("QueryPerformanceCounter\n"));
    return query_performance_counter_hk.call_original<decltype(&hooks::query_performance_counter)>()(lpPerformanceCount);
}