#include "includes.hpp"

bool AxisDEFENDER_Init(const char *secret_key)
{
    using namespace axisdefender;

    if (!secret_key || HASH(secret_key) != HASH_CT("TheWall_5423a_")) {
        SAFE_CALL(MessageBoxA)(
                NULL,
                XOR("Failed to validate client!"),
                XOR("AxisDefender"), MB_OK | MB_ICONERROR);

        return false;
    }

    hooks::query_performance_counter_hk.create_hook(NULL, HASH_CT("QueryPerformanceCounter"), &hooks::query_performance_counter);

    return true;
}

void AxisDEFENDER_Free()
{
}