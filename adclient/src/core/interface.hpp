#ifndef AEROANTICHEAT_INTERFACES_HPP
#define AEROANTICHEAT_INTERFACES_HPP

// exported functions.
extern "C" {
    __declspec(dllexport) bool AxisDEFENDER_Init(const char *secret_key);
    __declspec(dllexport) void AxisDEFENDER_Free();
}

#endif//AEROANTICHEAT_INTERFACES_HPP
