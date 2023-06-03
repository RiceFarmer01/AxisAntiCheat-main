#include "includes.hpp"

int __stdcall DllMain(HMODULE module, unsigned long, void *)
{
    using namespace axisdefender;

    utils::section_integrity_valid();

    return 1;
}