#ifndef AERODEFENDER_INCLUDES_HPP
#define AERODEFENDER_INCLUDES_HPP

#include <cstdint>
#include <iostream>
#include <windows.h>
#include <format>
#include <memoryapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <deque>

#include "utilities/safe_call.hpp"
#include "utilities/safe_syscall.hpp"
#include "xorstr.hpp"
#include "cryptography/crc_checksum.hpp"
#include "cryptography/fnv1a.hpp"
#include "core/win.hpp"
#include "core/image.hpp"
#include "core/utilities.hpp"
#include "core/interface.hpp"
#include "hooks/iat_hook.hpp"
#include "hooks/hooks.hpp"

#endif//AERODEFENDER_INCLUDES_HPP
