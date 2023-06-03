#include "includes.hpp"

bool axisdefender::utils::section_integrity_valid() {
    auto image_address = SAFE_MODULE_HASH(NULL);

    if (!image_address) {
        io::log("[!] Failed to get image base address.\n");
        return false;
    }

    auto image = pe::parse_image(image_address);
    const auto &sections = image.get_sections();

    if (sections.empty()) {
#ifdef _DEBUG
        io::log("[!] Failed to parse image sections!\n");
#endif
        return false;
    }

    unsigned long old_op_crc = 0xFFFFFFFF;

    for (auto &sec : sections) {
        if (sec.name_hash != HASH_CT(".text"))
            continue;

        auto start = reinterpret_cast<uint8_t*>(image.base() + sec.va);
        auto end = sec.size;

        for (size_t i = 0; i < end; i++) {
            auto op = reinterpret_cast<uint8_t*>(start[i]);

            old_op_crc = crc32::update_checksum((uint8_t)op, old_op_crc);
        }
    }

    printf("%lu\n", ~old_op_crc);

    return true;
}

__forceinline bool axisdefender::utils::is_debugger_or_remote_attached()
{
    uint32_t is_debugged = 0, is_remote_debugged = 0;

    auto peb = win::get_peb();

    if (!peb || peb->BeingDebugged) {
#ifdef _DEBUG
        io::log("[!] Debugger attached!");
#endif

        return true;
    }

    auto query_information_process = syscall::create_function(HASH_CT("NtQueryInformationProcess"));

    auto status = query_information_process.invoke_call<NTSTATUS>(
            INVALID_HANDLE_VALUE,
            nt::PROCESS_INFORMATION_CLASS::ProcessDebugFlags,
            &is_debugged,
            sizeof(is_debugged),
            NULL);

    if (!NT_SUCCESS(status)) {
#ifdef _DEBUG
        io::log("[!] NtQueryInformationProcess failed with status (%X)", (status & 0xFFFFFFFF));
#endif
        return true;
    }

    status = query_information_process.invoke_call<NTSTATUS>(
            INVALID_HANDLE_VALUE,
            nt::PROCESS_INFORMATION_CLASS::ProcessDebugPort,
            &is_remote_debugged,
            sizeof(is_remote_debugged),
            NULL);

    if (!NT_SUCCESS(status)) {
#ifdef _DEBUG
        io::log("[!] NtQueryInformationProcess failed with status (%X)", (status & 0xFFFFFFFF));
#endif
        return true;
    }

    if (is_remote_debugged != 0) {
#ifdef _DEBUG
        io::log("[!] Remote debugger attached!");
#endif
        return true;
    }
}