#ifndef AXISANTICHEAT_UTILS_HPP
#define AXISANTICHEAT_UTILS_HPP

namespace io {
    __forceinline void log(const char *txt, ...)
    {
#ifdef _DEBUG
        char buf[256];

        va_list args;
        va_start(args, txt);
        vsnprintf(buf, sizeof(buf), txt, args);
        va_end(args);

        auto handle = SAFE_CALL(GetStdHandle)(STD_OUTPUT_HANDLE);

        SAFE_CALL(WriteConsoleA)(handle, txt, strlen(txt), nullptr, nullptr);
#endif
    }
}// namespace io

namespace axisdefender {
    namespace utils {
        inline std::vector<std::uint8_t *> old_image_bytes{};

        bool is_debugger_or_remote_attached();
        bool section_integrity_valid();
//
//        __forceinline bool section_data_valid(void *address_of_pointer)
//        {
//            auto module_address = syscall::win::get_module_handle_from_hash<uintptr_t>(NULL);
//
//            if (!module_address)
//                return false;
//
//            auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER *>(module_address);
//
//            if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
//                return NULL;
//
//            auto nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(module_address + dos_headers->e_lfanew);
//
//            IMAGE_SECTION_HEADER *section_header = IMAGE_FIRST_SECTION(nt_headers64);
//
//            for (size_t i = 0; i < nt_headers64->FileHeader.NumberOfSections; i++, section_header++) {
//                if (HASH((const char *) section_header->Name) == HASH_CT(".data")) {
//                    DWORD_PTR data_section_start = (DWORD_PTR) module_address + section_header->VirtualAddress;
//                    DWORD_PTR data_section_end = data_section_start + section_header->Misc.VirtualSize;
//
//                    if (reinterpret_cast<DWORD_PTR>(address_of_pointer) >= data_section_start && reinterpret_cast<DWORD_PTR>(address_of_pointer) < data_section_end)
//                        return true;
//
//                    break;
//                }
//            }
//
//            return false;
//        }
    }// namespace utils
}// namespace axisdefender

#endif//AXISANTICHEAT_UTILS_HPP
