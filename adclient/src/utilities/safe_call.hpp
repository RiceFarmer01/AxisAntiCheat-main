#ifndef SAFE_CALL_HPP
#define SAFE_CALL_HPP

#include <Windows.h>
#include <cstdint>
#include <string>

#ifndef SYSCALL_NO_FORCEINLINE
#if defined(_MSC_VER)
#define SAFE_CALL_FORCEINLINE __forceinline
#endif
#else
#define SAFE_CALL_FORCEINLINE inline
#endif

#define SAFE_HASH_CT(str)                                                 \
    []() [[msvc::forceinline]] {                                          \
        constexpr uint32_t hash_out{::safe_call::fnv1a::hash_ctime(str)}; \
                                                                          \
        return hash_out;                                                  \
    }()

#define SAFE_HASH_R(str) ::safe_call::fnv1a::hash_rtime(str)

#define SAFE_CALL(function)                                                      \
    [&]() [[msvc::forceinline]] {                                                \
        constexpr uint32_t name_hash{::safe_call::fnv1a::hash_ctime(#function)}; \
                                                                                 \
        return ::safe_call::invoke_call<decltype(&function)>(name_hash);         \
    }()

#define SAFE_MODULE(module_name)                                                   \
    [&]() [[msvc::forceinline]] {                                                  \
        constexpr uint32_t name_hash{::safe_call::fnv1a::hash_ctime(module_name)}; \
                                                                                   \
        return ::safe_call::win::get_module_handle_from_hash<void *>(name_hash);   \
    }()

#define SAFE_MODULE_HASH(module_hash) ::safe_call::win::get_module_handle_from_hash<void *>(module_hash);

namespace safe_call {
    namespace nt {
        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } PEB_LDR_DATA, *PPEB_LDR_DATA;

        struct UNICODE_STRING {
            uint16_t Length;
            uint16_t MaximumLength;
            wchar_t *Buffer;
        };

        typedef struct _LDR_MODULE {
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
            PVOID BaseAddress;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
            SHORT LoadCount;
            SHORT TlsIndex;
            LIST_ENTRY HashTableEntry;
            ULONG TimeDateStamp;
        } LDR_MODULE, *PLDR_MODULE;

        typedef struct _PEB_FREE_BLOCK {
            _PEB_FREE_BLOCK *Next;
            ULONG Size;
        } PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            PVOID Reserved2[2];
            PVOID DllBase;
            PVOID EntryPoint;
            PVOID Reserved3;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            PVOID Reserved5[3];
            union {
                ULONG CheckSum;
                PVOID Reserved6;
            };
            ULONG TimeDateStamp;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

        typedef struct _RTL_DRIVE_LETTER_CURDIR {
            USHORT Flags;
            USHORT Length;
            ULONG TimeStamp;
            UNICODE_STRING DosPath;
        } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

        typedef struct _RTL_USER_PROCESS_PARAMETERS {
            ULONG MaximumLength;
            ULONG Length;
            ULONG Flags;
            ULONG DebugFlags;
            PVOID ConsoleHandle;
            ULONG ConsoleFlags;
            HANDLE StdInputHandle;
            HANDLE StdOutputHandle;
            HANDLE StdErrorHandle;
            UNICODE_STRING CurrentDirectoryPath;
            HANDLE CurrentDirectoryHandle;
            UNICODE_STRING DllPath;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
            PVOID Environment;
            ULONG StartingPositionLeft;
            ULONG StartingPositionTop;
            ULONG Width;
            ULONG Height;
            ULONG CharWidth;
            ULONG CharHeight;
            ULONG ConsoleTextAttributes;
            ULONG WindowFlags;
            ULONG ShowWindowFlags;
            UNICODE_STRING WindowTitle;
            UNICODE_STRING DesktopName;
            UNICODE_STRING ShellInfo;
            UNICODE_STRING RuntimeData;
            RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
        } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

        typedef struct _PEB {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            BOOLEAN Spare;
            HANDLE Mutant;
            PVOID ImageBaseAddress;
            PPEB_LDR_DATA LoaderData;
            RTL_USER_PROCESS_PARAMETERS ProcessParameters;
            PVOID SubSystemData;
            PVOID ProcessHeap;
            PVOID FastPebLock;
            uintptr_t FastPebLockRoutine;
            uintptr_t FastPebUnlockRoutine;
            ULONG EnvironmentUpdateCount;
            uintptr_t KernelCallbackTable;
            PVOID EventLogSection;
            PVOID EventLog;
            PPEB_FREE_BLOCK FreeList;
            ULONG TlsExpansionCounter;
            PVOID TlsBitmap;
            ULONG TlsBitmapBits[0x2];
            PVOID ReadOnlySharedMemoryBase;
            PVOID ReadOnlySharedMemoryHeap;
            uintptr_t ReadOnlyStaticServerData;
            PVOID AnsiCodePageData;
            PVOID OemCodePageData;
            PVOID UnicodeCaseTableData;
            ULONG NumberOfProcessors;
            ULONG NtGlobalFlag;
            BYTE Spare2[0x4];
            LARGE_INTEGER CriticalSectionTimeout;
            ULONG HeapSegmentReserve;
            ULONG HeapSegmentCommit;
            ULONG HeapDeCommitTotalFreeThreshold;
            ULONG HeapDeCommitFreeBlockThreshold;
            ULONG NumberOfHeaps;
            ULONG MaximumNumberOfHeaps;
            uintptr_t *ProcessHeaps;
            PVOID GdiSharedHandleTable;
            PVOID ProcessStarterHelper;
            PVOID GdiDCAttributeList;
            PVOID LoaderLock;
            ULONG OSMajorVersion;
            ULONG OSMinorVersion;
            ULONG OSBuildNumber;
            ULONG OSPlatformId;
            ULONG ImageSubSystem;
            ULONG ImageSubSystemMajorVersion;
            ULONG ImageSubSystemMinorVersion;
            ULONG GdiHandleBuffer[0x22];
            ULONG PostProcessInitRoutine;
            ULONG TlsExpansionBitmap;
            BYTE TlsExpansionBitmapBits[0x80];
            ULONG SessionId;
        } PEB, *PPEB;
    }// namespace nt

    constexpr uint32_t xor_key_1 = __TIME__[2];
    constexpr uint32_t xor_key_2 = __TIME__[4];
    constexpr uint32_t xor_key_offset = (xor_key_1 ^ xor_key_2);

    namespace fnv1a {
        constexpr uint32_t fnv_prime_value = 0x01000193;

        SAFE_CALL_FORCEINLINE consteval uint32_t
        hash_ctime(const char *input,
                   unsigned val = 0x811c9dc5 ^ ::safe_call::xor_key_offset) noexcept
        {
            return input[0] == '\0'
                           ? val
                           : hash_ctime(input + 1, (val ^ *input) * fnv_prime_value);
        }

        SAFE_CALL_FORCEINLINE constexpr uint32_t
        hash_rtime(const char *input,
                   unsigned val = 0x811c9dc5 ^ ::safe_call::xor_key_offset) noexcept
        {
            return input[0] == '\0'
                           ? val
                           : hash_rtime(input + 1, (val ^ *input) * fnv_prime_value);
        }
    }// namespace fnv1a

    namespace utils {
        SAFE_CALL_FORCEINLINE std::string wide_to_string(wchar_t *buffer) noexcept
        {
            const auto out{std::wstring(buffer)};

            if (out.empty())
                return "";

            return std::string(out.begin(), out.end());
        }
    }// namespace utils

    namespace win {
        SAFE_CALL_FORCEINLINE nt::PEB *get_peb() noexcept
        {
#if defined(_M_IX86) || defined(__i386__)
            return reinterpret_cast<::safe_call::nt::PEB *>(__readfsdword(0x30));
#else
            return reinterpret_cast<::safe_call::nt::PEB *>(__readgsqword(0x60));
#endif
        }

        template<typename T>
        static SAFE_CALL_FORCEINLINE T get_module_handle_from_hash(const uint32_t &module_hash) noexcept
        {
            auto peb = ::safe_call::win::get_peb();

            if (!peb)
                return NULL;

            if (!module_hash)
                return peb->ImageBaseAddress;

            auto head = &peb->LoaderData->InLoadOrderModuleList;

            for (auto it = head->Flink; it != head; it = it->Flink) {
                ::safe_call::nt::_LDR_DATA_TABLE_ENTRY *ldr_entry =
                        CONTAINING_RECORD(it, nt::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (!ldr_entry->BaseDllName.Buffer)
                    continue;

                auto name =
                        ::safe_call::utils::wide_to_string(ldr_entry->BaseDllName.Buffer);

                if (SAFE_HASH_R(name.data()) == module_hash)
                    return T(ldr_entry->DllBase);
            }

            return NULL;
        }

        template<typename T>
        static SAFE_CALL_FORCEINLINE T get_module_export_from_table(
                uintptr_t module_address, const uint32_t &export_hash) noexcept
        {
            auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER *>(module_address);

            if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
                return NULL;

            PIMAGE_EXPORT_DIRECTORY export_directory = nullptr;

            auto nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(
                    module_address + dos_headers->e_lfanew);
            auto nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    module_address + dos_headers->e_lfanew);

            PIMAGE_OPTIONAL_HEADER32 optional_header32 = &nt_headers32->OptionalHeader;
            PIMAGE_OPTIONAL_HEADER64 optional_header64 = &nt_headers64->OptionalHeader;

            // for 32bit modules.
            if (nt_headers32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                // does not have a export table.
                if (optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <=
                    0U)
                    return NULL;

                export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                        module_address +
                        optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                .VirtualAddress);
            }
            // for 64bit modules.
            else if (nt_headers64->OptionalHeader.Magic ==
                     IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                // does not have a export table.
                if (optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <=
                    0U)
                    return NULL;

                export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                        module_address +
                        optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                .VirtualAddress);
            }

            auto names_rva = reinterpret_cast<uint32_t *>(
                    module_address + export_directory->AddressOfNames);
            auto functions_rva = reinterpret_cast<uint32_t *>(
                    module_address + export_directory->AddressOfFunctions);
            auto name_ordinals = reinterpret_cast<unsigned short *>(
                    module_address + export_directory->AddressOfNameOrdinals);

            uint32_t number_of_names = export_directory->NumberOfNames;

            for (size_t i = 0ul; i < number_of_names; i++) {
                const char *export_name =
                        reinterpret_cast<const char *>(module_address + names_rva[i]);

                if (export_hash == SAFE_HASH_R(export_name))
                    return static_cast<T>(module_address + functions_rva[name_ordinals[i]]);
            }

            return NULL;
        }

        template<typename T>
        SAFE_CALL_FORCEINLINE T force_find_export(const uint32_t &export_hash) noexcept
        {
            auto peb = ::safe_call::win::get_peb();

            if (!peb || !export_hash)
                return NULL;

            auto head = &peb->LoaderData->InLoadOrderModuleList;

            for (auto it = head->Flink; it != head; it = it->Flink) {
                ::safe_call::nt::_LDR_DATA_TABLE_ENTRY *ldr_entry =
                        CONTAINING_RECORD(it, nt::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (!ldr_entry->BaseDllName.Buffer)
                    continue;

                auto name =
                        ::safe_call::utils::wide_to_string(ldr_entry->BaseDllName.Buffer);

                auto export_address =
                        ::safe_call::win::get_module_export_from_table<uintptr_t>(
                                reinterpret_cast<uintptr_t>(ldr_entry->DllBase), export_hash);

                if (!export_address)
                    continue;

                return static_cast<T>(export_address);
            }
        }
    }// namespace win

    template<typename T>
    SAFE_CALL_FORCEINLINE T invoke_call(uint32_t export_hash) noexcept
    {
        static auto exported_function =
                ::safe_call::win::force_find_export<uintptr_t>(export_hash);

        if (exported_function != NULL)
            return reinterpret_cast<T>(exported_function);
    }
}// namespace safe_call

#endif// SAFE_CALL_HPP