#ifndef AEROANTICHEAT_WIN_HPP
#define AEROANTICHEAT_WIN_HPP

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

    typedef LONG KPRIORITY, *PKPRIORITY;

    typedef struct _PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        struct _PEB *PebBaseAddress;
        ULONG_PTR AffinityMask;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation = 0,
        ProcessQuotaLimits = 1,
        ProcessIoCounters = 2,
        ProcessVmCounters = 3,
        ProcessTimes = 4,
        ProcessBasePriority = 5,
        ProcessRaisePriority = 6,
        ProcessDebugPort = 7,
        ProcessExceptionPort = 8,
        ProcessAccessToken = 9,
        ProcessLdtInformation = 10,
        ProcessLdtSize = 11,
        ProcessDefaultHardErrorMode = 12,
        ProcessIoPortHandlers = 13,
        ProcessPooledUsageAndLimits = 14,
        ProcessWorkingSetWatch = 15,
        ProcessUserModeIOPL = 16,
        ProcessEnableAlignmentFaultFixup = 17,
        ProcessPriorityClass = 18,
        ProcessWx86Information = 19,
        ProcessHandleCount = 20,
        ProcessAffinityMask = 21,
        ProcessPriorityBoost = 22,
        ProcessDeviceMap = 23,
        ProcessSessionInformation = 24,
        ProcessForegroundInformation = 25,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessLUIDDeviceMapsEnabled = 28,
        ProcessBreakOnTermination = 29,
        ProcessDebugObjectHandle = 30,
        ProcessDebugFlags = 31,
        ProcessHandleTracing = 32,
        ProcessExecuteFlags = 34,
        ProcessTlsInformation = 35,
        ProcessCookie = 36,
        ProcessImageInformation = 37,
        ProcessCycleTime = 38,
        ProcessPagePriority = 39,
        ProcessInstrumentationCallback = 40,
        ProcessThreadStackAllocation = 41,
        ProcessWorkingSetWatchEx = 42,
        ProcessImageFileNameWin32 = 43,
        ProcessImageFileMapping = 44,
        ProcessAffinityUpdateMode = 45,
        ProcessMemoryAllocationMode = 46,
        ProcessGroupInformation = 47,
        ProcessTokenVirtualizationEnabled = 48,
        ProcessConsoleHostProcess = 49,
        ProcessWindowInformation = 50,
        MaxProcessInfoClass
    } PROCESSINFOCLASS, PROCESS_INFORMATION_CLASS;
}// namespace nt

namespace win {
    __forceinline nt::PEB *get_peb()
    {
#if defined(_M_IX86) || defined(__i386__)
        return reinterpret_cast<::nt::PEB *>(__readfsdword(0x30));
#else
        return reinterpret_cast<::nt::PEB *>(__readgsqword(0x60));
#endif
    }
}// namespace win

#endif//AEROANTICHEAT_WIN_HPP
