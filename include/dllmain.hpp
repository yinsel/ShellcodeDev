#pragma once
#include <Windows.h>
#include <stdio.h>

// ----------------------------------------- 参考项目：https://github.com/Neo-Maoku/DllMainHijacking ----------------------------------------

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;
typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    ULONG                   Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
}CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBase;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, * PPEB;

size_t memFind(BYTE* mem, BYTE* search, size_t memSize, size_t length)
{
    size_t end = length - 1;
    size_t begin = 0;
    BOOL tmp;

    if (memSize < size_t(mem)) {
        //反向搜索
        for (size_t i = 0; size_t(mem) - i >= memSize; i++)
        {
            tmp = TRUE;

            while (begin <= end)
            {
                if ((search[begin] != 0xFF && *(mem - i + begin) != search[begin]) || (search[end] != 0xFF && *(mem - i + end) != search[end]))
                {
                    tmp = FALSE;
                    break;
                }

                begin++;
            }
            if (tmp)
                return size_t(mem) - i;
            else
                begin = 0;
        }
    }
    else {
        for (size_t i = 0; i + size_t(mem) < memSize; i++)
        {
            tmp = TRUE;

            while (begin <= end)
            {
                if ((search[begin] != 0xFF && *(mem + i + begin) != search[begin]) || (search[end] != 0xFF && *(mem + i + end) != search[end]))
                {
                    tmp = FALSE;
                    break;
                }

                begin++;
            }
            if (tmp)
                return size_t(mem) + i;
            else
                begin = 0;
        }
    }

    return 0;
}

BYTE* readSectionData(BYTE* buffer, PDWORD rdataLength, char* secName) {
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(buffer) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (strcmp(secName, (char*)sectionHeader[i].Name) == 0) {
            *rdataLength = sectionHeader[i].Misc.VirtualSize;
            return reinterpret_cast<BYTE*>(buffer) + sectionHeader[i].VirtualAddress;
        }
    }

    return 0;
}

size_t GetSkipFileAPIBrokering(VOID)
{
#if defined(_WIN64)
    volatile _DWORD offset = 0x15;
    return __readgsqword(0x1B + offset) + 0x17EE;
#elif defined(_WIN32)
    volatile _DWORD offset = 0x11;
    return __readfsdword(0x7 + offset) + 0xFCA;
#endif
}


VOID UNLOCK()
{
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)GetFuncAddrByHash(GetKernel32Addr(), GetProcAddressHash);
#ifdef _WIN64
    //LdrFastFailInLoaderCallout导出函数开始匹配的特征码
    volatile unsigned char lock_count_flag[] = { 0x66, 0x21, 0x88, 0xEE, 0x17, 0x00, 0x00 };
    //针对没有LdrFastFailInLoaderCallout导出函数的，全局特征码
    volatile unsigned char win7_lock_count_flag[] = { 0xF0, 0x44, 0x0F, 0xB1, 0x35, 0xFF, 0xFF, 0xFF, 0xFF, 0x41 };
#else
    volatile unsigned char lock_count_flag[] = { 0x66, 0x21, 0x88, 0xCA, 0x0F, 0x00, 0x00, 0xE8 };
    volatile unsigned char win7_lock_count_flag[] = { 0xC7, 0x45, 0xFC, 0xFE, 0xFF, 0xFF, 0xFF, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0x8B, 0x75, 0xD8 };
#endif

#ifdef _WIN64
    //LdrGetDllFullName导出函数开始匹配的特征码，有两个是为了兼容不同版本系统
    volatile unsigned char win10_staic_lock_flag1[] = { 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0x00 };
    volatile unsigned char win10_staic_lock_flag2[] = { 0x48, 0x8B, 0x1d, 0xFF, 0xFF, 0xFF, 0x00 };
#else
    volatile unsigned char win10_staic_lock_flag1[] = { 0x3b, 0x3d };
#endif

#ifdef _WIN32
    //上面的修改对server2012下32位程序还无法突破，需要额外解锁
    volatile unsigned char server12_staic_lock_flag[] = { 0x64, 0x8B, 0x1D, 0x18, 0x00, 0x00, 0x00, 0x83, 0x65, 0xDC, 0x00, 0xBA };
#endif

    HMODULE base = (HMODULE)GetNtdllAddr();
    DWORD rdataLength;
    volatile char sztext[] = { '.', 't', 'e', 'x', 't', '\0' };
    BYTE* textData = readSectionData((BYTE*)base, &rdataLength, (char*)sztext);

    //适用于win7 server 08以上的系统，需要格外解锁
    size_t addr = memFind(textData, (unsigned char*)lock_count_flag, (size_t)textData + rdataLength, sizeof(lock_count_flag));
    if (addr != 0)
    {
#ifdef _WIN64
        addr = (size_t)addr + 0x15;
        addr = addr + 5 + *(PDWORD)addr;
#else
        addr = (size_t)addr + 0xe;
        addr = *(PDWORD)addr;
#endif
        * (PDWORD)addr = (*(PDWORD)addr) & 0;

        size_t skipFileAPIBrokeringAddr = GetSkipFileAPIBrokering();
        (*(PWORD)skipFileAPIBrokeringAddr) = (*(PWORD)skipFileAPIBrokeringAddr) & 0xEFFF;
    }

    PPEB Peb = (PPEB)GetPEB();
    HMODULE hModule = (HMODULE)GetNtdllAddr();
    if (hModule == NULL)
        return;

    typedef NTSTATUS(NTAPI* RTLLEAVECRITICALSECTION)(PRTL_CRITICAL_SECTION CriticalSection);

    RTLLEAVECRITICALSECTION RtlLeaveCriticalSection = NULL;
    volatile char szRtlLeaveCriticalSection[] = { 'R', 't', 'l', 'L', 'e', 'a', 'v', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    RtlLeaveCriticalSection = (RTLLEAVECRITICALSECTION)pGetProcAddress((HMODULE)hModule, (char*)szRtlLeaveCriticalSection);

    RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)Peb->LoaderLock);

    //上面代码是解决使用LoadLibrary动态加载DLL的死锁，下面代码是解决静态导入的DLL的死锁问题
    volatile char szLdrFastFailInLoaderCallout[] = { 'L', 'd', 'r', 'F', 'a', 's', 't', 'F', 'a', 'i', 'l', 'I', 'n', 'L', 'o', 'a', 'd', 'e', 'r', 'C', 'a', 'l', 'l', 'o', 'u', 't', '\0' };
    size_t hookAddr = (size_t)pGetProcAddress((HMODULE)hModule, (char*)szLdrFastFailInLoaderCallout);
    if (hookAddr > 0) {
        //win7 和 08以上系统可以通过LdrFastFailInLoaderCallout导出函数定位到标记位地址
#ifdef _WIN64
        hookAddr = hookAddr + 0x18 + 5 + *(PDWORD)(hookAddr + 0x18);
#else
        hookAddr = *(PDWORD)(hookAddr + 0x13);
#endif
        * (PDWORD)hookAddr = 2;
    }
    else {
        //win7 和 08以下系统没有LdrFastFailInLoaderCallout导出函数，需要搜索特征码定位到标记位地址
        addr = memFind(textData, (unsigned char*)win7_lock_count_flag, (size_t)textData + rdataLength, sizeof(win7_lock_count_flag));
        if (addr != 0)
        {
#ifdef _WIN64
            hookAddr = addr + 0x5 + 4 + *(PDWORD)(addr + 0x5);
#else
            hookAddr = *(PDWORD)((size_t)addr + 0x8);
#endif
            * (PDWORD)hookAddr = 2;
        }
    }

    //系统有LdrGetDllFullName导出函数的，需要额外解锁EventMetadata，通过LdrGetDllFullName导出函数定位到标记位地址
    volatile char szLdrGetDllFullName[] = { 'L', 'd', 'r', 'G', 'e', 't', 'D', 'l', 'l', 'F', 'u', 'l', 'l', 'N', 'a', 'm', 'e', '\0' };
    hookAddr = (size_t)pGetProcAddress((HMODULE)hModule, (char*)szLdrGetDllFullName);
    if (hookAddr > 0) {
#ifdef _WIN64
        addr = memFind((BYTE*)hookAddr, (unsigned char*)win10_staic_lock_flag1, (size_t)hookAddr + 0x80, sizeof(win10_staic_lock_flag1));
        addr = addr > 0 ? addr : memFind((BYTE*)hookAddr, (unsigned char*)win10_staic_lock_flag2, (size_t)hookAddr + 0x80, sizeof(win10_staic_lock_flag2));
        if (addr != 0)
        {
            hookAddr = addr + 7 + *(PDWORD)(addr + 0x3);
            *(size_t*)(*(size_t*)(*(size_t*)hookAddr + 0x98) + 0x38) += 2;
        }
#else
        addr = memFind((BYTE*)hookAddr, (unsigned char*)win10_staic_lock_flag1, (size_t)hookAddr + 0x150, sizeof(win10_staic_lock_flag1));
        if (addr != 0)
        {
            hookAddr = *(PDWORD)(addr + 0x2);
            *(size_t*)(*(size_t*)(*(size_t*)hookAddr + 0x50) + 0x20) += 2;
        }

        //处理server2012特殊情况，解锁代码：mov ecx, offset dword_7710F74C inc eax，lock xadd [ecx], eax
        addr = memFind((BYTE*)hookAddr, (unsigned char*)server12_staic_lock_flag, (size_t)textData + rdataLength, sizeof(server12_staic_lock_flag));
        if (addr != 0)
        {
            hookAddr = *(PDWORD)(addr + sizeof(server12_staic_lock_flag));
            *(PDWORD)hookAddr = 2;
        }
#endif
    }
}
