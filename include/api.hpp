#pragma once
#include "header.h"

typedef HMODULE(WINAPI* LoadLibraryAFunc)(_In_ LPCSTR lpLibFileName);
typedef UINT(WINAPI* WinExecFunc)(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);
typedef int (WINAPI* MessageBoxAFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
typedef HMODULE(WINAPI* LoadLibraryAFunc)(_In_ LPCSTR lpLibFileName);
typedef UINT(WINAPI* WinExecFunc)(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);
typedef int (WINAPI* MessageBoxAFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
typedef int (WINAPI* MessageBoxWFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
typedef DWORD(WINAPI* GetFileAttributesAFunc)(_In_ LPCSTR lpFileName);
typedef VOID(WINAPI* ExitProcessFunc)(_In_ UINT uExitCode);
typedef HANDLE(WINAPI* CreateFileAFunc)(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);
typedef DWORD(WINAPI* GetFileSizeFunc)(_In_ HANDLE hFile, _Out_opt_ LPDWORD lpFileSizeHigh);
typedef LPVOID(WINAPI* VirtualAllocFunc)(_In_opt_ LPVOID lpAddress, _In_     SIZE_T dwSize, _In_     DWORD flAllocationType, _In_     DWORD flProtect);
typedef BOOL(WINAPI* ReadFileFunc)(_In_ HANDLE hFile, _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer, _In_ DWORD nNumberOfBytesToRead, _Out_opt_ LPDWORD lpNumberOfBytesRead, _Inout_opt_ LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* VirtualProtectFunc)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef HANDLE(WINAPI* GetStdHandleFunc)(_In_ DWORD nStdHandle);
typedef BOOL(WINAPI* WriteConsoleAFunc)(_In_ HANDLE hConsoleOutput, _In_reads_(nNumberOfCharsToWrite) CONST VOID* lpBuffer, _In_ DWORD nNumberOfCharsToWrite, _Out_opt_ LPDWORD lpNumberOfCharsWritten, _Reserved_ LPVOID lpReserved);
typedef VOID(WINAPI* SleepFunc)(_In_ DWORD dwMilliseconds);
typedef HWND(APIENTRY* GetConsoleWindowFunc)(VOID);
typedef FARPROC(WINAPI* GetProcAddressFunc)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

constexpr INLINE DWORD Hash(const char* functionName) {
	DWORD hash = 0;
	while (*functionName) {
		hash = (hash * 138) + *functionName;
		functionName++;
	}
	return hash;
}

constexpr auto LoadLibraryAHash = Hash("LoadLibraryA");
constexpr auto WinExecHash = Hash("WinExec");
constexpr auto MessageBoxAHash = Hash("MessageBoxA");
constexpr auto MessageBoxWHash = Hash("MessageBoxW");
constexpr auto GetFileAttributesAHash = Hash("GetFileAttributesA");
constexpr auto ExitProcessHash = Hash("ExitProcess");
constexpr auto CreateFileAHash = Hash("CreateFileA");
constexpr auto GetFileSizeHash = Hash("GetFileSize");
constexpr auto VirtualAllocHash = Hash("VirtualAlloc");
constexpr auto ReadFileHash = Hash("ReadFile");
constexpr auto VirtualProtectHash = Hash("VirtualProtect");
constexpr auto GetStdHandleHash = Hash("GetStdHandle");
constexpr auto WriteConsoleAHash = Hash("WriteConsoleA");
constexpr auto SleepHash = Hash("Sleep");
constexpr auto GetConsoleWindowHash = Hash("GetConsoleWindow");
constexpr auto RtlExitUserProcessHash = Hash("RtlExitUserProcess");
constexpr auto GetProcAddressHash = Hash("GetProcAddress");


typedef struct _FUNCTIONS {
	LoadLibraryAFunc pLoadLibraryA;
	WinExecFunc pWinExec;
	GetProcAddressFunc pGetProcAddress;

	MessageBoxAFunc pMessageBoxA;
}Functions, * PFunctions;

typedef struct _FUNCTION {
	_DWORD dwDllBase;
	DWORD* funcHashs;
	DWORD count;
}Function;

INLINE _DWORD GetFuncAddrByHash(_DWORD dwBase, _DWORD hash);

INLINE void InitWindowsAPI(PFunctions API) {
	_DWORD dwNtdll = GetNtdllAddr();
	_DWORD dwKernel32 = GetKernel32Addr();
	API->pLoadLibraryA = (LoadLibraryAFunc)GetFuncAddrByHash(dwKernel32, LoadLibraryAHash);
	volatile char szUser32[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' };

	_DWORD dwUser32 = (_DWORD)API->pLoadLibraryA((char*)szUser32);
	DWORD ntdllFunHashes[] = { 0x00 };
	DWORD kernel32FunHashes[] = { LoadLibraryAHash, WinExecHash,GetProcAddressHash};
	DWORD user32FunHashes[] = { MessageBoxAHash };

	Function functions[] = {
		{ dwNtdll,ntdllFunHashes,sizeof(ntdllFunHashes) / sizeof(DWORD) },
		{ dwKernel32,kernel32FunHashes,sizeof(kernel32FunHashes) / sizeof(DWORD)},
		{ dwUser32,user32FunHashes,sizeof(user32FunHashes) / sizeof(DWORD) }
	};

	void** api = (void**)API;

	int offset = 0;

	for (size_t i = 0; i < sizeof(functions) / sizeof(Function); i++) {
		const Function func = functions[i];
		for (DWORD j = 0; j < func.count; j++) {
			if (func.funcHashs[j] != 0x00) {
				*(api + offset) = (void*)GetFuncAddrByHash(func.dwDllBase, func.funcHashs[j]);
			}
			else {
				continue;
			}
			offset++;
		}
	}
}

INLINE _DWORD GetFuncAddrByHash(_DWORD dwBase, _DWORD hash) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	_PIMAGE_NT_HEADERS pNt = (_PIMAGE_NT_HEADERS)(dwBase + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pEAT = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	PDWORD pENT = (PDWORD)(dwBase + pExport->AddressOfNames);
	PWORD pEIT = (PWORD)(dwBase + pExport->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
		char* szFuncName = (char*)(dwBase + pENT[i]);
		if (Hash(szFuncName) == hash) {
			return dwBase + pEAT[pEIT[i]];
		}
	}
	return 0;
}