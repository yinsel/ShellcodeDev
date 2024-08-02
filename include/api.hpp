#pragma once

typedef HMODULE(WINAPI* LoadLibraryAFunc)(_In_ LPCSTR lpLibFileName);
typedef UINT(WINAPI* WinExecFunc)(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);
typedef int (WINAPI* MessageBoxAFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);


constexpr auto LoadLibraryAHash = Hash("LoadLibraryA");
constexpr auto WinExecHash = Hash("WinExec");
constexpr auto MessageBoxAHash = Hash("MessageBoxA");


typedef struct _FUNCTIONS {
	LoadLibraryAFunc pLoadLibraryA;
	WinExecFunc pWinExec;
	MessageBoxAFunc pMessageBoxA;
}Functions, * PFunctions;

typedef struct _FUNCTION {
	_DWORD dwDllBase;
	DWORD* funcHashs;
	DWORD count;
}Function;

INLINE void InitWindowsAPI(PFunctions API) {
	_DWORD dwNtdll = GetNtdllAddr();
	_DWORD dwKernel32 = GetKernel32Addr();

	API->pLoadLibraryA = (LoadLibraryAFunc)GetFuncAddrByHash(dwKernel32, LoadLibraryAHash);
	volatile char szUser32[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' };

	_DWORD dwUser32 = (_DWORD)API->pLoadLibraryA((char*)szUser32);
	DWORD ntdllFunHashes[] = { 0x00 };
	DWORD kernel32FunHashes[] = { LoadLibraryAHash, WinExecHash};
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