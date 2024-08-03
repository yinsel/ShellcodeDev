#include<intrin.h>

#if defined(_WIN64)
#define _PEB_Offset 0x60
#define _Ldr_Offset 0x18
#define _IOM_Offset 0x10
typedef DWORD64 _DWORD;
typedef PDWORD64 _PDWORD;
typedef PIMAGE_NT_HEADERS64 _PIMAGE_NT_HEADERS;
#else
#define _PEB_Offset 0x30
#define _Ldr_Offset 0x0C
#define _IOM_Offset 0x0C
typedef DWORD _DWORD;
typedef PDWORD _PDWORD;
typedef PIMAGE_NT_HEADERS _PIMAGE_NT_HEADERS;
#endif

#pragma warning(disable : 28251)
#pragma warning(disable : 6001)
#define INLINE __forceinline

extern "C" {
#pragma function(memset)
	void* __cdecl memset(void* dest, int value, size_t num) {
		__stosb(static_cast<unsigned char*>(dest), static_cast<unsigned char>(value), num);
		return dest;
	}
#pragma function(memcpy)
	void* __cdecl memcpy(void* dest, const void* src, size_t num) {
		__movsb(static_cast<unsigned char*>(dest), static_cast<const unsigned char*>(src), num);
		return dest;
	}
}

constexpr INLINE DWORD Hash(const char* functionName) {
	DWORD hash = 0;
	while (*functionName) {
		hash = (hash * 138) + *functionName;
		functionName++;
	}
	return hash;
}

INLINE _DWORD GetNtdllAddr() {
	_DWORD dwNtdll = 0;
	_TEB* pTeb = NtCurrentTeb();
	_PDWORD pPeb = (_PDWORD) * (_PDWORD)((_DWORD)pTeb + _PEB_Offset);
	_PDWORD pLdr = (_PDWORD) * (_PDWORD)((_DWORD)pPeb + _Ldr_Offset);
	_PDWORD InLoadOrderModuleList = (_PDWORD)((_DWORD)pLdr + _IOM_Offset);
	_PDWORD pModuleExe = (_PDWORD)*InLoadOrderModuleList;
	_PDWORD pModuleNtdll = (_PDWORD)*pModuleExe;
	dwNtdll = pModuleNtdll[6];
	return dwNtdll;
}

INLINE _DWORD GetKernel32Addr() {
	_DWORD dwKernel32 = 0;
	_TEB* pTeb = NtCurrentTeb();
	_PDWORD pPeb = (_PDWORD) * (_PDWORD)((_DWORD)pTeb + _PEB_Offset);
	_PDWORD pLdr = (_PDWORD) * (_PDWORD)((_DWORD)pPeb + _Ldr_Offset);
	_PDWORD InLoadOrderModuleList = (_PDWORD)((_DWORD)pLdr + _IOM_Offset);
	_PDWORD pModuleExe = (_PDWORD)*InLoadOrderModuleList;
	_PDWORD pModuleNtdll = (_PDWORD)*pModuleExe;
	_PDWORD pModuleKernel32 = (_PDWORD)*pModuleNtdll;
	dwKernel32 = pModuleKernel32[6];
	return dwKernel32;
}

INLINE _DWORD GetExeBaseAddr() {
	_DWORD dwExe = 0;
	_TEB* pTeb = NtCurrentTeb();
	_PDWORD pPeb = (_PDWORD) * (_PDWORD)((_DWORD)pTeb + _PEB_Offset);
	_PDWORD pLdr = (_PDWORD) * (_PDWORD)((_DWORD)pPeb + _Ldr_Offset);
	_PDWORD InLoadOrderModuleList = (_PDWORD)((_DWORD)pLdr + _IOM_Offset);
	_PDWORD pModuleExe = (_PDWORD)*InLoadOrderModuleList;
	dwExe = pModuleExe[6];
	return dwExe;
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
