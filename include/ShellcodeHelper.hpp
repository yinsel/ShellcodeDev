 #pragma once
__forceinline _DWORD** GetWindowsAPIs();
 
__forceinline _DWORD** GetWindowsAPIs() {
    _DWORD dwKernel32 = GetKernel32Addr();

    LoadLibraryAFunc _pLoadLibraryA = (LoadLibraryAFunc)GetFuncAddrByHash(dwKernel32, LoadLibraryAHash);
    GetProcessHeapFunc _GetProcessHeap = (GetProcessHeapFunc)GetFuncAddrByHash(dwKernel32, GetProcessHeapHash);
    HeapAllocFunc _pHeapAlloc = (HeapAllocFunc)GetFuncAddrByHash(dwKernel32, HeapAllocHash);

    const _DWORD kernel32Hashes[] = Kernel32Hashes;
    const _DWORD ntdllHashes[] = NtdllHashes;

    const _DWORD wininetHashes[] = WininetHashes;

    const _DWORD shell32Hashes[] = Shell32Hashes;

    const _DWORD user32Hashes[] = User32Hashes;

    // Define DLL names
    volatile char* szKernel32 = NULL;
    volatile char* szNtdll = NULL;
    volatile char szWininet[] = Wininet;
    volatile char szShell32[] = Shell32;
    volatile char szUser32[] = User32;

    typedef struct {
        const char* dllName;
        const _DWORD* hashes;
        size_t hashCount;
    } DllInfo;

    DllInfo dlls[] = { DLL };

    const int dllCount = sizeof(dlls) / sizeof(dlls[0]);
    _DWORD** functions = (_DWORD**)_pHeapAlloc(_GetProcessHeap(), 0, sizeof(_DWORD*) * dllCount);

    if (!functions) {
        return NULL;
    }

    for (int i = 0; i < dllCount; i++) {
        const DllInfo* dllInfo = &dlls[i];
        const _DWORD* hashes = dllInfo->hashes;
        size_t hashCount = dllInfo->hashCount;

        _DWORD* dllFunctions = (_DWORD*)_pHeapAlloc(_GetProcessHeap(), 0, sizeof(_DWORD) * hashCount);
        if (!dllFunctions) {
            return NULL;
        }

        _DWORD dwDll;

        if (i == 0) {
            dwDll = dwKernel32;
        }
        else if (i == 1) {
            dwDll = GetNtdllAddr();
        }
        else {
            dwDll = (_DWORD)_pLoadLibraryA(dllInfo->dllName);
        }

        if (!dwDll) {
            return NULL;
        }

        for (size_t j = 0; j < hashCount; j++) {
            dllFunctions[j] = (_DWORD)GetFuncAddrByHash(dwDll, hashes[j]);
        }

        functions[i] = dllFunctions;
    }
    return functions;
}