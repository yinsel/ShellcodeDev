#include<wininet.h>
typedef HMODULE
(*WINAPI
    LoadLibraryAFunc)(
        _In_ LPCSTR lpLibFileName
        );
typedef int
(*WINAPI
    MessageBoxAFunc)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType);
typedef int
(*WINAPI
    MessageBoxWFunc)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType);
typedef HRESULT(WINAPI* SHGetFolderPathWFunc)(
    HWND hwnd,
    int csidl,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath
    );
typedef HANDLE
(*WINAPI
    CreateFileWFunc)(
        _In_ LPCWSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        );
typedef VOID
(*WINAPI
    ExitProcessFunc)(
        _In_ UINT uExitCode
        );
typedef VOID
(*WINAPI
    SleepFunc)(
        _In_ DWORD dwMilliseconds
        );
typedef HINTERNET(*InternetOpenAFunc)(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
    );
typedef HINTERNET(*InternetOpenUrlAFunc)(
    _In_ HINTERNET hInternet,
    _In_ LPCSTR lpszUrl,
    _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
    _In_ DWORD dwHeadersLength,
    _In_ DWORD dwFlags,
    _In_opt_ DWORD_PTR dwContext
    );
typedef BOOL
(*HttpQueryInfoAFunc)(
    _In_ HINTERNET hRequest,
    _In_ DWORD dwInfoLevel,
    _Inout_updates_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
    _Inout_ LPDWORD lpdwBufferLength,
    _Inout_opt_ LPDWORD lpdwIndex
    );
typedef LPVOID
(*WINAPI
    VirtualAllocFunc)(
        _In_opt_ LPVOID lpAddress,
        _In_     SIZE_T dwSize,
        _In_     DWORD flAllocationType,
        _In_     DWORD flProtect
        );
typedef BOOL(*InternetReadFileFunc)(
    HANDLE hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
    );
typedef BOOL(*InternetCloseHandleFunc)(
    _In_ HANDLE hInternet
    );
typedef BOOL
(*WINAPI
    VirtualProtectFunc)(
        _In_  LPVOID lpAddress,
        _In_  SIZE_T dwSize,
        _In_  DWORD flNewProtect,
        _Out_ PDWORD lpflOldProtect
        );
typedef void (*RtlMoveMemoryFunc)(
    void* Destination,
    const void* Source,
    size_t      Length
    );
typedef HRSRC
(*WINAPI
    FindResourceAFunc)(
        _In_opt_ HMODULE hModule,
        _In_     LPCSTR lpName,
        _In_     LPCSTR lpType
        );
typedef HGLOBAL
(*WINAPI
    LoadResourceFunc)(
        _In_opt_ HMODULE hModule,
        _In_ HRSRC hResInfo
        );
typedef DWORD
(*WINAPI
    SizeofResourceFunc)(
        _In_opt_ HMODULE hModule,
        _In_ HRSRC hResInfo
        );
typedef LPVOID
(*WINAPI
    LockResourceFunc)(
        _In_ HGLOBAL hResData
        );