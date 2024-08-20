#include<intrin.h>
#if defined(_WIN64)
typedef DWORD64 _DWORD;
typedef PDWORD64 _PDWORD;
typedef PIMAGE_NT_HEADERS64 _PIMAGE_NT_HEADERS;
#define GetPEB GetPEB64
#define GetExeBaseAddr GetExeBaseAddr64
#define GetNtdllAddr GetNtdllAddr64
#define GetKernel32Addr GetKernel32Addr64
#else
typedef DWORD _DWORD;
typedef PDWORD _PDWORD;
typedef PIMAGE_NT_HEADERS _PIMAGE_NT_HEADERS;
#define GetPEB GetPEB32
#define GetExeBaseAddr GetExeBaseAddr32
#define GetNtdllAddr GetNtdllAddr32
#define GetKernel32Addr GetKernel32Addr32
#endif

#pragma warning(disable : 28251)
#pragma warning(disable : 6001)

extern "C" _DWORD GetPEB32();
extern "C" _DWORD GetExeBaseAddr32();
extern "C" _DWORD GetNtdllAddr32();
extern "C" _DWORD GetKernel32Addr32();

extern "C" _DWORD GetPEB64();
extern "C" _DWORD GetExeBaseAddr64();
extern "C" _DWORD GetNtdllAddr64();
extern "C" _DWORD GetKernel32Addr64();
