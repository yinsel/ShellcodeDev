#include<intrin.h>
#if defined(_WIN64)
#define _PEB_Offset_1 0x30
#define _PEB_Offset_2 0x30
#define _Ldr_Offset_1 0x08
#define _Ldr_Offset_2 0x10
#define _List_Offset_1 0x08
#define _List_Offset_2 0x08
typedef DWORD64 _DWORD;
typedef PDWORD64 _PDWORD;
typedef PIMAGE_NT_HEADERS64 _PIMAGE_NT_HEADERS;
#define GetPEB GetPEB64
#define GetExeBaseAddr GetExeBaseAddr64
#define GetNtdllAddr GetNtdllAddr64
#define GetKernel32Addr GetKernel32Addr64
#else
#define _PEB_Offset_1 0x18
#define _PEB_Offset_2 0x18
#define _Ldr_Offset_1 0x06
#define _Ldr_Offset_2 0x06
#define _List_Offset_1 0x06
#define _List_Offset_2 0x06
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
#define INLINE __forceinline

extern "C" INLINE _DWORD GetPEB32();
extern "C" INLINE  _DWORD GetExeBaseAddr32();
extern "C" INLINE _DWORD GetNtdllAddr32();
extern "C" INLINE  _DWORD GetKernel32Addr32();

extern "C" INLINE _DWORD GetPEB64();
extern "C" INLINE _DWORD GetExeBaseAddr64();
extern "C" INLINE _DWORD GetNtdllAddr64();
extern "C" INLINE _DWORD GetKernel32Addr64();

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



