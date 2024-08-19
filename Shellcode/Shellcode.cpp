#include<windows.h>
#include<wininet.h>
#include "api.hpp"
#include "dllmain.hpp"
#define EXPORT extern "C" __declspec(dllexport)

#include<stdio.h>

// 定义程序入口
#pragma comment(linker,"/entry:shellcode")

#pragma code_seg(".text")
void shellcode() {
	Functions API;
	InitWindowsAPI(&API);
	char msg[] = { 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '\0' };
	char calc[] = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0' };
	API.pMessageBoxA(0, msg, msg, 0);
	API.pWinExec(calc, SW_SHOW);
}

// DllMain 上线 shellcode

//BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
//{
//	HANDLE hThread;
//	switch (ul_reason_for_call)
//	{
//	case DLL_PROCESS_ATTACH:
//		// 解锁函数
//		UNLOCK();
//
//		// shellcode加载器
//
//
//		break;
//	case DLL_THREAD_ATTACH:
//		printf("\nthread attach of dll");
//		break;
//	case DLL_THREAD_DETACH:
//		printf("\nthread detach of dll");
//		break;
//	case DLL_PROCESS_DETACH:
//		printf("\nprocess detach of dll");
//		break;
//	}
//	return TRUE;
//}

