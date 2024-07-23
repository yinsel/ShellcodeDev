#include<windows.h>
#include<utils.h>
#include<stdio.h>
#define EXPORT extern "C" __declspec(dllexport)

// 定义程序入口
#pragma comment(linker,"/entry:shellcode")

void shellcode() {
	_DWORD dwKernel32 = GetKernel32Addr();
	// volatile用于禁止编译器优化变量，防止变量被放入数据段
	volatile char szUser32dll[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' };
	volatile char msg[] = { 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '\0' };
	LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)GetFuncAddrByHash(dwKernel32, szLoadLibraryA);
	_DWORD hUser32 = (_DWORD)pLoadLibraryA((char*)szUser32dll);
	MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)GetFuncAddrByHash((_DWORD)hUser32, szMessageBoxA);
	pMessageBoxA(0, (char*)msg, (char*)msg, 0);
}

// 将shellcode以函数的形式导出并放在名为shell的代码段，方便提取
#pragma code_seg("shell")
EXPORT void function() {
	// shellcode代码
	// ...
	return;
}