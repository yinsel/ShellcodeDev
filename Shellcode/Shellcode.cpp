#include<windows.h>
#include<utils.hpp>
#include<ShellcodeHelper.hpp>
#include<stdio.h>
#define EXPORT extern "C" __declspec(dllexport)

// 定义程序入口
#pragma comment(linker,"/entry:shellcode")

void shellcode() {
	_DWORD dwKernel32 = GetKernel32Addr();
	_DWORD** functions = GetWindowsAPIs();
	volatile char szshellcode[] = { 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '\0' };
	pMessageBoxA(0, (char*)szshellcode, (char*)szshellcode, 0);
}

// 将shellcode以函数的形式导出并放在名为shell的代码段，方便提取
#pragma code_seg("shell")
EXPORT void function() {
	// shellcode代码
	// ...
	return;
}