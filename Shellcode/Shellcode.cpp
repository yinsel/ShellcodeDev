#include<windows.h>
#include<wininet.h>

#include "utils.hpp"
#include "api.hpp"

#define EXPORT extern "C" __declspec(dllexport)

#include<stdio.h>

// 定义程序入口
#pragma comment(linker,"/entry:shellcode")

#pragma code_seg("shell")
void shellcode() {
	Functions API;
	InitWindowsAPI(&API);
	char msg[] = { 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '\0' };
	char calc[] = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0' };
	API.pMessageBoxA(0, msg, msg, 0);
	API.pWinExec(calc, SW_SHOW);
}