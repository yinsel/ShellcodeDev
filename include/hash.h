#pragma once

// constexpr用于编译时计算常量

constexpr DWORD Hash(const char* functionName) {
	DWORD hash = 0;
	while (*functionName) {
		hash = (hash * 138) + *functionName;
		functionName++;
	}
	return hash;
}

// 定义Hash
constexpr auto szLoadLibraryA = Hash("LoadLibraryA");
constexpr auto szMessageBoxA = Hash("MessageBoxA");