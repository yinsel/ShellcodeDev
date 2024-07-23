#pragma once

typedef HMODULE(WINAPI* LoadLibraryAFunc)(_In_ LPCSTR lpLibFileName);
typedef int (WINAPI* MessageBoxAFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);