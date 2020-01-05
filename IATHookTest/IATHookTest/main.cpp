#include "stdafx.h"
#include <Windows.h>

DWORD g_funcAddrOrigninal = NULL; // CreateProcessW函数的地址
DWORD g_funcIATfuncAddr = NULL; // 导入地址表的地址，就是存放函数地址的地址，用于卸载IAT Hook

typedef BOOL (*CreateProcessWFunc)(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);



BOOL MyCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	OutputDebugString(_T("MyCreateProcessW enter-----"));


	OutputDebugString(lpApplicationName);
	OutputDebugString(lpCommandLine);
	CreateProcessWFunc func = (CreateProcessWFunc)g_funcAddrOrigninal;
	BOOL ret = func(lpApplicationName,lpCommandLine,
		lpProcessAttributes,lpThreadAttributes,
		bInheritHandles,dwCreationFlags,
		lpEnvironment,lpCurrentDirectory,
		lpStartupInfo,lpProcessInformation);

	OutputDebugString(_T("MyCreateProcessW exit-----"));
	return ret;
}



 

void IATHOOKCreateProcessW()
{
	OutputDebugString(_T("IATHOOKCreateProcessW, enter "));
	//HMODULE hModuleExe = GetModuleHandle(NULL);
	// 在win7下的explorer.exe中 使用的是SHELL32.dll中的kernel.dll!!!所以这里其实地址应该是SHELL32.dll
	HMODULE hModuleExe = GetModuleHandle(_T("SHELL32.dll"));

	// 获取CreateProcessW函数地址
	HMODULE hModuleKernel = GetModuleHandle(_T("KERNEL32.dll")); 
	if(hModuleKernel == NULL)
	{
		OutputDebugString(_T("IATHOOKCreateProcessW,LoadLibrary kernel32.dll failed !!!"));
		return;
	}
	CreateProcessWFunc CreateProcessWAddress = (CreateProcessWFunc)GetProcAddress(hModuleKernel,"CreateProcessW");
	if(CreateProcessWAddress == NULL)
	{
		OutputDebugString(_T("IATHOOKCreateProcessW,GetProcAddress CreateProcessW failed !!!"));
		return;
	}
	g_funcAddrOrigninal = (DWORD)CreateProcessWAddress;

	// 获取PE结构
	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)hModuleExe;
	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((DWORD)hModuleExe + pDosHead->e_lfanew);

	// 保存映像基址和导入表的RVA
	ULONGLONG dwImageBase = pNtHead->OptionalHeader.ImageBase;
	ULONGLONG dwImpDicRva = pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// 导入表的VA，导入表的一项对应一个DLL模块
	PIMAGE_IMPORT_DESCRIPTOR pImageDes= (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + dwImpDicRva);
	PIMAGE_IMPORT_DESCRIPTOR pImageTemp = pImageDes;

	// 在导入表中查找要hook的模块是否存在
	bool bFind = false;
	while(pImageTemp->Name) // 最后一项结构体为全0
	{
		char* pName = (char*)(dwImageBase + pImageTemp->Name); // name地址
		CString cstrName = pName;
		if(cstrName.CompareNoCase(_T("kernel32.dll")) == 0)
		{
			OutputDebugString(_T("IATHOOKCreateProcessW,find kernel32.dll"));
			bFind = true;
			break;
		}
		pImageTemp++;
	}
	//return;
	bool bFindFnc = false;
	// 找到要HOOK的DLL模块
	if(bFind)
	{
		// 导入地址表，一项对应一个函数，进行遍历 查找到要hook的函数
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(dwImageBase + pImageTemp->FirstThunk);
		while(pThunk->u1.Function) // 最后一项结构体为全0
		{
			DWORD* pFuncAddr = (DWORD*)&(pThunk->u1.Function); // 这个地址上存放的是【函数的地址】
			
			// 取出函数的地址 和 之前在程序中找到的函数地址做比较，如果一样就找到了改函数的导入地址表了！
			if(*pFuncAddr == g_funcAddrOrigninal)
			{
				bFindFnc = true;
				DWORD dwMyHookAddr = (DWORD)MyCreateProcessW;
				g_funcIATfuncAddr = (DWORD)pFuncAddr;

				OutputDebugString(_T("IATHOOKCreateProcessW,CreateProcessW find"));
				BOOL bRet = WriteProcessMemory(GetCurrentProcess(),pFuncAddr,&dwMyHookAddr,sizeof(DWORD),NULL);
				if(bRet)
				{
					OutputDebugString(_T("IATHOOKCreateProcessW,WriteProcessMemory suc"));
				}
				else
				{
					OutputDebugString(_T("IATHOOKCreateProcessW,WriteProcessMemory fail !!!"));
				}

				break;
			}
			pThunk++;
		}
	}

	if(bFindFnc == false)
	{
		OutputDebugString(_T("IATHOOKCreateProcessW, not find CreateProcessW？？？"));
	}

}

void UNIATHOOKCreateProcessW()
{
	OutputDebugString(_T("UNIATHOOKCreateProcessW, enter "));
	if(g_funcIATfuncAddr)
	{
		if(g_funcAddrOrigninal)
		{
			OutputDebugString(_T("UNIATHOOKCreateProcessW,CreateProcessW find"));
			BOOL bRet = WriteProcessMemory(GetCurrentProcess(),(LPVOID)g_funcIATfuncAddr,&g_funcAddrOrigninal,sizeof(DWORD),NULL);
			if(bRet)
			{
				OutputDebugString(_T("UNIATHOOKCreateProcessW,WriteProcessMemory suc"));
			}
			else
			{
				OutputDebugString(_T("UNIATHOOKCreateProcessW,WriteProcessMemory fail !!!"));
			}
		}
	}
}

BOOL WINAPI DllMain (
	HANDLE hInst,
	ULONG ul_reason_for_call,
	LPVOID lpReserved) {

	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: 
		{
			IATHOOKCreateProcessW();
		}
		break;
	case DLL_PROCESS_DETACH: 
		{
			UNIATHOOKCreateProcessW();
		}
		break;
								
	case DLL_THREAD_ATTACH: 
		{
		}
		break;
								
	case DLL_THREAD_DETACH: 
		{
		}
		break;
	}

	return TRUE;
}