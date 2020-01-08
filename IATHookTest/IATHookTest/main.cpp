#include "stdafx.h"
#include <Windows.h>

DWORD g_funcAddrOrigninal = NULL; // CreateProcessW函数的地址
DWORD g_funcIATfuncAddr = NULL; // 导入地址表的地址，就是存放函数地址的地址，用于卸载IAT Hook

typedef BOOL (WINAPI *CreateProcessWFunc)(
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



BOOL WINAPI MyCreateProcessW(
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
	BOOL ret = FALSE;
	CString appName = lpApplicationName;
	CString strMsg;
	strMsg.Format(_T("是否打开程序:%s "),appName);
	if(IDYES == MessageBox(NULL,strMsg,_T("请选择"),MB_YESNO))
	{
		ret = func(lpApplicationName,lpCommandLine,
			lpProcessAttributes,lpThreadAttributes,
			bInheritHandles,dwCreationFlags,
			lpEnvironment,lpCurrentDirectory,
			lpStartupInfo,lpProcessInformation);
	}
	else
	{
		ret = TRUE;
	}

	OutputDebugString(_T("MyCreateProcessW exit-----"));
	return ret;
}



 

void IATHOOKCreateProcessW()
{
	OutputDebugString(_T("IATHOOKCreateProcessW, enter "));
	// 获取CreateProcessW函数地址，该函数是Kernel32.dll导出的函数
	HMODULE hModuleKernel = GetModuleHandle(_T("kernel32.dll")); 
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
	//CString addr;
	//addr.Format(_T("kernel->CreateProcessWAddress = %x"),g_funcAddrOrigninal);
	//OutputDebugString(addr);

	//HMODULE hModuleExe = GetModuleHandle(_T("SHELL32.dll"));
	// OD上看，在win7下的explorer.exe中 使用的是SHELL32.dll中的kernel.dll!!!所以这里起始地址应该是SHELL32.dll
	// 起始地址用SHELL32.dll模块在它的导入表能找到对应的kernel32.dll动态库，但是从在kernel32.dll的IAT找不到CreateProcessW :)
	// 妈蛋，笔者当然没有放弃，笔者继续分析，网上找了个 DEPENDS.EXE 来分析 kernel32.dll。确实找到了CreateProcessW是kernel32.dll中API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL模块的导出函数！
	// 所以这里的起始地址应该为kernel32.dll，然后找它导入表中的API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL模块，
	// 然后从API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL找它的IAT中的CreateProcessW，然后进行hook
	//HMODULE hModuleExe = GetModuleHandle(_T("kernel32.dll"));
	// 但是，从kernel32.dll的导入表中找到的API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL中IAT中找到的函数和内存中的函数地址仍然对不上号！
	// 所以笔者又去分析shell32.dll，通过DEPENDS.exe工具发现shell32.dll的PE结构也是有API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL，
	// 然后再看shell32.dll中链接的API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL好些是个快捷方式 应该是链接的shell32.dll中API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL
	// 所以这里的起始地址还是SHELL32.dll模块，同样是去找API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL然后找其中的IAT
	HMODULE hModuleExe = GetModuleHandle(_T("shell32.dll"));


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
		if(cstrName.CompareNoCase(_T("API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL")) == 0)
		{
			OutputDebugString(_T("IATHOOKCreateProcessW,find API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL"));
			bFind = true;
			break;
		}
		pImageTemp++;
	}

	bool bFindFnc = false;
	// 已经找到要HOOK的DLL模块
	if(bFind)
	{
		// 导入地址表，一项对应一个函数，进行遍历 查找到要hook的函数
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(dwImageBase + pImageTemp->FirstThunk);
		while(pThunk->u1.Function) // 最后一项结构体为全0
		{
			DWORD* pFuncAddr = (DWORD*)&(pThunk->u1.Function); // 这个地址上内存存放的是【函数的地址】
			// 取出函数的地址 和 之前在程序中找到的函数地址做比较，如果一样就找到了该函数的导入地址表了！
			//CString addr;
			//addr.Format(_T("IAT->funcAddr = %x"),*pFuncAddr);
			//OutputDebugString(addr);
			if(*pFuncAddr == g_funcAddrOrigninal)
			{
				bFindFnc = true;
				DWORD dwMyHookAddr = (DWORD)MyCreateProcessW;
				g_funcIATfuncAddr = (DWORD)pFuncAddr; // 将存放函数地址的内存地址保存，以便后面卸载hook

				OutputDebugString(_T("IATHOOKCreateProcessW, CreateProcessW was found"));
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
		OutputDebugString(_T("IATHOOKCreateProcessW, not find CreateProcessW！！！"));
	}

}

void UNIATHOOKCreateProcessW()
{
	OutputDebugString(_T("UNIATHOOKCreateProcessW, enter "));
	if(g_funcIATfuncAddr)
	{
		if(g_funcAddrOrigninal)
		{
			OutputDebugString(_T("UNIATHOOKCreateProcessW,CreateProcessW was found"));
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