#include "StdAfx.h"
#include "Utility.h"
#include <TlHelp32.h>
#include <string> // std::locale需要
#include <strsafe.h> // StringCchPrintf 需要

// GetModuleFileNameEx 需要下面几行
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif

#include <Psapi.h>  
#pragma comment (lib,"Psapi.lib")  

bool CUtility::m_bInitLog = false;

CUtility::CUtility(void)
{
}


CUtility::~CUtility(void)
{
}

BOOL CUtility::IsWindows64()
{
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(GetModuleHandle(_T("kernel32")), "IsWow64Process");
	BOOL bIsWow64 = FALSE;
	if (fnIsWow64Process)
		if (!fnIsWow64Process(::GetCurrentProcess(), &bIsWow64))
			bIsWow64 = FALSE;
	return bIsWow64;
}

CString CUtility::GetIEPath()
{
	TCHAR szPath[MAX_PATH];
	TCHAR *strLastSlash = NULL;
	GetSystemDirectoryW(szPath, sizeof(szPath) );
	szPath[MAX_PATH - 1] = 0;
	strLastSlash = wcschr( szPath, L'\\' );
	*strLastSlash = 0;
	if ( IsWindows64() )
	{
		wcscat_s( szPath,L"\\program files (x86)\\internet explorer\\iexplore.exe" );
	}
	else
	{
		wcscat_s( szPath,L"\\program files\\internet explorer\\iexplore.exe" );
	}
	return CString(szPath);
}

CString CUtility::GetModulePath(HMODULE hModule)
{
	TCHAR buf[MAX_PATH] = {'\0'};
	CString strDir, strTemp;

	::GetModuleFileName( hModule, buf, MAX_PATH);
	strTemp = buf;
	strDir = strTemp.Left( strTemp.ReverseFind('\\') + 1 );
	return strDir;
}

void CUtility::GetProcessHandle(CString strExePath,std::list<HANDLE>& handleList)
{
	CString exeName ;
	int index= strExePath.ReverseFind('\\');
	exeName = strExePath.Right(strExePath.GetLength()-index-1);

	HANDLE snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
	if( INVALID_HANDLE_VALUE == snapHandele)
	{
		return;
	}
	PROCESSENTRY32 entry = {0};
	entry.dwSize = sizeof(entry);// 长度必须赋值
	BOOL bRet = Process32First(snapHandele,&entry);
	CString  exeTempName;
	while (bRet) 
	{
		exeTempName = (entry.szExeFile);
		if( exeTempName.CompareNoCase(exeName) ==0 )
		{
			HANDLE procHandle=OpenProcess(PROCESS_ALL_ACCESS,FALSE,entry.th32ProcessID);  
			TCHAR exePath[MAX_PATH] = {0};
			if(procHandle)
			{
				if( GetModuleFileNameEx(procHandle,NULL,exePath,MAX_PATH) )
				{
					// 全路径获取到
					if(CString(exePath).CompareNoCase(strExePath) == 0)
					{
						// 进程句柄找到
						handleList.push_back(procHandle);
					}
					else
					{
						CloseHandle(procHandle);
					}
				}
				else
				{
					CloseHandle(procHandle);
				}
				
			}
		}
		bRet = Process32Next(snapHandele,&entry);
	}
	CloseHandle(snapHandele);
	return;
}

void CUtility::InjectDllToExe(CString strDllPath,CString strExePath)
{
	std::list<HANDLE> handleList;
	GetProcessHandle(strExePath,handleList);
	HANDLE targetProc = NULL;

	// 获取到的每个EXE进程句柄都进行DLL注入
	for(std::list<HANDLE>::iterator it = handleList.begin(); it != handleList.end(); it++)
	{
		targetProc = *it;
		bool ret = InjectDllToProc(strDllPath, targetProc);
		CloseHandle(targetProc);
		if(ret == false)
		{
			CString temp = _T("CUtility::InjectDllToExe");
			temp.AppendFormat(_T("handle:%d false\n"),targetProc);
			TRACE(temp);
		}
		
	}
	return;
}

bool CUtility::InjectDllToProc(CString strDllPath, HANDLE targetProc)
{
	if(targetProc == NULL)
	{
		return false;
	}
	/*
	注入DLL的思路步骤：
	1. 在目标进程中申请一块内存空间(使用VirtualAllocEx函数) 存放DLL的路径，方便后续执行LoadLibraryA
	2. 将DLL路线写入到目标进程(使用WriteProcessMemory函数)
	3. 获取LoadLibraryA函数地址(使用GetProcAddress)，将其做为线程的回调函数
	4. 在目标进程 创建线程并执行(使用CreateRemoteThread)
	*/

	std::string temp = W2Astring(strDllPath);
	int dllLen = temp.size();
	const char* pPath = temp.c_str();
	// 1.目标进程申请空间
	LPVOID pDLLPath = VirtualAllocEx(targetProc,NULL,dllLen,MEM_COMMIT,PAGE_READWRITE );
	if( pDLLPath == NULL )
	{
		TRACE(_T("CUtility::InjectDllToProc VirtualAllocEx failed\n"));
		return false;
	}
	SIZE_T wLen = 0;
	// 2.将DLL路径写进目标进程内存空间
	int ret = WriteProcessMemory(targetProc,pDLLPath,pPath,dllLen,&wLen); // 这里pPath不能直接使用strDllPath
	if( ret == 0 )
	{
		VirtualFreeEx(targetProc, pDLLPath, dllLen, MEM_DECOMMIT);
		TRACE(_T("CUtility::InjectDllToProc WriteProcessMemory failed\n"));
		return false;
	}
	// 3.获取LoadLibraryA函数地址
	FARPROC myLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
	if( myLoadLibrary == NULL )
	{
		VirtualFreeEx(targetProc, pDLLPath, dllLen, MEM_DECOMMIT);
		TRACE(_T("CUtility::InjectDllToProc GetProcAddress failed\n"));
		return false;
	}
	// 4.在目标进程执行LoadLibrary 注入指定的线程
	HANDLE tHandle = CreateRemoteThread(targetProc,NULL,NULL,
		(LPTHREAD_START_ROUTINE)myLoadLibrary,pDLLPath,NULL,NULL);
	if(tHandle == NULL)
	{
		VirtualFreeEx(targetProc, pDLLPath, dllLen, MEM_DECOMMIT);
		TRACE(_T("CUtility::InjectDllToProc CreateRemoteThread failed\n"));
		return false;
	}
	WaitForSingleObject(tHandle,INFINITE);
	VirtualFreeEx(targetProc, pDLLPath, dllLen, MEM_DECOMMIT);
	CloseHandle(tHandle);
	return true;
}

void CUtility::UninstallDllToExe(CString strDllPath,CString strExePath)
{
	std::list<HANDLE> handleList;
	GetProcessHandle(strExePath,handleList);
	HANDLE targetProc = NULL;

	// 获取到的每个EXE进程句柄都进行DLL卸载
	for(std::list<HANDLE>::iterator it = handleList.begin(); it != handleList.end(); it++)
	{
		targetProc = *it;
		bool ret = UninstallDllToProc(strDllPath, targetProc);
		CloseHandle(targetProc);
		if(ret == false)
		{
			CString temp = _T("CUtility::UninstallDllToExe");
			temp.Format(_T("handle:%d false\n"),targetProc);
			TRACE(temp);
		}
		
	}
	return;
}

bool CUtility::UninstallDllToProc(CString strDllPath, HANDLE targetProc)
{
    /*
    卸载步骤和注入DLL步骤实质差不多.
    注入DLL是 在目标进程中执行LoadLibraryA
    卸载DLL是 在目标进程中执行FreeLibrary函数，不同的是卸载不需要再目标进程中申请空间，
    因为FreeLibrary参数为HMODULE 实际上就是一个指针值。这个句柄已经加载就已经存在。
    */
	
    if( targetProc == NULL )
    {
        return false;
    }
	DWORD processID = GetProcessId(targetProc);

    // 1. 获取卸载dll的模块句柄
    HANDLE snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE ,processID);
    if( INVALID_HANDLE_VALUE == snapHandele)
    {
        return false;
    }
    MODULEENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);// 长度必须赋值
    BOOL ret = Module32First(snapHandele,&entry);
    HMODULE dllHandle = NULL;
	CString tempDllPath;
    while (ret) {
        //tempDllPath = entry.szModule;
		tempDllPath = entry.szExePath;
        if(tempDllPath.CompareNoCase((strDllPath)) == 0)
        {
            dllHandle = entry.hModule;
            break;
        }
        ret = Module32Next(snapHandele,&entry);
    }

    CloseHandle(snapHandele);
    if( dllHandle == NULL )
    {
        return false;
    }

    // 2.获取FreeLibrary函数地址
    FARPROC myLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"),"FreeLibrary");
    if( myLoadLibrary == NULL )
    {
        return false;
    }
    // 3.在目标进程执行FreeLibrary 卸载指定的线程
    HANDLE tHandle = CreateRemoteThread(targetProc,NULL,NULL,
                       (LPTHREAD_START_ROUTINE)myLoadLibrary,dllHandle,NULL,NULL);
    if(tHandle == NULL)
    {
        return false;
    }
    WaitForSingleObject(tHandle,INFINITE);
    CloseHandle(tHandle);
	return true;
}

CStringW CUtility::A2Wstring(std::string strA)

{
	int UnicodeLen = ::MultiByteToWideChar(CP_ACP,0,strA.c_str(),-1,NULL,0);
	wchar_t *pUnicode = new wchar_t[UnicodeLen*1]();
	::MultiByteToWideChar(CP_ACP,0,strA.c_str(),strA.size(),pUnicode,UnicodeLen);
	CString str(pUnicode);
	delete []pUnicode;
	return str;
}

std::string CUtility::W2Astring(const CString& strUnicode)
{
	char *pElementText = NULL;
	int iTextLen ;
	iTextLen = ::WideCharToMultiByte(CP_ACP,0,strUnicode,-1,NULL,0,NULL,NULL);
	pElementText = new char[iTextLen +1];
	memset(pElementText,0,(iTextLen+1)*sizeof(char));
	::WideCharToMultiByte(CP_ACP,0,strUnicode,strUnicode.GetLength(),pElementText,iTextLen,NULL,NULL);
	std::string str(pElementText);
	delete []pElementText;
	return str;
}


CString CUtility::GetErrorMsg(DWORD errorCode)
{
	{   
		// Retrieve the system error message for the last-error code  

		LPVOID lpMsgBuf;  
		LPVOID lpDisplayBuf;  

		FormatMessage(  
			FORMAT_MESSAGE_ALLOCATE_BUFFER |   
			FORMAT_MESSAGE_FROM_SYSTEM |  
			FORMAT_MESSAGE_IGNORE_INSERTS,  
			NULL,  
			errorCode,  
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  
			(LPTSTR) &lpMsgBuf,  
			0, NULL );  

		// Display the error message and exit the process  

		lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,   
			(lstrlen((LPCTSTR)lpMsgBuf)+40)*sizeof(TCHAR));   

		StringCchPrintf((LPTSTR)lpDisplayBuf,   
			LocalSize(lpDisplayBuf),  
			TEXT("%s"),   
			lpMsgBuf);  
		CString result = (LPTSTR)lpDisplayBuf;
		LocalFree(lpMsgBuf);  
		LocalFree(lpDisplayBuf);     
		return result;
	}
}
