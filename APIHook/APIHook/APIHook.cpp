// APIHook.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>

#define  COVEREDBYTES 4  //bytes need to cover

#define APPNAME "calc.exe"
#define LOGFILE_SUCCESS "C:\\DLL_SUCCESS.log"
#define LOGFILE_FAILED "C:\\DLL_FAIL.log"

//不同的系统硬编码的地址可能不同
//修改时仅修改g_dwTargetFunc和g_dwAddrCallTargetFun的值即可
//g_dwAddrCallTargetFun为ntdll中指令【call LdrpResolveDllName】的地址+1
//g_dwTargetFunc为ntdll中LdrpResolveDllName的地址

//cc's vm
DWORD g_dwTargetFunc = 0x7c93c673;//b76b;
DWORD g_dwAddrCallTargetFun = 0x7c93c5fd;//b6f5;

// Yu's vm 
// DWORD g_dwTargetFunc = 0x7c93b76b;
// DWORD g_dwAddrCallTargetFun = 0x7c93b6f5;

DWORD dwOffsetProxyFun;

BYTE OrgInstructionBuf[COVEREDBYTES] = {0};
BYTE JumpInstructionBuf[COVEREDBYTES] = {0};

typedef DWORD  (NTAPI * FNLDRPRESOLVEDLLNAME)(PWSTR, PWSTR,PWSTR,PWSTR, PVOID, PVOID);

DWORD NTAPI ProxyFun(PWSTR DllPath, PWSTR DllName, PWSTR FullDllName, PWSTR BaseDllName, PVOID arg_5, PVOID arg_6)
{
	DWORD dwBytesOperated;
	DWORD bResult;
	HANDLE hLogFile;
	LPCSTR lpLogPath;
	
	bResult = ((FNLDRPRESOLVEDLLNAME)g_dwTargetFunc)(DllPath, DllName, FullDllName, BaseDllName, arg_5, arg_6);

	if (bResult == 0)
		lpLogPath = LOGFILE_SUCCESS;
	else
		lpLogPath = LOGFILE_FAILED;
	hLogFile = CreateFile(lpLogPath, 
					FILE_APPEND_DATA, 
					FILE_SHARE_WRITE|FILE_SHARE_READ,
					0,
					OPEN_ALWAYS,
					FILE_ATTRIBUTE_NORMAL,
					NULL);
	if (hLogFile != INVALID_HANDLE_VALUE)
	{
		CHAR ProcessPath[MAX_PATH] = {0};
		CHAR LogBuf[MAX_PATH*2] ={0};
		CHAR DllNameBuf[MAX_PATH] = {0};

		WideCharToMultiByte(CP_ACP, 0, DllName, -1, DllNameBuf, MAX_PATH, NULL, NULL);

		GetModuleFileNameA(NULL, ProcessPath, MAX_PATH);
		sprintf(LogBuf, "%08x||%s||%s\r\n", bResult, DllNameBuf, ProcessPath);
		WriteFile(hLogFile, LogBuf, strlen(LogBuf), &dwBytesOperated, NULL);
		CloseHandle(hLogFile);
	}


	return bResult;
}

//direct cover the instructions call ldrpResolveDllName
BOOL HookFunc(PVOID TargetFun, PVOID ProxyFun)
{

	DWORD dwBytesOperated;

	ReadProcessMemory(GetCurrentProcess(),
		(PVOID)g_dwAddrCallTargetFun,
		OrgInstructionBuf,
		COVEREDBYTES,
		&dwBytesOperated);


		dwOffsetProxyFun = *(DWORD*)g_dwAddrCallTargetFun + (DWORD)ProxyFun - (DWORD)g_dwTargetFunc;//+ 0x76;


		WriteProcessMemory(GetCurrentProcess(), 
			(PVOID)g_dwAddrCallTargetFun,
			&dwOffsetProxyFun,
			COVEREDBYTES,
			&dwBytesOperated);

	return TRUE;
}



BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		HookFunc((PVOID)g_dwTargetFunc, (PVOID)ProxyFun);

		break;
	
	case DLL_PROCESS_DETACH:
		break;

	}
    return TRUE;
}

