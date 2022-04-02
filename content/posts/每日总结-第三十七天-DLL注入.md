---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "DLL注入"  
date: 2020-05-18T15:22:45+08:00  
categories : [                                
"notes",  
]  
draft: false  
---
## 参考文献  
逆向工程核心原理  
## Windows消息勾取  
### 消息钩子  
Windows操作系统向用户提供GUI，它以事件驱动方式工作，在操作系统中借助键盘、鼠标、选择菜单、按钮以及移动鼠标等都是事件(Event)。发生这些事件时，OS会把事先定义好的消息发送给相应的应用程序，应用程序分析收到的消息后执行相应的动作。  
常规Windows消息流  
1. 发生键盘输入事件时，WM_KETDOWN消息被添加到[OS message queue].  
2. OS判断那个应用程序发生了事件，然后从[OS message queue]中取出消息，添加到相应应用程序的[application message queue]中。  
3. 应用程序监视自身的[application message queue], 发现新添加的  
WM_KEYDOWN消息后，调用相应的事件处理程序处理。  
  
OS消息队列与应用程序消息队列之间存在一条钩链(Hook Chain)，设置好键盘消息钩子之后，处于钩链中的键盘消息钩子会比应用程序先看到相应信息。在键盘消息钩子函数的内部，除了可以查看消息之外，还可以修改消息本身，而且还能对消息实施拦截，阻止消息传递。  
  
### SetWindowsHookEx函数  
```c  
HHOOK SetWindowsHookEx(  
    int idHook,   // hook type  
    HOOKPROC lpfn,    // hook procedure  
    HINSTANCE hMod,    // hook procedure所属的DLL句柄 (Handle)  
    DWORD dwThreadID    // 想要挂钩的线程ID  
);  
```  
钩子过程(hook procedure)是由操作系统调用的回调函数，安装消息钩子时，钩子过程需要存在于某个DLL内部，且该DLL的实例句柄(instance procedure)即是hMod.  
如果dwThreadID参数被设置为0，则安装的钩子为全局安全钩子(Global Hook)，它会影响运行中的以及以后要运行的所有进程。  
像这样，使用`SetWindowsHookEx`设置好钩子之后，在某个进程中生成指定消息时，操作系统会将相关的DLL文件强制注入相应进程，然后调用注册的钩子过程。  
### 举例  
```c  
// HookMain.cpp  
#include "stdio.h"  
#include "conio.h"  
#include "windows.h"  
#define DEF_DLL_NAME "KeyHook.dll"  
#define DEL_HOOKSTART "HookStart"  
#define DEF_HOOKSTOP "HookStop"  
  
typedef void(*PFN_HOOKSTART)();  
typedef void(*PFN_HOOKSTOP)();  
  
int main()  
{  
	HMODULE hDll = NULL;  
	PFN_HOOKSTART HookStart = NULL;  
	PFN_HOOKSTOP HookStop = NULL;  
	char ch = 0;  
	hDll = LoadLibraryA(DEF_DLL_NAME);  
	if (hDll == NULL)  
	{  
		printf("load library failed\n");  
		return -1;  
	}  
	HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, DEL_HOOKSTART);  
	HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);  
	HookStart();  
	printf("print q to stop\n");  
	while (_getch() != 'q');  
	HookStop();  
	FreeLibrary(hDll);  
	return 0;  
}  
```  
先加载KeyHook.dll文件，然后调用`HookStart`函数开始钩取  
```c  
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#include "pch.h"  
#include "stdio.h"  
#include "tchar.h"  
#include "windows.h"  
#define DEF_PROCESS_NAME "notepad.exe"  
HINSTANCE g_hInstance = NULL;  
HHOOK g_hHook = NULL;  
HWND g_hWnd = NULL;  
  
BOOL APIENTRY DllMain( HMODULE hModule,  
                   DWORD  ul_reason_for_call,  
                   LPVOID lpReserved  
                 )  
{  
switch (ul_reason_for_call)  
{  
case DLL_PROCESS_ATTACH:  
		g_hInstance = hModule;  
		break;  
case DLL_THREAD_ATTACH:  
case DLL_THREAD_DETACH:  
case DLL_PROCESS_DETACH:  
    break;  
}  
return TRUE;  
}  
  
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)  
{  
	char szPath[MAX_PATH] = { 0, };  
	char *p = NULL;  
	if (nCode >= 0)  
	{  
		if (!(lParam & 0x80000000))  //释放键盘按键  
		{  
			GetModuleFileNameA(NULL, szPath, MAX_PATH);  
			p = strrchr(szPath, '\\');  
			//比较当前函数名称，如果名称是notepad.exe则消息不会传递给下一个勾子  
			if (!_stricmp(p + 1, DEF_PROCESS_NAME))  
			{  
				OutputDebugString(_T("knock\n"));  
				return 1;  
			}  
		}  
	}  
	// 将消息传递给应用程序(或者下一个钩子)  
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);  
}  
  
#ifdef __cplusplus  
extern "C" {  
#endif  
__declspec(dllexport) void HookStart()  
{  
	g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);  
}  
__declspec(dllexport) void HookStop()  
{  
	if (g_hHook)  
	{  
		UnhookWindowsHookEx(g_hHook);  
		g_hHook = NULL;  
	}  
}  
#ifdef __cplusplus  
}  
#endif // __cplusplus  
```  
调用Dll代码中的`HookStart`函数时，`SetWindowsHookEx`函数就会将`KeyboardProc`添加到键盘钩链。安装好键盘钩子后，无论哪个进程，只要发生键盘输入事件，OS就会强制将KeyHook.dll注入相应进程，加载了KeyHook.dll的进程中，发生键盘事件时会首先调用执行KeyHook.KeyboardProc()  
运行HookMain.cpp中的代码后，使用Process Explorer搜索加载了KeyHook.dll的进程:  
![](/images/57f3984cd5f90ddf8dba5af2411ee1fd/11884068-069b98395ffdaac0.png)  
如图，只要发生了键盘输入事件的进程都被注入了KeyHook.dll，在notepad中输入会在DebugView中看到相应的调试输出结果:  
![](/images/57f3984cd5f90ddf8dba5af2411ee1fd/11884068-f97871a605a26a4e.png)  
## Dll注入  
Dll被加载到进程后会自动运行DllMain()函数，用户可以把想执行的代码放到DllMain函数，每当加载Dll时，添加的代码就会自然而然得到执行，利用这个特性可以修复程序Bug，或者向程序添加新功能。  
Dll注入的工作原理就是从外部促使目标进程调用LoadLibrary()API，所以会强制调用DllMain函数。  
**Windows OS默认提供的消息钩取功能应用就是一种Dll注入技术，与常规的Dll注入唯一的区别就是OS会直接将已注册的钩取Dll注入目标进程。**  
向某个进程注入Dll时主要使用以下三种办法:  
- 创建远程线程`CreateRemoteThread()`  
- 使用注册表`AppInit_Dlls`值  
- 消息钩取`SetWindowsHookEx()`  
### CreateRemoteThread  
`CreateRemoteThread()API用来在目标进程中执行其创建出的线程，函数原型如下:  
```c  
HANDLE WINAPI CreateRemoteThread(  
_In_ HANDLE hProcess,   // 目标进程句柄  
_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,  
_In_ SIZE_T dwStackSize,  
_In_ LPTHREAD_START_ROUTINE lpStartAddress,  //线程函数地址  
_In_opt_ LPVOID lpParameter,   //  线程参数地址  
_In_ DWORD dwCreationFlags,  
_Out_opt_ LPDWORD lpThreadId  
);  
```  
除第一个参数外，其余参数与CreateThread()函数完全一样。hProcess参数是要执行线程的目标进程句柄  
```c  
// myhack.dll  
// dllmain.cpp : 定义 DLL 应用程序的入口点。  
#include "pch.h"  
#include "windows.h"  
#include "tchar.h"  
#include "urlmon.h"  
#pragma comment(lib, "urlmon.lib")  
#define DEL_URL (L"http://baidu.com/index.html")  
#define DEL_FILE_NAME (L"index.html")  
  
HMODULE g_hMod = NULL;  
  
DWORD WINAPI ThreadProc(LPVOID lParam)  
{  
	TCHAR szPath[_MAX_PATH] = { 0, };  
	if (!GetModuleFileName(g_hMod, szPath, MAX_PATH))  
		return FALSE;  
	OutputDebugString(szPath);  
	TCHAR *p = _tcsrchr(szPath, '\\');  
	if (!p)  
		return FALSE;  
	_tcscpy_s(p + 1, _MAX_PATH, DEL_FILE_NAME);  
	URLDownloadToFile(NULL, DEL_URL, szPath, 0, NULL);  
	return 0;  
}  
  
BOOL APIENTRY DllMain( HMODULE hModule,  
                   DWORD  ul_reason_for_call,  
                   LPVOID lpReserved  
                 )  
{  
	HANDLE hThread = NULL;  
	g_hMod = hModule;  
switch (ul_reason_for_call)  
{  
case DLL_PROCESS_ATTACH:  
		OutputDebugString(_T("myhack.dll Injection!!!"));  
		hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);  
		CloseHandle(hThread);  
		break;  
case DLL_THREAD_ATTACH:  
case DLL_THREAD_DETACH:  
case DLL_PROCESS_DETACH:  
    break;  
}  
return TRUE;  
}  
  
// InjectDll.c  
#include "windows.h"  
#include "tchar.h"  
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)  
{  
	HANDLE hProcess = NULL, hThread = NULL;  
	HMODULE hMod = NULL;  
	LPVOID pRemoteBuf = NULL;  
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);  
	LPTHREAD_START_ROUTINE pThreadProc;  
    // 获取目标进程句柄  
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))  
	{  
		_tprintf(L"OpenProcess(%d) failed!!![%d]\n", dwPID, GetLastError());  
		return FALSE;  
	}  
	// 在目标进程内存中分配szDllName大小的内存  
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);  
	if (pRemoteBuf == NULL)  
	{  
		_tprintf(L"VirtualAllocEx Failed\n");  
		CloseHandle(hProcess);  
		return FALSE;  
	}  
  
	// 将myhack.dll路径写入分配的内存  
	if (!WriteProcessMemory(hProcess, pRemoteBuf, szDllPath, dwBufSize, NULL))  
	{  
		_tprintf(L"WriteProcessMemory Failed\n");  
		VirtualFreeEx(hProcess, pRemoteBuf, (DWORD)(_tcslen(szDllPath) + 1), MEM_DECOMMIT);  
		CloseHandle(hProcess);  
		return FALSE;  
	}  
	  
	// 获取LoadLibraryW()API的地址, kernel32.dll在每个进程中加载的地址都相同  
	hMod = GetModuleHandle(_T("kernel32"));  
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");  
  
	// 在notepad.exe进程中运行线程  
	hThread = CreateRemoteThread(hProcess, // hProcess  
		NULL,                              // lpThreadAttributes  
		0,                                 // dwStackSize  
		pThreadProc,                       // lpStartAddress  
		pRemoteBuf,                        // lpParameter  
		0,                                 // dwCreationFlags  
		NULL);                             // lpThreadID  
  
	_tprintf(L"%d\n", hThread);  
	if (hThread == NULL)  
	{  
		_tprintf(L"[%s]\n", GetLastError());  
		return FALSE;  
	}  
	WaitForSingleObject(hThread, INFINITE);  
	VirtualFreeEx(hProcess, pRemoteBuf, (DWORD)(_tcslen(szDllPath) + 1), MEM_DECOMMIT);  
	CloseHandle(hThread);  
	CloseHandle(hProcess);  
  
	return TRUE;  
}  
  
int _tmain(int argc, TCHAR *argv[])  
{  
  
	if (argc != 3)  
	{  
		_tprintf(L"Usage: %s pid dll_path\n", argv[0]);  
		return 1;  
	}  
  
	// inject dll  
	if (InjectDll((DWORD)_tstol(argv[1]), argv[2]))  
		_tprintf(L"InjectDll(\"%s\") success!!!\n", argv[2]);  
	else  
		_tprintf(L"InjectDll(\"%s\") failed!!!\n", argv[2]);  
	return 0;  
}  
```  
运行时需要注意，第二个参数是notepad.exe进程的PID，第三个参数是要注入Dll的**完整路径**(或者我感觉Dll与notepad.exe在同一目录下也行)  
![](/images/57f3984cd5f90ddf8dba5af2411ee1fd/11884068-4878b604e978d393.png)  
![](/images/57f3984cd5f90ddf8dba5af2411ee1fd/11884068-ab7d397c15b6e4b9.png)  
### AppInit_DLLs  
进行DLL注入的第二种办法是使用注册表，Windows操作系统的注册表中默认提供了AppInit_DLLs与LoadAppInit_DLLs两个注册表项。如果将要注入的DLL的路径字符串写入AppInit_DLLs项目，然后把LoadAppInit_DLLs的项目值设置为1。重启后，指定DLL会注入所有运行进程。  
![](/images/57f3984cd5f90ddf8dba5af2411ee1fd/11884068-c0f70c5b15ae1657.png)  
  
原理：User32.dll被加载到进程时，会读取AppInit_DLLs注册表项，若有值，则调用LoadLibrary()API加载用户DLL，所以相应DLL并不会被加载到所有进程，而只是加载到会加载User32.dll的进程。  
## DLL卸载  
DLL卸载(DLL Ejection)是将强制插入进程的DLL弹出的一种技术，其基本工作原理与使用CreateRemoteThread API进行DLL注入的原理类似。  
DLL注入的原理是驱使目标进程调用LoadLibrary()API，同样，DLL卸载原理是驱使目标进程调用FreeLibrary()API  
```c  
//EjectDll.exe  
  
#include "windows.h"  
#include "tlhelp32.h"  
#include "tchar.h"  
  
#define DEF_PROC_NAME (L"notepad.exe")  
#define DEF_DLL_NAME (L"MYHACK.dll")  
  
DWORD FindProcessID(LPCTSTR szProcessName)  
{  
	DWORD dwPID = 0xFFFFFFFF;  
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;  
	PROCESSENTRY32 pe;  
  
	// 获取系统快照  
	pe.dwSize = sizeof(PROCESSENTRY32);  
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);  
  
	// 查找进程  
	Process32First(hSnapShot, &pe);  
	do  
	{  
		if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))  
		{  
			dwPID = pe.th32ProcessID;  
			break;  
		}  
	} while (Process32Next(hSnapShot, &pe));  
  
	CloseHandle(hSnapShot);  
	return dwPID;  
}  
  
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)  
{  
	TOKEN_PRIVILEGES tp;  
	HANDLE hToken;  
	LUID luid;  
  
	if (!OpenProcessToken(GetCurrentProcess(),  
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  
		&hToken))  
	{  
		_tprintf(L"OpneProcessToken error:%u\n", GetLastError());  
		return FALSE;  
	}  
	if (!LookupPrivilegeValue(NULL,  
		lpszPrivilege,  
		&luid))  
	{  
		_tprintf(L"LookupPrivilegeValue error: %u\n", GetLastError());  
		return FALSE;  
	}  
  
	tp.PrivilegeCount = 1;  
	tp.Privileges[0].Luid = luid;  
	if (bEnablePrivilege)  
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
	else  
		tp.Privileges[0].Attributes = 0;  
  
	// Enable the privilege or disable all privileges.  
	if (!AdjustTokenPrivileges(hToken,  
		FALSE,  
		&tp,  
		sizeof(TOKEN_PRIVILEGES),  
		(PTOKEN_PRIVILEGES) NULL,  
		(PDWORD) NULL))  
	{  
		_tprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError());  
		return FALSE;  
	}  
  
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)  
	{  
		_tprintf(L"The token does not have the specified privilege.\n");  
		return FALSE;  
	}  
	return TRUE;  
}  
  
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)  
{  
	BOOL bMore = FALSE, bFound = FALSE;  
	HANDLE hSnapshot, hProcess, hThread;  
	HMODULE hModule = NULL;  
	MODULEENTRY32 me = { sizeof(me) };  
	LPTHREAD_START_ROUTINE pThreadProc;  
  
	// dwPID = notepad进程ID  
	// 使用TH32CS_SNAPMODULE参数，获取加载到notepad进程的DLL名称  
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);  
  
	bMore = Module32First(hSnapshot, &me);  
	for (; bMore; bMore = Module32Next(hSnapshot, &me))  
	{  
		if (!_tcsicmp((LPCTSTR)me.szModule, szDllName))  
		{  
			bFound = TRUE;  
			break;  
		}  
	}  
  
	if (!bFound)  
	{  
		CloseHandle(hSnapshot);  
		return FALSE;  
	}  
  
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))  
	{  
		_tprintf(L"OpenProcess(%d) failed!!![%d]\n", dwPID, GetLastError());  
		return FALSE;  
	}  
  
	hModule = GetModuleHandle(L"kernel32.dll");  
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule,  
		"FreeLibrary");  
	hThread = CreateRemoteThread(hProcess, NULL, 0,  
		pThreadProc, me.modBaseAddr,  
		0, NULL);  
  
	WaitForSingleObject(hThread, INFINITE);  
  
	CloseHandle(hThread);  
	CloseHandle(hProcess);  
	CloseHandle(hSnapshot);  
  
	return TRUE;  
}  
  
int _tmain(int argc, TCHAR* argv[])  
{  
	DWORD dwPID = 0xFFFFFFFF;  
  
	// 查找process  
	dwPID = FindProcessID(DEF_PROC_NAME);  
	if (dwPID == 0xFFFFFFFF)  
	{  
		_tprintf(L"There is no %s process!\n", DEF_PROC_NAME);  
		return 1;  
	}  
  
	_tprintf(L"PID of %s is %d\n", DEF_PROC_NAME, dwPID);  
  
	//更改Privilege  
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))  
		return 1;  
  
	if (EjectDll(dwPID, DEF_DLL_NAME))  
	{  
		_tprintf(L"EjectDll(%d, %s) success!\n", dwPID, DEF_DLL_NAME);  
		return 0;  
	}  
	else  
	{  
		_tprintf(L"EjectDll(%d, %s) failed!\n", dwPID, DEF_DLL_NAME);  
		return 1;  
	}  
}  
```  
` CreateToolhelp32Snapshot()`API可以获取加载到进程的模块(DLL)信息，将获取的hSnapshot句柄传递给Module32First()/Module32Next()函数后，即可设置MODULEENTRY32结构体相关的模块信息。  
```c  
typedef struct tagMODULEENTRY32W  
{  
DWORD   dwSize;  
DWORD   th32ModuleID;       // This module  
DWORD   th32ProcessID;      // owning process  
DWORD   GlblcntUsage;       // Global usage count on the module  
DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context  
BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context  
DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr  
HMODULE hModule;            // The hModule of this module in th32ProcessID's context  
WCHAR   szModule[MAX_MODULE_NAME32 + 1];  
WCHAR   szExePath[MAX_PATH];  
} MODULEENTRY32W;  
```  
>dwFlags:   
TH32CS_INHERIT :使用这个标志表示，这个快照句柄是可继承的    
TH32CS_SNAPALL :表示使用了以下的全部标志,总共四个TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, and TH32CS_SNAPTHREAD.    
TH32CS_SNAPHEAPLIST:表示快照信息包含特定进程的堆栈列表    
TH32CS_SNAPMODULE :表示快照信息包含特定进程的使用模块的列表    
TH32CS_SNAPPROCESS:表示快照信息包含系统的所有进程的列表    
TH32CS_SNAPTHREAD :表示快照信息包含系统所有线程的列表    
th32ProcessID： 只有当dwFlags信息中包含TH32CS_SNAPHEAPLIST，TH32CS_SNAPMODULE 时这个值才有效，否则，这个值会被忽略    
  
szModule成员表示DLL的名称，modBaseAddr成员表示相应DLL被加载的地址(进程虚拟内存), 在EjectDll()函数的for循环中比较szModule与希望卸载的DLL文件名称，能够准确查找到相应模块信息。  
**使用FreeLibrary()方法仅适用于卸载自己强制注入的DLL文件，PE文件直接导入的DLL文件是没有办法在进程运行过程中卸载的**  
