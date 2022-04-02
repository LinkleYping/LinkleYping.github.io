# API勾取

## 调试钩取  
流程如下：  
1. 对想钩取的进程进行附加操作，使之成为被调试者  
2. 钩子：将API起始地址的第一个字节修改为0xCC  
3. 调用相应API时，控制权转移到调试器  
4. 执行需要的操作(操作参数、返回值等)  
5. 脱钩：将0xCC恢复为原来的值(正常运行API)  
6. 运行相应API（无0xCC的正常状态）  
7. 钩子：再次修改为0xCC（为了继续钩取）  
8. 控制权返还给被调试者  
```c  
# include "windows.h"  
# include "stdio.h"  
  
LPVOID g_pfWriteFile = NULL;  
CREATE_PROCESS_DEBUG_INFO g_cpdi;  
BYTE g_chINT3 = 0xCC;  
BYTE g_ch0rgByte = 0;  
  
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)  
{  
	// 获取WriteFile() API的地址  
	g_pfWriteFile = GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteFile");  
	printf("g_pfWriteFile：%d\n", g_pfWriteFile);  
	// API钩子 WriteFile()  
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_EVENT));  
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,  
		&g_ch0rgByte, sizeof(BYTE), NULL);  
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,  
		&g_chINT3, sizeof(BYTE), NULL);  
	return TRUE;  
}  
  
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)  
{  
	CONTEXT ctx;  
	PBYTE lpBuffer = NULL;  
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;  
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;  
  
	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)  
	{  
		if (g_pfWriteFile == per->ExceptionAddress)  
		{  
			// 将0xcc恢复为original byte  
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,  
				&g_ch0rgByte, sizeof(BYTE), NULL);  
  
			// 获取线程上下文  
			ctx.ContextFlags = CONTEXT_CONTROL;  
			GetThreadContext(g_cpdi.hThread, &ctx);  
  
			// 获取WriteFile的第2，3个参数  
			ReadProcessMemory(g_cpdi.hProcess, (LPCVOID)(ctx.Esp + 8),  
				&dwAddrOfBuffer, sizeof(DWORD), NULL);  
			ReadProcessMemory(g_cpdi.hProcess, (LPCVOID)(ctx.Esp + 0xc),  
				&dwNumOfBytesToWrite, sizeof(DWORD), NULL);  
			  
			/*dwAddrOfBuffer = ctx.Rsi;  
			dwNumOfBytesToWrite = ctx.Rdx;*/  
  
			printf("size: %d\n", dwNumOfBytesToWrite);  
  
			// 分配临时缓冲区  
			lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);  
			memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);  
  
			// 复制WriteFile缓冲区到临时缓冲区  
			ReadProcessMemory(g_cpdi.hProcess, (LPCVOID)dwAddrOfBuffer,  
				lpBuffer, dwNumOfBytesToWrite, NULL);  
			printf("\n original string: %s\n", lpBuffer);  
  
			// 小写字母转大写字母  
			for (i = 0; i < dwNumOfBytesToWrite; i++)  
			{  
				if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A)  
				{  
					lpBuffer[i] = lpBuffer[i] - 0x20;  
				}  
			}  
  
			printf("\n converted string: %s\n", lpBuffer);  
  
			// 将变换后的缓冲区换到WriteFile中  
			WriteProcessMemory(g_cpdi.hThread, (LPVOID)dwAddrOfBuffer,  
				lpBuffer, dwNumOfBytesToWrite, NULL);  
  
			free(lpBuffer);  
  
			// 将线程上下文的EIP更改为WriteFile的首地址  
			ctx.Eip = (DWORD)g_pfWriteFile;  
			SetThreadContext(g_cpdi.hThread, &ctx);  
			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);  
			Sleep(0);  
  
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3,  
				sizeof(BYTE), NULL);  
			return TRUE;  
		}  
	}  
	return FALSE;  
}  
  
void DebugLoop()  
{  
	DEBUG_EVENT de;  
	DWORD dwContinueStatus;  
	while (WaitForDebugEvent(&de, INFINITE))  
	{  
		dwContinueStatus = DBG_CONTINUE;  
		// 被调试进程生成或附加  
		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)  
			OnCreateProcessDebugEvent(&de);  
		// 异常  
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)  
		{  
			if (OnExceptionDebugEvent(&de))  
				continue;  
		}  
		// 中止  
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)  
			break;  
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);  
	}  
}  
  
int main(int argc, char* argv[])  
{  
	DWORD dwPID;  
	dwPID = atoi(argv[1]);  
  
	// 使调试器附加到一个活动进程并且调试它  
	if (!DebugActiveProcess(dwPID))  
	{  
		printf("DebugActiveProcess failed\n");  
		return 1;  
	}  
	DebugLoop();  
	return 0;  
}  
```  

