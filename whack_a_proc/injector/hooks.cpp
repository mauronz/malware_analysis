#include <stdio.h>
#include "hooks.h"
#include "include/pe_sieve_api.h"

DWORD addrs[1000];
DWORD count = 0;

VOID ScanProcess(DWORD dwPid) {
	t_params params = { 0 };
	if (dwPid == GetCurrentProcessId())
		return;
	params.pid = dwPid;
	params.quiet = true;
	PESieve_scan(params);
}

VOID __stdcall ah_Encryption(
	DWORD arg1,
	DWORD retvalue
) {
	CHAR line[1024];
	HANDLE hFile;
	DWORD dwBytes;
	DWORD origin;
	__asm {
		mov eax, dword ptr[ebp + 0x18]
		mov origin, eax
	}
	for (int i = 0; i < count; i++) {
		if (origin == addrs[i])
			return;
	}
	addrs[count++] = origin;
	wsprintfA(line, "%08x %08x\n", origin, retvalue);
	hFile = CreateFileA("log.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hFile, 0, NULL, FILE_END);
	WriteFile(hFile, line, lstrlenA(line), &dwBytes, NULL);
	CloseHandle(hFile);
}

VOID __stdcall bh_NtCreateThread(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN PVOID   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PVOID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PVOID         InitialTeb,
	IN BOOLEAN              CreateSuspended) {
	DWORD dwPid;
	if (!CreateSuspended) {
		dwPid = GetProcessId(ProcessHandle);
		ScanProcess(dwPid);
	}
}

VOID __stdcall bh_NtCreateThreadEx(
	OUT  PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  PVOID ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	IN  PVOID StartRoutine,
	IN  PVOID Argument OPTIONAL,
	IN  ULONG CreateFlags,
	IN  ULONG_PTR ZeroBits,
	IN  SIZE_T StackSize OPTIONAL,
	IN  SIZE_T MaximumStackSize OPTIONAL,
	IN  PVOID AttributeList OPTIONAL
	) {
	DWORD dwPid;
	if ((CreateFlags & CREATE_SUSPENDED) == 0) {
		dwPid = GetProcessId(ProcessHandle);
		ScanProcess(dwPid);
	}
}

VOID __stdcall bh_NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
	DWORD dwPid = GetProcessIdOfThread(ThreadHandle);
	ScanProcess(dwPid);
}