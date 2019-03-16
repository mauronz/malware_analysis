#include "hooks.h"
#include "injector.h"
#include "communication.h"
#include <Psapi.h>

#define MYPROC_NUM 100

extern HANDLE hPipe;

DWORD pMyProcesses[MYPROC_NUM] = { 0 };

VOID ScanProcess(DWORD dwPid, DWORD dwTid) {
	DWORD dwSize;
	DWORD dwCode = CODE_SCAN;

	if (dwPid == GetCurrentProcessId())
		return;
	WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
	WriteFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL);
	ReadFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
	if (dwCode == CODE_OK)
		MessageBoxA(NULL, "yes", "scan", 0);
	else
		MessageBoxA(NULL, "noo", "scan", 0);

	for (int i = 0; i < MYPROC_NUM && pMyProcesses[i]; i++) {
		if (dwPid == pMyProcesses[i]) {
			DWORD dwCode = CODE_INJECT;
			WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
			WriteFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL);
			WriteFile(hPipe, &dwTid, sizeof(dwTid), &dwSize, NULL);
			ReadFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
			if (dwCode == CODE_OK)
				MessageBoxA(NULL, "yes", "inject", 0);
			else
				MessageBoxA(NULL, "noo", "inject", 0);
		}
	}
}

VOID __stdcall ah_NtCreateUserProcess(
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK ProcessDesiredAccess,
	_In_ ACCESS_MASK ThreadDesiredAccess,
	_In_opt_ PVOID ProcessObjectAttributes,
	_In_opt_ PVOID ThreadObjectAttributes,
	_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
	_In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	_Inout_ PVOID CreateInfo,
	_In_opt_ PVOID AttributeList,
	ULONG retvalue
) {
	if (!retvalue) {
		for (int i = 0; i < MYPROC_NUM; i++) {
			if (!pMyProcesses[i]) {
				pMyProcesses[i] = GetProcessId(*ProcessHandle);
				break;
			}
		}
	}
}

VOID __stdcall ah_ZwMapViewOfSection(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	DWORD InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect,
	DWORD retvalue
) {
	WCHAR pFilename[100];
	WCHAR *pName;
	GetMappedFileNameW(ProcessHandle, *BaseAddress, pFilename, 100);
	pName = wcsrchr(pFilename, '\\');
	if (pName == NULL)
		return;
	if (!wcscmp(pName + 1, L"ntdll.dll")) {
		*BaseAddress = GetModuleHandleA("ntdll.dll");
	}
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
	DWORD dwTid;
	if (!CreateSuspended) {
		dwPid = GetProcessId(ProcessHandle);
		dwTid = GetThreadId(ThreadHandle);
		ScanProcess(dwPid, dwTid);
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
	DWORD dwTid;
	if ((CreateFlags & CREATE_SUSPENDED) == 0) {
		dwPid = GetProcessId(ProcessHandle);
		dwTid = GetThreadId(ThreadHandle);
		ScanProcess(dwPid, dwTid);
	}
}

VOID __stdcall bh_NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
	DWORD dwPid = GetProcessIdOfThread(ThreadHandle);
	DWORD dwTid = GetThreadId(ThreadHandle);
	ScanProcess(dwPid, dwTid);
}