#include "hooks.h"
#include "injector.h"
#include "include/pe_sieve_api.h"
#include <Psapi.h>

#define MYPROC_NUM 100

DWORD pMyProcesses[MYPROC_NUM] = { 0 };

VOID ScanProcess(DWORD dwPid) {
	HANDLE hProcess;
	t_params params = { 0 };

	MessageBoxA(NULL, "scan", "", 0);
	if (dwPid == GetCurrentProcessId())
		return;
	params.pid = dwPid;
	params.quiet = true;
	PESieve_scan(params);
	for (int i = 0; i < MYPROC_NUM && pMyProcesses[i]; i++) {
		if (dwPid == pMyProcesses[i]) {
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
			if (hProcess != INVALID_HANDLE_VALUE) {
				SetEntrypointHook(hProcess);
				CloseHandle(hProcess);
				break;
			}
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
	MessageBoxA(NULL, "ntcreateuerprocess", "", 0);
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