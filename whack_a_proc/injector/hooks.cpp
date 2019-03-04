#include "hooks.h"
#include "include/pe_sieve_api.h"
#include <Psapi.h>

VOID ScanProcess(DWORD dwPid) {
	t_params params = { 0 };
	if (dwPid == GetCurrentProcessId())
		return;
	params.pid = dwPid;
	params.quiet = true;
	PESieve_scan(params);
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