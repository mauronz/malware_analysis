#include "hooks.h"
#include "injector.h"
#include "communication.h"
#include <Psapi.h>

#define MYPROC_NUM 100

extern HANDLE hPipe;
extern HMODULE hGlobalModule;

DWORD pMyProcesses[MYPROC_NUM] = { 0 };

VOID ScanProcess(DWORD dwPid, DWORD dwTid) {
	DWORD dwSize;
	DWORD dwCode = CODE_SCAN;

	/*if (dwPid == GetCurrentProcessId())
		return;*/
	WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
	WriteFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL);
	ReadFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
	if (dwCode != CODE_OK)
		MessageBoxA(NULL, "Error code!", "scan", 0);

	if (dwTid == 0)
		return;

	for (int i = 0; i < MYPROC_NUM && pMyProcesses[i]; i++) {
		if (dwPid == pMyProcesses[i]) {
			DWORD dwCode = CODE_INJECT;
			WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
			WriteFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL);
			WriteFile(hPipe, &dwTid, sizeof(dwTid), &dwSize, NULL);
			ReadFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL);
			if (dwCode != CODE_OK)
				MessageBoxA(NULL, "Error code!", "scan", 0);
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

VOID __stdcall bh_LoadLibraryA(LPCSTR LibName) {
	LPVOID pRetAddress;
	HMODULE hModule;
	__asm {
		mov eax, [ebp]
		mov eax, [eax + 4]
		mov pRetAddress, eax
	}
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pRetAddress, &hModule) || hModule == GetModuleHandleA(NULL)) {
		ScanProcess(GetCurrentProcessId(), GetCurrentThreadId());
	}
}

VOID __stdcall bh_LoadLibraryW(LPCWSTR LibName) {
	LPVOID pRetAddress;
	HMODULE hModule;
	__asm {
		mov eax, [ebp]
		mov eax, [eax + 4]
		mov pRetAddress, eax
	}
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pRetAddress, &hModule) || hModule == GetModuleHandleA(NULL)) {
		ScanProcess(GetCurrentProcessId(), GetCurrentThreadId());
	}
}

VOID __stdcall ah_NtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection,
	DWORD retvalue) {
	LPVOID pRetAddress, pStackFrame;
	HMODULE hModule;
	BOOL bDoScan = FALSE;

	if (NewAccessProtection == PAGE_EXECUTE || NewAccessProtection == PAGE_EXECUTE_READ || NewAccessProtection == PAGE_EXECUTE_READWRITE || NewAccessProtection == PAGE_EXECUTE_WRITECOPY) {
		__asm {
			mov eax, [ebp]
			mov pStackFrame, eax
		}

		while (!bDoScan) {
			__asm {
				mov eax, pStackFrame
				mov eax, [eax]
				mov pStackFrame, eax
				mov eax, [eax + 4]
				mov pRetAddress, eax
			}
			if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pRetAddress, &hModule)) {
				if (hModule == GetModuleHandleA(NULL))
					bDoScan = TRUE;
				if (hModule == hGlobalModule)
					break;
			}
			else
				bDoScan = TRUE;
		}
		if (bDoScan)
			ScanProcess(GetProcessId(ProcessHandle), 0);
	}
}