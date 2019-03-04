#pragma once

#include <Windows.h>

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
);

VOID __stdcall bh_NtCreateThread(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN PVOID   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PVOID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PVOID         InitialTeb,
	IN BOOLEAN              CreateSuspended);

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
);

VOID __stdcall bh_NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);