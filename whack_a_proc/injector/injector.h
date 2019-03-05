#pragma once

#include <Windows.h>
#include <stdio.h>
#include "APIhooklib.h"

struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};

typedef NTSTATUS(WINAPI* TdefNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

extern "C" BOOL __declspec(dllexport) __cdecl inject();

BOOL SetEntrypointHook(HANDLE hProcess);
BOOL SetHooks();