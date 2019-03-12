#pragma once

#include <Windows.h>
#include <stdio.h>
#include "APIhooklib.h"
#include "include/pe_sieve_types.h"

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

typedef t_report (__stdcall *TdefPESieve_scan)(t_params args);

extern "C" BOOL __declspec(dllexport) __cdecl inject();

BOOL SetEntrypointHook(HANDLE hProcess);
BOOL SetHooks();