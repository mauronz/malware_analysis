// injector.cpp : Defines the exported functions for the DLL application.
//

#include "injector.h"
#include "hooks.h"
#include "APIhooklib.h"
#include "communication.h"

extern HMODULE hGlobalModule;
extern inject_config config;

BOOL SetHooks() {
	SetHookByName("ntdll.dll", "NtCreateThread", 8, CV_STDCALL, (FARPROC)bh_NtCreateThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtCreateThreadEx", 11, CV_STDCALL, (FARPROC)bh_NtCreateThreadEx, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtResumeThread", 2, CV_STDCALL, (FARPROC)bh_NtResumeThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtCreateUserProcess", 11, CV_STDCALL, NULL, (FARPROC)ah_NtCreateUserProcess, TRUE, FALSE);
	if (config.bProtectHook) {
		SetHookByName("ntdll.dll", "ZwMapViewOfSection", 10, CV_STDCALL, NULL, (FARPROC)ah_ZwMapViewOfSection, TRUE, FALSE);
	}
	if (config.level >= LEVEL_MEDIUM) {
		SetHookByName("ntdll.dll", "NtProtectVirtualMemory", 5, CV_STDCALL, NULL, (FARPROC)ah_NtProtectVirtualMemory, TRUE, FALSE);
	}
	if (config.level >= LEVEL_HIGH) {
		SetHookByName("kernel32.dll", "LoadLibraryW", 2, CV_STDCALL, (FARPROC)bh_LoadLibraryW, NULL, TRUE, FALSE);
		SetHookByName("kernel32.dll", "LoadLibraryA", 2, CV_STDCALL, (FARPROC)bh_LoadLibraryA, NULL, TRUE, FALSE);
	}
	return TRUE;
}