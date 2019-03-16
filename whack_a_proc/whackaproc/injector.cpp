// injector.cpp : Defines the exported functions for the DLL application.
//

#include "injector.h"
#include "hooks.h"
#include "APIhooklib.h"

extern HMODULE hGlobalModule;

BOOL SetHooks() {
	SetHookByName("ntdll.dll", "NtCreateThread", 8, CV_STDCALL, (FARPROC)bh_NtCreateThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtCreateThreadEx", 11, CV_STDCALL, (FARPROC)bh_NtCreateThreadEx, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtResumeThread", 2, CV_STDCALL, (FARPROC)bh_NtResumeThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "ZwMapViewOfSection", 10, CV_STDCALL, NULL, (FARPROC)ah_ZwMapViewOfSection, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtCreateUserProcess", 11, CV_STDCALL, NULL, (FARPROC)ah_NtCreateUserProcess, TRUE, FALSE);
	return TRUE;
}