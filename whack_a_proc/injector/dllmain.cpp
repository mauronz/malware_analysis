// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "injector.h"

HMODULE hGlobalModule;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	int argc;
	WCHAR **argv;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hGlobalModule = hModule;
		argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		if (argc < 3 || wcscmp(argv[2], L"inject")) {
			SetHooks();
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

