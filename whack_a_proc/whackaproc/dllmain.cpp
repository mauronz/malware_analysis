// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "injector.h"

HMODULE hGlobalModule;

HANDLE hPipe;

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
			WCHAR pPipeName[64];
			wsprintfW(pPipeName, L"\\\\.\\pipe\\whack%08x%08x", GetCurrentProcessId(), GetCurrentThreadId());
			hPipe = CreateFileW(pPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			DWORD dwMode = PIPE_READMODE_MESSAGE;
			SetNamedPipeHandleState(
				hPipe,    // pipe handle 
				&dwMode,  // new pipe mode 
				NULL,     // don't set maximum bytes 
				NULL);    // don't set maximum time 
			SetHooks();
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

