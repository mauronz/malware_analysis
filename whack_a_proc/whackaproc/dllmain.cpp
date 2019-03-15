// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "injector.h"

HMODULE hGlobalModule;
TdefPESieve_scan _PESieve_scan;

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
			/*WCHAR pFilename[MAX_PATH];
			GetModuleFileNameW(hModule, pFilename, MAX_PATH);
			wcscpy(wcsrchr(pFilename, '\\') + 1, L"pe-sieve.dll");
			HMODULE hPeSieveModule = LoadLibraryW(pFilename);
			if (hPeSieveModule == NULL) {
				MessageBoxW(NULL, L"Error while loading pe-sieve.dll.\nMake sure it is in the same folder of whackaproc.dll", L"Error", MB_ICONERROR | MB_OK);
				break;
			}
			_PESieve_scan = (TdefPESieve_scan)GetProcAddress(hPeSieveModule, "PESieve_scan");*/

			MessageBoxA(NULL, "sis", "", 0);

			WCHAR pPipeName[64];
			wsprintfW(pPipeName, L"\\\\.\\pipe\\whack%08x%08x", GetCurrentProcessId(), GetCurrentThreadId());
			hPipe = CreateFileW(pPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			if (hPipe == INVALID_HANDLE_VALUE) {
				wsprintfW(pPipeName, L"%d", GetLastError());
				MessageBoxW(NULL, pPipeName, L"", 0);
			}
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

