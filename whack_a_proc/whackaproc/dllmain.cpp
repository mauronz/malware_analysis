// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "injector.h"

HMODULE hGlobalModule;
TdefPESieve_scan _PESieve_scan;

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
			WCHAR pFilename[MAX_PATH];
			GetModuleFileNameW(hModule, pFilename, MAX_PATH);
			wcscpy(wcsrchr(pFilename, '\\') + 1, L"pe-sieve.dll");
			HMODULE hPeSieveModule = LoadLibraryW(pFilename);
			if (hPeSieveModule == NULL) {
				MessageBoxW(NULL, L"Error while loading pe-sieve.dll.\nMake sure it is in the same folder of whackaproc.dll", L"Error", MB_ICONERROR | MB_OK);
				break;
			}
			_PESieve_scan = (TdefPESieve_scan)GetProcAddress(hPeSieveModule, "PESieve_scan");
			SetHooks();
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

