#include "communication.h"
#include "include/pe_sieve_api.h"
#include "monitor.h"
#include <stdio.h>

#define BUFSIZE 1024

extern INJECT_CONFIG config;

HANDLE CreateThreadPipe(DWORD dwPid, DWORD dwTid) {
	WCHAR pPipeName[64];
	wsprintfW(pPipeName, L"\\\\.\\pipe\\whack%08x%08x", dwPid, dwTid);
	wprintf(L"%s\n", pPipeName);
	return CreateNamedPipeW(
		pPipeName,
		PIPE_ACCESS_DUPLEX,       // read/write access 
		PIPE_TYPE_MESSAGE |       // message type pipe 
		PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		BUFSIZE,                  // output buffer size 
		BUFSIZE,                  // input buffer size 
		0,                        // client time-out 
		NULL);                    // default security attribute
}

BOOL DoError(HANDLE hPipe) {
	DWORD dwSize, dwCode = CODE_ERROR;
	if (!WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL)) return FALSE;
	return TRUE;
}

BOOL DoScan(HANDLE hPipe) {
	pesieve::t_params params = { 0 };
	DWORD dwSize, dwPid, dwCode;
	if (!ReadFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL)) return FALSE;
	params.pid = dwPid;
	params.quiet = true;
	params.no_hooks = true;
	PESieve_scan(params);
	dwCode = CODE_OK;
	if (!WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL)) return FALSE;
	return TRUE;
}

BOOL DoInject(HANDLE hPipe) {
	DWORD dwSize, dwPid, dwTid, dwCode = CODE_ERROR;
	HANDLE hProcess;
	WCHAR pImageFilename[MAX_PATH], pMessage[200];
	BOOL bInject = FALSE;
	if (!ReadFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL)) return FALSE;
	if (!ReadFile(hPipe, &dwTid, sizeof(dwTid), &dwSize, NULL)) return FALSE;
	MessageBoxA(NULL, "injecting", "", 0);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess != INVALID_HANDLE_VALUE) {
		if (config.AllProcesses) {
			bInject = TRUE;
		}
		else {
			dwSize = sizeof(pImageFilename);
			QueryFullProcessImageNameW(hProcess, 0, pImageFilename, &dwSize);
			wsprintfW(pMessage, L"New process %s (PID: %d). Do you want to inject into it?", pImageFilename, dwPid);
			bInject = MessageBoxW(NULL, pMessage, L"Injector", MB_YESNO) == IDYES;
		}

		if (bInject) {
			if (SetEntrypointHook(hProcess) && CreateWorkerThread(dwPid, dwTid))
				dwCode = CODE_OK;
			else
				dwCode = CODE_ERROR;
		}
		else
			dwCode = CODE_OK;

		CloseHandle(hProcess);
	}
	if (!WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL)) return FALSE;
	return TRUE;
}

BOOL DoThread(HANDLE hPipe) {
	DWORD dwSize, dwPid, dwTid, dwCode = CODE_ERROR;
	if (!ReadFile(hPipe, &dwPid, sizeof(dwPid), &dwSize, NULL)) return FALSE;
	if (!ReadFile(hPipe, &dwTid, sizeof(dwTid), &dwSize, NULL)) return FALSE;
	if (CreateWorkerThread(dwPid, dwTid))
		dwCode = CODE_OK;
	if (!WriteFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL)) return FALSE;
	return TRUE;
}

BOOL DoInit(HANDLE hPipe) {
	DWORD dwSize;
	if (!WriteFile(hPipe, &config, sizeof(config), &dwSize, NULL)) return FALSE;
	return TRUE;
}

BOOL Communicate(HANDLE hPipe) {
	DWORD dwCode, dwSize;

	if (hPipe == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
		while (ReadFile(hPipe, &dwCode, sizeof(dwCode), &dwSize, NULL)) {
			switch (dwCode) {
			case CODE_SCAN:
				DoScan(hPipe);
				break;
			case CODE_INJECT:
				DoInject(hPipe);
				break;
			case CODE_THREAD:
				DoThread(hPipe);
				break;
			case CODE_INIT:
				DoInit(hPipe);
				break;
			default:
				DoError(hPipe);
			}
		}
	}
	CloseHandle(hPipe);
	return TRUE;
}