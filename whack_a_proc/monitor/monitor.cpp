#include "monitor.h"
#include "peb.h"
#include "ntdef.h"
#include "communication.h"
#include <stdio.h>

#pragma comment(lib, "pe-sieve.lib")

#define SHELLCODE_SIZE 96
#define MAX_THREAD_COUNT 1000

HANDLE hSemaphore;
HANDLE hThreadCountMutex;
DWORD dwThreadCount = 0;

DWORD dwDllPathSize = 0;
WCHAR pDllPath[MAX_PATH];

inject_config config;

BOOL SetEntrypointHook(HANDLE hProcess) {
	SIZE_T written;
	TdefNtQueryInformationProcess _NtQueryInformationProcess;
	LPVOID pRemoteAddress;
	PROCESS_BASIC_INFORMATION pbInfo;
	DWORD dwSize;
	PEB peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	BYTE pHeaderBuffer[0x400];
	DWORD dwEntrypoint;
	BYTE pShellcode[0x200];
	DWORD dwOffset = 0;
	DWORD dwOldProtect;
	WCHAR pImageFilename[MAX_PATH];
	dwSize = MAX_PATH;
	QueryFullProcessImageNameW(hProcess, 0, pImageFilename, &dwSize);

	if (dwDllPathSize == 0) {
		GetModuleFileNameW(NULL, pDllPath, MAX_PATH);
		wcscpy_s(wcsrchr(pDllPath, '\\') + 1, MAX_PATH, L"whackaproc.dll");
		dwDllPathSize = wcslen(pDllPath);
	}

	_NtQueryInformationProcess = (TdefNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (_NtQueryInformationProcess(hProcess, 0, &pbInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize)) {
		printf("[-] Error NtQueryInformationProcess\n");
		return FALSE;
	}
	ReadProcessMemory(hProcess, pbInfo.PebBaseAddress, &peb, sizeof(PEB), &dwSize);
	ReadProcessMemory(hProcess, peb.ImageBaseAddress, pHeaderBuffer, sizeof(pHeaderBuffer), &dwSize);
	pNtHeaders = (PIMAGE_NT_HEADERS)(pHeaderBuffer + ((PIMAGE_DOS_HEADER)pHeaderBuffer)->e_lfanew);
	dwEntrypoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	pRemoteAddress = VirtualAllocEx(hProcess, NULL, 0x200, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pRemoteAddress) {
		printf("[-] Error allocating remote memory\n");
		return FALSE;
	}

	/*
	mov eax, dword ptr [XXXX]
	mov ecx, XXXX
	mov [ecx], eax
	mov al, byte ptr [XXXX]
	add ecx, 4
	mov byte ptr [ecx], al
	*/
	BYTE pCustomMemcpy[] = { 0xA1, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x89, 0x01, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC1, 0x04, 0x88, 0x01 };
	*(DWORD *)(pCustomMemcpy + 1) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 4;
	*(DWORD *)(pCustomMemcpy + 6) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	*(DWORD *)(pCustomMemcpy + 13) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 4 + 4;

	// mov eax, offset oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, PAGE_EXECUTE_READWRITE
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = PAGE_EXECUTE_READWRITE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, 5
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = 5;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, entrypoint
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call VirtualProtect
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)VirtualProtect - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	CopyMemory(pShellcode + dwOffset, pCustomMemcpy, sizeof(pCustomMemcpy));
	dwOffset += sizeof(pCustomMemcpy);

	// mov eax, offset oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xa1;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, 5
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = 5;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, entrypoint
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call VirtualProtect
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)VirtualProtect - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// mov eax, offset libname
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 9;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call LoadLibraryW
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)LoadLibraryW - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// jmp entrypoint
	pShellcode[dwOffset++] = 0xe9;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// Leave  space for oldprotect
	dwOffset += 4;

	// Read original first 5 bytes at entrypoint
	ReadProcessMemory(hProcess, (PBYTE)peb.ImageBaseAddress + dwEntrypoint, pShellcode + dwOffset, 5, &written);
	dwOffset += 5;

	CopyMemory(pShellcode + dwOffset, pDllPath, dwDllPathSize * sizeof(WCHAR));

	if (!WriteProcessMemory(hProcess, pRemoteAddress, pShellcode, dwOffset + dwDllPathSize * sizeof(WCHAR), &written)) {
		printf("[-] Error writing the shellcode\n");
		return FALSE;
	}

	PVOID pRemoteEntrypoint = (PBYTE)peb.ImageBaseAddress + dwEntrypoint;
	if (!VirtualProtectEx(hProcess, pRemoteEntrypoint, 5, PAGE_READWRITE, &dwOldProtect)) {
		printf("[-] Error changing entrypoint protection\n");
		return FALSE;
	}

	// jmp shellcode
	pShellcode[0] = 0xe9;
	*(DWORD *)(pShellcode + 1) = (DWORD)pRemoteAddress - ((DWORD)peb.ImageBaseAddress + dwEntrypoint + 5);
	WriteProcessMemory(hProcess, pRemoteEntrypoint, pShellcode, 5, &written);

	if (!VirtualProtectEx(hProcess, pRemoteEntrypoint, 5, dwOldProtect, &dwOldProtect)) {
		printf("[-] Error resetting entrypoint protection\n");
		return FALSE;
	}

	return TRUE;
}

DWORD __stdcall ThreadRoutine(LPVOID lpParams) {
	Communicate((HANDLE)lpParams);
	ReleaseSemaphore(hSemaphore, 1, NULL);
	return 0;
}

HANDLE CreateWorkerThread(DWORD dwPid, DWORD dwTid) {
	HANDLE hPipe = CreateThreadPipe(dwPid, dwTid);
	if (hPipe == INVALID_HANDLE_VALUE)
		return NULL;
	WaitForSingleObject(hThreadCountMutex, INFINITE);
	dwThreadCount++;
	ReleaseMutex(hThreadCountMutex);
	return CreateThread(NULL, 0, ThreadRoutine, (LPVOID)hPipe, 0, NULL);
}

VOID PrintUsage(WCHAR *argv0) {
	wprintf(L"Usage: %s [options] target_command_line\n", argv0);
	wprintf(L"Options:\n/level [0,1,2]\n/protect");
}

int wmain(int argc, WCHAR **argv) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	LPWSTR pTargetCmd;
	LPWSTR pCmdline = GetCommandLineW();
	BOOL bRunning = TRUE, bPrintUsage = FALSE;
	int i = 1;

	hSemaphore = CreateSemaphoreW(NULL, 0, MAX_THREAD_COUNT, NULL);
	hThreadCountMutex = CreateMutexW(NULL, FALSE, NULL);

	config.bProtectHook = FALSE;
	config.level = LEVEL_MEDIUM;

	if (argc == 1)
		bPrintUsage = TRUE;

	while (i < argc && !bPrintUsage) {
		if (!wcscmp(argv[i], L"/protect")) {
			config.bProtectHook = TRUE;
		}
		else if (!wcscmp(argv[i], L"/level")) {
			if (i + 1 <= argc || !isdigit(argv[i + 1][0]))
				bPrintUsage = TRUE;
			else {
				config.level = (HookLevel)_wtoi(argv[i + 1]);
				if (config.level < LEVEL_LOW || config.level > LEVEL_HIGH)
					bPrintUsage = TRUE;
			}
			i += 2;
		}
		else
			break;
	}

	if (i >= argc)
		bPrintUsage = TRUE;

	if (bPrintUsage) {
		PrintUsage(argv[0]);
	}
	else {
		pTargetCmd = wcsstr(pCmdline, argv[i]);
		if (*(pTargetCmd - 1) == '"')
			pTargetCmd--;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		if (!CreateProcessW(NULL, pTargetCmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			printf("[-] Error creating process\n");
			return 1;
		}
		SetEntrypointHook(pi.hProcess);
		HANDLE hThread = CreateWorkerThread(pi.dwProcessId, pi.dwThreadId);
		ResumeThread(pi.hThread);
		DWORD dwRes;
		while (bRunning) {
			dwRes = WaitForSingleObject(hSemaphore, INFINITE);
			dwRes = WaitForSingleObject(hThreadCountMutex, INFINITE);
			if (--dwThreadCount == 0)
				bRunning = FALSE;
			ReleaseMutex(hThreadCountMutex);
		}
	}

	return 0;
}