// injector.cpp : Defines the exported functions for the DLL application.
//

#include "injector.h"
#include "hooks.h"
#include "peb.h"

#define SHELLCODE_SIZE 96

extern HMODULE hGlobalModule;

BOOL __cdecl inject() {
	int argc;
	SIZE_T written;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	TdefNtQueryInformationProcess _NtQueryInformationProcess;
	LPVOID pRemoteAddress;
	LPWSTR pTargetCmd;
	PROCESS_BASIC_INFORMATION pbInfo;
	DWORD dwSize;
	PEB peb;
	HANDLE hFile;
	PIMAGE_NT_HEADERS pNtHeaders;
	BYTE pHeaderBuffer[0x400];
	DWORD dwEntrypoint;
	BYTE pShellcode[0x200];
	DWORD dwOffset = 0;
	DWORD dwOldProtect;
	LPWSTR pCmdline = GetCommandLineW();
	LPWSTR *pArgv = CommandLineToArgvW(pCmdline, &argc);
	WCHAR pFilename[MAX_PATH];
	DWORD dwFilenameSize = GetModuleFileNameW(hGlobalModule, pFilename, MAX_PATH);

	if (argc > 3) {
		pTargetCmd = wcsstr(pCmdline, pArgv[3]);
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		if (!CreateProcessW(NULL, pTargetCmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			OutputDebugStringA("[-] Error creating process\n");
			return FALSE;
		}

		_NtQueryInformationProcess = (TdefNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (_NtQueryInformationProcess(pi.hProcess, 0, &pbInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize)) {
			OutputDebugStringA("[-] Error NtQueryInformationProcess\n");
			return FALSE;
		}
		ReadProcessMemory(pi.hProcess, pbInfo.PebBaseAddress, &peb, sizeof(PEB), &dwSize);
		
		hFile = CreateFileW(pArgv[3], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			OutputDebugStringA("[-] Error opening target file\n");
			return FALSE;
		}
		if (!ReadFile(hFile, pHeaderBuffer, sizeof(pHeaderBuffer), &dwSize, NULL) || dwSize != sizeof(pHeaderBuffer)) {
			OutputDebugStringA("[-] Error reading target file\n");
			return FALSE;
		}
		CloseHandle(hFile);
		pNtHeaders = (PIMAGE_NT_HEADERS)(pHeaderBuffer + ((PIMAGE_DOS_HEADER)pHeaderBuffer)->e_lfanew);
		dwEntrypoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

		pRemoteAddress = VirtualAllocEx(pi.hProcess, NULL, 0x200, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pRemoteAddress) {
			OutputDebugStringA("[-] Error allocating remote memory\n");
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

		// jmp entrypoint
		pShellcode[dwOffset++] = 0xe9;
		*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint - ((DWORD)pRemoteAddress + dwOffset + 4);
		dwOffset += sizeof(DWORD);

		// Leave  space for oldprotect
		dwOffset += 4;

		// Read original first 5 bytes at entrypoint
		ReadProcessMemory(pi.hProcess, (PBYTE)peb.ImageBaseAddress + dwEntrypoint, pShellcode + dwOffset, 5, &written);
		dwOffset += 5;

		CopyMemory(pShellcode + dwOffset, pFilename, dwFilenameSize * sizeof(WCHAR));

		if (!WriteProcessMemory(pi.hProcess, pRemoteAddress, pShellcode, dwOffset + dwFilenameSize * sizeof(WCHAR), &written)) {
			OutputDebugStringA("[-] Error writing the shellcode\n");
			return FALSE;
		}

		// jmp shellcode
		pShellcode[0] = 0xe9;
		*(DWORD *)(pShellcode + 1) = (DWORD)pRemoteAddress - ((DWORD)peb.ImageBaseAddress + dwEntrypoint + 5);
		WriteProcessMemory(pi.hProcess, (PBYTE)peb.ImageBaseAddress + dwEntrypoint, pShellcode, 5, &written);

		PBYTE pRemoteEntrypointAddress = (PBYTE)peb.ImageBaseAddress + ((PIMAGE_DOS_HEADER)pHeaderBuffer)->e_lfanew + 0x28;
		if (!VirtualProtectEx(pi.hProcess, pRemoteEntrypointAddress, sizeof(pRemoteAddress), PAGE_READWRITE, &dwOldProtect)) {
			OutputDebugStringA("[-] Error changing entrypoint protection\n");
			return FALSE;
		}

		pRemoteAddress = (PVOID)((DWORD)pRemoteAddress - (DWORD)peb.ImageBaseAddress);
		if (!WriteProcessMemory(pi.hProcess, pRemoteEntrypointAddress, &pRemoteAddress, sizeof(pRemoteAddress), &written)) {
			OutputDebugStringA("[-] Error overwriting the entrypoint\n");
			return FALSE;
		}
		if (!VirtualProtectEx(pi.hProcess, pRemoteEntrypointAddress, sizeof(pRemoteAddress), dwOldProtect, &dwOldProtect)) {
			OutputDebugStringA("[-] Error resetting entrypoint protection\n");
			return FALSE;
		}

		ResumeThread(pi.hThread);
	}
	return TRUE;
}

BOOL SetHooks() {
	SetHookByName("ntdll.dll", "NtCreateThread", 8, CV_STDCALL, (FARPROC)bh_NtCreateThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtCreateThreadEx", 11, CV_STDCALL, (FARPROC)bh_NtCreateThreadEx, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "NtResumeThread", 2, CV_STDCALL, (FARPROC)bh_NtResumeThread, NULL, TRUE, FALSE);
	SetHookByName("ntdll.dll", "ZwMapViewOfSection", 10, CV_STDCALL, NULL, (FARPROC)ah_ZwMapViewOfSection, TRUE, FALSE);
	return TRUE;
}