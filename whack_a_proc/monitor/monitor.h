#pragma once
#include <Windows.h>

BOOL SetEntrypointHook(HANDLE hProcess);
HANDLE CreateWorkerThread(DWORD dwPid, DWORD dwTid);