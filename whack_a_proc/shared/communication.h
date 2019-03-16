#pragma once
#include <Windows.h>

enum MessageCode {
	CODE_ERROR,
	CODE_OK,
	CODE_SCAN,
	CODE_INJECT,
	CODE_THREAD
};

BOOL Communicate(HANDLE hPipe);
HANDLE CreateThreadPipe(DWORD dwPid, DWORD dwTid);