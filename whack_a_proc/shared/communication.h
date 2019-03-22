#pragma once
#include <Windows.h>

enum MessageCode {
	CODE_ERROR,
	CODE_OK,
	CODE_SCAN,
	CODE_INJECT,
	CODE_THREAD,
	CODE_INIT
};

enum HookLevel {
	LEVEL_LOW,
	LEVEL_MEDIUM,
	LEVEL_HIGH
};

typedef struct _inject_config {
	BOOL bProtectHook;
	HookLevel level;
} inject_config;

BOOL Communicate(HANDLE hPipe);
HANDLE CreateThreadPipe(DWORD dwPid, DWORD dwTid);