#include <Windows.h>

enum CallConv {
	CV_STDCALL,
	CV_CDECL
};

/*
Set hooks for an API. Other than the dll and API names, the number of arguments is required.
There are two types of hook, one that is executed before the API, and one immediately after it.
It is possible to set only one or both the hooks (if the parameter is NULL the hook will not be set).
IMPORTANT: Both functions MUST be __stdcall. 
lpBeforeHook has the same prototype of the API, while lpAfterHook has as additional last parameter the return value of the API.
If bDoCall=TRUE, the API is called, otherwise it is bypassed. Note that if bDoCall=FALSE, the return value
of the last executed hook will be returned to the caller.
*/

extern "C" FARPROC __cdecl SetHookByName(
	LPSTR lpDllName, 
	LPSTR lpFuncName, 
	DWORD dwNumArgs,
	CallConv callConv,
	FARPROC lpBeforeHook, 
	FARPROC lpAfterHook,
	BOOL bDoCall,
	BOOL bOverrideRet);

extern "C" FARPROC __cdecl SetHookByAddr(
	LPVOID addr,
	DWORD dwNumArgs,
	CallConv callConv,
	FARPROC lpBeforeHook,
	FARPROC lpAfterHook,
	BOOL bDoCall,
	BOOL bOverrideRet);

extern "C" BOOL __cdecl RemoveHook(LPSTR lpDllName, LPSTR lpFuncName);
