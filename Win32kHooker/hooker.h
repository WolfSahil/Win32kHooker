#pragma once
#include "global.h"
#include "Hde64/hde64.h"

typedef PVOID(NTAPI* fptrW32GetSessionState)();
typedef BOOL(NTAPI* NtGdiBitBltPtr)(HDC hdcDst, INT x, INT y, INT cx, INT cy, HDC hdcSrc, INT xSrc, INT ySrc, DWORD rop4, DWORD crBackColor, FLONG fl);

extern NtGdiBitBltPtr OriginalNtGdiBitBlt;
extern PVOID NtGdiBitBltPtrAddress;
extern PEPROCESS GuiProcess;

BOOL HookedNtGdiBitBlt(
	HDC hdcDst,
	INT x,
	INT y,
	INT cx,
	INT cy,
	HDC hdcSrc,
	INT xSrc,
	INT ySrc,
	DWORD rop4,
	DWORD crBackColor,
	FLONG fl
);

fptrW32GetSessionState GetW32GetSessionStateAddr();
PVOID GetSessionState();
BOOL ResolveWin32kDataPtr(LPCSTR functionName, PDWORD64 DataPtrAddr, PDWORD64 FuncPtr);
BOOL InitializeHooker();
BOOL RemoveHooker();