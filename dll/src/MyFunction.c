#include "ReflectiveLoader.h"
#include <stdio.h>
#include "MinHook.h"

typedef int (WINAPI *CHANGEDISPLAYSETTINGSA)(DEVMODE, DWORD);
typedef int (WINAPI *CHANGEDISPLAYSETTINGSExA)(LPCTSTR, DEVMODE, HWND, DWORD, LPVOID);
typedef int (WINAPI *CHANGEDISPLAYSETTINGSExW)(LPCTSTR, DEVMODE, HWND, DWORD, LPVOID);
typedef int (WINAPI *CHANGEDISPLAYSETTINGSW)(DEVMODE, DWORD);


//override 
typedef int (WINAPI *SETWINDOWPOS)(HWND, HWND, int, int, int, int, UINT);
typedef int (WINAPI *DEFWINDOWPROC)(HWND, UINT, WPARAM, LPARAM);

// Pointer for calling original changedisplaysettings functions if we need to.
CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsA = NULL;
CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsExA = NULL;
CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsExW = NULL;
CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsW = NULL;

// Detour functions which override changedisplaysettings functions
int WINAPI DetourChangeDisplaySettingsA(DEVMODE *lpDevMode, DWORD dwflags)
{
	return DISP_CHANGE_SUCCESSFUL;
}

int WINAPI DetourChangeDisplaySettingsExA(LPCTSTR lpszDeviceName, DEVMODE *lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam)
{
	return DISP_CHANGE_SUCCESSFUL;
}

int WINAPI DetourChangeDisplaySettingsExW(LPCTSTR lpszDeviceName, DEVMODE *lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam)
{
	return DISP_CHANGE_SUCCESSFUL;
}

int WINAPI DetourChangeDisplaySettingsW(DEVMODE *lpDevMode, DWORD dwflags)
{
	return DISP_CHANGE_SUCCESSFUL;
}

DLLEXPORT BOOL
MyFunction(LPVOID lpUserdata, DWORD nUserdataLen)
{
	// Initialize MinHook
	if (MH_Initialize() != MH_OK)
	{
		return FALSE;
	}

	// Create a hook for each changedisplaysettings, in disabled state.
	if (MH_CreateHook(&ChangeDisplaySettingsA, &DetourChangeDisplaySettingsA,
		(&fpChangeDisplaySettingsA)) != MH_OK)
	{
		return FALSE;
	}

	if (MH_CreateHook(&ChangeDisplaySettingsExA, &DetourChangeDisplaySettingsExA,
		(&fpChangeDisplaySettingsExA)) != MH_OK)
	{
		return FALSE;
	}

	if (MH_CreateHook(&ChangeDisplaySettingsExW, &DetourChangeDisplaySettingsExW,
		(&fpChangeDisplaySettingsExW)) != MH_OK)
	{
		return FALSE;
	}

	if (MH_CreateHook(&ChangeDisplaySettingsW, &DetourChangeDisplaySettingsW,
		(&fpChangeDisplaySettingsW)) != MH_OK)
	{
		return FALSE;
	}

	// Enable each the hook for ChangeDisplaySettings.
	if (MH_EnableHook(&ChangeDisplaySettingsA) != MH_OK)
	{
		return FALSE;
	}

	if (MH_EnableHook(&ChangeDisplaySettingsExA) != MH_OK)
	{
		return FALSE;
	}

	if (MH_EnableHook(&ChangeDisplaySettingsExW) != MH_OK)
	{
		return FALSE;
	}

	if (MH_EnableHook(&ChangeDisplaySettingsW) != MH_OK)
	{
		return FALSE;
	}

	//LPSTR str = malloc(32 + nUserdataLen);
	//sprintf_s(str, 32 + nUserdataLen, "Hello from MyFunction: %s!", lpUserdata);
	//MessageBoxA(NULL, str, (LPCSTR)lpUserdata, MB_OK);
	//free(str);
	return TRUE;
}
