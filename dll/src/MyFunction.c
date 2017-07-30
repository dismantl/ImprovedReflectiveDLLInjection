#include "ReflectiveLoader.h"
#include <stdio.h>
#include "MinHook.h"

//typedef LONG (WINAPI *CHANGEDISPLAYSETTINGSA)(DEVMODE, DWORD);
typedef LONG (WINAPI *CHANGEDISPLAYSETTINGSExA)(LPCTSTR, DEVMODE, HWND, DWORD, LPVOID);
typedef LONG (WINAPI *CHANGEDISPLAYSETTINGSExW)(LPCTSTR, DEVMODE, HWND, DWORD, LPVOID);
//typedef LONG (WINAPI *CHANGEDISPLAYSETTINGSW)(DEVMODE, DWORD);

struct HRESULT (WINAPI *SetFullscreenState)(BOOL);



//override 
typedef LONG (WINAPI *SETWINDOWPOS)(HWND, HWND, int, int, int, int, UINT);
typedef LONG (WINAPI *DEFWINDOWPROC)(HWND, UINT, WPARAM, LPARAM);

// Pointer for calling original changedisplaysettings functions if we need to.
//CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsA = NULL;
CHANGEDISPLAYSETTINGSExA fpChangeDisplaySettingsExA = NULL;
CHANGEDISPLAYSETTINGSExW fpChangeDisplaySettingsExW = NULL;
//CHANGEDISPLAYSETTINGSA fpChangeDisplaySettingsW = NULL;

HRESULT fpSetFullscreenState = NULL;

// Detour functions which override changedisplaysettings functions
LONG WINAPI DetourChangeDisplaySettingsA(DEVMODE *lpDevMode, DWORD dwflags)
{
	return DISP_CHANGE_SUCCESSFUL;
}

LONG WINAPI DetourChangeDisplaySettingsExA(LPCTSTR lpszDeviceName, DEVMODE *lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam)
{
	return DISP_CHANGE_SUCCESSFUL;
}

LONG WINAPI DetourChangeDisplaySettingsExW(LPCTSTR lpszDeviceName, DEVMODE *lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam)
{
	return DISP_CHANGE_SUCCESSFUL;
}

// WINAPI DetourChangeDisplaySettingsW(DEVMODE *lpDevMode, DWORD dwflags)
//{
//	return DISP_CHANGE_SUCCESSFUL;
//}

 WINAPI DetourSetFullscreenState(BOOL Fullscreen)
 {
	 return S_OK;
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
//	if (MH_CreateHook(&ChangeDisplaySettingsA, &DetourChangeDisplaySettingsA,
//		(&fpChangeDisplaySettingsA)) != MH_OK)
//	{
//		return FALSE;
//	}

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

//	if (MH_CreateHook(&ChangeDisplaySettingsW, &DetourChangeDisplaySettingsW,
//		(&fpChangeDisplaySettingsW)) != MH_OK)
//	{
//		return FALSE;
//	}

	if (MH_CreateHook(&SetFullscreenState, &DetourSetFullscreenState,
		(&fpSetFullscreenState)) != MH_OK)
	{
		return FALSE;
	}

	// Enable each the hook for ChangeDisplaySettings.
//	if (MH_EnableHook(&ChangeDisplaySettingsA) != MH_OK)
//	{
//		return FALSE;
//	}

	if (MH_EnableHook(&ChangeDisplaySettingsExA) != MH_OK)
	{
		return FALSE;
	}

	if (MH_EnableHook(&ChangeDisplaySettingsExW) != MH_OK)
	{
		return FALSE;
	}

//	if (MH_EnableHook(&ChangeDisplaySettingsW) != MH_OK)
//	{
//		return FALSE;
//	}

//	if (MH_EnableHook(&SetFullscreenState) != MH_OK)
//	{
//		return FALSE;
//	}

	//LPSTR str = malloc(32 + nUserdataLen);
	//sprintf_s(str, 32 + nUserdataLen, "Hello from MyFunction: %s!", lpUserdata);
	//MessageBoxA(NULL, str, (LPCSTR)lpUserdata, MB_OK);
	//free(str);
	return TRUE;
}
