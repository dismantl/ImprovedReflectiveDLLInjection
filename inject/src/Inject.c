// Copyright (c) 2015, Dan Staples

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Tlhelp32.h>
#include "LoadLibraryR.h"
#include "Inject.h"

#pragma comment(lib,"Advapi32.lib")

#define MYFUNCTION_HASH		0x6654bba6 // hash of "MyFunction"

// Simple app to inject a reflective DLL into a process vis its process ID.
int WinMain() //int argc, char * argv[]
{
	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	DWORD dwProcessId     = 0;
	DWORD dwExitCode	  = 1;
	TOKEN_PRIVILEGES priv = {0};

#ifdef WIN_X64
	char * cpDllFile = "reflective_dll.x64.dll";
#else
	char * cpDllFile  = "reflective_dll.dll";
#endif

	do
	{
		// Usage: inject.exe [string] [pid] [dll_file]

		//if (argc == 2)
		//	dwProcessId = GetCurrentProcessId();
		//else
		//dwProcessId = atoi( argv[2] );
		dwProcessId = getPid("ffxiv_dx11.exe");

		//if( argc >= 4 )
		//	cpDllFile = argv[3];
		cpDllFile = "ffxiv-fixfullscreen.dll";

		hFile = CreateFileA( cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if( hFile == INVALID_HANDLE_VALUE )
			BREAK_WITH_ERROR( "Failed to open the DLL file" );

		dwLength = GetFileSize( hFile, NULL );
		if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );

		lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
		if( !lpBuffer )
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );

		if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
			BREAK_WITH_ERROR( "Failed to alloc a buffer!" );

		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			CloseHandle( hToken );
		}

		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId );
		if( !hProcess )
			BREAK_WITH_ERROR( "Failed to open the target process" );

		hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, NULL, MYFUNCTION_HASH, "user data", 1337); // originally (DWORD)(strlen(argv[1]) + 1)
		if( !hModule )
			BREAK_WITH_ERROR( "Failed to inject the DLL" );

		//printf( "[+] Injected the '%s' DLL into process %d.\n", cpDllFile, dwProcessId );
		
		WaitForSingleObject( hModule, -1 );

		if ( !GetExitCodeThread( hModule, &dwExitCode ) )
			BREAK_WITH_ERROR( "Failed to get exit code of thread" );

		//printf( "[+] Created thread exited with code %d.\n", dwExitCode );

		//char message[260] = "Injection successful. Thread exited with code: ";
		//char buffer[260];
		//sprintf(buffer, "%d", dwExitCode);
		//MessageBox(0, strcat(message, buffer), "Info", 1);

	} while( 0 );

	if( lpBuffer )
		HeapFree( GetProcessHeap(), 0, lpBuffer );

	if( hProcess )
		CloseHandle( hProcess );

	return dwExitCode;
}

DWORD getPid(char procName [260])
{
	HANDLE hsnap;
	PROCESSENTRY32 pt;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do
	{
		if (strcmp(pt.szExeFile,procName)==0)
		{
			DWORD pid = pt.th32ProcessID;
			CloseHandle(hsnap);
			printf("%d", pid);
			return pid;
		}
	} while (Process32Next(hsnap, &pt));
	CloseHandle(hsnap);
	return 0;
}