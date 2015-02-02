//===============================================================================================//
// Copyright (c) 2015, Dan Staples
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
#include "LoadLibraryR.h"
#include <stdio.h>
#include <malloc.h>
//===============================================================================================//
DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if( dwCompiledArch != 1 )
			return 0;
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if( VirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// call the loaded librarys DllMain to get its HMODULE
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}
				// revert to the previous protection flags...
				VirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR( 
	HANDLE hProcess, 
	LPVOID lpBuffer, 
	DWORD dwLength, 
	LPVOID lpParameter,
	DWORD dwFunctionHash,
	LPVOID lpUserdata, 
	DWORD nUserdataLen )
{
	BOOL bSuccess                             = FALSE;
	LPVOID lpRemoteLibraryBuffer              = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread                            = NULL;
	DWORD dwReflectiveLoaderOffset            = 0;
	DWORD dwThreadId                          = 0;
	DWORD i = 0;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// check if the library has a ReflectiveLoader...
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;

			DWORD nBufferSize = dwLength
				+ nUserdataLen
				+ 64; // shellcode buffer

			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, nBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;
			printf("Allocated memory address in remote process: 0x%p\n", lpRemoteLibraryBuffer);

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			ULONG_PTR uiReflectiveLoaderAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset;

			ULONG_PTR userdataAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwLength;
			if (!WriteProcessMemory(hProcess, (LPVOID)userdataAddr, lpUserdata, nUserdataLen, NULL))
				break;

			ULONG_PTR uiShellcodeAddr = userdataAddr + nUserdataLen;

			HMODULE kernel32 = LoadLibraryA("kernel32.dll");
			if (!kernel32)
				break;
			FARPROC exitthread = GetProcAddress(kernel32, "ExitThread");
			if (!exitthread)
				break;

			BYTE bootstrap[64] = { 0 };
			/*
			Shellcode pseudo-code:
			DWORD r = ReflectiveLoader(lpParameter, lpLibraryAddress, dwFunctionHash, lpUserData, nUserdataLen);
			ExitThread(r);
			*/
			// debugging (will cause infinite loop; step over in debugger)
			//bootstrap[i++] = 0xEB;
			//bootstrap[i++] = 0xFE;
#if defined(WIN_X86)
			// push <size of userdata>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &nUserdataLen, sizeof(nUserdataLen));
			i += sizeof(nUserdataLen);

			// push <address of userdata>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &userdataAddr, sizeof(userdataAddr));
			i += sizeof(userdataAddr);

			// push <hash of function>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &dwFunctionHash, sizeof(dwFunctionHash));
			i += sizeof(dwFunctionHash);

			// push <address of image base>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &lpRemoteLibraryBuffer, sizeof(lpRemoteLibraryBuffer));
			i += sizeof(lpRemoteLibraryBuffer);

			// push <lpParameter>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &lpParameter, sizeof(lpParameter));
			i += sizeof(lpParameter);

			// mov eax, <address of reflective loader>
			bootstrap[i++] = 0xB8; // MOV EAX (word/dword)
			MoveMemory(bootstrap + i, &uiReflectiveLoaderAddr, sizeof(uiReflectiveLoaderAddr));
			i += sizeof(uiReflectiveLoaderAddr);

			// call eax
			bootstrap[i++] = 0xFF; // CALL
			bootstrap[i++] = 0xD0; // EAX

			// Push eax (return code from ReflectiveLoader) (WINAPI/__stdcall)
			bootstrap[i++] = 0x50; // PUSH EAX

			// mov eax, <value of exitthread>
			bootstrap[i++] = 0xB8; // MOV EAX (word/dword)
			MoveMemory(bootstrap + i, &exitthread, sizeof(exitthread));
			i += sizeof(exitthread);

			// call eax
			bootstrap[i++] = 0xFF; // CALL
			bootstrap[i++] = 0xD0; // EAX
#elif defined(WIN_X64)
			// mov rcx, <lpParameter>
			bootstrap[i++] = 0x48;
			bootstrap[i++] = 0xB9;
			MoveMemory(bootstrap + i, &lpParameter, sizeof(lpParameter));
			i += sizeof(lpParameter);

			// mov rdx, <address of image base>
			bootstrap[i++] = 0x48;
			bootstrap[i++] = 0xBA;
			MoveMemory(bootstrap + i, &lpRemoteLibraryBuffer, sizeof(lpRemoteLibraryBuffer));
			i += sizeof(lpRemoteLibraryBuffer);

			// mov r8d, <hash of function>
			bootstrap[i++] = 0x41;
			bootstrap[i++] = 0xB8;
			MoveMemory(bootstrap + i, &dwFunctionHash, sizeof(dwFunctionHash));
			i += sizeof(dwFunctionHash);

			// mov r9, <address of userdata>
			bootstrap[i++] = 0x49;
			bootstrap[i++] = 0xB9;
			MoveMemory(bootstrap + i, &userdataAddr, sizeof(userdataAddr));
			i += sizeof(userdataAddr);

			// push <size of userdata>
			bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(bootstrap + i, &nUserdataLen, sizeof(nUserdataLen));
			i += sizeof(nUserdataLen);

			// move rax, <address of reflective loader>
			bootstrap[i++] = 0x48;
			bootstrap[i++] = 0xB8;
			MoveMemory(bootstrap + i, &uiReflectiveLoaderAddr, sizeof(uiReflectiveLoaderAddr));
			i += sizeof(uiReflectiveLoaderAddr);

			// call rax
			bootstrap[i++] = 0xFF; // CALL
			bootstrap[i++] = 0xD0; // RAX

			// mov rcx, rax (return code from ReflectiveLoader) (__fastcall)
			bootstrap[i++] = 0x48;
			bootstrap[i++] = 0x89;
			bootstrap[i++] = 0xC1;

			// mov rax, <value of exitthread>
			bootstrap[i++] = 0x48;
			bootstrap[i++] = 0xB8;
			MoveMemory(bootstrap + i, &exitthread, sizeof(exitthread));
			i += sizeof(exitthread);

			// call rax
			bootstrap[i++] = 0xFF; // CALL
			bootstrap[i++] = 0xD0; // RAX
#else
#error Architecture not supported!
#endif

			if (!WriteProcessMemory(hProcess, (LPVOID)uiShellcodeAddr, bootstrap, i, NULL))
				break;

			// Make sure our changes are written right away
			FlushInstructionCache(hProcess, lpRemoteLibraryBuffer, nBufferSize);

			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)uiShellcodeAddr, lpParameter, (DWORD)NULL, &dwThreadId);

		} while( 0 );

	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//
