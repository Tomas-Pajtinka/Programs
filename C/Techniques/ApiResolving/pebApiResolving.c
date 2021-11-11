#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h> 
#include <stdio.h>
//#include "..\..\Shared\stringUtilities.c"
#include "..\..\Shared\peParser.c"

FARPROC (*loadLibrary)(LPCSTR) = NULL; 
FARPROC (*getProcAddress)(HMODULE, LPCSTR) = NULL;

#ifdef _M_IX86
	int unicodeNameOffset = 0x28;
#elif _M_X64
    int unicodeNameOffset = 0x60;
#endif

PEB* getPeb(){
#ifdef _M_IX86
	return (PEB*)(__readfsdword(0x30));
#elif _M_X64
	return (PEB*)(__readgsqword(0x60));
#else
    perror("unsuported architecture.");
    return
#endif
}

//get address of LoadLibrary and GetProcAddress and save them into globals variables
void* inicialize(){
    PEB* peb = getPeb();
    for(PLIST_ENTRY pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink; pListEntry && pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink){
        PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        char *fullDllName = convertUnicodeToAscii(pLdrDataTableEntry->FullDllName);
        char *baseDllName = getLastItemFromPath(fullDllName);
        if(strcicmp(baseDllName, "kernel32.dll") == 0){
            struct Executable dll;
            dll.executableData = pLdrDataTableEntry->DllBase;
            dll.executableSize = 0;
            loadLibrary = getAddressOfExport(&dll, "LoadLibraryA");
            getProcAddress = getAddressOfExport(&dll, "GetProcessAffinityMask");
            break;
        }
        free(fullDllName);
    }
    if (loadLibrary == NULL){
        perror("Could not find LoadLibrary address.\n");
        exit(EXIT_FAILURE);
    }
    if(getProcAddress == NULL){
        perror("Could not find GetProcAddress address.\n");
        exit(EXIT_FAILURE);
    }
}

FARPROC resolveApi(char *api, char *dll){
    if (loadLibrary == NULL || getProcAddress == NULL){
        perror("Need to call inicialize function first.\n");
        exit(EXIT_FAILURE);
    }
    HANDLE hLibrary = loadLibrary(dll);
    return  getProcAddress(hLibrary, api);
}
