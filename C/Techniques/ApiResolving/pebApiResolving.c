#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h> 
#include <stdio.h>
//#include "..\..\Shared\stringUtilities.c"
//#include "..\..\Shared\peParser.c"
//#include "..\..\Shared\obfuscation.c"

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
    char *xorKey = "\xfc\x51\x1a\x5f\xc9\x57\xbc\x22\x5b\x47";
    char resolve[50];
    PEB* peb = getPeb();
    for(PLIST_ENTRY pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink; pListEntry && pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink){
        PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        char *fullDllName = convertUnicodeToAscii(pLdrDataTableEntry->FullDllName);
        char *baseDllName = getLastItemFromPath(fullDllName);
        memcpy(resolve,"\x97\x34\x68\x31\xac\x3b\x8f\x10\x75\x23\x90\x3d\x00", 13); //kernel32.dll
        if(strcicmp(baseDllName, decodeSimpleXor(resolve, 12, xorKey, 10)) == 0){
            struct Executable dll;
            dll.executableData = pLdrDataTableEntry->DllBase;
            dll.executableSize = 0;
            memcpy(resolve,"\xb0\x3e\x7b\x3b\x85\x3e\xde\x50\x3a\x35\x85\x10\x00", 13); //LoadLibraryA
            loadLibrary = getAddressOfExport(&dll, decodeSimpleXor(resolve, 12, xorKey, 10));
            memcpy(resolve,"\xbb\x34\x6e\x0f\xbb\x38\xdf\x47\x28\x34\xbd\x37\x7c\x36\xa7\x3e\xc8\x5b\x16\x26\x8f\x3a\x00", 23); //GetProcessAffinityMask
            getProcAddress = getAddressOfExport(&dll, decodeSimpleXor(resolve, 22, xorKey, 10));
            break;
        }
        free(fullDllName);
    }
    if (loadLibrary == NULL){
        //perror("Could not find LoadLibrary address.\n");
        exit(EXIT_FAILURE);
    }
    if(getProcAddress == NULL){
        //perror("Could not find GetProcAddress address.\n");
        exit(EXIT_FAILURE);
    }
}

FARPROC resolveApi(char *api, char *dll){
    if (loadLibrary == NULL || getProcAddress == NULL){
        //perror("Need to call inicialize function first.\n");
        exit(EXIT_FAILURE);
    }
    HANDLE hLibrary = loadLibrary(dll);
    return  getProcAddress(hLibrary, api);
}
