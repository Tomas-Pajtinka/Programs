
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h> 
#include <stdio.h>
//#include "..\..\Shared\stringUtilities.c"

FARPROC loadLibrary = NULL, getProcAddress = NULL;

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
        char *dllName = convertUnicodeToAscii(pLdrDataTableEntry->FullDllName);
        printf("%s\n",dllName);
    }
    system("pause");

}

FARPROC resolveApi(){

}
