#include <windows.h>
#include <TlHelp32.h> 

struct Executable{
    int executableSize;
    char *executableData;
} executable, *executablePtr;

//get offset of overlay
int getExecutableEntryPointFromOverlay(struct Executable *executable){
    HMODULE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)baseAddress + IDH->e_lfanew);
    int size = INH->OptionalHeader.SizeOfHeaders;
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    DWORD importDirectoryRVA = INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections and adds its sizes
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }
    return size;
}  

//get offset of overlay
int getSizeOfPeFile(){
    HMODULE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)baseAddress + IDH->e_lfanew);
    int size = INH->OptionalHeader.SizeOfHeaders;
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    DWORD importDirectoryRVA = INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections and adds its sizes
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }
    return size;
}   
