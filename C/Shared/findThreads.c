#include <windows.h>
#include <TlHelp32.h> 

struct Handles{
    HANDLE threadHandlesArray[MAXIMUM_WAIT_OBJECTS];
    HANDLE eventHandlesArray[MAXIMUM_WAIT_OBJECTS];
    DWORD processPidsArray[MAXIMUM_WAIT_OBJECTS];
    int itemsCount;
} handles;

struct TIDs{
    DWORD threadsPidsArray[MAXIMUM_WAIT_OBJECTS];
    int itemsCount;
    int maxItemsCount;
} tids;

//get handles of only 32 bit threads, because DLL is 32 bit
void getRemoteThreadHandles(struct Handles *handles){
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    handles->itemsCount = 0;
    int ownPid = GetCurrentProcessId();
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return;
    }
    do {
        if (is64bit(te32.th32OwnerProcessID) == 0){ //check if is 32 bit
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
            if (hThread != INVALID_HANDLE_VALUE && te32.th32OwnerProcessID != ownPid) {
                handles->processPidsArray[handles->itemsCount] = te32.th32OwnerProcessID; //save PID to array
                handles->threadHandlesArray[handles->itemsCount++] = hThread; //save thread handle to array
            }
        }
        if(handles->itemsCount >= MAXIMUM_WAIT_OBJECTS){
            break;
        }
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);
}

//get TIDS of only 32 bit threads, because DLL is 32 bit
void getRemoteThreadTIDs(struct TIDs *tids){
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    tids->itemsCount = 0;
    int ownPid = GetCurrentProcessId();
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return;
    }
    do {
        if (is64bit(te32.th32OwnerProcessID) == 0){ //check if is 32 bit
            if (te32.th32OwnerProcessID != ownPid)  {
                tids->threadsPidsArray[tids->itemsCount++] = te32.th32ThreadID; //save PID to array
            }
        }
        if(tids->itemsCount >= tids->maxItemsCount){
            break;
        }
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);
}

//Find out alertable threads
int findAlertableThread(HANDLE hKernel32, struct Handles *handles){
    HANDLE duplicateHandles[MAXIMUM_WAIT_OBJECTS];
    LPVOID f  = GetProcAddress(hKernel32, "SetEvent");
    for (int i = 0; i < handles->itemsCount; i++){
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, handles->processPidsArray[i]);
        if(hProcess == INVALID_HANDLE_VALUE){
            continue; //Could not open remote thread
        }
        handles->eventHandlesArray[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        DuplicateHandle(GetCurrentProcess(), handles->eventHandlesArray[i], hProcess, &duplicateHandles[i], 0, FALSE, DUPLICATE_SAME_ACCESS);   
        QueueUserAPC(f, handles->threadHandlesArray[i], (ULONG_PTR)duplicateHandles[i]); 
        CloseHandle(hProcess);
    }
    DWORD handleIndex = -1;
    DWORD i = WaitForMultipleObjects(handles->itemsCount, handles->eventHandlesArray, FALSE, 5000); //get index of alertable thread
    if(i != WAIT_TIMEOUT) {
        handleIndex = i;
    }
    for(i=0; i<handles->itemsCount; i++) {
        CloseHandle(handles->eventHandlesArray[i]);
        CloseHandle(duplicateHandles[i]);
        if(handleIndex != i) 
            CloseHandle(handles->threadHandlesArray[i]);
    }
    return handleIndex;
}
