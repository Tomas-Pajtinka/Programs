#include <windows.h>
#include <TlHelp32.h> 
#include <stdio.h>

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
