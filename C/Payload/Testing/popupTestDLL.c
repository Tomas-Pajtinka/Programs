#define WIN32_LEAN_AND_MEAN  
#include <windows.h>
typedef void* HANDLE;

HANDLE hMutex = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call,  LPVOID lpReserved)
{
 switch (ul_reason_for_call)
 {
 case DLL_PROCESS_ATTACH:
    hMutex = CreateMutexA(NULL,TRUE, "DllInjection");
    if (hMutex != NULL){
        MessageBox(0,"Injection of process successfull.","Message from DLL",0);
    }
    break;
 case DLL_THREAD_ATTACH:
    hMutex = CreateMutexA(NULL,TRUE, "DllInjection");
    if (hMutex != NULL){
        MessageBox(0,"Injection of process successfull.","Message from DLL",0);
    }
    break;
 case DLL_THREAD_DETACH:
    break;
 case DLL_PROCESS_DETACH:
    ReleaseMutex(hMutex);
    break;
 }
 return TRUE;
}
