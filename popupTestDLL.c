#define WIN32_LEAN_AND_MEAN  
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call,  LPVOID lpReserved)
{
 switch (ul_reason_for_call)
 {
 case DLL_PROCESS_ATTACH:
    MessageBox(0,"Injection of process successfull.","Message from DLL",0);
    break;
 case DLL_THREAD_ATTACH:
    MessageBox(0,"Injection of thread successfull.","Message from DLL",0);
    break;
 case DLL_THREAD_DETACH:
   break;
 case DLL_PROCESS_DETACH:
  break;
 }
 return TRUE;
}