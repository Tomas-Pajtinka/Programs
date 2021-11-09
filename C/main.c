#include "Shared\stringUtilities.c"
#include "Techniques/ApiResolving/pebApiResolving.c"

int main(int argc, char *argv[]){
    inicialize();
    void (*mb)(HWND, LPCTSTR, LPCTSTR, UINT) = resolveApi("MessageBox", "User32.dll");
    mb(0,"Injection of process successfull.","Message from DLL",0);
    puts("Injection successfull.");
    return 0;
}

