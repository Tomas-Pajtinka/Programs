#include "Shared\stringUtilities.c"
#include "Techniques/ApiResolving/pebApiResolving.c"

int main(int argc, char *argv[]){
    inicialize();
    void (*mb)(HWND, LPCTSTR, LPCTSTR, UINT) = resolveApi("MessageBoxA", "User32.dll");
    mb(0,"Dynamic API resolve succesfull.","Dynamic API resolve",0);
    puts("Resolving successfull.");
    return 0;
}

