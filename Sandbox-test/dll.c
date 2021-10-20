#include <windows.h>

int main(){
    HMODULE hLib = LoadLibraryA("test\\dll.dll");
    if (hLib == NULL){
        MessageBox(0,"Failure.","Failure",0);
    }

}