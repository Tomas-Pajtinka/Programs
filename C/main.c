#include "Techniques/Injections/apcDllInjectionOverlay.c"

int main(int argc, char *argv[]){
    apcDllInjection();
    puts("Injection successfull.");
    return 0;
}
