#include <windows.h>
#include <winternl.h>

char * convertUnicodeToAscii(UNICODE_STRING unicode){
    char *ascii = malloc(MAX_PATH);
    int u = 0;
    for(; u < unicode.Length/2 ; u++){
        ascii[u] = (unicode.Buffer+u)[0];
    }
    ascii[u] = 0x00;
    return ascii;
}

void getLastItemFromPath(char *module){
    char *processFileName;
    (processFileName = strrchr(module, '\\')) ? ++processFileName : (processFileName = module);   //get last item from path
}
