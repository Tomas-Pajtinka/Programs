#include <windows.h>
#include <winternl.h>

char *convertUnicodeToAscii(UNICODE_STRING unicode){
    char *ascii = malloc(MAX_PATH);
    int u = 0;
    for(; u < unicode.Length/2 ; u++){
        ascii[u] = (unicode.Buffer+u)[0];
    }
    ascii[u] = 0x00;
    return ascii;
}

char *getLastItemFromPath(char *module){
    char *lastItem;
    (lastItem = strrchr(module, '\\')) ? ++lastItem : (lastItem = module);   //get last item from path
    return lastItem;
}

int strcicmp(char const *a, char const *b)
{
    for (;; a++, b++) {
        int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (d != 0 || !*a)
            return d;
    }
}
