#include "Shared\stringUtilities.c"
#include "Shared\peParser.c"
#include "Shared\obfuscation.c"
#include "Techniques/ApiResolving/pebApiResolving.c"

int main(int argc, char *argv[]){
    char string[12] = "\x39\x00\x00\x07\x08\x09\x02\x36\x0a\x0b\x35";
    decodeSimpleXor(string, 11, "testing", 7);
    puts("A");
    puts(string);
    /*inicialize();
    void (*mb)(HWND, LPCTSTR, LPCTSTR, UINT) = resolveApi("MessageBoxA", "User32.dll");
    mb(0,"Dynamic API resolve succesfull.","Dynamic API resolve",0);
    puts("Resolving successfull.");*/

    return 0;
}

