#include <windows.h>
#include <TlHelp32.h> 
#include <stdio.h>

struct Overlay{
    int overlaySize;
    char *overlayData;
} overlay;

//get offset of overlay
int getSizeOfPeFile(){
    HMODULE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)baseAddress + IDH->e_lfanew);
    int size = INH->OptionalHeader.SizeOfHeaders;
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    DWORD importDirectoryRVA = INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections and adds its sizes
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }
    return size;
}   

void getOverlay(struct Overlay overlay){
    int offsetOfOverlay = getSizeOfPeFile();
    char *fileName = (char *)malloc(MAX_PATH);
    GetModuleFileNameA(NULL,fileName,MAX_PATH);
    if( strlen(fileName) == 0){
        perror("Could not retrive filename.\n");
        exit(EXIT_FAILURE);
    }
    FILE *fp = fopen(fileName, "rb"); // read mode
    if (fp == NULL){
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    long int sizeOfFile = ftell(fp);
    if ( fseek(fp, offsetOfOverlay, SEEK_SET) != 0 ) {
        perror("Could not set the file position.\n");
        exit(EXIT_FAILURE);
    }
    fread(&overlay.overlaySize, 4, 1, fp); //first 4 bytes of overlay are size of the file
    overlay.overlayData = (char *)malloc(overlay.overlaySize);
    fread(overlay.overlayData, 1, overlay.overlaySize, fp);
    fclose(fp);
}
