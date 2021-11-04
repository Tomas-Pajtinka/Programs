#include <windows.h>
#include <TlHelp32.h> 
#include <stdio.h>
#include "peParser.c"

struct Overlay{
    int overlaySize;
    char *overlayData;
} overlay;


void getOverlay(struct Overlay *overlay){
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
    fread(&overlay->overlaySize, 4, 1, fp); //first 4 bytes of overlay are size of the overlay
    overlay->overlayData = (char *)malloc(overlay->overlaySize);
    fread(overlay->overlayData, 1, overlay->overlaySize, fp);
    fclose(fp);
}
