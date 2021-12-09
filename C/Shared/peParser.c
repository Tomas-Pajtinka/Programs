#include <windows.h>
#include <TlHelp32.h> 

struct Executable{
    int executableSize;
    char *executableData;
} executable, *executablePtr;


int alignSize(DWORD aligment, DWORD size){
    return ((size / aligment) + 1 ) * aligment;
}

//function loads PE into memory
void loadPeToRemoteProcess(struct Executable *executable){
    //parse DOS and PE header
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)executable->executableData;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)executable->executableData + IDH->e_lfanew);
    DWORD sectionAlligmnet = INH->OptionalHeader.SectionAlignment;
    DWORD fileAlligment = INH->OptionalHeader.FileAlignment;
    //allocate memory in process with enought space for image
    LPVOID peBaseAddress = VirtualAlloc(NULL, INH->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID nextSectionAddress = peBaseAddress;
    if (nextSectionAddress == NULL){
        perror("Injection failed. Could not allocate memory in process.\n");
        exit(EXIT_FAILURE);
    }
    //write PE header to process
    memcpy(nextSectionAddress, executable->executableData, INH->OptionalHeader.SizeOfHeaders);
    //calculate next virtual address
    nextSectionAddress = (LPVOID)((int)nextSectionAddress + alignSize(sectionAlligmnet, INH->OptionalHeader.SizeOfHeaders));//virtual address, where should next write start
    //get section location
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    //loop through all sections and write their contetn into memory
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        memcpy(nextSectionAddress, (LPVOID)((int)executable->executableData + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData);
        //calculate next virtual address
        nextSectionAddress = (LPVOID)((int)nextSectionAddress + alignSize(sectionAlligmnet, sectionHeader->Misc.VirtualSize));
        //calculate address of nexr section record
        sectionLocation = sectionLocation +sectionSize;
    } 

    //Import resolve
    IMAGE_DATA_DIRECTORY importsDirectory = INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)peBaseAddress);
    HANDLE hLibrary = NULL;
    LPVOID procAddr = NULL;
    while( (void *)importDescriptor->Name != NULL){
        hLibrary = LoadLibraryA((char *)((int)peBaseAddress + importDescriptor->Name)); //Load libray by name from Import direcotry
        PIMAGE_THUNK_DATA thunk = NULL;
		thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)peBaseAddress + importDescriptor->FirstThunk);//get offset of IAT entry
        while( (void *)thunk->u1.Function != NULL){
            procAddr = GetProcAddress( hLibrary, (LPCSTR)((DWORD_PTR)peBaseAddress + thunk->u1.Function) + 2);//get address of function
            memcpy( thunk, &procAddr, 4);//copy address of function into IAT
            thunk++; //next IAT entry
        }
        importDescriptor++; //next import descriptor
    }


    //TODO relocations 
     
}

//get offset of overlay
int getExecutableEntryPoint(struct Executable *executable){
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)executable->executableData;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)executable->executableData + IDH->e_lfanew);
    return INH->OptionalHeader.AddressOfEntryPoint;
}  

//get offset of overlay
int getSizeOfPeFile(){
    HMODULE baseAddress = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((int)baseAddress + IDH->e_lfanew);
    int size = INH->OptionalHeader.SizeOfHeaders;
    DWORD sectionLocation = (DWORD)INH + sizeof(DWORD) /*PE signature*/ + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)INH->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER); //40 bytes
    for (int i = 0; i < INH->FileHeader.NumberOfSections; i++) {    //loop through all sections and adds its sizes
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        size = size + sectionHeader->SizeOfRawData;
        sectionLocation = sectionLocation +sectionSize;
    }
    return size;
}   


DWORD getAddressOfExport(struct Executable *executable, char *export){
    IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)executable->executableData;
    IMAGE_NT_HEADERS* INH = (IMAGE_NT_HEADERS*)((DWORD_PTR)executable->executableData + IDH->e_lfanew);
    IMAGE_DATA_DIRECTORY exportsDirectory = INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDescriptor = (PIMAGE_EXPORT_DIRECTORY)(exportsDirectory.VirtualAddress + (DWORD_PTR)executable->executableData);
    DWORD exportNames = (DWORD_PTR)executable->executableData + exportDescriptor->AddressOfNames;
    DWORD exportFunctionAddress = (DWORD_PTR)executable->executableData + exportDescriptor->AddressOfFunctions;
    exportNames -= 4;//I dont know why I have to repair index; TODO: repair
    for (int index = 0; index < exportDescriptor->NumberOfNames; index++){
        if( strcicmp( (char *)((int)*(DWORD **)exportNames + (int)executable->executableData), export) == 0){ //compares the export name with the searched export name 
            //export was found
            return (int)*(DWORD **)exportFunctionAddress + (int)executable->executableData;
            break;
        }
        exportNames += 4; // next name of export
        exportFunctionAddress += 4; // next address of export
    }


}
