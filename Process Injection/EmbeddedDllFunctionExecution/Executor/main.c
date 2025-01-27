#include <windows.h>
#include <stdio.h>
#include "dll.h"

void *GetExportedFunction(LPVOID imageBase, const char *functionName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)imageBase + dosHeader->e_lfanew);

    // Locate the export directory
    PIMAGE_DATA_DIRECTORY exportDirData = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData->Size == 0) {
        printf("No export directory found.\n");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)imageBase + exportDirData->VirtualAddress);

    // Get function names and addresses
    DWORD *names = (DWORD *)((BYTE *)imageBase + exportDir->AddressOfNames);
    DWORD *functions = (DWORD *)((BYTE *)imageBase + exportDir->AddressOfFunctions);
    WORD *nameOrdinals = (WORD *)((BYTE *)imageBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *name = (char *)((BYTE *)imageBase + names[i]);
        if (strcmp(name, functionName) == 0) {
            // Match found, return function address
            DWORD functionRVA = functions[nameOrdinals[i]];
            return (void *)((BYTE *)imageBase + functionRVA);
        }
    }

    printf("Function %s not found in exports.\n", functionName);
    return NULL;
}

BOOL LoadDllFromMemory(BYTE *pMemory, LPVOID *loadedImageBase) {
    // Parse DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMemory;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS header.\n");
        return FALSE;
    }

    // Parse NT headers
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)pMemory + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT header.\n");
        return FALSE;
    }

    // Allocate memory for the DLL
    LPVOID imageBase = VirtualAlloc((LPVOID)ntHeader->OptionalHeader.ImageBase,
                                    ntHeader->OptionalHeader.SizeOfImage,
                                    MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
    if (!imageBase) {
        printf("Failed to allocate memory.\n");
        return FALSE;
    }

    // Copy headers
    memcpy(imageBase, pMemory, ntHeader->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDst = (LPVOID)((BYTE *)imageBase + sectionHeader[i].VirtualAddress);
        LPVOID sectionSrc = (LPVOID)((BYTE *)pMemory + sectionHeader[i].PointerToRawData);
        memcpy(sectionDst, sectionSrc, sectionHeader[i].SizeOfRawData);
    }

    // Perform base relocation
    if ((ULONGLONG)imageBase != ntHeader->OptionalHeader.ImageBase) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE *)imageBase + relocDir->VirtualAddress);
            while (reloc->VirtualAddress) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *relocData = (WORD *)(reloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    if (relocData[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *patchAddr = (DWORD *)((BYTE *)imageBase + reloc->VirtualAddress + (relocData[i] & 0xFFF));
                        *patchAddr += (DWORD)((ULONGLONG)imageBase - ntHeader->OptionalHeader.ImageBase);
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((BYTE *)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // Resolve imports
    PIMAGE_DATA_DIRECTORY importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)imageBase + importDir->VirtualAddress);
        while (importDesc->Name) {
            char *dllName = (char *)((BYTE *)imageBase + importDesc->Name);
            HMODULE hModule = LoadLibraryA(dllName);
            if (!hModule) {
                printf("Failed to load dependency: %s\n", dllName);
                return FALSE;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE *)imageBase + importDesc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)imageBase + thunk->u1.AddressOfData);
                FARPROC func = GetProcAddress(hModule, importByName->Name);
                if (!func) {
                    printf("Failed to resolve function: %s\n", importByName->Name);
                    return FALSE;
                }
                thunk->u1.Function = (ULONGLONG)func;
                thunk++;
            }
            importDesc++;
        }
    }

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        PIMAGE_SECTION_HEADER section = &sectionHeader[i];
        LPVOID sectionAddress = (BYTE *)imageBase + section->VirtualAddress;
        DWORD protection = PAGE_READWRITE;

        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            protection = PAGE_EXECUTE_READ;
        else if (section->Characteristics & IMAGE_SCN_MEM_READ)
            protection = PAGE_READONLY;

        VirtualProtect(sectionAddress, section->SizeOfRawData, protection, &oldProtect);
    }

    *loadedImageBase = imageBase;
    printf("DLL successfully loaded from memory.\n");
    return TRUE;
}


int main(void) {
    typedef void (__cdecl *_RUN)(void); // definition of imported function
    _RUN _run;

    LPVOID imageBase;
    if (LoadDllFromMemory(rawData, &imageBase)) {
        // Resolve exported function
        void *testFunction = GetExportedFunction(imageBase, "run");
        if (testFunction) {
            printf("run function found at address: %p\n", testFunction);
            _run = (_RUN)testFunction;

            // Call the function
            _run();
        } else {
            printf("Failed to resolve '_run' function.\n");
        }
    } else {
        printf("Failed to load DLL from memory.\n");
    }
    return 0;
}
