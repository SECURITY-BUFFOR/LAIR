#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include <tlhelp32.h>

bool InjectDLL(HANDLE hProcess, const char* dllPath) {

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("Failed to allocate memory in target process. Error: %lu",GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Failed to write to target process memory. Error: %lu",GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle((LPCSTR) "kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        printf("Failed to get address of LoadLibraryA. Error: %lu",GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread. Error: %lu", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("Injection completed");
    return true;
}

HANDLE GetProcessHandleByName(const wchar_t *processName) {
    HANDLE hProcess = NULL;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(processName, pe32.szExeFile) == 0) { // Case-insensitive comparison
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return hProcess;
}



int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Please provide DLL path");
        return 1;
    }
    wchar_t *pname = L"notepad.exe";
    InjectDLL(GetProcessHandleByName(pname), argv[1]);

    return 0;
}
