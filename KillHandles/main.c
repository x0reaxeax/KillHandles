#include <Windows.h>
#include <Psapi.h>

#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS                  0x00000000L
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004L

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllTypesInformation = 3,
    ObjectHandleFlagInformation = 4
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

extern NTSTATUS __stdcall NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
);

extern NTSTATUS __stdcall NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

BOOL EnableDebugPrivilege(VOID) {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken
    )) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(
        NULL,
        SE_DEBUG_NAME,
        &luid
    )) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bRet = AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tkp,
        0,
        NULL,
        0
    );

    CloseHandle(hToken);

    return bRet;
}

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        fprintf(
            stderr,
            "usage: %s <pid> [dbgpriv (1)]\n", argv[0]
        );
        return EXIT_FAILURE;
    }

    ULONG cbBufSiz = 0x10000;
    DWORD dwPid = strtoul(argv[1], NULL, 0);

    if (argc >= 3 && 1 == atoi(argv[2])) {
        if (!EnableDebugPrivilege()) {
            fprintf(
                stderr,
                "[-] EnableDebugPrivilege failed: E%lu\n",
                GetLastError()
            );
            return EXIT_FAILURE;
        }
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_DUP_HANDLE,
        FALSE,
        dwPid
    );

    if (NULL == hProcess) {
        fprintf(
            stderr,
            "[-] OpenProcess failed: E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = VirtualAlloc(
        NULL,
        cbBufSiz,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NULL == pSysHandleInfo) {
        fprintf(
            stderr,
            "[-] VirtualAlloc failed: %u\n",
            GetLastError()
        );
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    NTSTATUS status = NtQuerySystemInformation(
        SystemHandleInformation,
        pSysHandleInfo,
        cbBufSiz,
        NULL
    );

    while (STATUS_INFO_LENGTH_MISMATCH == status) {
        VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
        cbBufSiz *= 2;
        pSysHandleInfo = VirtualAlloc(
            NULL,
            cbBufSiz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (NULL == pSysHandleInfo) {
            fprintf(
                stderr,
                "[-] VirtualAlloc failed: %u\n",
                GetLastError()
            );
            CloseHandle(hProcess);
            return EXIT_FAILURE;
        }

        status = NtQuerySystemInformation(
            SystemHandleInformation,
            pSysHandleInfo,
            cbBufSiz,
            NULL
        );
    }

    if (!NT_SUCCESS(status)) {
        fprintf(
            stderr,
            "[-] NtQuerySystemInformation failed: 0x%08X\n",
            status
        );
        goto _FINAL;
    }

    puts("[*] Pwning handles:\n");
    ULONG ulClosedHandleCount = 0, ulTotalHandleCount = 0;
    for (ULONG i = 0; i < pSysHandleInfo->HandleCount; i++) {
        if (dwPid == pSysHandleInfo->Handles[i].ProcessId) {
            ulTotalHandleCount++;
            if (NT_SUCCESS(status = NtDuplicateObject(
                hProcess,
                (HANDLE) pSysHandleInfo->Handles[i].Handle,
                NULL,
                NULL,
                0,
                0,
                DUPLICATE_CLOSE_SOURCE
            ))) {
                printf(
                    "    * 0x%04x - PWNED\n",
                    pSysHandleInfo->Handles[i].Handle
                );
                ulClosedHandleCount++;
            } else {
                printf(
                    "    * 0x%04x - FAILURE  [0x%08lx]\n"
                    "    * Access Mask:      [0x%08lx]\n",
                    pSysHandleInfo->Handles[i].Handle,
                    status,
                    pSysHandleInfo->Handles[i].GrantedAccess
                );
            }
            putchar('\n');
        }
    }

    printf(
        "\n[+] Closed %lu/%lu handles in PID %lu\n",
        ulClosedHandleCount,
        ulTotalHandleCount,
        dwPid
    );

_FINAL:
    VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return EXIT_FAILURE;
}