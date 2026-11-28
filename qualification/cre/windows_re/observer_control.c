/* Synthetic qualification controls; never count as recovered-program cases. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#if !defined(_WIN64)
#error Build the observer controls for the same Windows x64 ABI as the observer.
#endif

#define CONTROL_EXCEPTION ((DWORD)0xe0421001UL)
#define STDOUT_BYTES (80u * 1024u)

static int write_exact(HANDLE output, const void *data, DWORD length) {
    const BYTE *bytes = (const BYTE *)data;
    DWORD offset = 0;
    if (!output || output == INVALID_HANDLE_VALUE) return 1;
    while (offset < length) {
        DWORD written = 0;
        if (!WriteFile(output, bytes + offset, length - offset, &written, NULL) || !written)
            return 1;
        offset += written;
    }
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fputs("usage: observer_control.exe sleep|stdout|exception\n", stderr);
        return 2;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (!wcscmp(argv[1], L"sleep")) {
        static const char completed[] = "sleep completed\n";
        Sleep(1500);
        return write_exact(GetStdHandle(STD_OUTPUT_HANDLE), completed,
                           (DWORD)(sizeof(completed) - 1));
    }
    if (!wcscmp(argv[1], L"stdout")) {
        BYTE buffer[4096];
        DWORD emitted = 0;
        /* Binary WriteFile bypasses CRT newline translation. */
        memset(buffer, 'X', sizeof(buffer));
        while (emitted < STDOUT_BYTES) {
            DWORD count = (DWORD)sizeof(buffer);
            if (count > STDOUT_BYTES - emitted) count = STDOUT_BYTES - emitted;
            if (write_exact(GetStdHandle(STD_OUTPUT_HANDLE), buffer, count)) return 1;
            emitted += count;
        }
        return 0;
    }
    if (!wcscmp(argv[1], L"exception")) {
        /* This code is deliberately unrelated to the debugger's INT3 events. */
        RaiseException(CONTROL_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
        /* Reaching this point means another component improperly continued it. */
        fputs("control exception was incorrectly continued\n", stderr);
        return 3;
    }
    fputs("unknown observer control mode\n", stderr);
    return 2;
}
