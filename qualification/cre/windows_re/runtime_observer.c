/*
 * CRE Windows recovery qualification instrument.  Only launches a new, owned
 * x64 PE process.  No attach, privilege elevation, arbitrary address input or
 * recursive process termination.  See runtime_observer_README.md.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>

#if !defined(_WIN64)
#error This qualification observer requires the Windows x64 ABI.
#endif
_Static_assert(sizeof(wchar_t) == 2, "The argument sensor requires Windows UTF-16 code units.");

#define OUTPUT_LIMIT 65536u
#define EVENT_LIMIT 256u
#define COMMAND_LIMIT 32767u
#define ENV_LIMIT 65536u
#define CLEANUP_MS 2500u
#define CANCEL_EXIT ((DWORD)0xc000013aUL)

typedef struct {
    HANDLE read, file;
    uint64_t seen, retained;
    BOOL overflow, eof;
    DWORD error;
} Stream;

typedef struct {
    uint64_t seq, elapsed_ms, address, base;
    DWORD kind, pid, tid, code, first_chance, continuation, continue_error;
    BOOL continued;
    char name[160];
} Event;

typedef struct {
    BOOL available;
    DWORD error, entry_rva, image_size, export_rva, export_size;
    WORD machine, optional_magic;
    uint64_t base, entry;
} Image;

typedef struct {
    BOOL requested, install_attempted, installed, armed, hit;
    BOOL original_known, context_read, byte_restored, byte_restore_verified;
    BOOL install_protection_restored, protection_restored, context_rewound;
    BOOL continued, install_readback;
    BYTE original;
    DWORD original_protection, error, tid, eflags;
    uint64_t rip_before, rip_after, rsp;
    const char *operation;
} Breakpoint;

typedef struct {
    const wchar_t *receipt, *out, *err;
    const char *mode;
    DWORD timeout_ms;
    int target_index;
    int target_argc;
    wchar_t **target_argv;
    HANDLE process, initial_thread;
    DWORD pid, initial_tid;
    BOOL created, create_event_seen, exit_seen, exit_available, signaled;
    BOOL cancelled, abort_before_first_continue, timed_out, output_overflow;
    BOOL termination_attempted, termination_succeeded, cleanup_complete;
    DWORD exit_code, termination_error, observer_error;
    const char *error_operation, *termination_reason;
    uint64_t start_tick, termination_tick, continues, events_total, dropped;
    uint64_t ntdll_base, ntdll_size;
    DWORD bootstrap_breakpoints, dll_events, exception_events;
    Image image;
    Breakpoint bp;
    Stream out_stream, err_stream;
    Event events[EVENT_LIMIT];
    BOOL times_attempted, times_available, io_attempted, io_available;
    DWORD times_error, io_error;
    FILETIME creation_time, exit_time, kernel_time, user_time;
    IO_COUNTERS io;
} State;

static const char *jb(BOOL value) { return value ? "true" : "false"; }
static uint64_t tick(void) { return (uint64_t)GetTickCount64(); }
static uint64_t ft64(FILETIME f) {
    return ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime;
}
static void fail(State *s, const char *operation, DWORD error) {
    if (!s->error_operation) {
        s->error_operation = operation;
        s->observer_error = error ? error : ERROR_GEN_FAILURE;
    }
}
static void bp_fail(State *s, const char *operation, DWORD error) {
    if (!s->bp.operation) {
        s->bp.operation = operation;
        s->bp.error = error ? error : ERROR_GEN_FAILURE;
    }
    fail(s, operation, error);
}
static void close_owned(HANDLE *h) {
    if (*h && *h != INVALID_HANDLE_VALUE) CloseHandle(*h);
    *h = NULL;
}
static BOOL exact_read(HANDLE process, uint64_t address, void *buffer,
                       SIZE_T bytes, DWORD *error) {
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, (LPCVOID)(uintptr_t)address,
                           buffer, bytes, &got)) {
        *error = GetLastError();
        return FALSE;
    }
    if (got != bytes) { *error = ERROR_PARTIAL_COPY; return FALSE; }
    return TRUE;
}

/* Read the actual mapped PE, never substitute an on-disk preferred base. */
static BOOL read_image(HANDLE process, uint64_t base, Image *image, BOOL require_entry) {
    IMAGE_DOS_HEADER dos;
    IMAGE_FILE_HEADER file;
    IMAGE_OPTIONAL_HEADER64 opt;
    IMAGE_SECTION_HEADER sections[96];
    DWORD signature = 0, error = 0;
    uint64_t nt, section_address, header_end;
    unsigned matches = 0, i;
    memset(image, 0, sizeof(*image));
    image->base = base;
    if (!base || !exact_read(process, base, &dos, sizeof(dos), &error)) goto bad;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 64 ||
        dos.e_lfanew > 1048576) { error = ERROR_BAD_EXE_FORMAT; goto bad; }
    nt = base + (DWORD)dos.e_lfanew;
    if (nt < base || !exact_read(process, nt, &signature, sizeof(signature), &error)
        || !exact_read(process, nt + 4, &file, sizeof(file), &error)) goto bad;
    image->machine = file.Machine;
    if (signature != IMAGE_NT_SIGNATURE || file.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        !file.NumberOfSections || file.NumberOfSections > 96 ||
        file.SizeOfOptionalHeader < sizeof(opt) || file.SizeOfOptionalHeader > 4096) {
        error = ERROR_BAD_EXE_FORMAT; goto bad;
    }
    if (!exact_read(process, nt + 4 + sizeof(file), &opt, sizeof(opt), &error)) goto bad;
    image->optional_magic = opt.Magic;
    image->entry_rva = opt.AddressOfEntryPoint;
    image->image_size = opt.SizeOfImage;
    if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        image->export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        image->export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if (opt.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || !opt.SizeOfImage ||
        (require_entry && !opt.AddressOfEntryPoint) || opt.AddressOfEntryPoint >= opt.SizeOfImage ||
        opt.SizeOfHeaders > opt.SizeOfImage || opt.SizeOfHeaders < sizeof(dos)) {
        error = ERROR_BAD_EXE_FORMAT; goto bad;
    }
    section_address = nt + 4 + sizeof(file) + file.SizeOfOptionalHeader;
    header_end = section_address - base + (uint64_t)file.NumberOfSections * sizeof(sections[0]);
    if (header_end > opt.SizeOfHeaders || base + opt.SizeOfImage < base) {
        error = ERROR_BAD_EXE_FORMAT; goto bad;
    }
    if (!exact_read(process, section_address, sections,
                    (SIZE_T)file.NumberOfSections * sizeof(sections[0]), &error)) goto bad;
    for (i = 0; i < file.NumberOfSections; ++i) {
        uint64_t size = sections[i].Misc.VirtualSize;
        uint64_t end;
        if (size < sections[i].SizeOfRawData) size = sections[i].SizeOfRawData;
        end = (uint64_t)sections[i].VirtualAddress + size;
        if (end > opt.SizeOfImage) { error = ERROR_BAD_EXE_FORMAT; goto bad; }
        if (opt.AddressOfEntryPoint >= sections[i].VirtualAddress &&
            opt.AddressOfEntryPoint < end &&
            (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) ++matches;
    }
    if (require_entry && matches != 1) { error = ERROR_BAD_EXE_FORMAT; goto bad; }
    image->entry = base + opt.AddressOfEntryPoint;
    image->available = TRUE;
    return TRUE;
bad:
    image->error = error ? error : ERROR_BAD_EXE_FORMAT;
    return FALSE;
}

static BOOL command_put(wchar_t *command, size_t *used, wchar_t ch) {
    if (*used + 1 >= COMMAND_LIMIT) return FALSE;
    command[(*used)++] = ch;
    command[*used] = 0;
    return TRUE;
}
/* Windows CRT quoting, including quotes and trailing backslashes. */
static wchar_t *make_command(int argc, wchar_t **argv, int first) {
    wchar_t *result = (wchar_t *)calloc(COMMAND_LIMIT, sizeof(wchar_t));
    size_t used = 0;
    int i;
    if (!result) return NULL;
    for (i = first; i < argc; ++i) {
        const wchar_t *p = argv[i];
        if (i != first && !command_put(result, &used, L' ')) goto too_long;
        if (!command_put(result, &used, L'"')) goto too_long;
        while (*p) {
            size_t slashes = 0, n;
            while (*p == L'\\') { ++slashes; ++p; }
            n = slashes;
            if (*p == L'"' || !*p) n *= 2;
            while (n--) if (!command_put(result, &used, L'\\')) goto too_long;
            if (!*p) break;
            if (*p == L'"' && !command_put(result, &used, L'\\')) goto too_long;
            if (!command_put(result, &used, *p++)) goto too_long;
        }
        if (!command_put(result, &used, L'"')) goto too_long;
    }
    return result;
too_long:
    free(result);
    return NULL;
}

/* Only names in this sorted whitelist cross the process boundary. */
static wchar_t *make_environment(DWORD *error) {
    static const wchar_t *names[] = {
        L"LANG", L"LC_ALL", L"PATH", L"SYSTEMROOT", L"TEMP", L"TMP", L"WINDIR"
    };
    wchar_t *block = (wchar_t *)calloc(ENV_LIMIT, sizeof(wchar_t));
    size_t used = 0, i;
    if (!block) { *error = ERROR_NOT_ENOUGH_MEMORY; return NULL; }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        DWORD needed, got;
        size_t name_len = wcslen(names[i]);
        SetLastError(ERROR_SUCCESS);
        needed = GetEnvironmentVariableW(names[i], NULL, 0);
        if (!needed) {
            DWORD e = GetLastError();
            if (e != ERROR_SUCCESS && e != ERROR_ENVVAR_NOT_FOUND) { *error = e; goto bad; }
            continue;
        }
        if (needed > 32768 || used + name_len + 1 + needed + 1 >= ENV_LIMIT) {
            *error = ERROR_BUFFER_OVERFLOW; goto bad;
        }
        memcpy(block + used, names[i], name_len * sizeof(wchar_t));
        used += name_len;
        block[used++] = L'=';
        got = GetEnvironmentVariableW(names[i], block + used, needed);
        if (!got || got >= needed) { *error = GetLastError(); goto bad; }
        used += got + 1;
    }
    block[used] = 0; /* calloc also ensures an empty block has two NULs. */
    return block;
bad:
    free(block);
    return NULL;
}

static void module_basename(HANDLE file, char *name, size_t capacity) {
    wchar_t path[2048], *base;
    DWORD n;
    int converted;
    name[0] = 0;
    if (!file || file == INVALID_HANDLE_VALUE) return;
    n = GetFinalPathNameByHandleW(file, path, (DWORD)(sizeof(path) / sizeof(path[0])), 0);
    if (!n || n >= sizeof(path) / sizeof(path[0])) return;
    base = path;
    for (wchar_t *p = path; *p; ++p) if (*p == L'\\' || *p == L'/') base = p + 1;
    converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, base, -1,
                                     name, (int)capacity, NULL, NULL);
    if (!converted) name[0] = 0;
}

/* First DLL events may have no file handle/name. Read only the bounded mapped
 * export-directory Name, not an arbitrary target string or whole module. */
static BOOL mapped_export_name(HANDLE process, const Image *module, char name[160]) {
    IMAGE_EXPORT_DIRECTORY exports;
    char value[160] = {0};
    DWORD error = 0;
    SIZE_T count, i;
    if (!module->available || !module->export_rva ||
        module->export_size < sizeof(exports) ||
        (uint64_t)module->export_rva + module->export_size > module->image_size)
        return FALSE;
    if (!exact_read(process, module->base + module->export_rva, &exports, sizeof(exports), &error) ||
        !exports.Name || exports.Name >= module->image_size) return FALSE;
    count = module->image_size - exports.Name;
    if (count > sizeof(value)) count = sizeof(value);
    if (!exact_read(process, module->base + exports.Name, value, count, &error) ||
        !memchr(value, 0, count)) return FALSE;
    for (i = 0; value[i]; ++i)
        if ((unsigned char)value[i] < 32 || (unsigned char)value[i] > 126) return FALSE;
    memcpy(name, value, sizeof(value));
    return TRUE;
}

static Event *remember_event(State *s, const DEBUG_EVENT *event) {
    Event *e = NULL;
    ++s->events_total;
    if (s->events_total <= EVENT_LIMIT) {
        e = &s->events[s->events_total - 1];
        e->seq = s->events_total;
        e->elapsed_ms = tick() - s->start_tick;
        e->kind = event->dwDebugEventCode;
        e->pid = event->dwProcessId;
        e->tid = event->dwThreadId;
    } else ++s->dropped;
    return e;
}

static void terminate_owned(State *s, const char *reason) {
    if (!s->created || s->exit_seen || s->termination_attempted) return;
    s->termination_attempted = TRUE;
    s->termination_reason = reason;
    s->termination_tick = tick();
    s->termination_succeeded = TerminateProcess(s->process, CANCEL_EXIT);
    if (!s->termination_succeeded) {
        s->termination_error = GetLastError();
        fail(s, "TerminateProcess", s->termination_error);
    }
}

static void drain_stream(State *s, Stream *stream, const char *operation) {
    BYTE buffer[4096];
    unsigned pass;
    if (!stream->read || stream->eof) return;
    for (pass = 0; pass < 16; ++pass) {
        DWORD available = 0, got = 0, keep, wrote = 0;
        if (!PeekNamedPipe(stream->read, NULL, 0, NULL, &available, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) stream->eof = TRUE;
            else { stream->error = error; fail(s, operation, error); }
            return;
        }
        if (!available) return;
        if (available > sizeof(buffer)) available = sizeof(buffer);
        if (!ReadFile(stream->read, buffer, available, &got, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) stream->eof = TRUE;
            else { stream->error = error; fail(s, operation, error); }
            return;
        }
        if (!got) return;
        stream->seen += got;
        keep = got;
        if ((uint64_t)keep > OUTPUT_LIMIT - stream->retained)
            keep = (DWORD)(OUTPUT_LIMIT - stream->retained);
        if (keep && (!WriteFile(stream->file, buffer, keep, &wrote, NULL) || wrote != keep)) {
            stream->error = GetLastError();
            if (!stream->error) stream->error = ERROR_WRITE_FAULT;
            fail(s, operation, stream->error);
            return;
        }
        stream->retained += wrote;
        if (keep < got) {
            stream->overflow = TRUE;
            s->output_overflow = TRUE;
        }
    }
}

static void drain_both(State *s) {
    drain_stream(s, &s->out_stream, "stdout_capture");
    drain_stream(s, &s->err_stream, "stderr_capture");
}

/* Write exactly one owned entry byte, read it back, then restore page access. */
static BOOL write_entry(State *s, BYTE value, BOOL installing) {
    DWORD old = 0, ignored = 0, first_error = 0;
    SIZE_T wrote = 0;
    BYTE check = 0;
    BOOL changed = FALSE, verified = FALSE, protected_again;
    LPCVOID address = (LPCVOID)(uintptr_t)s->image.entry;
    if (!VirtualProtectEx(s->process, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &old)) {
        bp_fail(s, installing ? "install_VirtualProtectEx" : "restore_VirtualProtectEx", GetLastError());
        return FALSE;
    }
    if (installing) s->bp.original_protection = old;
    if (WriteProcessMemory(s->process, (LPVOID)address, &value, 1, &wrote) && wrote == 1) {
        changed = TRUE;
        s->bp.armed = installing;
        if (!installing) s->bp.byte_restored = TRUE;
        if (!FlushInstructionCache(s->process, address, 1)) first_error = GetLastError();
        if (exact_read(s->process, s->image.entry, &check, 1, &first_error) && check == value)
            verified = TRUE;
        else if (!first_error) first_error = ERROR_INVALID_DATA;
    } else first_error = GetLastError() ? GetLastError() : ERROR_PARTIAL_COPY;
    protected_again = VirtualProtectEx(s->process, (LPVOID)address, 1,
                                       installing ? old : s->bp.original_protection, &ignored);
    if (!protected_again && !first_error) first_error = GetLastError();
    if (installing) {
        s->bp.install_protection_restored = protected_again;
        s->bp.install_readback = verified;
    } else {
        s->bp.protection_restored = protected_again;
        s->bp.byte_restore_verified = verified;
    }
    if (!changed || !verified || !protected_again || first_error) {
        bp_fail(s, installing ? "install_entry_byte" : "restore_entry_byte", first_error);
        return FALSE;
    }
    return TRUE;
}

static void install_breakpoint(State *s) {
    DWORD error = 0;
    s->bp.install_attempted = TRUE;
    if (!exact_read(s->process, s->image.entry, &s->bp.original, 1, &error)) {
        bp_fail(s, "read_original_entry_byte", error); return;
    }
    s->bp.original_known = TRUE;
    if (s->bp.original == 0xcc) {
        bp_fail(s, "entry_already_INT3", ERROR_NOT_SUPPORTED); return;
    }
    s->bp.installed = write_entry(s, 0xcc, TRUE);
    if (!s->bp.installed && s->bp.armed) (void)write_entry(s, s->bp.original, FALSE);
}

static BOOL restore_at_breakpoint(State *s, DWORD tid) {
    CONTEXT context, verify;
    HANDLE thread = s->initial_thread;
    BOOL temporary = FALSE;
    s->bp.hit = TRUE;
    s->bp.tid = tid;
    if (tid != s->initial_tid) {
        thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        temporary = TRUE;
    }
    if (!thread) { bp_fail(s, "OpenThread_for_owned_event", GetLastError()); return FALSE; }
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) {
        bp_fail(s, "GetThreadContext", GetLastError()); goto bad;
    }
    s->bp.context_read = TRUE;
    s->bp.rip_before = context.Rip;
    s->bp.rsp = context.Rsp;
    s->bp.eflags = context.EFlags;
    if (context.Rip != s->image.entry + 1) {
        bp_fail(s, "unexpected_INT3_RIP", ERROR_NOT_SUPPORTED); goto bad;
    }
    if (!write_entry(s, s->bp.original, FALSE)) goto bad;
    context.Rip = s->image.entry;
    if (!SetThreadContext(thread, &context)) {
        bp_fail(s, "SetThreadContext", GetLastError()); goto bad;
    }
    memset(&verify, 0, sizeof(verify));
    verify.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &verify)) {
        bp_fail(s, "verify_GetThreadContext", GetLastError()); goto bad;
    }
    s->bp.rip_after = verify.Rip;
    s->bp.context_rewound = verify.Rip == s->image.entry;
    if (!s->bp.context_rewound) { bp_fail(s, "verify_entry_RIP", ERROR_INVALID_DATA); goto bad; }
    if (temporary) CloseHandle(thread);
    return TRUE;
bad:
    if (s->bp.armed && s->bp.original_known) (void)write_entry(s, s->bp.original, FALSE);
    if (temporary) CloseHandle(thread);
    return FALSE;
}

static void observe_events(State *s) {
    while (!s->exit_seen) {
        DEBUG_EVENT de;
        Event *e;
        DWORD continuation = DBG_CONTINUE;
        BOOL entry_continuation = FALSE;
        drain_both(s);
        if (!s->termination_attempted && tick() - s->start_tick >= s->timeout_ms) {
            s->timed_out = TRUE;
            terminate_owned(s, "timeout");
        }
        if (s->output_overflow) terminate_owned(s, "output_overflow");
        if (s->error_operation) terminate_owned(s, "observer_error");
        if (s->termination_attempted && tick() - s->termination_tick >= CLEANUP_MS) {
            fail(s, "debug_exit_cleanup_deadline", ERROR_TIMEOUT); break;
        }
        memset(&de, 0, sizeof(de));
        if (!WaitForDebugEvent(&de, 10)) {
            DWORD error = GetLastError();
            if (error != ERROR_SEM_TIMEOUT && error != ERROR_TIMEOUT)
                fail(s, "WaitForDebugEvent", error);
            continue;
        }
        e = remember_event(s, &de);
        if (de.dwProcessId != s->pid) {
            fail(s, "unexpected_debug_process", ERROR_INVALID_DATA);
        } else switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            HANDLE process_copy = NULL, thread_copy = NULL;
            s->create_event_seen = TRUE;
            s->image.base = (uint64_t)(uintptr_t)de.u.CreateProcessInfo.lpBaseOfImage;
            if (e) e->base = (uint64_t)(uintptr_t)de.u.CreateProcessInfo.lpBaseOfImage;
            if (!DuplicateHandle(GetCurrentProcess(), de.u.CreateProcessInfo.hProcess,
                                  GetCurrentProcess(), &process_copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                fail(s, "duplicate_debug_process_handle", GetLastError());
            if (!DuplicateHandle(GetCurrentProcess(), de.u.CreateProcessInfo.hThread,
                                  GetCurrentProcess(), &thread_copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                fail(s, "duplicate_debug_thread_handle", GetLastError());
            if (process_copy) { close_owned(&s->process); s->process = process_copy; }
            if (thread_copy) { close_owned(&s->initial_thread); s->initial_thread = thread_copy; }
            if (!s->termination_attempted &&
                !read_image(s->process, (uint64_t)(uintptr_t)de.u.CreateProcessInfo.lpBaseOfImage, &s->image, TRUE))
                fail(s, "read_mapped_PE32plus_x64", s->image.error);
            if (de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile);
            if (!strcmp(s->mode, "abort")) {
                s->abort_before_first_continue = s->continues == 0;
                terminate_owned(s, "operator_abort");
                s->cancelled = s->termination_succeeded && s->abort_before_first_continue;
            } else if (s->bp.requested && !s->termination_attempted && !s->error_operation) install_breakpoint(s);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            char name[160] = {0};
            Image module;
            BOOL module_read = FALSE;
            ++s->dll_events;
            module_basename(de.u.LoadDll.hFile, name, sizeof(name));
            memset(&module, 0, sizeof(module));
            /* Queued DLL events can arrive after TerminateProcess succeeds.
             * Retain/drain them, but do not require memory in the dying target.
             * Existing sensor errors remain recorded by fail(). */
            if (!s->termination_attempted && (!name[0] || !_stricmp(name, "ntdll.dll"))) {
                module_read = read_image(s->process, (uint64_t)(uintptr_t)de.u.LoadDll.lpBaseOfDll,
                                         &module, FALSE);
                if (!name[0] && module_read) (void)mapped_export_name(s->process, &module, name);
            }
            if (e) {
                e->base = (uint64_t)(uintptr_t)de.u.LoadDll.lpBaseOfDll;
                memcpy(e->name, name, sizeof(name));
            }
            if (!s->termination_attempted && !_stricmp(name, "ntdll.dll")) {
                if (module_read) {
                    s->ntdll_base = module.base;
                    s->ntdll_size = module.image_size;
                } else fail(s, "read_bootstrap_ntdll_image", module.error);
            }
            if (de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT:
            if (e) e->base = (uint64_t)(uintptr_t)de.u.UnloadDll.lpBaseOfDll;
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (e) e->address = (uint64_t)(uintptr_t)de.u.CreateThread.lpStartAddress;
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            if (e) e->code = de.u.ExitThread.dwExitCode;
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            if (e) e->code = de.u.DebugString.nDebugStringLength;
            break;
        case RIP_EVENT:
            if (e) { e->code = de.u.RipInfo.dwError; e->first_chance = de.u.RipInfo.dwType; }
            break;
        case EXCEPTION_DEBUG_EVENT: {
            uint64_t address = (uint64_t)(uintptr_t)de.u.Exception.ExceptionRecord.ExceptionAddress;
            DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
            ++s->exception_events;
            continuation = DBG_EXCEPTION_NOT_HANDLED;
            if (e) { e->address = address; e->code = code; e->first_chance = de.u.Exception.dwFirstChance; }
            if (!s->termination_attempted && code == EXCEPTION_BREAKPOINT && de.u.Exception.dwFirstChance &&
                s->bp.installed && s->bp.armed && address == s->image.entry && !s->error_operation) {
                if (restore_at_breakpoint(s, de.dwThreadId)) {
                    continuation = DBG_CONTINUE;
                    entry_continuation = TRUE;
                }
            } else if (!s->termination_attempted && code == EXCEPTION_BREAKPOINT && de.u.Exception.dwFirstChance &&
                       !s->bootstrap_breakpoints && !s->bp.hit &&
                       de.dwThreadId == s->initial_tid && s->ntdll_size &&
                       address >= s->ntdll_base && address - s->ntdll_base < s->ntdll_size &&
                       !(address >= s->image.base && address - s->image.base < s->image.image_size)) {
                ++s->bootstrap_breakpoints;
                continuation = DBG_CONTINUE;
            } else if (!s->termination_attempted && code == EXCEPTION_BREAKPOINT && de.u.Exception.dwFirstChance &&
                       !s->bootstrap_breakpoints && !s->bp.hit &&
                       de.dwThreadId == s->initial_tid && !s->ntdll_size &&
                       !(address >= s->image.base && address - s->image.base < s->image.image_size)) {
                /* Do not misreport a missing observer identity as a target crash. */
                fail(s, "bootstrap_module_identity_unavailable", ERROR_NOT_SUPPORTED);
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            s->exit_seen = TRUE;
            s->exit_available = TRUE;
            s->exit_code = de.u.ExitProcess.dwExitCode;
            if (e) e->code = s->exit_code;
            break;
        default:
            break;
        }
        if (s->error_operation) terminate_owned(s, "observer_error");
        if (e) e->continuation = continuation;
        if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continuation)) {
            DWORD error = GetLastError();
            if (e) e->continue_error = error;
            fail(s, "ContinueDebugEvent", error);
            terminate_owned(s, "observer_error");
            /* One bounded retry releases the current event during termination. */
            if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continuation)) break;
            ++s->continues;
            if (e) e->continued = TRUE;
            if (entry_continuation) s->bp.continued = TRUE;
        } else {
            ++s->continues;
            if (e) e->continued = TRUE;
            if (entry_continuation) s->bp.continued = TRUE;
        }
    }
    if (s->bp.requested && !s->bp.hit && !s->error_operation && !s->timed_out && !s->output_overflow)
        bp_fail(s, "entry_breakpoint_not_reached", ERROR_NOT_FOUND);
}

static void finish_process(State *s) {
    uint64_t deadline;
    DWORD wait;
    if (!s->created) return;
    wait = WaitForSingleObject(s->process, 1000);
    s->signaled = wait == WAIT_OBJECT_0;
    if (!s->signaled) fail(s, "owned_process_not_signaled", wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
    deadline = tick() + 500;
    do {
        drain_both(s);
        if (s->out_stream.eof && s->err_stream.eof) break;
        Sleep(5);
    } while (tick() < deadline);
    s->times_attempted = TRUE;
    if (s->signaled) {
        s->times_available = GetProcessTimes(s->process, &s->creation_time, &s->exit_time,
                                             &s->kernel_time, &s->user_time);
        if (!s->times_available) s->times_error = GetLastError();
    } else s->times_error = ERROR_IO_INCOMPLETE;
    s->io_attempted = TRUE;
    s->io_available = GetProcessIoCounters(s->process, &s->io);
    if (!s->io_available) s->io_error = GetLastError();
    s->cleanup_complete = s->exit_seen && s->signaled && s->out_stream.eof && s->err_stream.eof;
    if (!s->cleanup_complete) fail(s, "incomplete_owned_process_cleanup", ERROR_IO_INCOMPLETE);
}

static const char *event_name(DWORD kind) {
    switch (kind) {
        case CREATE_PROCESS_DEBUG_EVENT: return "create_process";
        case EXIT_PROCESS_DEBUG_EVENT: return "exit_process";
        case CREATE_THREAD_DEBUG_EVENT: return "create_thread";
        case EXIT_THREAD_DEBUG_EVENT: return "exit_thread";
        case LOAD_DLL_DEBUG_EVENT: return "load_dll";
        case UNLOAD_DLL_DEBUG_EVENT: return "unload_dll";
        case EXCEPTION_DEBUG_EVENT: return "exception";
        case OUTPUT_DEBUG_STRING_EVENT: return "debug_string_metadata";
        case RIP_EVENT: return "rip_event";
        default: return "unknown";
    }
}
static void json_string(FILE *file, const char *value) {
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    fputc('"', file);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', file); fputc(*p, file); }
        else if (*p < 32) fprintf(file, "\\u%04x", (unsigned)*p);
        else fputc(*p, file);
    }
    fputc('"', file);
}
static void stream_json(FILE *file, const Stream *stream) {
    fprintf(file, "{\"bytes_seen\":%llu,\"bytes_retained\":%llu,\"overflow\":%s,\"eof\":%s,\"error\":%lu}",
            (unsigned long long)stream->seen, (unsigned long long)stream->retained,
            jb(stream->overflow), jb(stream->eof), (unsigned long)stream->error);
}

/* Observe this process's actual wmain argv. This is not a claim about how the
 * child CRT subsequently parses the constructed command line. Hex preserves
 * every UTF-16 code unit without a locale/UTF-8 conversion or trailing NUL. */
static void command_json(FILE *file, const State *s) {
    size_t remaining = COMMAND_LIMIT - 1;
    BOOL truncated = FALSE;
    int i;
    fprintf(file, "{\"source\":\"observer_wmain_argv\",\"target_crt_arguments_observed\":false,"
            "\"arguments_count\":%d,\"arguments_utf16le_hex\":[", s->target_argc);
    for (i = 0; i < s->target_argc; ++i) {
        const wchar_t *p = s->target_argv[i];
        if (i) fputc(',', file);
        fputc('"', file);
        while (*p && remaining) {
            uint16_t unit = (uint16_t)*p++;
            fprintf(file, "%02x%02x", (unsigned)(unit & 255u), (unsigned)(unit >> 8));
            --remaining;
        }
        if (*p) truncated = TRUE;
        fputc('"', file);
        if (truncated) break;
    }
    fprintf(file, "],\"arguments_truncated\":%s,\"utf16_code_units_limit\":%u}",
            jb(truncated), COMMAND_LIMIT - 1);
}

static BOOL write_receipt(State *s) {
    FILE *f = _wfopen(s->receipt, L"wb");
    unsigned i, retained = s->events_total > EVENT_LIMIT ? EVENT_LIMIT : (unsigned)s->events_total;
    BOOL ok = !s->error_operation && s->created && s->cleanup_complete;
    if (!f) return FALSE;
    fprintf(f, "{\"schema\":\"cre-win32-observer-v1\",\"observer_ok\":%s,\"mode\":", jb(ok));
    json_string(f, s->mode);
    fprintf(f, ",\"command\":");
    command_json(f, s);
    fprintf(f, ",\"created\":%s,\"pid\":%lu,\"target_exit\":{\"available\":%s,\"code\":%lu},",
            jb(s->created), (unsigned long)s->pid, jb(s->exit_available), (unsigned long)s->exit_code);
    fprintf(f, "\"image\":{\"available\":%s,\"error\":%lu,\"source\":\"CREATE_PROCESS_DEBUG_EVENT_and_ReadProcessMemory\","
            "\"base_hex\":\"0x%llx\",\"entry_rva\":%lu,\"entry_address_hex\":\"0x%llx\","
            "\"image_size\":%lu,\"machine\":%u,\"optional_magic\":%u},",
            jb(s->image.available), (unsigned long)s->image.error,
            (unsigned long long)s->image.base, (unsigned long)s->image.entry_rva,
            (unsigned long long)s->image.entry, (unsigned long)s->image.image_size,
            (unsigned)s->image.machine, (unsigned)s->image.optional_magic);
    fprintf(f, "\"breakpoint\":{\"requested\":%s,\"install_attempted\":%s,\"installed\":%s,\"hit\":%s,"
            "\"original_byte\":%u,\"original_known\":%s,\"install_readback\":%s,"
            "\"context_read\":%s,\"byte_restored\":%s,\"byte_restore_verified\":%s,"
            "\"install_protection_restored\":%s,\"protection_restored\":%s,\"context_rewound\":%s,"
            "\"continued\":%s,\"thread_id\":%lu,\"rip_before_hex\":\"0x%llx\",\"rip_after_hex\":\"0x%llx\","
            "\"rsp_hex\":\"0x%llx\",\"eflags\":%lu,\"error\":%lu,\"operation\":",
            jb(s->bp.requested), jb(s->bp.install_attempted), jb(s->bp.installed), jb(s->bp.hit),
            (unsigned)s->bp.original, jb(s->bp.original_known), jb(s->bp.install_readback),
            jb(s->bp.context_read), jb(s->bp.byte_restored), jb(s->bp.byte_restore_verified),
            jb(s->bp.install_protection_restored), jb(s->bp.protection_restored), jb(s->bp.context_rewound),
            jb(s->bp.continued), (unsigned long)s->bp.tid, (unsigned long long)s->bp.rip_before,
            (unsigned long long)s->bp.rip_after, (unsigned long long)s->bp.rsp,
            (unsigned long)s->bp.eflags, (unsigned long)s->bp.error);
    json_string(f, s->bp.operation);
    fprintf(f, "},\"cancelled\":%s,\"abort_before_first_continue\":%s,\"timed_out\":%s,\"output_overflow\":%s,",
            jb(s->cancelled), jb(s->abort_before_first_continue), jb(s->timed_out), jb(s->output_overflow));
    fprintf(f, "\"termination\":{\"attempted\":%s,\"succeeded\":%s,\"error\":%lu,\"reason\":",
            jb(s->termination_attempted), jb(s->termination_succeeded), (unsigned long)s->termination_error);
    json_string(f, s->termination_reason);
    fprintf(f, "},\"streams\":{\"stdout\":"); stream_json(f, &s->out_stream);
    fprintf(f, ",\"stderr\":"); stream_json(f, &s->err_stream);
    fprintf(f, "},\"metrics\":{\"times\":{\"attempted\":%s,\"available\":%s,\"error\":%lu,"
            "\"creation_100ns\":\"%llu\",\"exit_100ns\":\"%llu\",\"kernel_100ns\":\"%llu\",\"user_100ns\":\"%llu\"},"
            "\"io\":{\"attempted\":%s,\"available\":%s,\"error\":%lu,\"read_operations\":\"%llu\","
            "\"write_operations\":\"%llu\",\"other_operations\":\"%llu\",\"read_bytes\":\"%llu\","
            "\"write_bytes\":\"%llu\",\"other_bytes\":\"%llu\"}},",
            jb(s->times_attempted), jb(s->times_available), (unsigned long)s->times_error,
            (unsigned long long)ft64(s->creation_time), (unsigned long long)ft64(s->exit_time),
            (unsigned long long)ft64(s->kernel_time), (unsigned long long)ft64(s->user_time),
            jb(s->io_attempted), jb(s->io_available), (unsigned long)s->io_error,
            (unsigned long long)s->io.ReadOperationCount, (unsigned long long)s->io.WriteOperationCount,
            (unsigned long long)s->io.OtherOperationCount, (unsigned long long)s->io.ReadTransferCount,
            (unsigned long long)s->io.WriteTransferCount, (unsigned long long)s->io.OtherTransferCount);
    fprintf(f, "\"debug\":{\"create_event_seen\":%s,\"bootstrap_breakpoints\":%lu,\"dll_events\":%lu,"
            "\"exception_events\":%lu,\"successful_continuations\":%llu,\"ntdll_base_hex\":\"0x%llx\",\"ntdll_size\":%llu},",
            jb(s->create_event_seen), (unsigned long)s->bootstrap_breakpoints, (unsigned long)s->dll_events,
            (unsigned long)s->exception_events, (unsigned long long)s->continues,
            (unsigned long long)s->ntdll_base, (unsigned long long)s->ntdll_size);
    fprintf(f, "\"events_total\":%llu,\"events_dropped\":%llu,\"events\":[",
            (unsigned long long)s->events_total, (unsigned long long)s->dropped);
    for (i = 0; i < retained; ++i) {
        const Event *e = &s->events[i];
        if (i) fputc(',', f);
        fprintf(f, "{\"sequence\":%llu,\"elapsed_ms\":%llu,\"type\":",
                (unsigned long long)e->seq, (unsigned long long)e->elapsed_ms);
        json_string(f, event_name(e->kind));
        fprintf(f, ",\"process_id\":%lu,\"thread_id\":%lu,\"address_hex\":\"0x%llx\",\"base_hex\":\"0x%llx\","
                "\"code\":%lu,\"first_chance\":%lu,\"continuation_status\":%lu,\"continued\":%s,\"continue_error\":%lu,\"module_basename\":",
                (unsigned long)e->pid, (unsigned long)e->tid, (unsigned long long)e->address,
                (unsigned long long)e->base, (unsigned long)e->code, (unsigned long)e->first_chance,
                (unsigned long)e->continuation, jb(e->continued), (unsigned long)e->continue_error);
        json_string(f, e->name);
        fputc('}', f);
    }
    fprintf(f, "],\"bounds\":{\"timeout_ms\":%lu,\"stream_bytes_each\":%u,\"retained_events\":%u,\"termination_debug_drain_ms\":%u},"
            "\"child_environment\":{\"policy\":\"whitelist\",\"names\":[\"LANG\",\"LC_ALL\",\"PATH\",\"SYSTEMROOT\",\"TEMP\",\"TMP\",\"WINDIR\"]},"
            "\"cleanup\":{\"exit_event_seen\":%s,\"process_signaled\":%s,\"complete\":%s,\"descendant_retirement\":\"unknown\"},"
            "\"observer_error\":{\"operation\":",
            (unsigned long)s->timeout_ms, OUTPUT_LIMIT, EVENT_LIMIT, CLEANUP_MS,
            jb(s->exit_seen), jb(s->signaled), jb(s->cleanup_complete));
    json_string(f, s->error_operation);
    fprintf(f, ",\"win32\":%lu}}\n", (unsigned long)s->observer_error);
    {
        BOOL written = !ferror(f);
        if (fclose(f) != 0) written = FALSE;
        return written;
    }
}

static BOOL parse_args(State *s, int argc, wchar_t **argv) {
    int i;
    BOOL saw_mode = FALSE, saw_timeout = FALSE;
    s->mode = "run";
    s->timeout_ms = 5000;
    for (i = 1; i < argc; ++i) {
        const wchar_t *option = argv[i];
        if (!wcscmp(option, L"--")) { s->target_index = i + 1; break; }
        if (++i >= argc) return FALSE;
        if (!wcscmp(option, L"--receipt") && !s->receipt) s->receipt = argv[i];
        else if (!wcscmp(option, L"--stdout") && !s->out) s->out = argv[i];
        else if (!wcscmp(option, L"--stderr") && !s->err) s->err = argv[i];
        else if (!wcscmp(option, L"--mode") && !saw_mode) {
            saw_mode = TRUE;
            if (!wcscmp(argv[i], L"run")) s->mode = "run";
            else if (!wcscmp(argv[i], L"breakpoint")) s->mode = "breakpoint";
            else if (!wcscmp(argv[i], L"abort")) s->mode = "abort";
            else return FALSE;
        } else if (!wcscmp(option, L"--timeout-ms") && !saw_timeout) {
            wchar_t *end;
            unsigned long value;
            saw_timeout = TRUE;
            errno = 0;
            value = wcstoul(argv[i], &end, 10);
            if (errno || !*argv[i] || *end || value < 100 || value > 60000) return FALSE;
            s->timeout_ms = (DWORD)value;
        } else return FALSE;
    }
    if (!s->receipt || !s->out || !s->err || !s->target_index || s->target_index >= argc ||
        argc - s->target_index > 128 || !_wcsicmp(s->receipt, s->out) ||
        !_wcsicmp(s->receipt, s->err) || !_wcsicmp(s->out, s->err)) return FALSE;
    s->bp.requested = !strcmp(s->mode, "breakpoint");
    s->target_argc = argc - s->target_index - 1;
    s->target_argv = argv + s->target_index + 1;
    return TRUE;
}

int wmain(int argc, wchar_t **argv) {
    State *s = (State *)calloc(1, sizeof(*s));
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES security;
    HANDLE out_write = NULL, err_write = NULL, null_input = NULL, inherit[3];
    wchar_t *command = NULL, *environment = NULL;
    SIZE_T attribute_bytes = 0;
    BOOL attribute_initialized = FALSE, receipt_written;
    DWORD error = 0;
    int result;
    if (!s) return 2;
    if (!parse_args(s, argc, argv)) {
        fputs("usage: observer.exe --receipt FILE --stdout FILE --stderr FILE --mode run|breakpoint|abort --timeout-ms 5000 -- TARGET ARGS...\n", stderr);
        free(s);
        return 2;
    }
    memset(&startup, 0, sizeof(startup));
    memset(&pi, 0, sizeof(pi));
    memset(&security, 0, sizeof(security));
    startup.StartupInfo.cb = sizeof(startup);
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    s->out_stream.file = CreateFileW(s->out, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (s->out_stream.file == INVALID_HANDLE_VALUE) { fail(s, "open_stdout_file", GetLastError()); goto done; }
    s->err_stream.file = CreateFileW(s->err, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (s->err_stream.file == INVALID_HANDLE_VALUE) { fail(s, "open_stderr_file", GetLastError()); goto done; }
    if (!CreatePipe(&s->out_stream.read, &out_write, &security, 4096) ||
        !SetHandleInformation(s->out_stream.read, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&s->err_stream.read, &err_write, &security, 4096) ||
        !SetHandleInformation(s->err_stream.read, HANDLE_FLAG_INHERIT, 0)) {
        fail(s, "create_capture_pipes", GetLastError()); goto done;
    }
    null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (null_input == INVALID_HANDLE_VALUE) { fail(s, "open_null_stdin", GetLastError()); goto done; }
    command = make_command(argc, argv, s->target_index);
    if (!command) { fail(s, "build_bounded_command_line", ERROR_BUFFER_OVERFLOW); goto done; }
    environment = make_environment(&error);
    if (!environment) { fail(s, "build_whitelist_environment", error); goto done; }
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_bytes);
    if (!attribute_bytes) { fail(s, "size_handle_attribute_list", GetLastError()); goto done; }
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_bytes);
    if (!startup.lpAttributeList) { fail(s, "allocate_handle_attribute_list", ERROR_NOT_ENOUGH_MEMORY); goto done; }
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_bytes)) {
        fail(s, "initialize_handle_attribute_list", GetLastError()); goto done;
    }
    attribute_initialized = TRUE;
    inherit[0] = null_input; inherit[1] = out_write; inherit[2] = err_write;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherit, sizeof(inherit), NULL, NULL)) {
        fail(s, "set_explicit_inherited_handles", GetLastError()); goto done;
    }
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_input;
    startup.StartupInfo.hStdOutput = out_write;
    startup.StartupInfo.hStdError = err_write;
    s->start_tick = tick();
    if (!CreateProcessW(argv[s->target_index], command, NULL, NULL, TRUE,
                         DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT |
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                         environment, NULL, &startup.StartupInfo, &pi)) {
        fail(s, "CreateProcessW", GetLastError()); goto done;
    }
    s->created = TRUE;
    s->pid = pi.dwProcessId;
    s->initial_tid = pi.dwThreadId;
    /* PROCESS_INFORMATION handles are owned separately from debug-event handles. */
    s->process = pi.hProcess; pi.hProcess = NULL;
    s->initial_thread = pi.hThread; pi.hThread = NULL;
    close_owned(&out_write); close_owned(&err_write); close_owned(&null_input);
    if (!DebugSetProcessKillOnExit(TRUE)) fail(s, "DebugSetProcessKillOnExit", GetLastError());
    observe_events(s);
    finish_process(s);
done:
    close_owned(&out_write); close_owned(&err_write); close_owned(&null_input);
    close_owned(&pi.hProcess); close_owned(&pi.hThread);
    close_owned(&s->initial_thread); close_owned(&s->process);
    close_owned(&s->out_stream.read); close_owned(&s->err_stream.read);
    if (s->out_stream.file && s->out_stream.file != INVALID_HANDLE_VALUE && !FlushFileBuffers(s->out_stream.file))
        fail(s, "flush_stdout_file", GetLastError());
    if (s->err_stream.file && s->err_stream.file != INVALID_HANDLE_VALUE && !FlushFileBuffers(s->err_stream.file))
        fail(s, "flush_stderr_file", GetLastError());
    close_owned(&s->out_stream.file); close_owned(&s->err_stream.file);
    if (attribute_initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    free(command); free(environment);
    receipt_written = write_receipt(s);
    result = receipt_written && !s->error_operation && s->created && s->cleanup_complete ? 0 : 1;
    if (!receipt_written) fputs("observer: unable to write complete receipt\n", stderr);
    free(s);
    return result;
}
