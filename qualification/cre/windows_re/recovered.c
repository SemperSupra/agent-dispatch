/*
 * Independently authored, behavior-derived dos2unix paired-mode subset.
 * Reference implementation source and frozen validation fixtures were not read.
 * Discovery lineage and intentional differences: recovered-contract.md.
 * The executable identifies itself as CRE; it does not advertise upstream modes
 * that it does not implement. Python/build infrastructure is not needed at run time.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <wchar.h>

#define PROGRAM "cre-dos2unix"
#define MAX_INPUT_BYTES ((size_t)64 * 1024 * 1024)
#define MAX_OUTPUT_BYTES ((size_t)128 * 1024 * 1024)

typedef struct {
    unsigned char *data;
    size_t size, capacity;
} Bytes;

typedef enum { BYTE_TEXT, UTF16_LE, UTF16_BE } Encoding;
typedef enum { CONVERTED, BINARY_SKIP, INVALID_UTF16, ALLOCATION_FAILED } Conversion;

typedef struct {
    Encoding encoding;
    unsigned binary_symbol;
    uint64_t binary_line;
    size_t invalid_offset;
} ConversionInfo;

static int append_bytes(Bytes *buffer, const unsigned char *data, size_t count, size_t limit) {
    size_t capacity;
    unsigned char *replacement;
    if (buffer->size > limit || count > limit - buffer->size) return 0;
    if (buffer->size + count > buffer->capacity) {
        capacity = buffer->capacity ? buffer->capacity : 4096;
        while (capacity < buffer->size + count) {
            if (capacity > limit / 2) { capacity = limit; break; }
            capacity *= 2;
        }
        replacement = (unsigned char *)realloc(buffer->data, capacity);
        if (!replacement) return 0;
        buffer->data = replacement;
        buffer->capacity = capacity;
    }
    if (count) memcpy(buffer->data + buffer->size, data, count);
    buffer->size += count;
    return 1;
}

static char *display_path(const wchar_t *path) {
    int needed = WideCharToMultiByte(CP_ACP, 0, path, -1, NULL, 0, NULL, NULL);
    char *result;
    if (!needed) return NULL;
    result = (char *)malloc((size_t)needed);
    if (!result) return NULL;
    if (!WideCharToMultiByte(CP_ACP, 0, path, -1, result, needed, NULL, NULL)) {
        free(result);
        return NULL;
    }
    return result;
}

static void pair_problem(const char *input, const char *output) {
    fprintf(stderr, PROGRAM ": problems converting file %s to file %s\n", input, output);
}

static void windows_error(DWORD error) {
    wchar_t *wide = NULL;
    char *message = NULL;
    DWORD count = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0,
                                 (wchar_t *)&wide, 0, NULL);
    if (count && wide) message = display_path(wide);
    if (message) {
        /* The OS message already has CRLF. The observed C text stream expands
           its LF again and the following newline produces the observed blank line. */
        fprintf(stderr, PROGRAM ": %s\n", message);
    } else {
        fprintf(stderr, PROGRAM ": Windows error %lu\n", (unsigned long)error);
    }
    free(message);
    if (wide) LocalFree(wide);
}

static void help(void) {
    fputs(
        "CRE dos2unix reconstruction: observed paired-mode subset\n"
        "Usage: cre-dos2unix -n INPUT OUTPUT [INPUT OUTPUT ...]\n"
        "  -n, --newfile  Convert regular files to named outputs, in argument order.\n"
        "  --            Treat following arguments as filenames.\n"
        "  -h, --help    Show this subset's help.\n"
        "  -V, --version Show the CRE implementation identity.\n"
        "CRLF becomes LF; lone CR and existing LF are preserved. A complete leading\n"
        "UTF-8 BOM is removed. Valid BOM-marked UTF-16LE/BE is converted to UTF-8.\n"
        "Binary files are skipped; skipped inputs preserve an existing output.\n"
        "A final unmatched input is ignored for compatibility with the observation.\n"
        "Each input is limited to 64 MiB. Other upstream modes are unsupported.\n"
        "See recovered-contract.md for measured scope and intentional differences.\n",
        stdout);
}

static void version(void) {
    fputs("cre-dos2unix 0.1\n"
          "Independent CRE reconstruction of a measured dos2unix 7.5.7 subset.\n"
          "Windows x64; paired regular-file conversion; see --help for limits.\n",
          stdout);
}

static int read_input(const wchar_t *path, const char *shown, const char *output, Bytes *input) {
    struct _stat64 status;
    FILE *file;
    unsigned char chunk[65536];
    size_t count;
    int saved_errno;
    if (_wstat64(path, &status) != 0) {
        saved_errno = errno;
        fprintf(stderr, PROGRAM ": %s: %s\n", shown, strerror(saved_errno));
        fprintf(stderr, PROGRAM ": Skipping %s, not a regular file.\n", shown);
        return 2;
    }
    if ((status.st_mode & _S_IFMT) != _S_IFREG) {
        fprintf(stderr, PROGRAM ": Skipping %s, not a regular file.\n", shown);
        return 2;
    }
    if (status.st_size < 0 || (uint64_t)status.st_size > MAX_INPUT_BYTES) {
        fprintf(stderr, PROGRAM ": input exceeds the documented 64 MiB limit: %s\n", shown);
        return 1;
    }
    file = _wfopen(path, L"rb");
    if (!file) {
        saved_errno = errno;
        fprintf(stderr, PROGRAM ": %s: %s\n", shown, strerror(saved_errno));
        pair_problem(shown, output);
        return 1;
    }
    while ((count = fread(chunk, 1, sizeof(chunk), file)) != 0) {
        if (!append_bytes(input, chunk, count, MAX_INPUT_BYTES)) {
            fputs(PROGRAM ": input allocation or documented size limit exceeded\n", stderr);
            fclose(file);
            return 1;
        }
    }
    if (ferror(file)) {
        saved_errno = errno ? errno : EIO;
        fclose(file);
        fprintf(stderr, PROGRAM ": %s: %s\n", shown, strerror(saved_errno));
        pair_problem(shown, output);
        return 1;
    }
    if (fclose(file) != 0) {
        saved_errno = errno ? errno : EIO;
        fprintf(stderr, PROGRAM ": %s: %s\n", shown, strerror(saved_errno));
        pair_problem(shown, output);
        return 1;
    }
    return 0;
}

static uint32_t unit16(const unsigned char *data, Encoding encoding) {
    if (encoding == UTF16_LE) return (uint32_t)data[0] | ((uint32_t)data[1] << 8);
    return ((uint32_t)data[0] << 8) | (uint32_t)data[1];
}

/* Returns one decoded scalar, EOF, or a malformed UTF-16 refusal. */
static int next_character(const Bytes *input, Encoding encoding, size_t *offset, uint32_t *value) {
    uint32_t first, second;
    if (*offset == input->size) return 0;
    if (encoding == BYTE_TEXT) {
        *value = input->data[(*offset)++];
        return 1;
    }
    if (input->size - *offset < 2) return -1;
    first = unit16(input->data + *offset, encoding);
    if (first >= 0xD800 && first <= 0xDBFF) {
        if (input->size - *offset < 4) return -1;
        second = unit16(input->data + *offset + 2, encoding);
        if (second < 0xDC00 || second > 0xDFFF) return -1;
        *value = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
        *offset += 4;
        return 1;
    }
    if (first >= 0xDC00 && first <= 0xDFFF) return -1;
    *value = first;
    *offset += 2;
    return 1;
}

static int append_character(Bytes *output, Encoding encoding, uint32_t value) {
    unsigned char encoded[4];
    size_t count;
    if (encoding == BYTE_TEXT || value <= 0x7F) {
        encoded[0] = (unsigned char)value;
        count = 1;
    } else if (value <= 0x7FF) {
        encoded[0] = (unsigned char)(0xC0 | (value >> 6));
        encoded[1] = (unsigned char)(0x80 | (value & 0x3F));
        count = 2;
    } else if (value <= 0xFFFF) {
        encoded[0] = (unsigned char)(0xE0 | (value >> 12));
        encoded[1] = (unsigned char)(0x80 | ((value >> 6) & 0x3F));
        encoded[2] = (unsigned char)(0x80 | (value & 0x3F));
        count = 3;
    } else {
        encoded[0] = (unsigned char)(0xF0 | (value >> 18));
        encoded[1] = (unsigned char)(0x80 | ((value >> 12) & 0x3F));
        encoded[2] = (unsigned char)(0x80 | ((value >> 6) & 0x3F));
        encoded[3] = (unsigned char)(0x80 | (value & 0x3F));
        count = 4;
    }
    return append_bytes(output, encoded, count, MAX_OUTPUT_BYTES);
}

static int binary_character(uint32_t value) {
    /* Additional isolated discovery established that formfeed is text, while
       BEL, BS, SUB and ESC are binary; DEL and high bytes are preserved. */
    return value < 0x20 && value != 0x09 && value != 0x0A && value != 0x0C && value != 0x0D;
}

static Conversion convert(const Bytes *input, Bytes *output, ConversionInfo *info) {
    size_t offset = 0;
    uint64_t line = 1;
    int pending_cr = 0, next;
    uint32_t value = 0;
    memset(info, 0, sizeof(*info));
    info->encoding = BYTE_TEXT;
    if (input->size >= 2 && input->data[0] == 0xFF && input->data[1] == 0xFE) {
        info->encoding = UTF16_LE;
        offset = 2;
    } else if (input->size >= 2 && input->data[0] == 0xFE && input->data[1] == 0xFF) {
        info->encoding = UTF16_BE;
        offset = 2;
    } else if (input->size >= 3 && input->data[0] == 0xEF &&
               input->data[1] == 0xBB && input->data[2] == 0xBF) {
        offset = 3;
    }
    while ((next = next_character(input, info->encoding, &offset, &value)) != 0) {
        if (next < 0) { info->invalid_offset = offset; return INVALID_UTF16; }
        if (binary_character(value)) {
            info->binary_symbol = (unsigned)value;
            info->binary_line = line;
            return BINARY_SKIP;
        }
        if (pending_cr) {
            if (value != 0x0A && !append_character(output, info->encoding, 0x0D))
                return ALLOCATION_FAILED;
            pending_cr = 0;
        }
        if (value == 0x0D) pending_cr = 1;
        else {
            if (!append_character(output, info->encoding, value)) return ALLOCATION_FAILED;
            if (value == 0x0A) ++line;
        }
    }
    if (pending_cr && !append_character(output, info->encoding, 0x0D)) return ALLOCATION_FAILED;
    return CONVERTED;
}

static wchar_t *output_directory(const wchar_t *output) {
    const wchar_t *last = NULL, *scan;
    size_t count;
    wchar_t *result;
    for (scan = output; *scan; ++scan) if (*scan == L'\\' || *scan == L'/') last = scan;
    if (!last) {
        result = (wchar_t *)malloc(2 * sizeof(wchar_t));
        if (result) { result[0] = L'.'; result[1] = 0; }
        return result;
    }
    count = (size_t)(last - output) + 1;
    result = (wchar_t *)malloc((count + 1) * sizeof(wchar_t));
    if (!result) return NULL;
    memcpy(result, output, count * sizeof(wchar_t));
    result[count] = 0;
    return result;
}

static int commit_output(const wchar_t *path, const Bytes *output,
                         const char *shown_input, const char *shown_output) {
    wchar_t temporary[MAX_PATH + 1];
    wchar_t *directory = output_directory(path);
    FILE *file;
    int write_failed = 0, saved_errno = 0;
    DWORD error;
    if (!directory) {
        fputs(PROGRAM ": unable to allocate output directory\n", stderr);
        return 1;
    }
    if (wcslen(directory) > MAX_PATH - 14) {
        free(directory);
        windows_error(ERROR_FILENAME_EXCED_RANGE);
        pair_problem(shown_input, shown_output);
        return 1;
    }
    if (!GetTempFileNameW(directory, L"cre", 0, temporary)) {
        error = GetLastError();
        free(directory);
        windows_error(error);
        pair_problem(shown_input, shown_output);
        return 1;
    }
    free(directory);
    file = _wfopen(temporary, L"wb");
    if (!file) {
        saved_errno = errno;
        DeleteFileW(temporary);
        fprintf(stderr, PROGRAM ": %s\n", strerror(saved_errno));
        pair_problem(shown_input, shown_output);
        return 1;
    }
    if (output->size && fwrite(output->data, 1, output->size, file) != output->size) {
        write_failed = 1;
        saved_errno = errno ? errno : EIO;
    }
    if (fclose(file) != 0 && !write_failed) {
        write_failed = 1;
        saved_errno = errno ? errno : EIO;
    }
    if (write_failed) {
        DeleteFileW(temporary);
        fprintf(stderr, PROGRAM ": %s\n", strerror(saved_errno));
        pair_problem(shown_input, shown_output);
        return 1;
    }
    if (!MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = GetLastError();
        DeleteFileW(temporary);
        windows_error(error);
        pair_problem(shown_input, shown_output);
        return 1;
    }
    return 0;
}

static int convert_pair(const wchar_t *input_path, const wchar_t *output_path) {
    Bytes input = {0}, output = {0};
    ConversionInfo info;
    Conversion conversion;
    int result;
    char *shown_input = display_path(input_path);
    char *shown_output = display_path(output_path);
    if (!shown_input || !shown_output) {
        fputs(PROGRAM ": unable to encode diagnostic filenames\n", stderr);
        result = 1;
        goto done;
    }
    result = read_input(input_path, shown_input, shown_output, &input);
    if (result) goto done;
    conversion = convert(&input, &output, &info);
    if (conversion == BINARY_SKIP) {
        fprintf(stderr, PROGRAM ": Binary symbol 0x%02X found at line %llu\n",
                info.binary_symbol, (unsigned long long)info.binary_line);
        fprintf(stderr, PROGRAM ": Skipping binary file %s\n", shown_input);
        result = 0;
        goto done;
    }
    if (conversion == INVALID_UTF16) {
        fprintf(stderr, PROGRAM ": invalid UTF-16%s in %s at byte %llu; output unchanged\n",
                info.encoding == UTF16_LE ? "LE" : "BE", shown_input,
                (unsigned long long)info.invalid_offset);
        result = 1;
        goto done;
    }
    if (conversion == ALLOCATION_FAILED) {
        fputs(PROGRAM ": output allocation or documented size limit exceeded\n", stderr);
        result = 1;
        goto done;
    }
    result = commit_output(output_path, &output, shown_input, shown_output);
    if (result) goto done;
    if (info.encoding == BYTE_TEXT) {
        fprintf(stderr, PROGRAM ": converting file %s to file %s in Unix format...\n",
                shown_input, shown_output);
    } else {
        fprintf(stderr, PROGRAM ": converting UTF-16%s file %s to UTF-8 file %s in Unix format...\n",
                info.encoding == UTF16_LE ? "LE" : "BE", shown_input, shown_output);
    }
done:
    free(shown_input);
    free(shown_output);
    free(input.data);
    free(output.data);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    int index, paired_mode = 0, options = 1, result = 0;
    const wchar_t *pending_input = NULL;
    if (argc == 1) { help(); return 1; }
    for (index = 1; index < argc; ++index) {
        const wchar_t *argument = argv[index];
        if (options && !wcscmp(argument, L"--")) { options = 0; continue; }
        if (options && argument[0] == L'-') {
            if (!wcscmp(argument, L"-n") || !wcscmp(argument, L"--newfile")) {
                paired_mode = 1;
                continue;
            }
            if (!wcscmp(argument, L"-h") || !wcscmp(argument, L"--help")) { help(); return 0; }
            if (!wcscmp(argument, L"-V") || !wcscmp(argument, L"--version")) { version(); return 0; }
            /* Intentional stdout difference: honest subset help, same observed
               unknown-option stream selection and nonzero status. */
            help();
            return 1;
        }
        if (!paired_mode) { help(); return 1; }
        if (!pending_input) pending_input = argument;
        else {
            result |= convert_pair(pending_input, argument);
            pending_input = NULL;
        }
    }
    /* Observed d18: a final unmatched input is ignored, after prior pairs commit. */
    return result;
}
