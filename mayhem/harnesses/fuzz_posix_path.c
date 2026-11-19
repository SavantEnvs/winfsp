/*
 * fuzz_posix_path -- WinFsp POSIX <-> Windows path mapping (src/shared/ku/posix.c).
 *
 * The FUSE layer and Cygwin/WSL-style file systems convert every file name the kernel or the
 * application hands them with the exported FspPosixMapWindowsToPosixPathEx() /
 * FspPosixMapPosixToWindowsPathEx() (UTF-16 <-> UTF-8, '\\' <-> '/', and the U+F0XX private use
 * encoding of characters Windows forbids in names), and FspPosixEncodeWindowsPath() /
 * FspPosixDecodeWindowsPath() for in-place conversion.
 *
 * Input layout: u8 flags (bit0: Translate), then the path bytes, used twice: as a NUL-terminated
 * UTF-8 POSIX path (mapped to Windows and back), and as a NUL-terminated UTF-16LE Windows path
 * (mapped to POSIX and back, and encoded/decoded in place).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winfsp/winfsp.h>

static size_t wlen(const WCHAR *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    BOOLEAN translate;
    char *posix = 0, *posix2 = 0;
    WCHAR *win = 0, *win2 = 0, *wcopy = 0;
    size_t n;

    if (len < 1)
        return -1;
    translate = buf[0] & 1;
    buf++, len--;

    /* POSIX (UTF-8) -> Windows -> POSIX */
    posix = malloc(len + 1);
    if (0 == posix)
        goto exit;
    memcpy(posix, buf, len);
    posix[len] = '\0';
    if (NT_SUCCESS(FspPosixMapPosixToWindowsPathEx(posix, &win, translate)))
    {
        if (NT_SUCCESS(FspPosixMapWindowsToPosixPathEx(win, &posix2, translate)))
            FspPosixDeletePath(posix2), posix2 = 0;
        FspPosixDeletePath(win), win = 0;
    }

    /* Windows (UTF-16) -> POSIX -> Windows, and the in-place encode/decode */
    n = len / 2;
    wcopy = malloc((n + 1) * sizeof(WCHAR));
    if (0 == wcopy)
        goto exit;
    for (size_t i = 0; n > i; i++)
        wcopy[i] = (WCHAR)(buf[2 * i] | (buf[2 * i + 1] << 8));
    wcopy[n] = 0;
    if (NT_SUCCESS(FspPosixMapWindowsToPosixPathEx(wcopy, &posix2, translate)))
    {
        if (NT_SUCCESS(FspPosixMapPosixToWindowsPathEx(posix2, &win2, translate)))
            FspPosixDeletePath(win2), win2 = 0;
        FspPosixDeletePath(posix2), posix2 = 0;
    }
    n = wlen(wcopy);
    FspPosixEncodeWindowsPath(wcopy, (ULONG)n);
    FspPosixDecodeWindowsPath(wcopy, (ULONG)n);

exit:
    free(posix);
    free(wcopy);
    return 0;
}
