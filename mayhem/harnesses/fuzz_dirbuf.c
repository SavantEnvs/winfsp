/*
 * fuzz_dirbuf -- WinFsp directory buffers (src/dll/dirbuf.c, FspFileSystemAddDirInfo in fsop.c).
 *
 * A file system answers ReadDirectory by filling a directory buffer with one FSP_FSCTL_DIR_INFO
 * per entry (FspFileSystemAcquireDirectoryBuffer[Ex] / FillDirectoryBuffer / Release), which
 * WinFsp grows, indexes and sorts by name; it then serves the kernel's reads with
 * FspFileSystemReadDirectoryBuffer(), resuming after a Marker (the last file name the caller saw,
 * which comes from the application doing the directory listing) by binary search.
 *
 * Input layout:
 *   u8   flags     bit0: pass the marker; bit1: read a second page after the last name returned;
 *                  bit2: Reset on acquire
 *   u16  capacity  CapacityHint for FspFileSystemAcquireDirectoryBufferEx
 *   u16  length    size of the caller's read buffer
 *   u8   m         marker length in WCHARs, then m*2 bytes UTF-16LE marker
 *   then entries: u8 n (name length in WCHARs), n*2 bytes UTF-16LE name; the harness builds a
 *   well-formed FSP_FSCTL_DIR_INFO (Size = header + name bytes) for each, as a file system does.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winfsp/winfsp.h>

static WCHAR *read_name(const uint8_t **p, const uint8_t *end, unsigned n, WCHAR *dst)
{
    for (unsigned i = 0; n > i; i++)
        dst[i] = (WCHAR)((*p)[2 * i] | ((*p)[2 * i + 1] << 8));
    *p += 2 * (size_t)n;
    (void)end;
    return dst;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const uint8_t *p = buf, *end = buf + len;
    uint8_t flags, m;
    ULONG capacity, length, bytes;
    WCHAR marker[256], marker2[256];
    PVOID dirbuf = 0, out = 0;
    NTSTATUS result;
    union { FSP_FSCTL_DIR_INFO d; UINT8 b[sizeof(FSP_FSCTL_DIR_INFO) + 256 * sizeof(WCHAR)]; } di;

    if (len < 6)
        return -1;
    flags = p[0];
    capacity = (ULONG)(p[1] | (p[2] << 8));
    length = (ULONG)(p[3] | (p[4] << 8));
    m = p[5];
    p += 6;
    if ((size_t)(end - p) < 2 * (size_t)m)
        return -1;
    read_name(&p, end, m, marker);
    marker[m] = 0;

    if (FspFileSystemAcquireDirectoryBufferEx(&dirbuf, flags & 4, capacity, &result))
    {
        while (end - p >= 1)
        {
            unsigned n = *p++;
            if ((size_t)(end - p) < 2 * (size_t)n)
                break;
            memset(&di, 0, sizeof di);
            read_name(&p, end, n, di.d.FileNameBuf);
            di.d.Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + n * sizeof(WCHAR));
            di.d.FileInfo.FileSize = n;
            if (!FspFileSystemFillDirectoryBuffer(&dirbuf, &di.d, &result))
                break;
        }
        FspFileSystemReleaseDirectoryBuffer(&dirbuf);
    }

    out = malloc(length ? length : 1);
    if (0 == out)
        goto exit;
    bytes = 0;
    FspFileSystemReadDirectoryBuffer(&dirbuf, (flags & 1) ? marker : 0, out, length, &bytes);

    if ((flags & 2) && bytes <= length)
    {
        /* the next page resumes after the last entry of this one, like the kernel's next read */
        PUINT8 q = out, last = 0;
        while (q + sizeof(UINT16) <= (PUINT8)out + bytes)
        {
            UINT16 size;
            memcpy(&size, q, sizeof size);
            if (size < sizeof(FSP_FSCTL_DIR_INFO) || q + size > (PUINT8)out + bytes)
                break;
            last = q;
            q += FSP_FSCTL_DEFAULT_ALIGN_UP(size);
        }
        if (0 != last)
        {
            UINT16 size;
            memcpy(&size, last, sizeof size);
            unsigned n = (size - sizeof(FSP_FSCTL_DIR_INFO)) / sizeof(WCHAR);
            if (n > 255)
                n = 255;
            memcpy(marker2, last + sizeof(FSP_FSCTL_DIR_INFO), n * sizeof(WCHAR));
            marker2[n] = 0;
            bytes = 0;
            FspFileSystemReadDirectoryBuffer(&dirbuf, marker2, out, length, &bytes);
        }
    }

exit:
    free(out);
    FspFileSystemDeleteDirectoryBuffer(&dirbuf);
    return 0;
}
