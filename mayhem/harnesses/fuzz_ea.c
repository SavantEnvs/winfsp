/*
 * fuzz_ea -- WinFsp extended attribute list walking and packing (src/dll/fsop.c).
 *
 * A file system receives an EA list (FILE_FULL_EA_INFORMATION chain) with CreateEx/SetEa requests
 * and walks it with the exported FspFileSystemEnumerateEa(); for QueryEa it packs the stored EAs
 * into the caller's buffer with FspFileSystemAddEa() and terminates the chain with
 * FspFileSystemAddEa(0, ...) (tst/memfs/memfs.cpp GetEa/SetEa).  This harness does both: every EA
 * the enumeration yields is packed into an output buffer of a fuzz-chosen size, then the output
 * is terminated and walked again.
 *
 * Input layout: u16 output buffer length, then the EA list.  The EA list comes from the calling
 * process and the WinFsp driver checks it with IoCheckEaBufferValidity() before it reaches the
 * file system (src/sys/util.c FspEaBufferFromOriginatingProcessValidate); lists that check would
 * reject are rejected here too (valid_ea_buffer(), the documented IoCheckEaBufferValidity rules).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winfsp/winfsp.h>

struct out
{
    PFILE_FULL_EA_INFORMATION Ea;
    ULONG Length, BytesTransferred, Count;
    BOOLEAN Full;
};

static int valid_ea_buffer(const uint8_t *buf, size_t len)
{
    size_t off = 0;
    if (0 == len)
        return 0;
    for (;;)
    {
        FILE_FULL_EA_INFORMATION ea;
        size_t entry;
        if (len - off < FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName))
            return 0;
        memcpy(&ea, buf + off, FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName));
        entry = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + ea.EaNameLength + 1 + ea.EaValueLength;
        if (entry > len - off || 0 != buf[off + FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + ea.EaNameLength])
            return 0;
        if (0 == ea.NextEntryOffset)
            return 1;
        if (ea.NextEntryOffset != ((entry + 3) & ~(size_t)3) || ea.NextEntryOffset >= len - off)
            return 0;
        off += ea.NextEntryOffset;
    }
}

static NTSTATUS AddEaFn(FSP_FILE_SYSTEM *FileSystem, PVOID Context, PFILE_FULL_EA_INFORMATION SingleEa)
{
    struct out *out = Context;
    (void)FileSystem;
    out->Count++;
    if (!out->Full && !FspFileSystemAddEa(SingleEa, out->Ea, out->Length, &out->BytesTransferred))
        out->Full = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS CountEaFn(FSP_FILE_SYSTEM *FileSystem, PVOID Context, PFILE_FULL_EA_INFORMATION SingleEa)
{
    (void)FileSystem; (void)SingleEa;
    ++*(ULONG *)Context;
    return STATUS_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    struct out out;
    PFILE_FULL_EA_INFORMATION in;
    ULONG inlen, count = 0;

    if (len < 2)
        return -1;
    memset(&out, 0, sizeof out);
    out.Length = (ULONG)(buf[0] | (buf[1] << 8));
    buf += 2, len -= 2;
    if (len > 0xffff || !valid_ea_buffer(buf, len))
        return -1;
    inlen = (ULONG)len;

    /* exact-size heap copies (ULONG aligned, like the kernel's buffers) so ASan sees overruns */
    in = malloc(inlen);
    out.Ea = malloc(out.Length ? out.Length : 1);
    if (0 == in || 0 == out.Ea)
        goto exit;
    memcpy(in, buf, inlen);
    memset(out.Ea, 0, out.Length);

    FspFileSystemEnumerateEa(0, AddEaFn, &out, in, inlen);
    if (!out.Full)
    {
        FspFileSystemAddEa(0, out.Ea, out.Length, &out.BytesTransferred);
        FspFileSystemEnumerateEa(0, CountEaFn, &count, out.Ea, out.BytesTransferred);
    }

exit:
    free(in);
    free(out.Ea);
    return 0;
}
