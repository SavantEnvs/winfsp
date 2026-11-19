/*
 * fuzz_reparse -- WinFsp reparse point (symlink) resolution (src/dll/fsop.c) and path splitting
 * (src/dll/path.c).
 *
 * A user-mode file system answers the kernel's "resolve reparse points" request by calling the
 * exported FspFileSystemFindReparsePoint() and FspFileSystemResolveReparsePoints() with a
 * GetReparsePointByName callback that returns the reparse data stored on each path component
 * (tst/memfs/memfs.cpp does exactly this).  That data was supplied by whoever created the
 * symlink/junction (FSCTL_SET_REPARSE_POINT), so it is attacker-controlled.
 *
 * Input layout:
 *   u8   flags      bit0: ResolveLastPathComponent; bit1: also run FspFileSystemCanReplaceReparsePoint
 *   u16  n          FileName length in WCHARs (capped at the kernel's path limit, 1023 + NUL)
 *   n*2  FileName   UTF-16LE (as the kernel passes it in the request)
 *   then records answering successive GetReparsePointByName calls:
 *   u8 kind (0: not a reparse point, 1: name not found, 2: other error, 3: reparse data),
 *   u16 size, size bytes of reparse data.  When records run out, components are plain files.
 *
 * Reparse data is only handed back if it passes the checks the WinFsp driver applies when it is
 * stored (FsRtlValidateReparsePointBuffer in src/sys/fsctl.c FSCTL_SET_REPARSE_POINT, mirrored by
 * valid_reparse_data() below); data that would have been rejected cannot exist on a volume.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winfsp/winfsp.h>

#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE (16 * 1024)

struct ctx
{
    const uint8_t *p, *end;
};

static int rd16(const uint8_t **p, const uint8_t *end, uint16_t *v)
{
    if (end - *p < 2)
        return 0;
    *v = (uint16_t)((*p)[0] | ((*p)[1] << 8));
    *p += 2;
    return 1;
}

/* FsRtlValidateReparsePointBuffer, as documented for the WDK */
static int valid_reparse_data(const uint8_t *buf, size_t size)
{
    union { REPARSE_DATA_BUFFER rd; uint8_t b[32]; } u;     /* aligned copy of the header */
    const REPARSE_DATA_BUFFER *rd = &u.rd;
    size_t hdr;
    if (size < REPARSE_DATA_BUFFER_HEADER_SIZE || size > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
        return 0;
    memset(&u, 0, sizeof u);
    memcpy(u.b, buf, size < sizeof u.b ? size : sizeof u.b);
    if (0 == rd->ReparseTag || 1 == rd->ReparseTag)
        return 0;   /* IO_REPARSE_TAG_RESERVED_ZERO/ONE */
    hdr = IsReparseTagMicrosoft(rd->ReparseTag) ?
        REPARSE_DATA_BUFFER_HEADER_SIZE : REPARSE_GUID_DATA_BUFFER_HEADER_SIZE;
    if (size < hdr || (size_t)rd->ReparseDataLength + hdr != size)
        return 0;
    if (IO_REPARSE_TAG_SYMLINK == rd->ReparseTag || IO_REPARSE_TAG_MOUNT_POINT == rd->ReparseTag)
    {
        size_t base = IO_REPARSE_TAG_SYMLINK == rd->ReparseTag ?
            FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) :
            FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
        const USHORT *f = &rd->SymbolicLinkReparseBuffer.SubstituteNameOffset;
        if (size < base)
            return 0;
        /* SubstituteName and PrintName must lie inside PathBuffer */
        if ((size_t)f[0] + f[1] > size - base || (size_t)f[2] + f[3] > size - base)
            return 0;
    }
    return 1;
}

static NTSTATUS GetReparsePointByName(FSP_FILE_SYSTEM *FileSystem, PVOID Context,
    PWSTR FileName, BOOLEAN IsDirectory, PVOID Buffer, PSIZE_T PSize)
{
    struct ctx *ctx = Context;
    uint16_t size = 0;
    uint8_t kind;
    (void)FileSystem; (void)FileName; (void)IsDirectory;

    if (ctx->p >= ctx->end)
        return STATUS_NOT_A_REPARSE_POINT;
    kind = *ctx->p++ & 3;
    if (3 == kind)
    {
        if (!rd16(&ctx->p, ctx->end, &size))
            size = 0;
        if (size > ctx->end - ctx->p)
            size = (uint16_t)(ctx->end - ctx->p);
    }
    const uint8_t *data = ctx->p;
    ctx->p += size;

    switch (kind)
    {
    case 0:
        return STATUS_NOT_A_REPARSE_POINT;
    case 1:
        return STATUS_OBJECT_NAME_NOT_FOUND;
    case 2:
        return STATUS_ACCESS_DENIED;
    default:
        if (!valid_reparse_data(data, size))
            return STATUS_NOT_A_REPARSE_POINT;
        if (0 != Buffer)
        {
            /* the memfs contract: too small a buffer is an error, otherwise copy and size */
            if (size > *PSize)
                return STATUS_BUFFER_TOO_SMALL;
            memcpy(Buffer, data, size);
            *PSize = size;
        }
        return STATUS_SUCCESS;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const uint8_t *p = buf, *end = buf + len;
    uint16_t n;
    uint8_t flags;
    WCHAR *name, *copy;
    struct ctx ctx;

    if (len < 3)
        return -1;
    flags = *p++;
    rd16(&p, end, &n);
    if (n > FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR) - 1)
        n = FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR) - 1;
    if ((size_t)(end - p) < (size_t)n * 2)
        n = (uint16_t)((end - p) / 2);

    name = malloc((n + 1) * sizeof(WCHAR));
    copy = malloc((n + 1) * sizeof(WCHAR));
    if (0 == name || 0 == copy)
        goto exit;
    for (uint16_t i = 0; n > i; i++)
        name[i] = (WCHAR)(p[2 * i] | (p[2 * i + 1] << 8));
    name[n] = 0;
    p += 2 * (size_t)n;

    /* path.c: split and recombine the name (what the DLL does with every request path) */
    {
        WCHAR root[2] = L"\\";
        PWSTR a, b;
        memcpy(copy, name, (n + 1) * sizeof(WCHAR));
        FspPathSuffix(copy, &a, &b, root);
        FspPathCombine(copy, b);
        FspPathPrefix(copy, &a, &b, root);
        FspPathCombine(copy, b);
    }

    /* the ResolveReparsePoints file system operation, as tst/memfs/memfs.cpp implements it */
    {
        UINT32 index = 0;
        IO_STATUS_BLOCK ios;
        SIZE_T size = FSP_FSCTL_TRANSACT_RSP_BUFFER_SIZEMAX;
        PVOID out = malloc(size);
        if (0 == out)
            goto exit;

        ctx.p = p; ctx.end = end;
        memcpy(copy, name, (n + 1) * sizeof(WCHAR));
        if (!FspFileSystemFindReparsePoint(0, GetReparsePointByName, &ctx, copy, &index))
            index = 0;

        memset(&ios, 0, sizeof ios);
        memcpy(copy, name, (n + 1) * sizeof(WCHAR));
        FspFileSystemResolveReparsePoints(0, GetReparsePointByName, &ctx,
            copy, index, flags & 1, &ios, out, &size);
        free(out);
    }

    /* SetReparsePoint: may the reparse data in the next record replace the one after it? */
    p = ctx.p < end ? ctx.p : end;
    if (flags & 2)
    {
        uint16_t s1 = 0, s2 = 0;
        if (rd16(&p, end, &s1) && s1 <= end - p)
        {
            const uint8_t *b1 = p;
            p += s1;
            s2 = (uint16_t)(end - p);
            if (valid_reparse_data(b1, s1) && valid_reparse_data(p, s2))
            {
                /* copies give each buffer its exact size, so ASan sees any overread */
                void *c1 = malloc(s1 ? s1 : 1), *c2 = malloc(s2 ? s2 : 1);
                if (0 != c1 && 0 != c2)
                {
                    memcpy(c1, b1, s1);
                    memcpy(c2, p, s2);
                    FspFileSystemCanReplaceReparsePoint(c1, s1, c2, s2);
                }
                free(c1);
                free(c2);
            }
        }
    }

exit:
    free(name);
    free(copy);
    return 0;
}
