/*
 * mayhem/shim/win32.c -- Linux implementations of the few Win32 functions that the WinFsp DLL
 * sources compiled by mayhem/build.sh actually call (see mayhem/shim/include/windows.h).
 *
 * Only what the fuzzed code paths need is implemented, with Windows semantics:
 *   - heap:    HeapAlloc/HeapReAlloc/HeapFree -> malloc/realloc/free (so ASan sees every buffer)
 *   - memory:  RtlMoveMemory/RtlFillMemory -> memmove/memset (src/shared/um/minimal.h builds
 *              memcpy/memmove/memset on top of these)
 *   - strings: lstrlenA/lstrlenW (lstrlenW counts 16-bit WCHARs; NULL -> 0 as on Windows)
 *   - SRW locks: the harnesses are single-threaded, so the locks only track their state and
 *              abort() on misuse (release of an unheld lock, recursive exclusive acquire)
 *   - interlocked intrinsics used by inc/winfsp/fsctl.h
 *   - CP_UTF8 MultiByteToWideChar/WideCharToMultiByte (src/shared/ku/posix.c path mapping)
 * Functions the linked objects reference but nothing here reaches abort() in unreachable.c.
 */
#include <windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void shim_unreachable(const char *name)
{
    fprintf(stderr, "mayhem shim: unexpected call to %s\n", name);
    abort();
}

#define HEAP_ZERO_MEMORY 0x00000008

HANDLE WINAPI GetProcessHeap(void)
{
    return (HANDLE)(UINT_PTR)1;
}

LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    (void)hHeap;
    /* HeapAlloc(0) returns a valid, unique pointer */
    return (dwFlags & HEAP_ZERO_MEMORY) ? calloc(1, dwBytes ? dwBytes : 1) : malloc(dwBytes ? dwBytes : 1);
}

LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    (void)hHeap; (void)dwFlags;
    if (0 == lpMem)
        return 0;   /* HeapReAlloc does not allocate on NULL */
    return realloc(lpMem, dwBytes ? dwBytes : 1);
}

BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    (void)hHeap; (void)dwFlags;
    free(lpMem);
    return TRUE;
}

VOID NTAPI RtlMoveMemory(VOID *Destination, CONST VOID *Source, DWORD Length)
{
    if (0 != Length)    /* RtlMoveMemory(p, NULL, 0) is a valid no-op on Windows */
        memmove(Destination, Source, Length);
}

VOID NTAPI RtlFillMemory(VOID *Destination, DWORD Length, BYTE Fill)
{
    if (0 != Length)
        memset(Destination, Fill, Length);
}

int WINAPI lstrlenA(LPCSTR lpString)
{
    return 0 != lpString ? (int)strlen(lpString) : 0;
}

int WINAPI lstrlenW(LPCWSTR lpString)
{
    int n = 0;
    if (0 == lpString)
        return 0;
    while (lpString[n])
        n++;
    return n;
}

static DWORD shim_last_error;
DWORD WINAPI GetLastError(void)
{
    return shim_last_error;
}
VOID WINAPI SetLastError(DWORD dwErrCode)
{
    shim_last_error = dwErrCode;
}

/* SRWLOCK: Ptr holds 0 (free), (void*)1 (exclusive) or (void*)(2 + 2*n) (n+1 shared holders) */
VOID WINAPI InitializeSRWLock(PSRWLOCK SRWLock)
{
    SRWLock->Ptr = 0;
}
VOID WINAPI AcquireSRWLockExclusive(PSRWLOCK SRWLock)
{
    if (0 != SRWLock->Ptr)
        shim_unreachable("AcquireSRWLockExclusive on a held lock (deadlock)");
    SRWLock->Ptr = (PVOID)(UINT_PTR)1;
}
VOID WINAPI ReleaseSRWLockExclusive(PSRWLOCK SRWLock)
{
    if ((PVOID)(UINT_PTR)1 != SRWLock->Ptr)
        shim_unreachable("ReleaseSRWLockExclusive on a lock not held exclusively");
    SRWLock->Ptr = 0;
}
VOID WINAPI AcquireSRWLockShared(PSRWLOCK SRWLock)
{
    UINT_PTR v = (UINT_PTR)SRWLock->Ptr;
    if (1 == v)
        shim_unreachable("AcquireSRWLockShared on an exclusively held lock (deadlock)");
    SRWLock->Ptr = (PVOID)(0 == v ? 2 : v + 2);
}
VOID WINAPI ReleaseSRWLockShared(PSRWLOCK SRWLock)
{
    UINT_PTR v = (UINT_PTR)SRWLock->Ptr;
    if (v < 2)
        shim_unreachable("ReleaseSRWLockShared on a lock not held shared");
    SRWLock->Ptr = (PVOID)(2 == v ? 0 : v - 2);
}

/* inc/winfsp/fsctl.h declares these MSVC intrinsics with MSVC's 32-bit long */
long mayhem_InterlockedExchange(long volatile *Target, long Value)
{
    volatile INT32 *p = (volatile INT32 *)Target;
    INT32 old = *p;
    *p = (INT32)Value;
    return old;
}
void *mayhem_InterlockedExchangePointer(void *volatile *Target, void *Value)
{
    void *old = *Target;
    *Target = Value;
    return old;
}
void mayhem_ReadWriteBarrier(void)
{
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
}

/* src/dll/ntstatus.c maps every Win32 error; the harnessed code can only produce these few */
NTSTATUS FspNtStatusFromWin32(DWORD Error)
{
    switch (Error)
    {
    case ERROR_SUCCESS:                 return STATUS_SUCCESS;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_NOT_ENOUGH_MEMORY:       return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    case ERROR_INSUFFICIENT_BUFFER:     return STATUS_BUFFER_TOO_SMALL;
    case ERROR_NO_UNICODE_TRANSLATION:  return ((NTSTATUS)0xC0000162L); /* STATUS_UNMAPPABLE_CHARACTER */
    default:                            return STATUS_UNSUCCESSFUL;
    }
}

/*
 * MultiByteToWideChar/WideCharToMultiByte for CP_UTF8 with dwFlags == 0, following the documented
 * Windows (Vista+) behavior: cb/cch == -1 means NUL-terminated and the count includes the NUL;
 * an output size of 0 returns the required size; a too-small output fails with
 * ERROR_INSUFFICIENT_BUFFER and returns 0; invalid UTF-8 (overlong forms, surrogates, > U+10FFFF,
 * truncated sequences) and unpaired UTF-16 surrogates are replaced by U+FFFD.
 */
static int shim_utf8_decode(const UINT8 *s, int n, UINT32 *pc)
{
    UINT32 c = s[0], min;
    int len, i;
    if (c < 0x80) { *pc = c; return 1; }
    else if (0xc0 == (c & 0xe0)) { len = 2; c &= 0x1f; min = 0x80; }
    else if (0xe0 == (c & 0xf0)) { len = 3; c &= 0x0f; min = 0x800; }
    else if (0xf0 == (c & 0xf8)) { len = 4; c &= 0x07; min = 0x10000; }
    else { *pc = 0xfffd; return 1; }
    for (i = 1; len > i; i++)
    {
        if (i >= n || 0x80 != (s[i] & 0xc0)) { *pc = 0xfffd; return i; }
        c = (c << 6) | (s[i] & 0x3f);
    }
    if (c < min || c > 0x10ffff || (0xd800 <= c && c <= 0xdfff)) { *pc = 0xfffd; return len; }
    *pc = c;
    return len;
}

int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar)
{
    const UINT8 *s = (const UINT8 *)lpMultiByteStr;
    int n, i = 0, o = 0;
    if (CP_UTF8 != CodePage || 0 != dwFlags || 0 == s || 0 == cbMultiByte || cbMultiByte < -1 ||
        cchWideChar < 0 || (0 != cchWideChar && 0 == lpWideCharStr))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    n = -1 == cbMultiByte ? (int)strlen((const char *)s) + 1 : cbMultiByte;
    while (n > i)
    {
        UINT32 c;
        int need;
        i += shim_utf8_decode(s + i, n - i, &c);
        need = 0x10000 <= c ? 2 : 1;
        if (0 != cchWideChar)
        {
            if (o + need > cchWideChar)
            {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            if (2 == need)
            {
                c -= 0x10000;
                lpWideCharStr[o] = (WCHAR)(0xd800 | (c >> 10));
                lpWideCharStr[o + 1] = (WCHAR)(0xdc00 | (c & 0x3ff));
            }
            else
                lpWideCharStr[o] = (WCHAR)c;
        }
        o += need;
    }
    return o;
}

int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    const WCHAR *w = lpWideCharStr;
    int n, i = 0, o = 0;
    if (CP_UTF8 != CodePage || 0 != dwFlags || 0 != lpDefaultChar || 0 != lpUsedDefaultChar ||
        0 == w || 0 == cchWideChar || cchWideChar < -1 ||
        cbMultiByte < 0 || (0 != cbMultiByte && 0 == lpMultiByteStr))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (-1 == cchWideChar)
    {
        n = 0;
        while (w[n])
            n++;
        n++;
    }
    else
        n = cchWideChar;
    while (n > i)
    {
        UINT32 c = w[i++];
        UINT8 buf[4];
        int len, k;
        if (0xd800 <= c && c <= 0xdbff && n > i && 0xdc00 <= w[i] && w[i] <= 0xdfff)
            c = 0x10000 + ((c - 0xd800) << 10) + (w[i++] - 0xdc00);
        else if (0xd800 <= c && c <= 0xdfff)
            c = 0xfffd;
        if (c < 0x80) { buf[0] = (UINT8)c; len = 1; }
        else if (c < 0x800) { buf[0] = (UINT8)(0xc0 | (c >> 6)); buf[1] = (UINT8)(0x80 | (c & 0x3f)); len = 2; }
        else if (c < 0x10000) { buf[0] = (UINT8)(0xe0 | (c >> 12)); buf[1] = (UINT8)(0x80 | ((c >> 6) & 0x3f));
            buf[2] = (UINT8)(0x80 | (c & 0x3f)); len = 3; }
        else { buf[0] = (UINT8)(0xf0 | (c >> 18)); buf[1] = (UINT8)(0x80 | ((c >> 12) & 0x3f));
            buf[2] = (UINT8)(0x80 | ((c >> 6) & 0x3f)); buf[3] = (UINT8)(0x80 | (c & 0x3f)); len = 4; }
        if (0 != cbMultiByte)
        {
            if (o + len > cbMultiByte)
            {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            for (k = 0; len > k; k++)
                lpMultiByteStr[o + k] = (CHAR)buf[k];
        }
        o += len;
    }
    return o;
}
