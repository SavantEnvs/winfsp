/*
 * mayhem/tests/winfsp_tests_main.c -- Linux driver for a subset of upstream's own unit tests
 * (tst/winfsp-tests/{fuse-opt,path,dirbuf,posix}-test.c, run by ext/tlib).
 *
 * Upstream's winfsp-tests.c main() needs a mounted WinFsp file system; this replaces it with one
 * that registers only the suites whose code builds on Linux (see mayhem/build.sh; -DSUITES_FUSE
 * for the x86 build of fuse_opt.c, -DSUITES_WINFSP for the x64 rest) and runs the test cases
 * mayhem/test.sh names.  It also supplies the few CRT functions those tests use that
 * glibc gets wrong under -fshort-wchar (16-bit wchar_t, as on Windows): wcslen/wcscmp/wcscpy_s
 * and StringCbPrintfW.  The test sources themselves are compiled unmodified.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

void tlib_add_test_suite(const char *name, void (*fn)(void));
void tlib_run_tests(int argc, char *argv[]);
#define TESTSUITE(fn) do { void fn(void); tlib_add_test_suite(#fn, fn); } while (0)

/* globals that tst/winfsp-tests/winfsp-tests.h declares */
BOOLEAN OptExternal = FALSE;
int RunningInContainer = 0;

size_t wcslen(const wchar_t *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

int wcscmp(const wchar_t *s, const wchar_t *t)
{
    while (*s && *s == *t)
        s++, t++;
    return (int)(unsigned)*s - (int)(unsigned)*t;
}

int wcscpy_s(wchar_t *dst, size_t size, const wchar_t *src)
{
    size_t n = wcslen(src);
    if (0 == dst || n >= size)
        abort();    /* the MSVC CRT invokes the invalid parameter handler */
    for (size_t i = 0; n >= i; i++)
        dst[i] = src[i];
    return 0;
}

/* StringCbPrintfW: narrow the (ASCII) format, format with vsnprintf, widen the result */
HRESULT StringCbPrintfW(wchar_t *dst, size_t cb, const wchar_t *fmt, ...)
{
    char nfmt[256], out[1024];
    size_t i, cch = cb / sizeof(wchar_t);
    va_list ap;
    for (i = 0; fmt[i] && sizeof nfmt - 1 > i; i++)
        nfmt[i] = (char)fmt[i];
    nfmt[i] = '\0';
    va_start(ap, fmt);
    vsnprintf(out, sizeof out, nfmt, ap);
    va_end(ap);
    for (i = 0; out[i] && cch - 1 > i; i++)
        dst[i] = (wchar_t)(unsigned char)out[i];
    dst[i] = 0;
    return out[i] ? (HRESULT)0x8007007A /* STRSAFE_E_INSUFFICIENT_BUFFER */ : 0;
}

/* referenced by the Cygwin branch of inc/fuse/winfsp_fuse.h (the default fuse env); never called */
void *cygwin_create_path(int what, const void *from) { (void)what; (void)from; abort(); }
int cygwin_winpid_to_pid(int winpid) { (void)winpid; abort(); }
void fsp_fuse_signal_handler(int sig) { (void)sig; abort(); }

int main(int argc, char *argv[])
{
#if defined(SUITES_FUSE)
    TESTSUITE(fuse_opt_tests);
#endif
#if defined(SUITES_WINFSP)
    TESTSUITE(posix_tests);
    TESTSUITE(path_tests);
    TESTSUITE(dirbuf_tests);
#endif
    tlib_run_tests(argc, argv);
    return 0;
}
