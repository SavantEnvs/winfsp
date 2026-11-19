/*
 * fuzz_fuse_opt -- WinFsp-FUSE command line / "-o" option parser (src/dll/fuse/fuse_opt.c).
 *
 * The input is an argv: NUL-separated strings (at most 64), placed after a fixed argv[0] the way a
 * FUSE file system's main() hands its command line to fuse_opt_parse().  It is parsed through the
 * exported fsp_fuse_opt_parse() against an option table that exercises every template kind the
 * parser supports: flags, "-x %s" (value in the next argument), "key=%d/%i/%o/%u/%x/%s", the size
 * modifiers hh/h/l/ll/z/j/t, FUSE_OPT_KEY entries, and the KEEP/DISCARD keys; a processing
 * callback re-adds options with fsp_fuse_opt_add_opt[_escaped]/insert_arg.  The resulting argv is
 * then re-matched with fsp_fuse_opt_match() and freed with fsp_fuse_opt_free_args().
 * Everything allocated for one input is freed before returning; no state is kept across inputs.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fuse/fuse_opt.h>

/*
 * Every option target gets its own 8-byte, 8-aligned slot: a template may be matched without a
 * value (e.g. "hh=%hhu" given as "hh="), in which case the parser stores the template's int value
 * at the target, as libfuse does; a slot keeps that store in bounds and aligned.
 */
#define SLOT(name) union { long long ll; double d; void *p; } name
struct data
{
    SLOT(flag_d); SLOT(flag_f); SLOT(ro);
    SLOT(i_d); SLOT(i_i); SLOT(i_o); SLOT(i_u); SLOT(i_x);
    SLOT(hh); SLOT(h); SLOT(l); SLOT(ll); SLOT(z); SLOT(j); SLOT(t);
    SLOT(s); SLOT(name);
    int keyhit;
    char *opts;     /* collected by the proc via fsp_fuse_opt_add_opt[_escaped] */
};

enum { KEY_HELP = 100, KEY_VERSION, KEY_FSNAME, KEY_SUBTYPE, KEY_REINSERT };

#define O(t, f, v) { t, offsetof(struct data, f), v }
static const struct fuse_opt opts[] =
{
    O("-d", flag_d, 1), O("debug", flag_d, 1), O("-f", flag_f, 1), O("ro", ro, 1),
    O("-n %s", name, 0), O("--name=%s", name, 0), O("str=%s", s, 0), O("chr=%c", s, 0),
    O("dec=%d", i_d, 0), O("int=%i", i_i, 0), O("umask=%o", i_o, 0), O("uid=%u", i_u, 0),
    O("hex=%x", i_x, 0), O("HEX=%X", i_x, 0), O("hh=%hhu", hh, 0), O("h=%hd", h, 0),
    O("l=%ld", l, 0), O("ll=%lld", ll, 0), O("q=%qd", ll, 0), O("z=%zu", z, 0), O("j=%jd", j, 0),
    O("t=%td", t, 0), O("w=%5d", i_d, 0), O("float=%f", i_d, 0),
    FUSE_OPT_KEY("-h", KEY_HELP), FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_KEY("-V", KEY_VERSION), FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_KEY("fsname=", KEY_FSNAME), FUSE_OPT_KEY("subtype=", KEY_SUBTYPE),
    FUSE_OPT_KEY("-r ", KEY_REINSERT),
    FUSE_OPT_KEY("ro", FUSE_OPT_KEY_KEEP), FUSE_OPT_KEY("rw", FUSE_OPT_KEY_DISCARD),
    FUSE_OPT_KEY("--keep", FUSE_OPT_KEY_KEEP), FUSE_OPT_KEY("--discard", FUSE_OPT_KEY_DISCARD),
    FUSE_OPT_END,
};

/*
 * The parser allocates through env->memalloc/memfree.  A repeated "%s" option overwrites the
 * previous string without freeing it (as with libfuse), so allocations are tracked per input and
 * whatever is still live at the end is released: memory use stays bounded across inputs.
 */
struct chunk { struct chunk *prev, *next; max_align_t align[]; };
static struct chunk live = { &live, &live };
static void *track_alloc(size_t size)
{
    struct chunk *c = malloc(sizeof *c + size);
    if (0 == c)
        return 0;
    c->next = live.next; c->prev = &live;
    live.next->prev = c; live.next = c;
    return c->align;
}
static void track_free(void *p)
{
    if (0 == p)
        return;
    struct chunk *c = (struct chunk *)((char *)p - offsetof(struct chunk, align));
    c->prev->next = c->next; c->next->prev = c->prev;
    free(c);
}
static void track_free_all(void)
{
    while (live.next != &live)
        track_free(live.next->align);
}

static struct fsp_fuse_env env = { 'C', track_alloc, track_free };

static int proc(void *data0, const char *arg, int key, struct fuse_args *outargs)
{
    struct data *data = data0;
    data->keyhit++;
    switch (key)
    {
    case KEY_HELP:
        return 0;
    case KEY_VERSION:
        return fsp_fuse_opt_add_arg(&env, outargs, "-ofsname=version");
    case KEY_FSNAME:
        return fsp_fuse_opt_add_opt_escaped(&env, &data->opts, arg);
    case KEY_SUBTYPE:
        return -1 == fsp_fuse_opt_add_opt(&env, &data->opts, arg) ? -1 : 1;
    case KEY_REINSERT:
        return fsp_fuse_opt_insert_arg(&env, outargs, 1, arg);
    case FUSE_OPT_KEY_OPT:
        return 1 == (data->keyhit & 1) ? 1 : fsp_fuse_opt_add_opt_escaped(&env, &data->opts, arg);
    case FUSE_OPT_KEY_NONOPT:
    default:
        return 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    enum { MAXARGS = 64 };
    char *argv[MAXARGS + 2], *copy;
    int argc = 0;
    struct data data;
    struct fuse_args args;

    copy = malloc(len + 1);
    if (0 == copy)
        return 0;
    memcpy(copy, buf, len);
    copy[len] = '\0';

    argv[argc++] = "fuzz_fuse_opt";
    for (size_t i = 0; len >= i && MAXARGS >= argc; )
    {
        argv[argc++] = copy + i;
        i += strlen(copy + i) + 1;
    }
    argv[argc] = 0;

    memset(&data, 0, sizeof data);
    args.argc = argc;
    args.argv = argv;
    args.allocated = 0;

    if (0 == fsp_fuse_opt_parse(&env, &args, &data, opts, proc))
    {
        for (int i = 0; args.argc > i; i++)
            fsp_fuse_opt_match(&env, opts, args.argv[i]);
        if (0 != data.opts)
            fsp_fuse_opt_match(&env, opts, data.opts);
    }
    fsp_fuse_opt_free_args(&env, &args);

    track_free_all();   /* data.s/name/opts and anything a repeated option orphaned */
    free(copy);
    return 0;
}
