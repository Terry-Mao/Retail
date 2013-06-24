/*
    TODO
    free resource
    review code
*/

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/inotify.h>


typedef struct {
    int     fd; // tail file fd
    int     pfd; // pos file fd
    char    *name; // tail file name
    int     times; // pos file current save times
    mode_t  mode; // tail file mode
    off_t   size; // tail file current size
    time_t  mtime; // tail file modify time
    int     ignore; // ignore tail file
    int     tailable; // file tailable
    ino_t   ino;
    dev_t   dev;
    int     err; // last errno 
} file_spec_t;

#define UINT64_LEN          sizeof("18446744073709551615") - 1 
#define memzero(buf, n)     (void) memset(buf, 0, n)
#define min(val1, val2)     ((val1 > val2) ? (val2) : (val1))    
#define is_tailable(mod) \
    (S_ISREG(mod) || S_ISFIFO(mod) || S_ISSOCK(mod) || S_ISCHR(mod))
#define LOG_INFO            0
#define LOG_DEBUG           1
#define file_spec_t_init(f) \
    f->fd = -1; \
    f->pfd = -1; \
    f->name = NULL; \
    f->times = 0; \
    f->ignore = 0;\
    f->tailable = 0;\
    f->err = 0

static const uint32_t inotify_wd_mask = (IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
static const uint32_t inotify_pwd_mask = (IN_CREATE | IN_MOVED_TO | IN_ATTRIB);
static int show_help = 0;
static int log_level = LOG_INFO;
static int flush_times = 50;
static char *pos_file = NULL;
static char *tail_file = NULL;

static int64_t str_to_int64(char *p);
static int check_fspec(file_spec_t *f);
static ssize_t dump_remainder(int fd);
static int write_stdout(const char *buf, size_t size);
static int recheck(file_spec_t *f);
static void record_open_fd(file_spec_t *f, int fd, off_t size, struct stat const *st);
static int dump_pos(file_spec_t *f, char *buf, size_t size);
static int get_options(int argc, char * const*argv);
static void log_info(const char *fmt, ...);
static void log_debug(const char *fmt, ...);
static void tail_forever_inotify(const char *tail_file, const char *pos_file);

int main(int argc, char * const *argv) 
{
    if(get_options(argc, argv) == -1) {
        return -1;
    }

    if(show_help) {
        log_info(
        "usage : \n"
        "         -h/? for help\n"
        "         -f set tail file name\n"
        "         -p set pos file\n"
        "         -d set debug flag\n"
        "         -s set save pos file times\n"
        );
        return 0;
    }

    tail_forever_inotify(tail_file, pos_file);
    return -1;
}

static void
tail_forever_inotify(const char *tail_file, const char *pos_file)
{/*{{{*/
    int                     wd, fwd, tfwd, pwd, max_realloc;
    char                    prev, *p, posbuf[UINT64_LEN + 1], *evbuf, *evp, *name, *pos_name;
    size_t                  fnlen, dirlen, evlen;
    ssize_t                 poslen, evbuf_off, len;
    struct                  stat stats;
    struct inotify_event    *ev;
    file_spec_t             fspec, *f;

    if(tail_file == NULL || pos_file == NULL) {
        log_info("requires tail file and pos file\n");
        return;
    }

    f = &fspec;
    file_spec_t_init(f);
    evlen = 0;
    evbuf_off = 0;
    len = 0;
    max_realloc = 10;
    memzero(posbuf, UINT64_LEN + 1);
    name = NULL;
    pos_name = NULL;
    pwd = -1;
    tfwd = -1;
    fwd = -1;
    evbuf = NULL;
    wd = inotify_init();
    if(wd < 0) {
        log_info("inotify_init() failed (%s)", strerror(errno));
        goto free;
    }
    
    name = malloc(strlen(tail_file) + 1);
    if(name == NULL) {
        log_info("malloc() failed (%s)", strerror(errno));
        goto free;
    } 

    pos_name = malloc(strlen(pos_file) + 1);
    if(pos_name == NULL) {
        log_info("malloc() failed (%s)", strerror(errno));
        goto free;
    } 

    (void) strcpy(name, tail_file);
    (void) strcpy(pos_name, pos_file);
    f->name = name;
    fnlen = strlen(name);
    evlen = fnlen;
    p = strrchr(name, '/');
    dirlen = ((p == NULL) ? 0 : p - name);
    prev = name[dirlen];
    name[dirlen] = '\0';
    pwd = inotify_add_watch(wd, dirlen ? name : ".", inotify_pwd_mask);
    if(pwd < 0) {
        log_info("inotify_add_watch() failed (%s)", strerror(errno));
        goto free;
    }

    log_debug("add file watch %s\n", name);
    name[dirlen] = prev;
    fwd = inotify_add_watch(wd, name, inotify_wd_mask);
    if(fwd < 0) {
        log_info("inotify_add_watch() failed (%s)", strerror(errno));
        goto free;
    }

    log_debug("add dir watch %s\n", name);
    // open file
    f->fd = open(name, O_RDONLY);
    if(f->fd < 0) {
        log_info("open() failed (%s)", strerror(errno));
        goto free;
    }

    if(fstat(f->fd, &stats) != 0) {
        log_info("fstat() failed (%s)", strerror(errno));
        goto free;
    }

    if(!S_ISREG(stats.st_mode)) {
        // not tailable file
        log_info("not a tailable file");
        goto free;
    }

    f->mtime = stats.st_mtime;
    f->dev =stats.st_dev;
    f->mode = stats.st_mode;
    f->ino = stats.st_ino;
    // open pos file
    f->pfd = open(pos_name, (O_RDWR | O_CREAT), 0644);
    if(f->pfd < 0) {
        log_info("open() failed (%s)", strerror(errno));
        goto free;
    }

    // parse pos file
    poslen = read(f->pfd, posbuf, UINT64_LEN); 
    if(poslen < 0) {
        log_info("read() failed (%s)", strerror(errno));
        goto free;
    } else if(poslen == 0) {
        f->size = 0;
    } else {
        if((p = strchr(posbuf, '\n')) == NULL) {
            // pos file format error
            log_info("pos file format error");
            goto free;
        }

        posbuf[p - posbuf] = '\0';
        f->size = str_to_int64(posbuf);
        if(lseek(f->fd, f->size, SEEK_SET) < 0) {
            log_info("lseek() failed (%s)", strerror(errno));
            goto free;
        }
    }

    // new data can be available since last time we checked before watched by inotify
    if(check_fspec(f) == -1) {
        log_info("check_fspec() failed\n"); 
        goto free;
    }

    // inotify
    evlen += sizeof(struct inotify_event) + 1;
    evbuf = (char *) malloc(evlen);
    if(evbuf == NULL) {
        log_info("malloc() failed (%s)", strerror(errno));
        goto free;
    }

    for( ;; ) {
        // need read more event buf
        if(len <= evbuf_off) {
            evbuf_off = 0;
            len = read(wd, evbuf, evlen);
            if((len == 0 || (len < 0 && errno == EINVAL)) && (max_realloc--)) {
                len = 0;
                evlen *= 2;
                evbuf = realloc (evbuf, evlen);
                continue;
            }

            if(len == 0 || len < 0) {
                log_info("read() failed (%s)", strerror(errno));
                goto free;
            }
        }

        evp = evbuf + evbuf_off; 
        ev = (struct inotify_event *) evp;
        evbuf_off += sizeof(*ev) + ev->len;
        if(ev->len) {
            log_debug("has dir event %s\n", ev->name);
            // if has event name
            if(pwd == ev->wd && strcmp(ev->name, (name + dirlen + 1)) != 0) {
                // not a watched dir
                continue;
            } else if(pwd != ev->wd) {
                continue;
            }

            // readd watch
            log_debug("readd file watch %s\n", name);
            if((tfwd = inotify_add_watch(wd, name, inotify_wd_mask)) < 0) {
                goto free;
            }

            // must be same
            fwd = tfwd;
            log_info("file create or move recheck\n");
            if(recheck(f) == -1) {
                log_info("recheck() failed\n");
                goto free;
            }
        } else {
            // file has chagne?
            if(fwd != ev->wd) {
                continue;
            }

            log_debug("has file event\n");
        }

        if (ev->mask & (IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF)) {
            /* For IN_DELETE_SELF, we always want to remove the watch.
               However, for IN_MOVE_SELF (the file we're watching has
               been clobbered via a rename), when tailing by NAME, we
               must continue to watch the file.  It's only when following
               by file descriptor that we must remove the watch.  */
            if ((ev->mask & IN_DELETE_SELF) || (ev->mask & IN_MOVE_SELF)) {
                log_debug("remove file watch %s\n", name);
                inotify_rm_watch(wd, fwd);
            }

            log_debug("file delete or move recheck\n");
            if(recheck(f) == -1) {
                log_info("recheck() failed\n");
                goto free;
            }

            continue;
        }

        log_debug("file changed\n");
        // file has changed
        if(check_fspec(f) == -1) {
            log_info("check_fspec() failed\n");
            goto free;
        }

        // continue read events
    }

free:
    // free resource
    log_info("free resource\n");
    if(wd > 0) {
        (void) close(wd); 
        wd = -1;
    }

    if(name != NULL) {
        free(name); 
        name = NULL;
    }

    if(pos_name != NULL) {
        free(pos_name); 
        pos_name = NULL;
    }

    if(pwd > 0) {
        (void) close(pwd);
        pwd = -1;
    }

    if(fwd > 0) {
        (void) close(fwd);
        fwd = -1;
    }

    if(f->fd > 0) {
        (void) close(f->fd); 
        f->fd = -1;
    }

    if(f->pfd > 0) {
        (void) close(f->pfd);
        f->pfd = -1;
    }
}/*}}}*/

static int64_t
str_to_int64(char *p)
{/*{{{*/
    int64_t i;

    i = 0;
    while(*p >= '0' && *p <= '9') {
        i = i * 10 + *p++ - '0';
    }

    return i;
} /*}}}*/

static int
check_fspec(file_spec_t *f)
{/*{{{*/
    struct stat stats;
    char        buf[UINT64_LEN + 2];
    int         len;
    ssize_t     size;

    if(fstat(f->fd, &stats) != 0) {
        f->err = errno;
        (void) close(f->fd);
        f->fd = -1;
        log_debug("fstat failed() (%s)\n", strerror(errno));
        return 0;
    }

    if(S_ISREG(f->mode) && stats.st_size < f->size) {
        // file truncated
        if(lseek(f->fd, stats.st_size, SEEK_SET) < 0) {
            // fatal error
            log_info("lseek() failed (%s)\n", strerror(errno));
            return -1;
        }

        f->size = stats.st_size; 
    } else if (stats.st_size == f->size && f->mtime == stats.st_mtime) {
        // file no change
        log_debug("file nochange\n");
    }

    if((size = dump_remainder(f->fd)) == -1) {
        log_info("dump_remainer() failed\n");
        return -1;
    }
    // read file
    f->size += size;
    // flush to stdout
    if(fflush(stdout) != 0) {
        log_info("fflush() failed (%s)\n", strerror(errno));
        return -1;
    }

    // flush pos
    if(f->times++ < flush_times) {
        log_debug("times : %d, flush_times : %d\n", f->times, flush_times);
        return 0;
    }

    if((len = sprintf(buf, "%ld\n", f->size)) < 0) {
        log_info("sprintf() failed (%s)\n", strerror(errno));
        return -1;
    }

    if(dump_pos(f, buf, len) == -1) {
        log_info("dump_pos() failed\n");
        return -1;
    }

    // reset times
    f->times = 0;

    return 0;
}/*}}}*/

static ssize_t
dump_remainder(int fd)
{/*{{{*/
    ssize_t writes, reads;
    char    buffer[BUFSIZ];

    writes = 0;
    for( ;; ) {
        reads = read(fd, buffer, BUFSIZ);
        if(reads == - 1) {
            if(errno == EINTR) {
                continue;
            } 

            log_info("read() failed (%s)\n", strerror(errno));
            return -1;
        } else if(reads == 0) {
            // no more contents
            log_debug("read() nomore contents\n");
            break; 
        }

        writes += (ssize_t) reads;
        if(write_stdout(buffer, (size_t) reads) == -1) {
            log_info("write_stdout failed\n");
            return -1;
        }
    }

    return writes; 
}/*}}}*/

static int
write_stdout(const char *buf, size_t size)
{/*{{{*/
    if(size > 0 && fwrite(buf, 1, size, stdout) == 0) {
        log_info("fwrite() failed (%s)\n", strerror(errno));
        return -1;
    }

    return 0;
}/*}}}*/

static int
recheck(file_spec_t *f)
{/*{{{*/
    int        ok, was_tailable, new_file;
    int         fd, prev_err;
    struct stat new_stats;

    ok = 1;
    was_tailable = f->tailable;
    fd = open(f->name, O_RDONLY);
    prev_err = f->err;
    // file dosen't exist then mark the file as not tailable
    f->tailable = !(fd == -1);

    if(fd == -1 || fstat(fd, &new_stats) < 0) {
        ok = 0;
        f->err = errno;
        if(!f->tailable) {
            if (was_tailable) {
                // become inaccessible
                log_info("file become inaccessible\n");
            } else {
                // say nothing... it's still not tailable
            }
        } else if (prev_err != errno) {
            // err changed
            log_info("error changed (%s)\n", strerror(errno));
        }
    } else if(!is_tailable(new_stats.st_mode)) {
        // replaced with an untailable file
        log_info("replaced with an untailable file\n");
        ok = 0;
        f->err = -1;
        f->ignore = 1;
    } else {
        // file open succeed
        f->err = 0;
    }

    new_file = 0;
    if (!ok) {
        (void) close(fd);
        (void) close(f->fd);
        f->fd = -1;
    } else if (prev_err && prev_err != ENOENT) {
        // become accessible
        log_info("file become accessible\n");
        new_file = 1;
    } else if (f->ino != new_stats.st_ino || f->dev != new_stats.st_dev) {
        new_file = 1;
        if (f->fd != -1) {
            // Close the old one
            log_info("close the old file\n");
            (void) close(f->fd);
        } else {
            // following end of new file
        }
    } else {
        if(f->fd == -1) {
            /* This happens when one iteration finds the file missing,
               then the preceding <dev,inode> pair is reused as the
               file is recreated.  */
            new_file = 1;
        } else {
            (void) close(fd);
        }
    }

    if(new_file) {
        /* Start at the beginning of the file.  */
        log_info("open new file\n");
        record_open_fd (f, fd, 0, &new_stats);
        if(lseek(fd, 0, SEEK_SET) < 0) {
            log_info("lseek failed (%s)\n", strerror(errno));
            return -1;
        }

        if(dump_pos(f, "0\n", 2) == -1) {
            log_info("dump_pos() failed\n");
            return -1;
        }
    }

    return 0;
}/*}}}*/

static void
record_open_fd(file_spec_t *f, int fd, off_t size, struct stat const *st)
{/*{{{*/
    f->fd = fd;
    f->size = size;
    f->mtime = st->st_mtime;
    f->dev = st->st_dev;
    f->ino = st->st_ino;
    f->mode = st->st_mode;
    f->ignore = 0;
}/*}}}*/

static int
dump_pos(file_spec_t *f, char *buf, size_t size)
{/*{{{*/
    if(pwrite(f->pfd, buf, size, 0) < 0) {
        log_info("pwrite() failed (%s)\n", strerror(errno));
        return -1;
    }

    return 0;
}/*}}}*/

static int 
get_options(int argc, char * const*argv)
{/*{{{*/
    char   *p;
    int     i;

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if (*p++ != '-') {
            log_info("invalid option: \"%s\"\n", argv[i]);
            return -1;
        }

        while (*p) {
            switch (*p++) {
                case '?':
                case 'h':
                    show_help = 1;
                    break;

                case 'f':
                    if (*p) {
                        tail_file = p;
                        goto next;
                    }

                    if(argv[++i]) {
                        tail_file = argv[i];
                        goto next;
                    }

                    log_info("option \"-f\" requires tail file\n");
                    return -1;

                case 'p':
                    if(*p) {
                        pos_file = argv[i]; 
                        goto next;
                    }

                    if(argv[++i]) {
                        pos_file = argv[i];
                        goto next;
                    }

                case 'd':
                    log_level = LOG_DEBUG;
                    goto next;

                case 's':
                    if(*p) {
                        flush_times=(int) str_to_int64(argv[i]);
                        goto next;
                    }

                    if(argv[++i]) {
                        flush_times=(int) str_to_int64(argv[i]);
                        goto next;
                    }

                default:
                    log_info("invalid option: \"%c\"\n", *(p - 1));
                    return -1;
            }
        }

next:
        continue;
    }

    return 0;
}/*}}}*/

static void 
log_info(const char *fmt, ...)
{/*{{{*/
    va_list args;

    if(log_level < LOG_INFO) {
        return;
    }

    va_start(args, fmt);
    (void) vfprintf(stderr, fmt, args);
    va_end(args);
}/*}}}*/

static void 
log_debug(const char *fmt, ...)
{/*{{{*/
    va_list args;

    if(log_level < LOG_DEBUG) {
        return;
    }

    va_start(args, fmt);
    (void) vfprintf(stderr, fmt, args);
    va_end(args);
}/*}}}*/
