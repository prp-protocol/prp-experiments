#define _GNU_SOURCE
#include "held_spawn.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const unsigned char token[] = "EXP002-EXEC-V1\n";
static int error(struct hs_child *c, int e)
{
    if (!e)
        e = EIO;
    if (!c->primary)
        c->primary = e;
    else if (!c->secondary)
        c->secondary = e;
    errno = e;
    return -1;
}
static int clock_ns(int64_t *out)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return -1;
    if (ts.tv_sec < 0 || ts.tv_sec > INT64_MAX / 1000000000 || ts.tv_nsec < 0 ||
        ts.tv_nsec >= 1000000000) {
        errno = EOVERFLOW;
        return -1;
    }
    if ((int64_t)ts.tv_sec * 1000000000 > INT64_MAX - ts.tv_nsec) {
        errno = EOVERFLOW;
        return -1;
    }
    *out = (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
    return 0;
}
static int admit(struct hs_child *c, int64_t end)
{
    int64_t now;
    if (clock_ns(&now))
        return error(c, errno);
    if (now < c->last_ns)
        return error(c, ERANGE);
    c->last_ns = now;
    if (now >= end)
        return error(c, ETIMEDOUT);
    return c->primary ? (errno = c->primary, -1) : 0;
}
static void close_once(struct hs_child *c, int *fd)
{
    int old = *fd;
    *fd = -1;
    if (old >= 0 && close(old))
        (void)error(c, errno);
}
void hs_init(struct hs_child *c)
{
    memset(c, 0, sizeof(*c));
    c->pidfd = c->gate = c->exec_error = -1;
    c->release_count = -1;
}
static int exclusive(void)
{
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action))
        return -1;
    if (action.sa_handler != SIG_DFL || (action.sa_flags & SA_NOCLDWAIT)) {
        errno = EPERM;
        return -1;
    }
    /* Gate EPIPE must be a recorded error, never asynchronous owner death. */
    if (sigaction(SIGPIPE, NULL, &action))
        return -1;
    if (action.sa_handler != SIG_IGN) {
        errno = EPERM;
        return -1;
    }
    DIR *dir = opendir("/proc/self/task");
    if (!dir)
        return -1;
    unsigned count = 0;
    struct dirent *entry;
    int saved = 0;
    errno = 0;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] != '.')
            ++count;
        if (count > 1)
            break;
    }
    if (!entry && errno)
        saved = errno;
    if (closedir(dir) && !saved)
        saved = errno;
    if (saved || count != 1) {
        errno = saved ? saved : EPERM;
        return -1;
    }
    return 0;
}
static int strings(char *const *v)
{
    size_t bytes = 0;
    if (!v)
        return -1;
    for (unsigned i = 0; i < 64; i++) {
        if (!v[i])
            return 0;
        size_t n = strnlen(v[i], 4097);
        if (n > 4096 || bytes + n + 1 > 65536)
            return -1;
        bytes += n + 1;
    }
    return -1;
}
static int validate(const struct hs_plan *p)
{
    int fds[9] = {p->executable, p->streams[0], p->streams[1], p->streams[2], p->streams[3]};
    if (p->network_count != 0 && p->network_count != 4) {
        errno = EINVAL;
        return -1;
    }
    for (unsigned i = 0; i < p->network_count; i++)
        fds[5 + i] = p->network[i];
    unsigned char magic[4];
    struct stat st;
    if (p->launch_end_ns <= 0 || strings(p->argv) || strings(p->envp) || !p->argv[0]) {
        errno = EINVAL;
        return -1;
    }
    for (unsigned i = 0; i < 5 + p->network_count; i++) {
        int flags;
        if (fds[i] < (int)(4 + p->network_count)) {
            errno = EINVAL;
            return -1;
        }
        if ((flags = fcntl(fds[i], F_GETFD)) < 0)
            return -1;
        if (!(flags & FD_CLOEXEC)) {
            errno = EINVAL;
            return -1;
        }
        for (unsigned j = 0; j < i; j++)
            if (fds[i] == fds[j]) {
                errno = EINVAL;
                return -1;
            }
    }
    if (fstat(p->executable, &st) || !S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (pread(p->executable, magic, sizeof(magic), 0) != sizeof(magic) ||
        memcmp(magic, "\177ELF", 4)) {
        errno = ENOEXEC;
        return -1;
    }
    return 0;
}
static _Noreturn void child_error(int fd, int e)
{
    /* Single bounded error write; failure/short output remains unknown upstream. */
    ssize_t reported = write(fd, &e, sizeof(e));
    (void)reported;
    _exit(127);
}
static _Noreturn void child_main(const struct hs_plan *p, int gate, int execerr,
                                 const sigset_t *oldmask)
{
    unsigned char received[sizeof(token) - 1];
    size_t used = 0;
    int keep[3] = {gate, execerr, p->executable};
    for (int i = 0; i < 4; i++)
        if (dup2(p->streams[i], i) < 0)
            child_error(execerr, errno);
    for (unsigned i = 0; i < p->network_count; i++)
        if (dup2(p->network[i], 4 + (int)i) < 0)
            child_error(execerr, errno);
    for (int i = 0; i < 3; i++)
        for (int j = i + 1; j < 3; j++)
            if (keep[j] < keep[i]) {
                int t = keep[i];
                keep[i] = keep[j];
                keep[j] = t;
            }
    unsigned first = 4 + p->network_count;
    for (int i = 0; i < 3; i++) {
        if (first < (unsigned)keep[i] &&
            syscall(SYS_close_range, first, (unsigned)keep[i] - 1, 0) < 0)
            child_error(execerr, errno);
        first = (unsigned)keep[i] + 1;
    }
    if (syscall(SYS_close_range, first, UINT_MAX, 0) < 0)
        child_error(execerr, errno);
    /* Finite gate reads; EAGAIN/EINTR/errors refuse instead of renewing time. */
    for (unsigned calls = 0; used < sizeof(received) && calls < sizeof(received); calls++) {
        int64_t now;
        if (clock_ns(&now) || now >= p->launch_end_ns)
            child_error(execerr, ETIMEDOUT);
        int64_t ms = (p->launch_end_ns - now) / 1000000;
        if (ms > INT_MAX)
            child_error(execerr, EOVERFLOW);
        struct pollfd event = {.fd = gate, .events = POLLIN};
        if (poll(&event, 1, (int)ms) != 1 || !(event.revents & POLLIN))
            child_error(execerr, ETIMEDOUT);
        ssize_t n = read(gate, received + used, sizeof(received) - used);
        if (n <= 0)
            child_error(execerr, n < 0 ? errno : EPIPE);
        used += (size_t)n;
    }
    if (used != sizeof(received) || memcmp(received, token, sizeof(received)))
        child_error(execerr, EPROTO);
    int64_t now;
    if (clock_ns(&now) || now >= p->launch_end_ns)
        child_error(execerr, ETIMEDOUT);
    if (close(gate) || sigprocmask(SIG_SETMASK, oldmask, NULL))
        child_error(execerr, errno);
    if (clock_ns(&now) || now >= p->launch_end_ns)
        child_error(execerr, ETIMEDOUT);
    syscall(SYS_execveat, p->executable, "", p->argv, p->envp, AT_EMPTY_PATH);
    child_error(execerr, errno);
}
int hs_create(struct hs_child *c, const struct hs_plan *p)
{
    int gate[2] = {-1, -1}, errors[2] = {-1, -1};
    sigset_t block, oldmask;
    int masked = 0;
    if (c->started)
        return error(c, EALREADY);
    c->started = 1;
    c->launch_end_ns = p->launch_end_ns;
    if (validate(p) || exclusive())
        return error(c, errno);
    if (admit(c, p->launch_end_ns))
        return -1;
    if (pipe2(gate, O_CLOEXEC | O_NONBLOCK) || pipe2(errors, O_CLOEXEC | O_NONBLOCK)) {
        error(c, errno);
        goto done;
    }
    /* All standard descriptors must already exist; no gate may alias a target. */
    if (gate[0] < (int)(4 + p->network_count) || gate[1] < (int)(4 + p->network_count) ||
        errors[0] < (int)(4 + p->network_count) || errors[1] < (int)(4 + p->network_count)) {
        error(c, EINVAL);
        goto done;
    }
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &block, &oldmask)) {
        error(c, errno);
        goto done;
    }
    masked = 1;
    if (admit(c, p->launch_end_ns))
        goto done;
    pid_t pid = fork();
    if (pid < 0) {
        error(c, errno);
        goto done;
    }
    if (!pid)
        child_main(p, gate[0], errors[1], &oldmask);
    c->pid = pid;
    c->owned = 1; /* retain before close, pidfd or clock can fail */
    c->gate = gate[1];
    gate[1] = -1;
    c->exec_error = errors[0];
    errors[0] = -1;
    c->pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (c->pidfd < 0)
        error(c, errno);
    (void)admit(c, p->launch_end_ns);
done:
    close_once(c, &gate[0]);
    close_once(c, &gate[1]);
    close_once(c, &errors[0]);
    close_once(c, &errors[1]);
    if (masked && sigprocmask(SIG_SETMASK, &oldmask, NULL))
        error(c, errno);
    if (c->owned)
        (void)admit(c, p->launch_end_ns);
    if (c->primary)
        close_once(c, &c->gate);
    return c->primary ? -1 : 0;
}
int hs_release(struct hs_child *c, int64_t end)
{
    if (!c->owned || c->retired || c->pidfd < 0 || c->gate < 0 || c->release_attempted ||
        end != c->launch_end_ns)
        return error(c, EPERM);
    if (admit(c, end))
        return -1;
    c->release_attempted = c->release_possible = 1;
    c->release_count = write(c->gate, token, sizeof(token) - 1);
    if (c->release_count != (ssize_t)sizeof(token) - 1)
        error(c, c->release_count < 0 ? errno : EIO);
    (void)admit(c, end);
    close_once(c, &c->gate);
    return c->primary ? -1 : 0;
}
int hs_cancel_gate(struct hs_child *c)
{
    close_once(c, &c->gate);
    return c->primary ? -1 : 0;
}
void hs_retire(struct hs_child *c)
{
    c->retired = 1;
    close_once(c, &c->gate);
}
size_t hs_layout(unsigned structure, unsigned field)
{
    static const size_t plan[] = {sizeof(struct hs_plan),
                                  offsetof(struct hs_plan, executable),
                                  offsetof(struct hs_plan, streams),
                                  offsetof(struct hs_plan, argv),
                                  offsetof(struct hs_plan, envp),
                                  offsetof(struct hs_plan, launch_end_ns),
                                  offsetof(struct hs_plan, network_count),
                                  offsetof(struct hs_plan, network)};
    static const size_t child[] = {sizeof(struct hs_child),
                                   offsetof(struct hs_child, pid),
                                   offsetof(struct hs_child, pidfd),
                                   offsetof(struct hs_child, gate),
                                   offsetof(struct hs_child, exec_error),
                                   offsetof(struct hs_child, started),
                                   offsetof(struct hs_child, owned),
                                   offsetof(struct hs_child, retired),
                                   offsetof(struct hs_child, release_attempted),
                                   offsetof(struct hs_child, release_possible),
                                   offsetof(struct hs_child, primary),
                                   offsetof(struct hs_child, secondary),
                                   offsetof(struct hs_child, release_count),
                                   offsetof(struct hs_child, last_ns),
                                   offsetof(struct hs_child, launch_end_ns)};
    if (structure == 0 && field < sizeof(plan) / sizeof(*plan))
        return plan[field];
    if (structure == 1 && field < sizeof(child) / sizeof(*child))
        return child[field];
    return SIZE_MAX;
}
