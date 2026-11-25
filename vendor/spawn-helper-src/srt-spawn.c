#define _GNU_SOURCE// srt-spawn: spawn helper for Linux. The Dart VM's exit-code thread reaps
// any child with waitpid(-1), so the status of a directly spawned command
// can be lost. This helper (the one the VM may reap) forks the real command
// and reports its exact wait status over a pipe.
//
// usage: srt-spawn STATUSFD:KEEP FILE ARGV0 [ARG...]
// TELOSNEX DEVIATION: the embedding API may insert "" --setsid before FILE.
// pipe protocol: 8 bytes {int32 pid, int32 errno} once the command has been
// exec'd (errno != 0: exec failed, pid 0), then 4 bytes {int32 wait status}.
#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static volatile pid_t child_pid;

static void forward(int sig) {
  pid_t p = child_pid;
  if (p > 0) kill(p, sig);
}

static void write_all(int fd, const void *buf, size_t n) {
  const char *p = buf;
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return;
    }
    p += w;
    n -= (size_t)w;
  }
}

int main(int argc, char **argv) {
  if (argc < 4) return 125;
  // TELOSNEX DEVIATION: opt in to a new session for the real command, not
  // this status relay; older helpers would fail to exec the empty filename.
  int new_session = argc >= 6 && !argv[2][0] && !strcmp(argv[3], "--setsid");
  int file_arg = new_session ? 4 : 2;
  int sfd = atoi(argv[1]);
  fcntl(sfd, F_SETFD, FD_CLOEXEC);
  // Only descriptors 0..KEEP-1 (the stdio slots) reach the command, as in
  // Node: close whatever else the parent leaked, except the status pipe.
  {
    char *colon = strchr(argv[1], ':');
    int keep = colon ? atoi(colon + 1) : 3;
    if (keep < 3) keep = 3;
    int ok = 1;
    if (sfd >= keep) {
      if (sfd > keep &&
          syscall(SYS_close_range, (unsigned)keep, (unsigned)sfd - 1, 0) != 0)
        ok = 0;
      if (syscall(SYS_close_range, (unsigned)sfd + 1, ~0U, 0) != 0) ok = 0;
    } else if (syscall(SYS_close_range, (unsigned)keep, ~0U, 0) != 0) {
      ok = 0;
    }
    if (!ok) {
      // close_range unavailable (old kernel, seccomp): close one by one.
      int failed = 0;
      DIR *d = opendir("/proc/self/fd");
      if (d) {
        int dfd = dirfd(d);
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
          if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
          int fd = atoi(e->d_name);
          if (fd < keep || fd == sfd || fd == dfd) continue;
          close(fd);
        }
        closedir(d);
      } else {
        failed = errno ? errno : EMFILE;
      }
      if (failed) {
        // Cannot enumerate descriptors: fail closed, do not exec.
        int msg[2] = {0, failed};
        write_all(sfd, msg, sizeof msg);
        return 125;
      }
    }
  }
  int ep[2];
  if (pipe2(ep, O_CLOEXEC) != 0) return 125;

  sigset_t all, old;
  sigfillset(&all);
  sigprocmask(SIG_BLOCK, &all, &old);
  pid_t pid = fork();
  if (pid < 0) {
    int msg[2] = {0, errno};
    write_all(sfd, msg, sizeof msg);
    return 125;
  }
  if (pid == 0) {
    sigprocmask(SIG_SETMASK, &old, NULL);
    close(ep[0]);
    // TELOSNEX DEVIATION: set up the command's process group before exec
    // and report failure through the same channel as an exec error.
    if (!new_session || setsid() >= 0)
      execve(argv[file_arg], argv + file_arg + 1, environ);
    int e = errno;
    write_all(ep[1], &e, sizeof e);
    _exit(127);
  }
  close(ep[1]);
  child_pid = pid;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = forward;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  for (int s = 1; s <= SIGRTMAX; s++) {
    if (s == SIGPIPE) continue;
    if (s == SIGKILL || s == SIGSTOP || s == SIGCHLD || s == SIGSEGV ||
        s == SIGBUS || s == SIGFPE || s == SIGILL)
      continue;
    struct sigaction cur;
    if (sigaction(s, NULL, &cur) == 0 && cur.sa_handler == SIG_IGN) continue;
    sigaction(s, &sa, NULL);
  }
  signal(SIGPIPE, SIG_IGN);
  sigprocmask(SIG_SETMASK, &old, NULL);

  int e = 0;
  ssize_t r;
  do {
    r = read(ep[0], &e, sizeof e);
  } while (r < 0 && errno == EINTR);
  if (r != (ssize_t)sizeof e) e = 0;
  int msg[2] = {e ? 0 : (int)pid, e};
  write_all(sfd, msg, sizeof msg);

  int status = 0;
  pid_t w;
  do {
    w = waitpid(pid, &status, 0);
  } while (w < 0 && errno == EINTR);
  sigprocmask(SIG_BLOCK, &all, NULL);
  child_pid = 0;
  sigprocmask(SIG_SETMASK, &old, NULL);
  if (w != pid) return 125;
  if (e == 0) write_all(sfd, &status, sizeof status);
  return 0;
}
