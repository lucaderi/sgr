#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Standard C. */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Process lookup, files, and user/group identities. */
#include <dirent.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* IPv4 and Linux socket diagnostics. */
#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* Privilege reduction. */
#include <sys/capability.h>
#include <sys/prctl.h>

typedef struct nlmsghdr nlmsghdr_t;           /* header for netlink message*/
typedef struct inet_diag_msg inet_diag_msg_t; /* base socket identity addr, port, cookie */
typedef struct sockaddr_nl sockaddr_nl_t;     /* netlink socket addr struct */

/* A service is identified by process name, protocol, and local port. */
typedef struct {
  uint8_t protocol;
  uint16_t port;
  uint32_t inode; /* Used only to find the process /proc. */
  char process[256];
} service_t;

typedef struct {
  service_t *items;
  size_t count, capacity;
} snapshot_t;

enum event { OPEN,
             CLOSE,
             EVENT_COUNT };
static const char *const event_names[] = {"open", "close"};

typedef struct {
  uint64_t events[EVENT_COUNT];
  uint64_t collection_errors;
  time_t last_success;
} counters_t;

static volatile sig_atomic_t running = 1;

static void stop_monitor(int signal_number) {
  (void)signal_number;
  running = 0;
}

static void *allocate(void *old, size_t size) {
  void *result = realloc(old, size);
  if (!result) {
    perror("netmon: memory allocation");
    exit(EXIT_FAILURE);
  }
  return result;
}

static void snapshot_free(snapshot_t *snapshot) {
  free(snapshot->items);
  *snapshot = (snapshot_t){0};
}

/* typesafe */
static int key_compare(const service_t *a, const service_t *b) {
  const char *a_process = a->process[0] ? a->process : "unknown";
  const char *b_process = b->process[0] ? b->process : "unknown";
  int process = strcmp(a_process, b_process);
  if (process)
    return process;
  if (a->protocol != b->protocol)
    return a->protocol < b->protocol ? -1 : 1;
  return (a->port > b->port) - (a->port < b->port);
}

/* Used in qsort */
static int service_compare(const void *left, const void *right) {
  return key_compare(left, right);
}

static size_t group_end(const snapshot_t *snapshot, size_t start) {
  size_t end = start + 1;
  while (end < snapshot->count &&
         key_compare(&snapshot->items[start], &snapshot->items[end]) == 0)
    ++end;
  return end;
}

static void snapshot_sort(snapshot_t *snapshot) {
  if (snapshot->count > 1)
    qsort(snapshot->items, snapshot->count, sizeof(service_t), service_compare);
}

static const char *protocol_name(uint8_t protocol) {
  return protocol == IPPROTO_TCP ? "tcp" : "udp";
}

static void snapshot_append(snapshot_t *snapshot, const inet_diag_msg_t *msg,
                            uint8_t protocol) {
  /* Bound IPv4 sockets outside the entire 127/8 loopback range. */
  if (msg->idiag_family != AF_INET || msg->id.idiag_sport == 0 ||
      (ntohl(msg->id.idiag_src[0]) >> 24) == 127 ||
      (protocol == IPPROTO_TCP && msg->idiag_state != TCP_LISTEN))
    return;
  if (snapshot->count == snapshot->capacity) {
    if (snapshot->capacity > SIZE_MAX / sizeof(service_t) / 2) {
      fprintf(stderr, "netmon: snapshot too large\n");
      exit(EXIT_FAILURE);
    }
    snapshot->capacity = snapshot->capacity ? snapshot->capacity * 2 : 32;
    snapshot->items = allocate(snapshot->items,
                               snapshot->capacity * sizeof(service_t));
  }
  service_t *service = &snapshot->items[snapshot->count++];
  *service = (service_t){
      .protocol = protocol,
      .port = ntohs(msg->id.idiag_sport),
      .inode = msg->idiag_inode,
  };
}

/* Netlink collection: request, multipart validation, and record decoding. */
static int fail(int error) {
  errno = error;
  return -1;
}

static int request_sockets(int fd, uint32_t sequence, uint8_t protocol) {
  struct {
    nlmsghdr_t header;
    struct inet_diag_req_v2 diagnostic;
  } request = {
      .header = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),
                 .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                 .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                 .nlmsg_seq = sequence},
      .diagnostic = {.sdiag_family = AF_INET, .sdiag_protocol = protocol, .idiag_states = protocol == IPPROTO_TCP ? 1U << TCP_LISTEN : UINT32_MAX}};
  sockaddr_nl_t kernel = {.nl_family = AF_NETLINK};

  ssize_t sent;
  do {
    sent = sendto(fd, &request, request.header.nlmsg_len, 0,
                  (struct sockaddr *)&kernel, sizeof(kernel));
  } while (sent < 0 && errno == EINTR && running);
  if (sent < 0)
    return -1;
  return (size_t)sent == request.header.nlmsg_len ? 0 : fail(EIO);
}

static int receive_sockets(int fd, uint32_t sequence, uint8_t protocol,
                           snapshot_t *snapshot) {
  /* The union ensures alignment for Netlink headers and diagnostic records. */
  union {
    nlmsghdr_t alignment;
    unsigned char bytes[65536];
  } buffer;

  for (;;) {
    sockaddr_nl_t sender = {0};
    struct iovec iov = {buffer.bytes, sizeof(buffer.bytes)};
    struct msghdr message = {
        .msg_name = &sender,
        .msg_namelen = sizeof(sender),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    ssize_t received = recvmsg(fd, &message, 0);
    if (received < 0) {
      if (errno == EINTR && running)
        continue;
      return -1;
    }
    if (received == 0 || (message.msg_flags & MSG_TRUNC))
      return fail(EMSGSIZE);
    if (message.msg_namelen != sizeof(sender) ||
        sender.nl_family != AF_NETLINK || sender.nl_pid != 0)
      return fail(EPROTO);

    int remaining = (int)received;
    for (nlmsghdr_t *header = (nlmsghdr_t *)buffer.bytes;
         NLMSG_OK(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
      if (header->nlmsg_seq != sequence)
        return fail(EPROTO);
      if (header->nlmsg_flags & NLM_F_DUMP_INTR)
        return fail(EAGAIN);
      size_t length = NLMSG_PAYLOAD(header, 0);
      if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) {
        bool done = header->nlmsg_type == NLMSG_DONE;
        int status = 0; /* DONE and ERROR both start with a signed status. */
        if ((done && length && length < sizeof(status)) ||
            (!done && length < sizeof(struct nlmsgerr)))
          return fail(EPROTO);
        if (length)
          memcpy(&status, NLMSG_DATA(header), sizeof(status));
        if (status)
          return fail(status < 0 && status >= -4095 ? -status : EPROTO);
        if (done)
          return 0;
        continue;
      }
      if (header->nlmsg_type == NLMSG_NOOP)
        continue;
      if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
          length < sizeof(inet_diag_msg_t))
        return fail(EPROTO);
      inet_diag_msg_t diagnostic;
      memcpy(&diagnostic, NLMSG_DATA(header), sizeof(diagnostic));
      snapshot_append(snapshot, &diagnostic, protocol);
    }
    if (remaining != 0)
      return fail(EPROTO);
  }
}

static int collect_services(snapshot_t *snapshot) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (fd < 0)
    return -1;

  sockaddr_nl_t local = {.nl_family = AF_NETLINK};
  struct timeval timeout = {.tv_sec = 5};
  int result = -1;
  if (bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0 &&
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
      request_sockets(fd, 1, IPPROTO_TCP) == 0 &&
      receive_sockets(fd, 1, IPPROTO_TCP, snapshot) == 0 &&
      request_sockets(fd, 2, IPPROTO_UDP) == 0)
    result = receive_sockets(fd, 2, IPPROTO_UDP, snapshot);

  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return result;
}

/* Process correlation: optional, best effort, never a discovery source. */
static bool numeric_name(const char *name) {
  return *name && name[strspn(name, "0123456789")] == '\0';
}

static void resolve_processes(snapshot_t *snapshot) {
  DIR *proc = opendir("/proc");
  if (!proc)
    return;
  struct dirent *process;
  while (running && (process = readdir(proc))) {
    if (!numeric_name(process->d_name))
      continue;
    long number = strtol(process->d_name, NULL, 10);
    if (number <= 0 || number > INT_MAX)
      continue;
    char path[PATH_MAX], name[256] = "";
    snprintf(path, sizeof(path), "/proc/%ld/fd", number);
    DIR *fds = opendir(path);
    if (!fds)
      continue;
    bool metadata_read = false;
    struct dirent *entry;
    while (running && (entry = readdir(fds))) {
      if (!numeric_name(entry->d_name))
        continue;
      char link[128];
      ssize_t length = readlinkat(dirfd(fds), entry->d_name, link,
                                  sizeof(link) - 1);
      if (length < 0)
        continue;
      link[length] = '\0';
      uint32_t inode;
      int consumed = 0;
      if (sscanf(link, "socket:[%" SCNu32 "]%n", &inode, &consumed) != 1 ||
          consumed == 0 || link[consumed] != '\0' || inode == 0)
        continue;
      for (size_t i = 0; i < snapshot->count; ++i) {
        service_t *service = &snapshot->items[i];
        if (service->inode != inode || service->process[0])
          continue;
        if (!metadata_read) {
          snprintf(path, sizeof(path), "/proc/%ld/comm", number);
          FILE *comm = fopen(path, "r");
          if (comm) {
            size_t size = fread(name, 1, sizeof(name) - 1, comm);
            name[size] = '\0';
            if (size && name[size - 1] == '\n')
              name[size - 1] = '\0';
            fclose(comm);
          }
          metadata_read = true;
        }
        strcpy(service->process, name);
      }
    }
    closedir(fds);
  }
  closedir(proc);
}

static void log_service(const char *event, const service_t *service) {
  fprintf(stderr, "[%s] process=%s protocol=%s port=%u\n", event,
          service->process[0] ? service->process : "unknown",
          protocol_name(service->protocol), (unsigned)service->port);
}

static void record_event(counters_t *counters, enum event event,
                         const service_t *service, bool verbose) {
  ++counters->events[event];
  if (verbose)
    log_service(event_names[event], service);
}

static void compare_snapshots(const snapshot_t *old, const snapshot_t *current,
                              counters_t *counters, bool verbose) {
  size_t a = 0, b = 0;
  while (a < old->count || b < current->count) {
    int order = a == old->count ? 1 : b == current->count ? -1
                                                          : key_compare(&old->items[a], &current->items[b]);
    if (order < 0) {
      record_event(counters, CLOSE, &old->items[a], verbose);
      a = group_end(old, a);
    } else if (order > 0) {
      record_event(counters, OPEN, &current->items[b], verbose);
      b = group_end(current, b);
    } else {
      a = group_end(old, a);
      b = group_end(current, b);
    }
  }
}

/* Metrics: one series per process, protocol, and port. */
static void write_label(FILE *file, const char *text) {
  for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
    if (*p == '\n')
      fputs("\\n", file);
    else {
      if (*p == '\\' || *p == '"')
        fputc('\\', file);
      /* Linux comm is bytes, while Prometheus labels require UTF-8. */
      fputc(*p >= 32 && *p < 127 ? *p : '?', file);
    }
  }
}

static void metric(FILE *file, const char *name, const char *type, uint64_t value) {
  fprintf(file, "# TYPE netmon_%s %s\nnetmon_%s %" PRIu64 "\n", name, type, name, value);
}

static int render_metrics(FILE *file, const snapshot_t *snapshot,
                          const counters_t *counters, bool initialized) {
  if (initialized) {
    size_t tcp = 0, udp = 0;
    for (size_t i = 0; i < snapshot->count; i = group_end(snapshot, i)) {
      if (snapshot->items[i].protocol == IPPROTO_TCP)
        ++tcp;
      else
        ++udp;
    }
    fprintf(file, "# TYPE netmon_services gauge\n"
                  "netmon_services{protocol=\"tcp\"} %zu\n"
                  "netmon_services{protocol=\"udp\"} %zu\n",
            tcp, udp);
    fputs("# TYPE netmon_service_up gauge\n", file);
    for (size_t i = 0; i < snapshot->count; i = group_end(snapshot, i)) {
      const service_t *service = &snapshot->items[i];
      fprintf(file, "netmon_service_up{process=\"");
      write_label(file, service->process[0] ? service->process : "unknown");
      fprintf(file, "\",protocol=\"%s\",port=\"%u\"} 1\n",
              protocol_name(service->protocol), (unsigned)service->port);
    }

    fputs("# TYPE netmon_process_services gauge\n", file);
    for (size_t i = 0; i < snapshot->count;) {
      const service_t *service = &snapshot->items[i];
      const char *process = service->process[0] ? service->process : "unknown";
      size_t count = 0, next = i;
      while (next < snapshot->count) {
        const service_t *candidate = &snapshot->items[next];
        const char *candidate_process = candidate->process[0]
                                            ? candidate->process
                                            : "unknown";
        if (strcmp(process, candidate_process) ||
            service->protocol != candidate->protocol)
          break;
        ++count;
        next = group_end(snapshot, next);
      }
      fputs("netmon_process_services{process=\"", file);
      write_label(file, process);
      fprintf(file, "\",protocol=\"%s\"} %zu\n",
              protocol_name(service->protocol), count);
      i = next;
    }
  }
  for (size_t i = 0; i < EVENT_COUNT; ++i) {
    char name[64];
    snprintf(name, sizeof(name), "%s_events_total", event_names[i]);
    metric(file, name, "counter", counters->events[i]);
  }
  metric(file, "last_success_timestamp_seconds", "gauge", counters->last_success);
  metric(file, "collection_errors_total", "counter", counters->collection_errors);
  return ferror(file) ? -1 : 0;
}

static int publish_metrics(const char *path, const snapshot_t *snapshot,
                           const counters_t *counters, bool initialized) {
  size_t length = strlen(path) + sizeof(".tmp.XXXXXX");
  char *temporary = allocate(NULL, length);
  snprintf(temporary, length, "%s.tmp.XXXXXX", path);
  int result = -1, fd = mkstemp(temporary);
  if (fd < 0) {
    free(temporary);
    return -1;
  }
  FILE *file = fdopen(fd, "w");
  if (!file) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
  } else {
    if (fchmod(fd, 0644) == 0 &&
        render_metrics(file, snapshot, counters, initialized) == 0 &&
        fflush(file) == 0 && fsync(fd) == 0)
      result = 0;
    int saved_errno = errno;
    if (fclose(file) != 0 && result == 0) {
      result = -1;
      saved_errno = errno;
    }
    errno = saved_errno;
    if (result == 0)
      result = rename(temporary, path);
  }
  int saved_errno = errno;
  if (result < 0)
    unlink(temporary);
  free(temporary);
  errno = saved_errno;
  return result;
}

/* Privilege reduction: sudo is only used during startup, never in the loop. */
static int parse_identity(const char *value, uint32_t *id) {
  if (!value || !numeric_name(value))
    return fail(EINVAL);
  errno = 0;
  uintmax_t number = strtoumax(value, NULL, 10);
  if (errno || number == 0 || number >= UINT32_MAX)
    return fail(EINVAL);
  *id = (uint32_t)number;
  return 0;
}

static int restrict_privileges(const char *output) {
  bool root = geteuid() == 0;
  uid_t uid = getuid();
  gid_t gid = getgid();
  cap_value_t retained[] = {CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH};

  if (root) {
    uint32_t user, group;
    if (parse_identity(getenv("SUDO_UID"), &user) < 0 ||
        parse_identity(getenv("SUDO_GID"), &group) < 0 ||
        !getpwuid(user) || !getgrgid(group)) {
      fprintf(stderr, "netmon: root startup requires a valid non-root sudo caller\n");
      return fail(EINVAL);
    }
    uid = user;
    gid = group;
    /* Dropping the bounding set does not remove current effective privileges. */
    for (int capability = 0;; ++capability) {
      int present = cap_get_bound(capability);
      if (present < 0) {
        if (errno == EINVAL)
          break;
        return -1;
      }
      if (capability == retained[0] || capability == retained[1])
        continue;
      if (present && cap_drop_bound(capability) < 0)
        return -1;
    }
    if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) < 0 ||
        setgroups(0, NULL) < 0 || setresgid(gid, gid, gid) < 0 ||
        setresuid(uid, uid, uid) < 0)
      return -1;
  } else if (uid == 0 || uid != geteuid() || gid != getegid()) {
    return fail(EPERM);
  }

  cap_t capabilities = cap_init();
  if (!capabilities)
    return -1;
  int error = 0;
  if (root &&
      (cap_set_flag(capabilities, CAP_PERMITTED, 2, retained, CAP_SET) < 0 ||
       cap_set_flag(capabilities, CAP_EFFECTIVE, 2, retained, CAP_SET) < 0))
    error = errno;
  if (!error && cap_set_proc(capabilities) < 0)
    error = errno;
  cap_free(capabilities);
  if (error)
    return fail(error);
  if (prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) < 0 ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) < 0 ||
      prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0)
    return -1;

  /* Test actual write permission after dropping privileges, before monitoring. */
  size_t length = strlen(output) + sizeof(".tmp.XXXXXX");
  char *temporary = allocate(NULL, length);
  snprintf(temporary, length, "%s.tmp.XXXXXX", output);
  int fd = mkstemp(temporary);
  error = fd < 0 ? errno : 0;
  if (fd >= 0) {
    close(fd);
    if (unlink(temporary) < 0)
      error = errno;
  }
  free(temporary);
  if (error)
    return fail(error);
  fprintf(stderr, "netmon: uid=%lu gid=%lu; capabilities=%s; no_new_privs=1\n",
          (unsigned long)uid, (unsigned long)gid,
          root ? "sys_ptrace,dac_read_search" : "none");
  return 0;
}

/* CLI and monitoring loop. The process stays in the foreground for supervision. */
static void usage(FILE *file) {
  fputs("Usage: netmon --output PATH [options]\n"
        "  -i, --interval SECONDS       Poll interval, integer 1..86400 (default 5)\n"
        "  -o, --output PATH            Prometheus textfile path (required)\n"
        "  -v, --verbose                Log initial services and subsequent events\n"
        "  -h, --help                   Show help\n"
        "sudo startup automatically drops to the invoking user before monitoring.\n",
        file);
}

int main(int argc, char **argv) {
  const char *output = NULL;
  long interval = 5; /* 5 secons interval*/
  bool verbose = false;
  static const struct option options[] = {
      /* getopt structure */
      {"interval", required_argument, NULL, 'i'},
      {"output", required_argument, NULL, 'o'},
      {"verbose", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };
  int option;
  while ((option = getopt_long(argc, argv, "i:o:vh", options, NULL)) != -1) {
    switch (option) {
    case 'i': {
      char *end;
      errno = 0;
      interval = strtol(optarg, &end, 10);
      if (errno || !numeric_name(optarg) || *end || interval < 1 || interval > 86400) {
        fprintf(stderr, "netmon: interval must be an integer from 1 to 86400\n"); /* max 24h */
        return EXIT_FAILURE;
      }
      break;
    }
    case 'o':
      output = optarg;
      break;
    case 'v':
      verbose = true;
      break;
    case 'h':
      usage(stdout);
      return EXIT_SUCCESS;
    default:
      usage(stderr);
      return EXIT_FAILURE;
    }
  }
  if (optind != argc || !output || strlen(output) < 5 ||
      strcmp(output + strlen(output) - 5, ".prom")) {
    fprintf(stderr, "netmon: --output is required and must end in .prom\n");
    usage(stderr);
    return EXIT_FAILURE;
  }

  if (restrict_privileges(output) < 0) {
    perror("netmon: privilege/output setup failed; refusing to monitor");
    return EXIT_FAILURE;
  }

  struct sigaction action = {.sa_handler = stop_monitor}; /* safe failure function */
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, NULL) < 0 ||
      sigaction(SIGTERM, &action, NULL) < 0) {
    perror("netmon: signal setup");
    return EXIT_FAILURE;
  }
  /* Fail early if the required diagnostic socket cannot be initialized. */
  int probe = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (probe < 0) {
    perror("netmon: Netlink initialization");
    return EXIT_FAILURE;
  }
  close(probe);
  snapshot_t previous = {0};
  counters_t counters = {0};
  bool initialized = false;
  int exit_status = EXIT_SUCCESS;
  fprintf(stderr, "netmon: monitoring exposed IPv4 TCP/UDP bindings; output=%s\n", output);

  while (running) {
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
      perror("netmon: monotonic clock");
      exit_status = EXIT_FAILURE;
      break;
    }
    deadline.tv_sec += interval;
    snapshot_t current = {0};
    bool collected = collect_services(&current) == 0;
    if (collected && running) {
      resolve_processes(&current);
      snapshot_sort(&current);
    }
    if (!running) {
      snapshot_free(&current);
      break;
    }
    if (!collected) {
      perror("netmon: collection failed; retaining previous snapshot");
      ++counters.collection_errors;
      snapshot_free(&current);
    } else {
      if (initialized)
        compare_snapshots(&previous, &current, &counters, verbose);
      else if (verbose)
        for (size_t i = 0; i < current.count; i = group_end(&current, i))
          log_service("initial", &current.items[i]);
      snapshot_free(&previous);
      previous = current;
      initialized = true;
      counters.last_success = time(NULL);
    }
    if (publish_metrics(output, &previous, &counters, initialized) < 0)
      perror("netmon: metrics publication failed");
    int error;
    while (running && (error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                                               &deadline, NULL)) != 0) {
      if (error != EINTR) {
        errno = error;
        perror("netmon: sleep");
        exit_status = EXIT_FAILURE;
        running = 0;
      }
    }
  }
  snapshot_free(&previous);
  return exit_status;
}
